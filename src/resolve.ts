/**
 * @fileoverview Resolves one question: DDR, CDN redirects, edge cache and the
 * upstream resolver. Shared by the `/dns-query` and `/resolve` endpoints.
 */

import {lookupLocal, lookupShared, store} from './cache.js';
import {
  BLOCKLIST_ENABLED,
  BLOCK_AAAA,
  BLOCK_ANY,
  BLOCK_HTTPS,
  BLOCK_PTR,
  BLOCK_UNDELEGATED,
  ECS_ENABLED,
  REDIRECTS,
  TYPE_A,
  TYPE_AAAA,
  TYPE_HTTPS,
  TYPE_SVCB,
  HEDGE_DELAY_MS,
  UPSTREAM_TIMEOUT_MS,
} from './config.js';
import {
  buildQuery,
  encodeName,
  minTtl,
  parseAnswers,
  respond,
  u16,
} from './dns.js';
import {getBlocklist} from './blocklist.js';
import {addEch} from './ech.js';
import {makeEcs} from './ecs.js';
import type {Env, Question, ResolveOptions, Result} from './types.js';
import {isBlocked} from './trie.js';
import {isUndelegated} from './undelegated.js';

const encoder = new TextEncoder();

/** Types refused locally with NODATA (see config.ts). */
const BLOCKED_TYPES = new Set<number>([
  ...(BLOCK_ANY ? [255] : []),
  ...(BLOCK_AAAA ? [TYPE_AAAA] : []),
  ...(BLOCK_PTR ? [12] : []),
  ...(BLOCK_HTTPS ? [TYPE_HTTPS] : []),
]);

/**
 * Sends a query to one DoH resolver.
 */
async function post(
  url: string,
  wire: Uint8Array,
  controller: AbortController
): Promise<Uint8Array> {
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        accept: 'application/dns-message',
      },
      body: wire,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`upstream ${response.status}`);
    }
    const body = new Uint8Array(await response.arrayBuffer());
    if (body.length < 12) {
      throw new Error('short upstream response');
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Sends a query to the upstream resolver. If it has not answered within
 * HEDGE_DELAY_MS, the query is also sent on a second connection (to
 * UPSTREAM_BACKUP if set), and the first answer wins.
 */
async function forward(env: Env, wire: Uint8Array): Promise<Uint8Array> {
  const controllers = [new AbortController(), new AbortController()];
  let done = false;
  const hedge = async () => {
    await new Promise(resolve => setTimeout(resolve, HEDGE_DELAY_MS));
    if (done) {
      throw new Error('not needed');
    }
    return post(env.UPSTREAM_BACKUP || env.UPSTREAM, wire, controllers[1]);
  };
  try {
    return await Promise.any([
      post(env.UPSTREAM, wire, controllers[0]),
      hedge(),
    ]);
  } finally {
    done = true;
    controllers.forEach(c => c.abort()); // Cancel the loser.
  }
}

/**
 * Answers the original question with only the A/AAAA records of `resp`.
 * @param resp Upstream response for the redirect target.
 * @param q The question the client asked.
 */
function redirected(resp: Uint8Array, q: Question): Result {
  const rcode = resp[3] & 15;
  const records = parseAnswers(resp)
    .filter(a => a.type === TYPE_A || a.type === TYPE_AAAA)
    .map(a => [
      0xc0,
      12, // Owner name: pointer to the question.
      ...resp.subarray(a.start, a.start + 10 + a.length),
    ]);
  return {body: respond(q, rcode, records), ttl: minTtl(resp)};
}

/**
 * Builds the Discovery of Designated Resolvers answer (RFC 9462).
 * @param host This gateway's hostname.
 */
function ddrAnswer(q: Question, host: string): Uint8Array {
  const alpn = [0, 1, 0, 6, 2, 104, 50, 2, 104, 51]; // Key 1: "h2", "h3".
  const path = encoder.encode('/dns-query{?dns}');
  const rdata = [
    0,
    1, // Priority 1.
    ...encodeName(host),
    ...alpn,
    0,
    7,
    ...u16(path.length),
    ...path, // Key 7: dohpath.
  ];
  const record = [
    0xc0,
    12, // Owner name: pointer to the question.
    0,
    TYPE_SVCB,
    0,
    1, // Class IN.
    0,
    0,
    1,
    44, // TTL 300.
    ...u16(rdata.length),
    ...rdata,
  ];
  return respond(q, 0, [record]);
}

/**
 * Cache key: name, type, client subnet and DNSSEC flags.
 * @return A URL, as the Cache API only accepts requests as keys.
 */
function cacheKey(
  host: string,
  q: Question,
  ecs: number[] | null,
  dnssec: boolean,
  cd: boolean
): string {
  const subnet = ecs ? ecs.slice(4).join('-') : 'none';
  const flags = `${+dnssec}${+cd}`;
  const name = encodeURIComponent(q.name);
  return `https://${host}/__cache/${name}/${q.type}/${subnet}/${flags}`;
}

/**
 * Asks the upstream resolver, following a CDN redirect if one applies.
 */
async function askUpstream(
  q: Question,
  env: Env,
  ecs: number[] | null,
  flags: {dnssec: boolean; cd: boolean}
): Promise<Result> {
  const target = REDIRECTS[q.name];
  if (target && (q.type === TYPE_A || q.type === TYPE_AAAA)) {
    const question = [...encodeName(target), ...u16(q.type), 0, 1];
    const resp = await forward(env, buildQuery(question, ecs, flags));
    return redirected(resp, q);
  }
  const body = await forward(env, buildQuery(q.raw, ecs, flags));
  body.set(u16(q.id), 0);
  return {body, ttl: minTtl(body)};
}

/** Queries in flight, so identical concurrent ones share one upstream call. */
const pending = new Map<string, Promise<Result>>();

/**
 * Copies a result for another client's question (same name, other id/case).
 */
function retarget({body, ttl}: Result, q: Question): Result {
  const copy = body.slice();
  copy.set(u16(q.id), 0);
  copy.set(q.raw, 12);
  return {body: copy, ttl};
}

/**
 * Runs `task` once per `key` at a time: concurrent callers share its result.
 */
async function coalesce(
  key: string,
  q: Question,
  task: () => Promise<Result>
): Promise<Result> {
  const joined = pending.get(key);
  if (joined) {
    try {
      return retarget(await joined, q);
    } catch {
      // The other request failed; fall through and try on our own.
    }
  }
  const own = task();
  pending.set(key, own);
  const done = () => {
    if (pending.get(key) === own) {
      pending.delete(key);
    }
  };
  own.then(done, done);
  return own;
}

/**
 * Resolves a question.
 * @throws If the upstream resolver fails.
 */
export async function resolve(
  q: Question,
  options: ResolveOptions
): Promise<Result> {
  const {env, host, cache, waitUntil} = options;
  const flags = {dnssec: !!options.dnssec, cd: !!options.cd};

  const isDdr =
    q.type === TYPE_SVCB &&
    (q.name === '_dns.resolver.arpa' || q.name === `_dns.${host}`);
  if (isDdr) {
    return {body: ddrAnswer(q, host), ttl: 300};
  }
  if (BLOCK_UNDELEGATED && isUndelegated(q.name)) {
    return {body: respond(q, 3, []), ttl: 3600};
  }

  if (BLOCKLIST_ENABLED) {
    const blocklist = await getBlocklist(env, host, options.timing);
    if (blocklist && isBlocked(blocklist, q.name)) {
      return {body: respond(q, 3, []), ttl: 300}; // NXDOMAIN.
    }
  }

  if (BLOCKED_TYPES.has(q.type)) {
    return {body: respond(q, 0, []), ttl: 3600};
  }

  const target = REDIRECTS[q.name];
  if (target && (q.type === TYPE_SVCB || q.type === TYPE_HTTPS)) {
    // Service hints would reveal the original IPs: answer NODATA.
    return {body: respond(q, 0, []), ttl: 60};
  }

  let ecs = null;
  if (options.ecs !== undefined) {
    ecs = options.ecs;
  } else if (ECS_ENABLED && options.ip) {
    ecs = makeEcs(options.ip);
  }

  const key = cacheKey(host, q, ecs, flags.dnssec, flags.cd);
  const fetchFresh = async () => {
    const result = await coalesce(key, q, async () =>
      addEch(q, await askUpstream(q, env, ecs, flags), ecs, wire =>
        forward(env, wire)
      )
    );
    store(cache, key, result, waitUntil);
    return result;
  };
  const refreshInBackground = () => {
    const refreshing = fetchFresh().catch(() => {});
    waitUntil?.(refreshing);
  };

  // 1. Memory: instant. A stale or expiring answer is served at once and
  //    renewed in the background.
  const local = lookupLocal(key, q);
  if (local) {
    if (local.refresh) {
      refreshInBackground();
    }
    return local.result;
  }

  // 2. The Cache API and the upstream resolver race: whichever answers first
  //    wins (reading the Cache API can take longer than asking the upstream).
  //    The upstream call always finishes, so it renews the cache either way.
  const started = performance.now();
  const fetching = fetchFresh();
  waitUntil?.(fetching.catch(() => {}));
  const shared = lookupShared(cache, key, q).catch(() => null);
  const first = await Promise.race([
    shared.then(hit => hit?.result ?? null),
    fetching.catch(() => null),
  ]);
  if (options.timing) {
    options.timing.first = performance.now() - started;
  }
  if (first) {
    return first;
  }
  // The Cache API had nothing, or the upstream failed: use what is left.
  const hit = await shared;
  return hit ? hit.result : fetching;
}
