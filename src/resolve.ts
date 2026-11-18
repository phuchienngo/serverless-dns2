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
  CNAME_UNCLOAK,
  ECS_ENABLED,
  REDIRECTS,
  TYPE_A,
  TYPE_AAAA,
  TYPE_ANY,
  TYPE_HINFO,
  TYPE_HTTPS,
  TYPE_SVCB,
  HEDGE_MAX_MS,
  HEDGE_MIN_MS,
  UPSTREAM,
  UPSTREAM_BACKUP,
  UPSTREAM_TIMEOUT_MS,
} from './config.js';
import {
  buildQuery,
  cnameTargets,
  EDE_BLOCKED,
  EDE_STALE_ANSWER,
  addOptOption,
  copyRd,
  edeOption,
  encodeName,
  padResponse,
  minTtl,
  parseAnswers,
  respond,
  respondNegative,
  stripOpt,
  u16,
  u32,
} from './dns.js';
import {getBlocklist, isReady, peekBlocklist, peekRules} from './blocklist.js';
import {addEch, startEchProbe} from './ech.js';
import {makeEcs} from './ecs.js';
import type {Env, Question, ResolveOptions, Result} from './types.js';
import {isBlocked} from './blockset.js';
import {isUndelegated} from './undelegated.js';

const encoder = new TextEncoder();

/** Types refused locally with NODATA (see config.ts). */
const BLOCKED_TYPES = new Set<number>([
  ...(BLOCK_ANY ? [TYPE_ANY] : []),
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

/** Recent upstream latency in ms (moving average), for the hedge delay. */
let latencyAverage = 30;

/**
 * Sends a query to the upstream resolver. If it has not answered after about
 * three times its recent latency, the query is also sent on a second
 * connection (to UPSTREAM_BACKUP if set), and the first answer wins.
 */
async function forward(env: Env, wire: Uint8Array): Promise<Uint8Array> {
  const controllers = [new AbortController(), new AbortController()];
  const delay = Math.min(
    HEDGE_MAX_MS,
    Math.max(HEDGE_MIN_MS, 3 * latencyAverage)
  );
  const started = performance.now();
  let done = false;
  const hedge = async () => {
    await new Promise(resolve => setTimeout(resolve, delay));
    if (done) {
      throw new Error('not needed');
    }
    return post(UPSTREAM_BACKUP || UPSTREAM, wire, controllers[1]);
  };
  try {
    const body = await Promise.any([
      post(UPSTREAM, wire, controllers[0]),
      hedge(),
    ]);
    const elapsed = Math.min(performance.now() - started, 300);
    latencyAverage = 0.8 * latencyAverage + 0.2 * elapsed;
    return body;
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
  const result = await resolveQuestion(q, options);
  let body = copyRd(result.body, q.rd);
  if (!q.edns) {
    // The upstream always sends an OPT record; a client that sent none must
    // not get one (RFC 6891).
    body = stripOpt(body);
  } else {
    if (result.stale) {
      body = addOptOption(body, edeOption(EDE_STALE_ANSWER, ''));
    }
    if (q.padding) {
      body = padResponse(body); // Last, so that the size is final.
    }
  }
  return {...result, body};
}

/** @return A record whose owner is the question's name, class IN. */
function record(type: number, ttl: number, rdata: number[]): number[] {
  return [
    0xc0,
    12, // Owner name: pointer to the question.
    ...u16(type),
    0,
    1,
    ...u32(ttl),
    ...u16(rdata.length),
    ...rdata,
  ];
}

async function resolveQuestion(
  q: Question,
  options: ResolveOptions
): Promise<Result> {
  const {env, host} = options;

  if (q.opcode !== 0) {
    return {body: respond(q, 4, []), ttl: 0}; // NOTIMP.
  }
  if (q.ednsVersion > 0) {
    return {body: respond(q, 16, []), ttl: 0}; // BADVERS (RFC 6891).
  }

  const isDdr =
    q.type === TYPE_SVCB &&
    (q.name === '_dns.resolver.arpa' || q.name === `_dns.${host}`);
  if (isDdr) {
    return {body: ddrAnswer(q, host), ttl: 300};
  }
  if (q.name === 'localhost' || q.name.endsWith('.localhost')) {
    // RFC 6761: localhost names are the loopback address.
    const address =
      q.type === TYPE_A
        ? [record(TYPE_A, 3600, [127, 0, 0, 1])]
        : q.type === TYPE_AAAA
          ? [record(TYPE_AAAA, 3600, [...new Array(15).fill(0), 1])]
          : [];
    return {
      body: address.length
        ? respond(q, 0, address)
        : respondNegative(q, 0, 3600),
      ttl: 3600,
    };
  }
  if (BLOCK_UNDELEGATED && isUndelegated(q.name)) {
    return {body: respondNegative(q, 3, 3600), ttl: 3600};
  }

  if (BLOCKLIST_ENABLED) {
    if (!isReady()) {
      // This isolate has not loaded the blocklist yet. Start answering while
      // it loads, and discard the answer if the name turns out to be listed.
      const loading = getBlocklist(env, host, options.timing);
      const answering = answer(q, options);
      answering.catch(() => {});
      await loading;
      const reason = blockReason(q.name);
      if (reason) {
        return nxdomain(q, reason);
      }
      return uncloak(q, await answering);
    }
    const reason = blockReason(q.name);
    if (reason) {
      return nxdomain(q, reason);
    }
    return uncloak(q, await answer(q, options));
  }

  return answer(q, options);
}

/**
 * @return Why the name is blocked, or null if it is not: an allow rule wins,
 *     then the blocklist (name or a parent domain) and the regex block rules.
 */
function blockReason(name: string): string | null {
  const {block, allow} = peekRules();
  if (allow?.test(name)) {
    return null;
  }
  const hashes = peekBlocklist();
  if (hashes && isBlocked(hashes, name)) {
    return 'blocklist';
  }
  return block?.test(name) ? 'regex rule' : null;
}

/** NXDOMAIN with an Extended DNS Error saying the name was blocked. */
function nxdomain(q: Question, reason: string): Result {
  return {
    body: respondNegative(q, 3, 300, {code: EDE_BLOCKED, text: reason}),
    ttl: 300,
  };
}

/**
 * CNAME uncloaking: if any CNAME target in the answer is blocked, the name is
 * a tracker hiding behind a first-party subdomain, so answer NXDOMAIN.
 * Checked on every response (a few lookups) rather than stored in the cache,
 * so newer rules apply to cached answers too.
 */
function uncloak(q: Question, result: Result): Result {
  if (!CNAME_UNCLOAK || peekRules().allow?.test(q.name)) {
    return result;
  }
  for (const target of cnameTargets(result.body)) {
    if (blockReason(target)) {
      return nxdomain(q, `CNAME target ${target} is blocked`);
    }
  }
  return result;
}

/**
 * Answers a question that is neither special nor blocked: local rules, then
 * the caches and the upstream resolver.
 */
async function answer(q: Question, options: ResolveOptions): Promise<Result> {
  const {env, host, cache, waitUntil} = options;
  const flags = {dnssec: !!options.dnssec, cd: !!options.cd};

  if (BLOCKED_TYPES.has(q.type)) {
    if (q.type === TYPE_ANY) {
      // RFC 8482: a minimal HINFO answer.
      const text = [...encoder.encode('RFC8482')];
      const hinfo = record(TYPE_HINFO, 3600, [text.length, ...text, 0]);
      return {body: respond(q, 0, [hinfo]), ttl: 3600};
    }
    return {body: respondNegative(q, 0, 3600), ttl: 3600};
  }

  const target = REDIRECTS[q.name];
  if (target && (q.type === TYPE_SVCB || q.type === TYPE_HTTPS)) {
    // Service hints would reveal the original IPs: answer NODATA.
    return {body: respondNegative(q, 0, 60), ttl: 60};
  }

  let ecs = null;
  if (options.ecs !== undefined) {
    ecs = options.ecs;
  } else if (ECS_ENABLED && options.ip) {
    ecs = makeEcs(options.ip);
  }

  const key = cacheKey(host, q, ecs, flags.dnssec, flags.cd);
  const fetchFresh = async () => {
    const result = await coalesce(key, q, async () => {
      const probe = startEchProbe(q, ecs, wire => forward(env, wire));
      return addEch(await askUpstream(q, env, ecs, flags), q, probe);
    });
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
