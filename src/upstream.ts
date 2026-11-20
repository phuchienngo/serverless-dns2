/**
 * @fileoverview Talking to the upstream DoH resolver: hedged requests and
 * sharing one request between identical concurrent queries.
 */

import {
  HEDGE_MAX_MS,
  HEDGE_MIN_MS,
  UPSTREAM,
  UPSTREAM_BACKUP,
  UPSTREAM_TIMEOUT_MS,
} from './config.js';
import {buildQuery} from './query.js';
import {RCODE_REFUSED} from './constants.js';
import {encodeName, HEADER_BYTES, rcodeOf, u16} from './wire.js';
import {redirectedResult, redirectTarget} from './redirects.js';
import {minTtl} from './response.js';
import type {Question, Result} from './types.js';

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
    if (body.length < HEADER_BYTES) {
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
 * three times its recent latency, the query is sent again (to UPSTREAM_BACKUP
 * if set, else to UPSTREAM, usually on the same connection), and the first
 * answer wins.
 */
export async function forward(wire: Uint8Array): Promise<Uint8Array> {
  const primary = new AbortController();
  let hedged: AbortController | undefined;
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
    hedged = new AbortController();
    return post(UPSTREAM_BACKUP || UPSTREAM, wire, hedged);
  };
  try {
    const body = await Promise.any([
      post(UPSTREAM, wire, primary),
      hedge(),
    ]);
    const elapsed = Math.min(performance.now() - started, 300);
    latencyAverage = 0.8 * latencyAverage + 0.2 * elapsed;
    return body;
  } finally {
    done = true;
    primary.abort(); // Cancel the loser.
    hedged?.abort();
  }
}

/** The DNSSEC flags of a query to the upstream resolver. */
export interface QueryFlags {
  dnssec: boolean;
  cd: boolean;
  ad: boolean;
}

/**
 * @return The flags to ask the upstream with: those of the client's question.
 *     AD without DO asks for the AD flag only (RFC 6840 5.7).
 */
export function queryFlags(q: Question): QueryFlags {
  return {dnssec: q.dnssecOk, cd: q.cd, ad: q.ad && !q.dnssecOk};
}

/**
 * Sends a question to the upstream resolver. Some name servers refuse a query
 * that carries a client subnet (Akamai's, asked through Google): the question
 * is then asked once more without one (RFC 7871 7.1.3).
 */
async function ask(
  question: number[],
  ecs: number[] | null,
  flags: QueryFlags
): Promise<Uint8Array> {
  const body = await forward(buildQuery(question, ecs, flags));
  return ecs && rcodeOf(body) === RCODE_REFUSED
    ? forward(buildQuery(question, null, flags))
    : body;
}

/**
 * Asks the upstream resolver, following a CDN redirect if one applies.
 */
export async function askUpstream(
  q: Question,
  ecs: number[] | null,
  flags: QueryFlags
): Promise<Result> {
  const target = redirectTarget(q);
  if (target) {
    const question = [...encodeName(target), ...u16(q.type), 0, 1];
    return redirectedResult(await ask(question, ecs, flags), q);
  }
  const body = await ask(q.raw, ecs, flags);
  body.set(u16(q.id), 0);
  return {body, ttl: minTtl(body)};
}

/** Queries in flight, so identical concurrent ones share one upstream call. */
const pending = new Map<string, Promise<Result>>();

/** Forgets the latency average and the queries in flight (for tests). */
export function resetUpstream(): void {
  latencyAverage = 30;
  pending.clear();
}

/**
 * Copies a result for another client's question (same name, other id/case).
 */
function retarget({body, ttl}: Result, q: Question): Result {
  const copy = body.slice();
  copy.set(u16(q.id), 0);
  copy.set(q.raw, HEADER_BYTES);
  return {body: copy, ttl};
}

/**
 * Runs `task` once per `key` at a time: concurrent callers share its result.
 */
export async function coalesce(
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
