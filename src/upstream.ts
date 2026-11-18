/**
 * @fileoverview Talking to the upstream DoH resolver: hedged requests and
 * sharing one request between identical concurrent queries.
 */

import {
  HEDGE_MAX_MS,
  HEDGE_MIN_MS,
  REDIRECTS,
  UPSTREAM,
  UPSTREAM_BACKUP,
  UPSTREAM_TIMEOUT_MS,
} from './config.js';
import {TYPE_A, TYPE_AAAA} from './constants.js';
import {
  buildQuery,
  encodeName,
  minTtl,
  parseAnswers,
  QUESTION_POINTER,
  respond,
  u16,
} from './dns.js';
import type {Env, Question, Result} from './types.js';

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
export async function forward(env: Env, wire: Uint8Array): Promise<Uint8Array> {
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
      ...QUESTION_POINTER,
      ...resp.subarray(a.start, a.start + 10 + a.length),
    ]);
  return {body: respond(q, rcode, records), ttl: minTtl(resp)};
}

/**
 * Asks the upstream resolver, following a CDN redirect if one applies.
 */
export async function askUpstream(
  q: Question,
  env: Env,
  ecs: number[] | null,
  flags: {dnssec: boolean; cd: boolean; ad: boolean}
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
