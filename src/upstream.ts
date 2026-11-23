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
import {noSubnet} from './ecs.js';
import {buildQuery} from './query.js';
import {RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED} from './constants.js';
import {
  encodeName,
  FLAG_QR_OR_RA,
  HEADER_BYTES,
  questionCount,
  rcodeOf,
  readRecords,
  u16,
  type DnsRecord,
} from './wire.js';
import {redirectedResult, redirectTarget} from './redirects.js';
import {minTtl} from './response.js';
import type {Question, Result} from './types.js';

interface UpstreamReply {
  body: Uint8Array;
  records: DnsRecord[];
}

const lower = (b: Uint8Array) => b.map(c => (c >= 65 && c <= 90 ? c + 32 : c));

/**
 * @return Whether `reply` answers `query`: the same id and the same question
 *     (compared without regard to case, which an upstream may change). A reply
 *     with no question is only an error reply.
 */
function answers(query: Uint8Array, reply: Uint8Array): boolean {
  if (reply[0] !== query[0] || reply[1] !== query[1]) {
    return false;
  }
  if (questionCount(reply) === 0) {
    return ![RCODE_NOERROR, RCODE_NXDOMAIN].includes(rcodeOf(reply));
  }
  let end = HEADER_BYTES; // The end of the query's name.
  while (query[end] !== 0) {
    end += query[end] + 1;
  }
  end += 1 + 4; // Root label, type and class.
  return (
    questionCount(reply) === 1 &&
    reply.length >= end &&
    lower(reply.subarray(HEADER_BYTES, end)).every(
      (c, i) => c === lower(query.subarray(HEADER_BYTES, end))[i]
    )
  );
}

/**
 * Sends a query to one DoH resolver.
 */
async function post(
  url: string,
  wire: Uint8Array,
  controller: AbortController
): Promise<UpstreamReply> {
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
    if (
      body.length < HEADER_BYTES ||
      (body[2] & FLAG_QR_OR_RA) === 0 ||
      !answers(wire, body)
    ) {
      throw new Error('bad upstream response');
    }
    return {body, records: readRecords(body)};
  } finally {
    clearTimeout(timer);
  }
}

/** Recent upstream latency in ms (moving average), for the hedge delay. */
let latencyAverage = 30;

function recordLatency(started: number): void {
  const elapsed = Math.min(performance.now() - started, 300);
  latencyAverage = 0.8 * latencyAverage + 0.2 * elapsed;
}

/**
 * Sends a query to the upstream resolver. If it has not answered after about
 * three times its recent latency, the query is sent again (to UPSTREAM_BACKUP
 * if set, else to UPSTREAM, usually on the same connection), and the first
 * answer wins.
 */
async function forward(wire: Uint8Array): Promise<UpstreamReply> {
  const primary = new AbortController();
  let hedged: AbortController | undefined;
  const delay = Math.min(
    HEDGE_MAX_MS,
    Math.max(HEDGE_MIN_MS, 3 * latencyAverage)
  );
  const started = performance.now();
  const preferred = post(UPSTREAM, wire, primary);
  let timer: ReturnType<typeof setTimeout> | null = null;
  const backup = new Promise<UpstreamReply>((resolve, reject) => {
    timer = setTimeout(() => {
      hedged = new AbortController();
      post(UPSTREAM_BACKUP ?? UPSTREAM, wire, hedged).then(resolve, reject);
    }, delay);
  });
  try {
    const reply = await Promise.any([preferred, backup]);
    recordLatency(started);
    return reply;
  } finally {
    clearTimeout(timer);
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
 * Sends one query with ECS and one without, in parallel. The ECS answer takes
 * precedence unless it is REFUSED (RFC 7871 7.1.3) or fails. Both are hedged, so a slow
 * upstream connection does not hold either of them back.
 */
export async function queryUpstream(
  question: number[],
  ecs: number[] | null,
  flags?: QueryFlags
): Promise<UpstreamReply> {
  const preferred = forward(buildQuery(question, ecs ?? noSubnet(), flags));
  if (!ecs) {
    return preferred;
  }
  const fallback = forward(buildQuery(question, noSubnet(), flags));
  void fallback.catch(() => {}); // Only read if the ECS answer is unusable.
  try {
    const reply = await preferred;
    return rcodeOf(reply.body) === RCODE_REFUSED ? fallback : reply;
  } catch {
    return fallback; // The subnet query failed; the other one may not have.
  }
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
    const {body, records} = await queryUpstream(question, ecs, flags);
    return redirectedResult(body, q, records);
  }
  const {body, records} = await queryUpstream(q.raw, ecs, flags);
  body.set(u16(q.id), 0);
  if (questionCount(body) === 1) {
    body.set(q.raw, HEADER_BYTES); // The client's own case (RFC 4343).
  }
  return {body, ttl: minTtl(body, records)};
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
  if (questionCount(body) === 1) {
    copy.set(q.raw, HEADER_BYTES);
  }
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
