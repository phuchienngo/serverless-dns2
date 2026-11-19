/**
 * @fileoverview DNS64 (RFC 6147): an AAAA answer made from A records, for
 * clients that reach IPv4-only hosts through a NAT64 gateway.
 */

import {DNS64_PREFIX} from './config.js';
import {RCODE_NOERROR, TYPE_A, TYPE_AAAA} from './constants.js';
import {
  makeQuestion,
  makeRecord,
  parseAnswers,
  rcodeOf,
  respond,
} from './dns.js';
import type {Question, Result} from './types.js';

/**
 * IPv4 blocks that are never embedded (RFC 6052 3.1, RFC 8215): private,
 * loopback, link-local, documentation, benchmarking, multicast and reserved
 * addresses, as [address, prefix length].
 */
const NOT_GLOBAL: Array<[number[], number]> = [
  [[0, 0, 0, 0], 8],
  [[10, 0, 0, 0], 8],
  [[100, 64, 0, 0], 10],
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16],
  [[172, 16, 0, 0], 12],
  [[192, 0, 0, 0], 24],
  [[192, 0, 2, 0], 24],
  [[192, 88, 99, 0], 24],
  [[192, 168, 0, 0], 16],
  [[198, 18, 0, 0], 15],
  [[198, 51, 100, 0], 24],
  [[203, 0, 113, 0], 24],
  [[224, 0, 0, 0], 3],
];

const toNumber = (a: number[]) =>
  ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0;

function isGlobal(address: number[]): boolean {
  const n = toNumber(address);
  return !NOT_GLOBAL.some(([base, bits]) => {
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) >>> 0 === (toNumber(base) & mask) >>> 0;
  });
}

/**
 * Synthesizes AAAA records when an AAAA answer has none (RFC 6147 5.1.2).
 * Not done for a client that validates DNSSEC (DO without CD, 5.5): it would
 * reject them. The records are owned by the question name, their TTL is the
 * smaller of the A record's and the AAAA answer's (5.1.7).
 * @param result The answer to the AAAA question.
 * @param lookup Resolves the A question.
 * @param memo Keeps what is synthesized, so that the A lookup is not repeated.
 * @return `result` itself if nothing is synthesized.
 */
export async function synthesize(
  q: Question,
  result: Result,
  lookup: (q: Question) => Promise<Result>,
  memo: {get: () => Result | null; set: (result: Result) => void}
): Promise<Result> {
  if (
    q.type !== TYPE_AAAA ||
    (q.dnssecOk && !q.cd) ||
    rcodeOf(result.body) !== RCODE_NOERROR ||
    parseAnswers(result.body).some(r => r.type === TYPE_AAAA)
  ) {
    return result;
  }
  const memoized = memo.get();
  if (memoized) {
    return memoized;
  }
  const a = await lookup(
    makeQuestion(q.name, TYPE_A, {dnssecOk: q.dnssecOk, cd: q.cd})
  ).catch(() => null); // The AAAA answer stands if the A lookup fails.
  if (!a || rcodeOf(a.body) !== RCODE_NOERROR) {
    return result;
  }
  const records = parseAnswers(a.body)
    .filter(r => r.type === TYPE_A && r.length === 4)
    .map(r => ({ttl: r.ttl, address: [...a.body.subarray(r.data, r.end)]}))
    .filter(r => isGlobal(r.address))
    .map(r => ({
      ttl: Math.min(r.ttl, result.ttl),
      rdata: [...DNS64_PREFIX, ...r.address],
    }));
  if (!records.length) {
    return result;
  }
  const synthesized = {
    body: respond(
      q,
      RCODE_NOERROR,
      records.map(r => makeRecord(TYPE_AAAA, r.ttl, r.rdata))
    ),
    ttl: Math.min(...records.map(r => r.ttl)),
    stale: result.stale || a.stale,
  };
  memo.set(synthesized);
  return synthesized;
}
