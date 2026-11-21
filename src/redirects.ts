/**
 * @fileoverview Redirects (REDIRECTS in config.ts): a name is answered with
 * the A and AAAA records of another name, as if they were its own. Nothing
 * here is signed, so a client that asks for DNSSEC records (DO) is not
 * redirected, like ECH and DNS64 do.
 */

import {REDIRECTS} from './config.js';
import {
  RCODE_NOERROR,
  TTL_SHORT,
  TYPE_A,
  TYPE_AAAA,
  TYPE_HTTPS,
  TYPE_SVCB,
} from './constants.js';
import {minTtl, respond, respondNegative} from './response.js';
import {QUESTION_POINTER, rcodeOf, type DnsRecord} from './wire.js';
import type {Question, Result} from './types.js';

/**
 * @return The name to ask for an A or AAAA question, if its name is
 *     redirected; null otherwise.
 */
export function redirectTarget(q: Question): string | null {
  const isAddress = q.type === TYPE_A || q.type === TYPE_AAAA;
  return !q.dnssecOk && isAddress ? (REDIRECTS[q.name] ?? null) : null;
}

/**
 * @return NODATA for an HTTPS or SVCB question of a redirected name: their
 *     service hints would reveal the original addresses. Null otherwise.
 */
export function redirectedHints(q: Question): Result | null {
  const isService = q.type === TYPE_SVCB || q.type === TYPE_HTTPS;
  if (q.dnssecOk || !isService || !REDIRECTS[q.name]) {
    return null;
  }
  return {
    body: respondNegative(q, RCODE_NOERROR, TTL_SHORT),
    ttl: TTL_SHORT,
  };
}

/**
 * Answers the original question with only the A/AAAA records of `resp`.
 * @param resp The upstream response for the redirect target.
 * @param q The question the client asked.
 */
export function redirectedResult(
  resp: Uint8Array,
  q: Question,
  records: readonly DnsRecord[]
): Result {
  const addresses = records
    .filter(
      a => a.section === 'answer' && (a.type === TYPE_A || a.type === TYPE_AAAA)
    )
    .map(a => [...QUESTION_POINTER, ...resp.subarray(a.start, a.end)]);
  return {body: respond(q, rcodeOf(resp), addresses), ttl: minTtl(resp, records)};
}
