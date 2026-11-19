/**
 * @fileoverview Blocking: the blocklist, regex block and allow rules, and CNAME
 * uncloaking. The lists themselves are loaded by blocklist.ts.
 */

import {isBlocked} from './blockset.js';
import {peekBlocklist, peekRules} from './blocklist.js';
import {BLOCK_REBINDING, CNAME_UNCLOAK} from './config.js';
import {EDE_BLOCKED, RCODE_NXDOMAIN, TTL_BLOCKED} from './constants.js';
import {
  cnameTargets,
  parseAnswers,
  respondNegative,
  type DnsRecord,
} from './dns.js';
import {rebindingAddress} from './rebinding.js';
import type {Question, Result} from './types.js';

/**
 * @return Why the name is blocked, or null if it is not: an allow rule wins,
 *     then the blocklist (name or a parent domain) and the regex block rules.
 */
export function blockReason(name: string): string | null {
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
export function nxdomain(q: Question, reason: string): Result {
  return {
    body: respondNegative(q, RCODE_NXDOMAIN, TTL_BLOCKED, {
      code: EDE_BLOCKED,
      text: reason,
    }),
    ttl: TTL_BLOCKED,
  };
}

/** The records of the answer section; none if the message cannot be read. */
function answersOf(body: Uint8Array): DnsRecord[] {
  try {
    return parseAnswers(body);
  } catch {
    return [];
  }
}

/**
 * CNAME uncloaking: if any CNAME target in the answer is blocked, the name is
 * a tracker hiding behind a first-party subdomain, so answer NXDOMAIN.
 * Checked on every response (a few lookups) rather than stored in the cache,
 * so newer rules apply to cached answers too.
 * @param answers The records of the answer section, if already read.
 */
export function uncloak(
  q: Question,
  result: Result,
  answers?: DnsRecord[]
): Result {
  if (!CNAME_UNCLOAK || peekRules().allow?.test(q.name)) {
    return result;
  }
  for (const target of cnameTargets(result.body, answers)) {
    if (blockReason(target)) {
      return nxdomain(q, `CNAME target ${target} is blocked`);
    }
  }
  return result;
}

/**
 * DNS rebinding: a name that resolves to an address in the client's own
 * network gets NXDOMAIN (see rebinding.ts). Like uncloaking, it is checked on
 * every response and not stored in the cache.
 * @param answers The records of the answer section, if already read.
 */
export function rebinding(
  q: Question,
  result: Result,
  answers?: DnsRecord[]
): Result {
  if (!BLOCK_REBINDING || peekRules().allow?.test(q.name)) {
    return result;
  }
  return rebindingAddress(result.body, answers)
    ? nxdomain(q, 'dns rebinding')
    : result;
}

/**
 * What the answer for a name that is not blocked must pass: the rebinding
 * and uncloaking checks, which read the answer section once.
 */
export function screen(q: Question, result: Result): Result {
  const answers = answersOf(result.body);
  if (!answers.length) {
    return result; // Nothing in it to check.
  }
  const rebound = rebinding(q, result, answers);
  return rebound === result ? uncloak(q, result, answers) : rebound;
}
