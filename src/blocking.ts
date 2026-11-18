/**
 * @fileoverview Blocking: the blocklist, regex block and allow rules, and CNAME
 * uncloaking. The lists themselves are loaded by blocklist.ts.
 */

import {isBlocked} from './blockset.js';
import {peekBlocklist, peekRules} from './blocklist.js';
import {CNAME_UNCLOAK} from './config.js';
import {EDE_BLOCKED, RCODE_NXDOMAIN, TTL_BLOCKED} from './constants.js';
import {cnameTargets, respondNegative} from './dns.js';
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

/**
 * CNAME uncloaking: if any CNAME target in the answer is blocked, the name is
 * a tracker hiding behind a first-party subdomain, so answer NXDOMAIN.
 * Checked on every response (a few lookups) rather than stored in the cache,
 * so newer rules apply to cached answers too.
 */
export function uncloak(q: Question, result: Result): Result {
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
