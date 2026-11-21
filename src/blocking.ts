/**
 * @fileoverview Blocking: the blocklist, regex block and allow rules, and CNAME
 * uncloaking. The lists themselves are loaded by blocklist.ts.
 */

import {isBlocked} from './blockset.js';
import {peekBlocklist, peekRules} from './blocklist.js';
import {BLOCK_REBINDING, CNAME_UNCLOAK} from './config.js';
import {EDE_BLOCKED, RCODE_NXDOMAIN, TTL_BLOCKED} from './constants.js';
import {cnameTargets, respondNegative} from './response.js';
import {parseAnswers, type DnsRecord} from './wire.js';
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
    blocked: true,
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
 * Checks of an answer for a name that is not blocked. Each says why the
 * answer must not be used, or gives null. They run on every response, also
 * cached ones, and are not stored in the cache, so newer rules apply to
 * cached answers too.
 */
const SCREENS: Array<{
  enabled: boolean;
  reason: (result: Result, answers: DnsRecord[]) => string | null;
}> = [
  {
    // DNS rebinding: a name that resolves to an address in the client's own
    // network (see rebinding.ts).
    enabled: BLOCK_REBINDING,
    reason: ({body}, answers) =>
      rebindingAddress(body, answers) ? 'dns rebinding' : null,
  },
  {
    // CNAME uncloaking: a blocked CNAME target means a tracker hiding behind
    // a first-party subdomain.
    enabled: CNAME_UNCLOAK,
    reason: ({body}, answers) => {
      const target = cnameTargets(body, answers).find(blockReason);
      return target ? `CNAME target ${target} is blocked` : null;
    },
  },
];

/**
 * What the answer for a name that is not blocked must pass (see SCREENS); an
 * allow rule exempts the name. The answer section is read once.
 * @return `result`, or NXDOMAIN with the reason of the first check it fails.
 */
export function screen(q: Question, result: Result): Result {
  const answers = answersOf(result.body);
  if (!answers.length || peekRules().allow?.test(q.name)) {
    return result; // Nothing in it to check, or the name is allowed.
  }
  for (const {enabled, reason} of SCREENS) {
    const why = enabled ? reason(result, answers) : null;
    if (why) {
      return nxdomain(q, why);
    }
  }
  return result;
}
