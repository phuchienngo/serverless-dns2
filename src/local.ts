/**
 * @fileoverview Answers that need no upstream: queries that are refused, and
 * names and types the gateway answers itself (DDR, localhost, undelegated
 * names, ANY).
 */

import {BLOCK_ANY, BLOCK_UNDELEGATED} from './config.js';
import {
  ALPN_HTTP,
  CLASS_IN,
  EDE_PRODUCED,
  RCODE_BADVERS,
  RCODE_FORMERR,
  RCODE_NOERROR,
  RCODE_NOTIMP,
  RCODE_NXDOMAIN,
  RCODE_REFUSED,
  SVCPARAM_ALPN,
  SVCPARAM_DOHPATH,
  TTL_DISCOVERY,
  TTL_LOCAL,
  TTL_UNCACHED,
  TYPES_FORMERR,
  TYPES_NOTIMP,
  TYPE_A,
  TYPE_AAAA,
  TYPE_ANY,
  TYPE_HINFO,
  TYPE_RESINFO,
  TYPE_SVCB,
} from './constants.js';
import {utf8} from './wire.js';
import {redirectedHints} from './redirects.js';
import {makeRecord, respond, respondNegative} from './response.js';
import {alpnValue, svcbRdata} from './svcb.js';
import type {Question, Result} from './types.js';
import {isUndelegated} from './undelegated.js';

const FORMERR_TYPES = new Set(TYPES_FORMERR);
const NOTIMP_TYPES = new Set(TYPES_NOTIMP);

/**
 * Builds the Discovery of Designated Resolvers answer (RFC 9462).
 * @param host This gateway's hostname.
 */
export function ddrAnswer(
  q: Question,
  host: string,
  hints: number[][] = []
): Uint8Array {
  const rdata = svcbRdata(1, host, [
    [SVCPARAM_ALPN, alpnValue(ALPN_HTTP)],
    [SVCPARAM_DOHPATH, utf8('/dns-query{?dns}')],
  ]);
  const record = makeRecord(TYPE_SVCB, TTL_DISCOVERY, rdata);
  return respond(q, RCODE_NOERROR, [record], undefined, hints);
}

/** Resolver information (RFC 9606) lists the Extended DNS Errors we produce. */
function resinfo(q: Question): Result {
  const exterr = utf8(`exterr=${EDE_PRODUCED.join(',')}`);
  const record = makeRecord(TYPE_RESINFO, TTL_DISCOVERY, [
    exterr.length,
    ...exterr,
  ]);
  return {body: respond(q, RCODE_NOERROR, [record]), ttl: TTL_DISCOVERY};
}

/** @return Whether this is the DDR query for this gateway (RFC 9462). */
export function isDdr(q: Question, host: string): boolean {
  return (
    q.type === TYPE_SVCB &&
    (q.name === '_dns.resolver.arpa' || q.name === `_dns.${host}`)
  );
}

/** An error response with no records, which clients should not cache. */
function error(q: Question, rcode: number): Result {
  return {body: respond(q, rcode, []), ttl: TTL_UNCACHED};
}

/**
 * @return The response code for a question that must not be resolved, or null.
 */
function refuseQuestion(q: Question): number | null {
  if (q.malformed) {
    return RCODE_FORMERR; // RFC 6891 6.1.1.
  }
  if (q.opcode !== 0) {
    return RCODE_NOTIMP;
  }
  if (q.ednsVersion > 0) {
    return RCODE_BADVERS; // RFC 6891 6.1.3.
  }
  if (FORMERR_TYPES.has(q.type)) {
    return RCODE_FORMERR;
  }
  if (NOTIMP_TYPES.has(q.type)) {
    return RCODE_NOTIMP;
  }
  const [classHigh, classLow] = q.raw.slice(-2);
  if (((classHigh << 8) | classLow) !== CLASS_IN) {
    return RCODE_REFUSED; // The cache key has no class: serve IN only.
  }
  return null;
}

/** RFC 6761: localhost names are the loopback address. */
function localhost(q: Question): Result {
  const address =
    q.type === TYPE_A
      ? [makeRecord(TYPE_A, TTL_LOCAL, [127, 0, 0, 1])]
      : q.type === TYPE_AAAA
        ? [makeRecord(TYPE_AAAA, TTL_LOCAL, [...new Array(15).fill(0), 1])]
        : [];
  return {
    body: address.length
      ? respond(q, RCODE_NOERROR, address)
      : respondNegative(q, RCODE_NOERROR, TTL_LOCAL),
    ttl: TTL_LOCAL,
  };
}

/**
 * Answers a question that is refused or special: invalid queries,
 * `resolver.arpa` (except the DDR query itself), localhost and undelegated names.
 * @return Null if the name must be resolved normally.
 */
export function localAnswer(q: Question, host: string): Result | null {
  const refusal = refuseQuestion(q);
  if (refusal !== null) {
    return error(q, refusal);
  }
  if (isDdr(q, host)) {
    return null; // Needs the resolver's addresses: see resolve.ts.
  }
  if (q.type === TYPE_RESINFO && q.name === host) {
    return resinfo(q);
  }
  if (q.name === 'resolver.arpa' || q.name.endsWith('.resolver.arpa')) {
    // RFC 9462: reserved for DDR; never forwarded.
    return {
      body: respondNegative(q, RCODE_NOERROR, TTL_DISCOVERY),
      ttl: TTL_DISCOVERY,
    };
  }
  if (q.name === 'localhost' || q.name.endsWith('.localhost')) {
    return localhost(q);
  }
  if (BLOCK_UNDELEGATED && isUndelegated(q.name)) {
    return {
      body: respondNegative(q, RCODE_NXDOMAIN, TTL_LOCAL),
      ttl: TTL_LOCAL,
    };
  }
  return null;
}

/**
 * Answers ANY (see config.ts), and HTTPS/SVCB queries for redirected names.
 * @return Null if the question is forwarded.
 */
export function typeAnswer(q: Question): Result | null {
  if (BLOCK_ANY && q.type === TYPE_ANY) {
    // RFC 8482: a minimal HINFO answer.
    const text = utf8('RFC8482');
    const hinfo = makeRecord(TYPE_HINFO, TTL_LOCAL, [text.length, ...text, 0]);
    return {body: respond(q, RCODE_NOERROR, [hinfo]), ttl: TTL_LOCAL};
  }
  return redirectedHints(q);
}
