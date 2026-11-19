/**
 * @fileoverview DNS64 (RFC 6147): an AAAA answer made from A records, for
 * clients that reach IPv4-only hosts through a NAT64 gateway.
 */

import {lookupLocal, store} from './cache.js';
import {DNS64_PREFIX} from './config.js';
import {
  RCODE_NOERROR,
  RCODE_NXDOMAIN,
  TTL_LOCAL,
  TYPE_A,
  TYPE_AAAA,
  TYPE_CNAME,
  TYPE_PTR,
} from './constants.js';
import {
  makeQuestion,
  makeRecord,
  encodeName,
  parseAnswers,
  readName,
  rcodeOf,
  respond,
} from './dns.js';
import {inBlocks, type Ipv4Block} from './ipv4.js';
import type {Question, Result} from './types.js';

/**
 * IPv4 blocks that are never embedded (RFC 6052 3.1, RFC 8215): private,
 * loopback, link-local, documentation, benchmarking, multicast and reserved
 * addresses, as [address, prefix length].
 */
const NOT_GLOBAL: Ipv4Block[] = [
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

const isGlobal = (address: number[]) => !inBlocks(address, NOT_GLOBAL);

/** The A records `ipv4only.arpa` has (RFC 7050): never global addresses. */
const IPV4ONLY = 'ipv4only.arpa';
const IPV4ONLY_ADDRESSES = [
  [192, 0, 0, 170],
  [192, 0, 0, 171],
];

/**
 * The AAAA answer for `ipv4only.arpa` (RFC 7050): its two addresses inside the
 * prefix, which is how a client learns the prefix. Made locally.
 * @return Null for any other question.
 */
export function ipv4onlyAnswer(q: Question): Result | null {
  if (q.type !== TYPE_AAAA || q.name !== IPV4ONLY) {
    return null;
  }
  const records = IPV4ONLY_ADDRESSES.map(a =>
    makeRecord(TYPE_AAAA, TTL_LOCAL, [...DNS64_PREFIX, ...a])
  );
  return {body: respond(q, RCODE_NOERROR, records), ttl: TTL_LOCAL};
}

/**
 * @return The IPv4 address that a `ip6.arpa` name stands for, if the address
 *     it names is inside the NAT64 prefix.
 */
function embeddedAddress(name: string): number[] | null {
  const suffix = '.ip6.arpa';
  if (!name.endsWith(suffix)) {
    return null;
  }
  const nibbles = name.slice(0, -suffix.length).split('.');
  if (nibbles.length !== 32 || !nibbles.every(n => /^[0-9a-f]$/.test(n))) {
    return null;
  }
  const bytes: number[] = [];
  const forward = nibbles.reverse().map(n => parseInt(n, 16));
  for (let i = 0; i < 32; i += 2) {
    bytes.push((forward[i] << 4) | forward[i + 1]);
  }
  const inPrefix = DNS64_PREFIX.every((b, i) => bytes[i] === b);
  return inPrefix ? bytes.slice(12) : null;
}

/** The AAAA answer made from the A records of the name (RFC 6147 5.1). */
async function synthesizeAaaa(
  q: Question,
  result: Result,
  lookup: (q: Question) => Promise<Result>
): Promise<Result | null> {
  const a = await lookup(
    makeQuestion(q.name, TYPE_A, {dnssecOk: q.dnssecOk, cd: q.cd})
  ).catch(() => null); // The AAAA answer stands if the A lookup fails.
  if (!a || rcodeOf(a.body) !== RCODE_NOERROR) {
    return null;
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
    return null;
  }
  return {
    body: respond(
      q,
      RCODE_NOERROR,
      records.map(r => makeRecord(TYPE_AAAA, r.ttl, r.rdata))
    ),
    ttl: Math.min(...records.map(r => r.ttl)),
    stale: result.stale || a.stale,
  };
}

/**
 * The PTR answer for an address inside the prefix (RFC 6147 5.3.1): a CNAME to
 * the reverse name of the embedded IPv4 address, then that name's PTR records.
 */
async function synthesizePtr(
  q: Question,
  result: Result,
  lookup: (q: Question) => Promise<Result>
): Promise<Result | null> {
  const address = embeddedAddress(q.name);
  if (!address || !isGlobal(address)) {
    return null;
  }
  const target = `${[...address].reverse().join('.')}.in-addr.arpa`;
  const ptr = await lookup(
    makeQuestion(target, TYPE_PTR, {dnssecOk: q.dnssecOk, cd: q.cd})
  ).catch(() => null);
  if (!ptr || rcodeOf(ptr.body) !== RCODE_NOERROR) {
    return null;
  }
  const owner = encodeName(target);
  const names = parseAnswers(ptr.body)
    .filter(r => r.type === TYPE_PTR)
    .map(r => ({ttl: r.ttl, name: readName(ptr.body, r.data).name}));
  if (!names.length) {
    return null;
  }
  const ttl = Math.min(...names.map(n => n.ttl), result.ttl);
  const records = [
    makeRecord(TYPE_CNAME, ttl, owner),
    ...names.map(n =>
      makeRecord(TYPE_PTR, Math.min(n.ttl, ttl), encodeName(n.name), owner)
    ),
  ];
  return {
    body: respond(q, RCODE_NOERROR, records),
    ttl,
    stale: result.stale || ptr.stale,
  };
}

/** How an answer to a question of one type is made from another lookup. */
interface Synthesizer {
  /** The response codes of the upstream answer that it replaces. */
  rcodes: number[];
  make: (
    q: Question,
    result: Result,
    lookup: (q: Question) => Promise<Result>
  ) => Promise<Result | null>;
}

const SYNTHESIZERS: Record<number, Synthesizer> = {
  [TYPE_AAAA]: {rcodes: [RCODE_NOERROR], make: synthesizeAaaa},
  [TYPE_PTR]: {rcodes: [RCODE_NOERROR, RCODE_NXDOMAIN], make: synthesizePtr},
};

/**
 * @return What makes the answer for `q`, if the upstream has none of its own.
 *     Not for a client that validates DNSSEC (DO without CD, RFC 6147 5.5):
 *     it would reject what is made.
 */
function synthesizerFor(q: Question, result: Result): Synthesizer | null {
  const synthesizer = SYNTHESIZERS[q.type];
  if (
    !synthesizer ||
    (q.dnssecOk && !q.cd) ||
    !synthesizer.rcodes.includes(rcodeOf(result.body)) ||
    parseAnswers(result.body).some(r => r.type === q.type)
  ) {
    return null;
  }
  return synthesizer;
}

/**
 * Resolves a question with DNS64 (RFC 6147): `ipv4only.arpa` is answered
 * locally, and what the upstream has no answer for is made from another
 * lookup, AAAA records from A records and PTR records for the prefix. AAAA
 * records are owned by the question name (a CNAME chain is flattened), their
 * TTL is the smaller of the A record's and the AAAA answer's (5.1.7). What is
 * made is kept in memory under `key`, so the lookup is not repeated.
 * DNS64 is a courtesy: if making an answer fails, the upstream's stands.
 * @param resolveOne Resolves a question the normal way.
 */
export async function withDns64(
  q: Question,
  key: string,
  resolveOne: (q: Question) => Promise<Result>
): Promise<Result> {
  const local = ipv4onlyAnswer(q);
  if (local) {
    return local;
  }
  const result = await resolveOne(q);
  try {
    const synthesizer = synthesizerFor(q, result);
    if (!synthesizer) {
      return result;
    }
    const kept = lookupLocal(key, q);
    if (kept && !kept.refresh) {
      return kept.result;
    }
    const made = await synthesizer.make(q, result, resolveOne);
    if (!made) {
      return result;
    }
    store(undefined, key, made);
    return made;
  } catch {
    return result;
  }
}
