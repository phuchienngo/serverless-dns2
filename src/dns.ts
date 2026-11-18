/**
 * @fileoverview Helpers for reading and writing DNS messages (RFC 1035).
 */

import {MAX_QUERY} from './config.js';
import type {Question} from './types.js';

/** One record of the answer section; `start` is its TYPE field's offset. */
export interface AnswerRecord {
  start: number;
  type: number;
  ttl: number;
  length: number;
}

const encoder = new TextEncoder();

/**
 * @return The two big-endian bytes of a 16-bit number.
 */
export function u16(n: number): number[] {
  return [n >> 8, n & 255];
}

/**
 * Maps each byte to one character, so any bytes round-trip unchanged.
 */
export function latin1(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}

/**
 * Lower-cases ASCII letters only, which keeps the length in bytes.
 */
export function lowerAscii(s: string): string {
  return s.replace(/[A-Z]/g, c => c.toLowerCase());
}

/**
 * @param name A domain name such as `example.com`.
 * @return The name in DNS wire format.
 */
export function encodeName(name: string): number[] {
  const out = [];
  for (const label of name.replace(/\.$/, '').split('.').filter(Boolean)) {
    const bytes = encoder.encode(label);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  return out;
}

/**
 * Parses the single question of a DNS query.
 * @throws If the message is not a well-formed single-question query.
 */
export function parseQuestion(buf: Uint8Array): Question {
  if (buf.length < 17 || buf.length > MAX_QUERY) {
    throw new Error('bad length');
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const isResponse = buf[2] & 0x80;
  if (isResponse || view.getUint16(4) !== 1) {
    throw new Error('not a query');
  }

  const labels = [];
  let offset = 12;
  for (;;) {
    const length = buf[offset];
    const isCompressed = length & 0xc0;
    if (
      length === undefined ||
      isCompressed ||
      offset + 1 + length >= buf.length
    ) {
      throw new Error('bad name');
    }
    if (length === 0) {
      break;
    }
    labels.push(latin1(buf.subarray(offset + 1, offset + 1 + length)));
    offset += length + 1;
  }
  offset++; // Root label.
  if (offset + 4 > buf.length) {
    throw new Error('truncated');
  }
  return {
    id: view.getUint16(0),
    name: lowerAscii(labels.join('.')),
    type: view.getUint16(offset),
    raw: Array.from(buf.subarray(12, offset + 4)),
  };
}

/**
 * Builds a query for the upstream resolver, with an EDNS0 OPT record.
 * @param question Question section (name, type, class).
 * @param ecs EDNS client-subnet option bytes, if any.
 *     `dnssec` sets the DO bit, `cd` sets the CD bit.
 */
export function buildQuery(
  question: number[],
  ecs: number[] | null,
  {dnssec = false, cd = false}: {dnssec?: boolean; cd?: boolean} = {}
): Uint8Array {
  const option = ecs || [];
  const opt = [
    0, // Root name.
    0,
    41, // Type OPT.
    16,
    0, // UDP payload size 4096.
    0,
    0,
    dnssec ? 0x80 : 0,
    0, // Extended RCODE, version, flags (DO).
    ...u16(option.length),
    ...option,
  ];
  const header = [0, 0, 1, cd ? 0x10 : 0, 0, 1, 0, 0, 0, 0, 0, 1];
  return new Uint8Array([...header, ...question, ...opt]);
}

/**
 * Builds a response message for the given question.
 * @param records Resource records, already encoded.
 */
export function respond(
  q: Question,
  rcode: number,
  records: number[][]
): Uint8Array {
  const header = [
    ...u16(q.id),
    0x81, // QR, RD.
    0x80 | rcode, // RA, response code.
    0,
    1, // One question.
    ...u16(records.length),
    0,
    0,
    0,
    0, // No authority or additional records.
  ];
  return new Uint8Array([...header, ...q.raw, ...records.flat()]);
}

/**
 * @param offset Start of a possibly compressed name.
 * @return Offset of the first byte after the name.
 */
export function skipName(b: Uint8Array, offset: number): number {
  for (;;) {
    if (offset >= b.length) {
      throw new Error('bad response');
    }
    const length = b[offset];
    if (length === 0) {
      return offset + 1;
    }
    if ((length & 0xc0) === 0xc0) {
      return offset + 2;
    }
    offset += length + 1;
  }
}

/**
 * Reads a possibly compressed name.
 * @return The name with a trailing dot, and the
 *     offset of the first byte after it.
 */
export function readName(
  b: Uint8Array,
  offset: number
): {name: string; next: number} {
  const labels = [];
  let next = -1;
  for (let jumps = 0; jumps < 32;) {
    if (offset >= b.length) {
      throw new Error('bad name');
    }
    const length = b[offset];
    if (length === 0) {
      return {name: labels.join('.') + '.', next: next < 0 ? offset + 1 : next};
    }
    if ((length & 0xc0) === 0xc0) {
      if (next < 0) {
        next = offset + 2;
      }
      offset = ((length & 0x3f) << 8) | b[offset + 1];
      jumps++;
      continue;
    }
    labels.push(latin1(b.subarray(offset + 1, offset + 1 + length)));
    offset += length + 1;
  }
  throw new Error('name loop');
}

/**
 * Lists the records of the answer section.
 *     `start` is the offset of the record's TYPE field.
 */
export function parseAnswers(resp: Uint8Array): AnswerRecord[] {
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  let offset = skipName(resp, 12) + 4;
  const records = [];
  for (let i = 0, count = view.getUint16(6); i < count; i++) {
    offset = skipName(resp, offset);
    if (offset + 10 > resp.length) {
      throw new Error('bad response');
    }
    const length = view.getUint16(offset + 8);
    if (offset + 10 + length > resp.length) {
      throw new Error('bad response');
    }
    records.push({
      start: offset,
      type: view.getUint16(offset),
      ttl: view.getUint32(offset + 4),
      length,
    });
    offset += 10 + length;
  }
  return records;
}

/**
 * @return The lower-cased CNAME targets in the answer section, without the
 *     trailing dot. Empty if the message cannot be read.
 */
export function cnameTargets(resp: Uint8Array): string[] {
  try {
    return parseAnswers(resp)
      .filter(a => a.type === 5)
      .map(a =>
        lowerAscii(readName(resp, a.start + 10).name.replace(/\.$/, ''))
      );
  } catch {
    return [];
  }
}

/**
 * @return Smallest answer TTL in seconds (at most an hour), or 30
 *     when there is no answer or the message cannot be read.
 */
export function minTtl(resp: Uint8Array): number {
  try {
    const answers = parseAnswers(resp);
    if (answers.length) {
      return Math.min(...answers.map(a => a.ttl), 3600);
    }
    return Math.min(negativeTtl(resp) ?? 30, 3600);
  } catch {
    return 30;
  }
}

/**
 * @return How long an empty or NXDOMAIN answer may be cached (RFC 2308): the
 *     smaller of the SOA record's TTL and its MINIMUM field; null if the
 *     authority section has no SOA record.
 */
function negativeTtl(resp: Uint8Array): number | null {
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  const answers = view.getUint16(6);
  const authority = view.getUint16(8);
  let offset = skipName(resp, 12) + 4;
  for (let i = 0; i < answers + authority; i++) {
    offset = skipName(resp, offset);
    const length = view.getUint16(offset + 8);
    const rdata = offset + 10;
    if (i >= answers && view.getUint16(offset) === 6) {
      const minimum = view.getUint32(rdata + length - 4);
      return Math.min(view.getUint32(offset + 4), minimum);
    }
    offset = rdata + length;
  }
  return null;
}
