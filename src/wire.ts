/**
 * @fileoverview The DNS wire format (RFC 1035): numbers, names, reading the
 * records of a message, and the EDNS options of its OPT record.
 */

import {TYPE_OPT} from './constants.js';

const encoder = new TextEncoder();

/** Header flag bits: RD is in byte 2 of a message, CD in byte 3. */
export const FLAG_RD = 0x01;
export const FLAG_CD = 0x10;
/** QR in byte 2 and RA in byte 3 have the same bit. */
export const FLAG_QR_OR_RA = 0x80;
/** The response code, the low bits of byte 3 (the rest is in the OPT record). */
export const RCODE_MASK = 0x0f;

/** The DO bit, in the flags field of an OPT record. */
export const FLAG_DO = 0x8000;

/** Size of the header, and of a record's TYPE, CLASS, TTL and RDLENGTH. */
export const HEADER_BYTES = 12;
export const RECORD_FIXED_BYTES = 10;

/** Owner name of a record: a pointer to the question, right after the header. */
export const QUESTION_POINTER = [0xc0, 12];

/**
 * @return The two big-endian bytes of a 16-bit number.
 */
export function u16(n: number): number[] {
  return [n >> 8, n & 255];
}

/**
 * @return The four big-endian bytes of a 32-bit number.
 */
export function u32(n: number): number[] {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
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

/** Where a record sits in a message. */
export type Section = 'answer' | 'authority' | 'additional';

/** One resource record of a message, located by offsets. */
export interface DnsRecord {
  section: Section;
  /** Offset of the owner name. */
  name: number;
  /** Offset of the TYPE field (the owner name ends just before it). */
  start: number;
  type: number;
  ttl: number;
  /** Offset of the RDATA. */
  data: number;
  /** RDLENGTH. */
  length: number;
  /** Offset of the first byte after the record. */
  end: number;
}

/**
 * Lists every record of a message, in order. All other readers and editors of
 * the record sections are built on this.
 * @throws If a record runs past the end of the message.
 */
export function readRecords(resp: Uint8Array): DnsRecord[] {
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  const counts: Array<[Section, number]> = [
    ['answer', view.getUint16(6)],
    ['authority', view.getUint16(8)],
    ['additional', view.getUint16(10)],
  ];
  let offset = skipName(resp, HEADER_BYTES) + 4; // Skip the question.
  const records: DnsRecord[] = [];
  for (const [section, count] of counts) {
    for (let i = 0; i < count; i++) {
      const name = offset;
      const start = skipName(resp, offset);
      if (start + RECORD_FIXED_BYTES > resp.length) {
        throw new Error('bad response');
      }
      const length = view.getUint16(start + 8);
      const end = start + RECORD_FIXED_BYTES + length;
      if (end > resp.length) {
        throw new Error('bad response');
      }
      records.push({
        section,
        name,
        start,
        type: view.getUint16(start),
        ttl: view.getUint32(start + 4),
        data: start + RECORD_FIXED_BYTES,
        length,
        end,
      });
      offset = end;
    }
  }
  return records;
}

/** The records of one section; OPT pseudo-records are not listed. */
function section(resp: Uint8Array, which: Section): DnsRecord[] {
  return readRecords(resp).filter(
    r => r.section === which && r.type !== TYPE_OPT
  );
}

/** Lists the answer records. */
export function parseAnswers(resp: Uint8Array): DnsRecord[] {
  return section(resp, 'answer');
}

/** Lists the authority records. */
export function parseAuthority(resp: Uint8Array): DnsRecord[] {
  return section(resp, 'authority');
}

/** Lists the additional records other than OPT. */
export function parseAdditional(resp: Uint8Array): DnsRecord[] {
  return section(resp, 'additional');
}

/** The OPT records of a message (in the additional section). */
export function optRecords(resp: Uint8Array): DnsRecord[] {
  return readRecords(resp).filter(
    r => r.section === 'additional' && r.type === TYPE_OPT
  );
}

/** One EDNS option inside an OPT record: offsets of its header and its end. */
export interface OptOption {
  code: number;
  start: number;
  end: number;
}

/**
 * Splits the RDATA of an OPT record into options.
 * @return `exact` is false if the options do not fill the RDATA exactly.
 */
export function readOptions(
  view: DataView,
  opt: DnsRecord
): {options: OptOption[]; exact: boolean} {
  const options: OptOption[] = [];
  let at = opt.data;
  while (at + 4 <= opt.end) {
    const end = at + 4 + view.getUint16(at + 2);
    options.push({code: view.getUint16(at), start: at, end});
    at = end;
  }
  return {options, exact: at === opt.end};
}

/**
 * @return The EDNS options of the message's OPT record (none if it has no OPT).
 * @throws If the records of the message do not parse.
 */
export function optOptions(
  msg: Uint8Array
): Array<{code: number; data: Uint8Array}> {
  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const [opt] = optRecords(msg);
  if (!opt) {
    return [];
  }
  return readOptions(view, opt).options.map(o => ({
    code: o.code,
    data: msg.subarray(o.start + 4, o.end),
  }));
}

/** @return The response code of a message, without the bits held in OPT. */
export function rcodeOf(resp: Uint8Array): number {
  return resp[3] & RCODE_MASK;
}
