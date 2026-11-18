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
  if (offset - 12 > 255) {
    throw new Error('name too long'); // RFC 1035 2.3.4.
  }
  if (offset + 4 > buf.length) {
    throw new Error('truncated');
  }
  const opt = findOpt(buf, offset + 4);
  return {
    id: view.getUint16(0),
    name: lowerAscii(labels.join('.')),
    type: view.getUint16(offset),
    raw: Array.from(buf.subarray(12, offset + 4)),
    edns: opt !== null,
    dnssecOk: !!opt && (opt.flags & 0x8000) !== 0,
    cd: (buf[3] & 0x10) !== 0,
    ad: (buf[3] & 0x20) !== 0,
    rd: (buf[2] & 1) !== 0,
    opcode: (buf[2] >> 3) & 15,
    ednsVersion: opt?.version ?? 0,
    padding: opt?.padding ?? false,
    malformed: opt?.malformed ?? false,
  };
}

/**
 * Looks for the OPT record in the additional section of a query.
 * @param offset Where the records after the question start.
 * @return Its flags field (the DO bit is 0x8000), EDNS version and whether it
 *     has a Padding option; null if there is no OPT record.
 */
function findOpt(
  buf: Uint8Array,
  offset: number
): {
  flags: number;
  version: number;
  padding: boolean;
  malformed: boolean;
} | null {
  try {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const records = view.getUint16(6) + view.getUint16(8) + view.getUint16(10);
    let found: {
      flags: number;
      version: number;
      padding: boolean;
      malformed: boolean;
    } | null = null;
    for (let i = 0; i < records; i++) {
      const start = offset;
      offset = skipName(buf, offset);
      const length = view.getUint16(offset + 8);
      if (view.getUint16(offset) === 41) {
        // RFC 6891 6.1.1: one OPT record, owned by the root, whose options
        // fill its RDATA exactly.
        let malformed: boolean = found !== null || offset - start !== 1;
        let padding = false;
        const end = offset + 10 + length;
        let at = offset + 10;
        for (
          ;
          end <= buf.length && at + 4 <= end;
          at += 4 + view.getUint16(at + 2)
        ) {
          padding ||= view.getUint16(at) === OPTION_PADDING;
        }
        malformed ||= end > buf.length || at !== end;
        found ??= {
          flags: view.getUint16(offset + 6),
          version: buf[offset + 5],
          padding,
          malformed,
        };
        found.malformed ||= malformed;
      }
      offset += 10 + length;
    }
    return found;
  } catch {
    // A damaged record section: treat the query as having no EDNS.
  }
  return null;
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
  {
    dnssec = false,
    cd = false,
    ad = false,
  }: {dnssec?: boolean; cd?: boolean; ad?: boolean} = {}
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
  const header = [
    0,
    0,
    1,
    (cd ? 0x10 : 0) | (ad ? 0x20 : 0),
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    1,
  ];
  return new Uint8Array([...header, ...question, ...opt]);
}

/** Extended DNS Error codes (RFC 8914) that are used. */
export const EDE_STALE_ANSWER = 3;
export const EDE_BLOCKED = 15;

const OPTION_EDE = 15;
const OPTION_PADDING = 12;

/**
 * Builds a response message for the given question.
 * @param records Resource records, already encoded.
 * @param ede Extended DNS Error (RFC 8914) to attach: an info code and a short
 *     text. Like the OPT record that carries it, only sent if the query had one.
 */
export function respond(
  q: Question,
  rcode: number,
  records: number[][],
  ede?: {code: number; text: string}
): Uint8Array {
  return build(q, rcode, records, [], ede);
}

/**
 * Builds an NXDOMAIN or NODATA response. It carries a made-up SOA record in
 * the authority section, without which clients cannot cache the negative
 * answer (RFC 2308).
 * @param ttl How long the answer may be cached, in seconds.
 */
export function respondNegative(
  q: Question,
  rcode: number,
  ttl: number,
  ede?: {code: number; text: string}
): Uint8Array {
  const rdata = [
    ...encodeName('dns.invalid'), // MNAME.
    ...encodeName('hostmaster.invalid'), // RNAME.
    0,
    0,
    0,
    1, // Serial.
    ...u32(3600), // Refresh.
    ...u32(600), // Retry.
    ...u32(86400), // Expire.
    ...u32(ttl), // Minimum: the negative-caching TTL.
  ];
  const soa = [
    0xc0,
    12, // Owner name: pointer to the question.
    0,
    6, // Type SOA.
    0,
    1, // Class IN.
    ...u32(ttl),
    ...u16(rdata.length),
    ...rdata,
  ];
  return build(q, rcode, [], [soa], ede);
}

export function u32(n: number): number[] {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}

function build(
  q: Question,
  rcode: number,
  answers: number[][],
  authority: number[][],
  ede?: {code: number; text: string}
): Uint8Array {
  // A query without an OPT record must get a response without one (RFC 6891).
  const opt = q.edns ? optRecord(q, rcode, ede) : [];
  const header = [
    ...u16(q.id),
    0x80 | (q.opcode << 3) | (q.rd ? 1 : 0), // QR, opcode, RD as asked.
    0x80 | (q.cd ? 0x10 : 0) | (rcode & 15), // RA, CD as asked, response code.
    0,
    1, // One question.
    ...u16(answers.length),
    ...u16(authority.length),
    0,
    opt.length ? 1 : 0, // Additional records: the OPT record.
  ];
  return new Uint8Array([
    ...header,
    ...q.raw,
    ...answers.flat(),
    ...authority.flat(),
    ...opt,
  ]);
}

/** An EDNS option holding an Extended DNS Error (RFC 8914). */
export function edeOption(code: number, text: string): number[] {
  const bytes = encoder.encode(text);
  return [...u16(OPTION_EDE), ...u16(2 + bytes.length), ...u16(code), ...bytes];
}

/**
 * An OPT record that echoes the DO bit, with an Extended DNS Error if given.
 * @param rcode The full response code; its upper bits go in this record.
 */
function optRecord(
  q: Question,
  rcode: number,
  ede?: {code: number; text: string}
): number[] {
  const option = ede ? edeOption(ede.code, ede.text) : [];
  return [
    0, // Root name.
    0,
    41, // Type OPT.
    ...u16(1232), // UDP payload size.
    rcode >> 4, // Extended RCODE.
    0, // Version.
    q.dnssecOk ? 0x80 : 0,
    0, // Flags (DO).
    ...u16(option.length),
    ...option,
  ];
}

/**
 * Adds an option to the OPT record of a response.
 * @return The response unchanged if it has no OPT record.
 */
export function addOptOption(resp: Uint8Array, option: number[]): Uint8Array {
  try {
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const before = view.getUint16(6) + view.getUint16(8);
    const total = before + view.getUint16(10);
    let offset = skipName(resp, 12) + 4;
    for (let i = 0; i < total; i++) {
      offset = skipName(resp, offset);
      const length = view.getUint16(offset + 8);
      const end = offset + 10 + length;
      if (i >= before && view.getUint16(offset) === 41) {
        const out = new Uint8Array(resp.length + option.length);
        out.set(resp.subarray(0, end));
        out.set(option, end);
        out.set(resp.subarray(end), end + option.length);
        new DataView(out.buffer).setUint16(offset + 8, length + option.length);
        return out;
      }
      offset = end;
    }
  } catch {
    // Not a message we can edit: leave it as it is.
  }
  return resp;
}

/**
 * Pads a response to a multiple of 468 bytes with an EDNS Padding option, for
 * a client that padded its query (RFC 7830, RFC 8467).
 */
export function padResponse(resp: Uint8Array): Uint8Array {
  const block = 468;
  const size = (block - ((resp.length + 4) % block)) % block;
  return addOptOption(resp, [
    ...u16(OPTION_PADDING),
    ...u16(size),
    ...new Array<number>(size).fill(0),
  ]);
}

/**
 * @return The response with its RD flag set as in the query (RFC 1035); the
 *     upstream always answers RD=1. The input is not changed.
 */
export function copyRd(resp: Uint8Array, rd: boolean): Uint8Array {
  if (resp.length < 12 || (resp[2] & 1) === (rd ? 1 : 0)) {
    return resp;
  }
  const out = resp.slice();
  out[2] = (out[2] & ~1) | (rd ? 1 : 0);
  return out;
}

/**
 * Removes OPT records from a response, for a client whose query had none.
 */
export function stripOpt(resp: Uint8Array): Uint8Array {
  try {
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const before = view.getUint16(6) + view.getUint16(8);
    const total = before + view.getUint16(10);
    let offset = skipName(resp, 12) + 4;
    const cuts: Array<[number, number]> = [];
    for (let i = 0; i < total; i++) {
      const start = offset;
      offset = skipName(resp, offset);
      const type = view.getUint16(offset);
      offset += 10 + view.getUint16(offset + 8);
      if (i >= before && type === 41) {
        cuts.push([start, offset]);
      }
    }
    if (!cuts.length) {
      return resp;
    }
    const parts: Uint8Array[] = [];
    let from = 0;
    for (const [start, end] of cuts) {
      parts.push(resp.subarray(from, start));
      from = end;
    }
    parts.push(resp.subarray(from));
    const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    new DataView(out.buffer).setUint16(10, total - before - cuts.length);
    return out;
  } catch {
    return resp;
  }
}

/**
 * Removes every EDNS option with the given code from the OPT record.
 * @return The message unchanged if it has no such option or cannot be read.
 */
export function removeOptOption(resp: Uint8Array, code: number): Uint8Array {
  try {
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const before = view.getUint16(6) + view.getUint16(8);
    const total = before + view.getUint16(10);
    let offset = skipName(resp, 12) + 4;
    for (let i = 0; i < total; i++) {
      offset = skipName(resp, offset);
      const type = view.getUint16(offset);
      const length = view.getUint16(offset + 8);
      const data = offset + 10;
      offset = data + length;
      if (i < before || type !== 41) {
        continue;
      }
      const kept: number[] = [];
      let found = false;
      for (let p = data; p + 4 <= offset;) {
        const size = view.getUint16(p + 2);
        if (view.getUint16(p) === code) {
          found = true;
        } else {
          kept.push(...resp.subarray(p, p + 4 + size));
        }
        p += 4 + size;
      }
      if (!found) {
        return resp;
      }
      const out = new Uint8Array(data + kept.length + (resp.length - offset));
      out.set(resp.subarray(0, data), 0);
      out.set(kept, data);
      out.set(resp.subarray(offset), data + kept.length);
      new DataView(out.buffer).setUint16(data - 2, kept.length);
      return out;
    }
    return resp;
  } catch {
    return resp;
  }
}

/**
 * Lists the records of the additional section other than OPT; `start` is the
 * offset of the record's TYPE field.
 */
export function parseAdditional(resp: Uint8Array): AnswerRecord[] {
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  const before = view.getUint16(6) + view.getUint16(8);
  const total = before + view.getUint16(10);
  let offset = skipName(resp, 12) + 4;
  const records = [];
  for (let i = 0; i < total; i++) {
    offset = skipName(resp, offset);
    if (offset + 10 > resp.length) {
      throw new Error('bad response');
    }
    const length = view.getUint16(offset + 8);
    if (offset + 10 + length > resp.length) {
      throw new Error('bad response');
    }
    const type = view.getUint16(offset);
    if (i >= before && type !== 41) {
      records.push({
        start: offset,
        type,
        ttl: view.getUint32(offset + 4),
        length,
      });
    }
    offset += 10 + length;
  }
  return records;
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
 * Lists the records of the authority section; `start` is the offset of the
 * record's TYPE field.
 */
export function parseAuthority(resp: Uint8Array): AnswerRecord[] {
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  const answers = view.getUint16(6);
  const total = answers + view.getUint16(8);
  let offset = skipName(resp, 12) + 4;
  const records = [];
  for (let i = 0; i < total; i++) {
    offset = skipName(resp, offset);
    if (offset + 10 > resp.length) {
      throw new Error('bad response');
    }
    const length = view.getUint16(offset + 8);
    if (offset + 10 + length > resp.length) {
      throw new Error('bad response');
    }
    if (i >= answers) {
      records.push({
        start: offset,
        type: view.getUint16(offset),
        ttl: view.getUint32(offset + 4),
        length,
      });
    }
    offset += 10 + length;
  }
  return records;
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
