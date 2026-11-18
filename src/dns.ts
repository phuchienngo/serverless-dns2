/**
 * @fileoverview Helpers for reading and writing DNS messages (RFC 1035).
 */

import {MAX_QUERY} from './config.js';
import {
  CLASS_IN,
  OPTION_EDE,
  OPTION_PADDING,
  TYPE_CNAME,
  TYPE_OPT,
  TYPE_SOA,
} from './constants.js';
import type {Question} from './types.js';

const encoder = new TextEncoder();

/** Header flag bits: in byte 2 (RD) and byte 3 (CD, AD) of a message. */
const FLAG_RD = 0x01;
const RCODE_MASK = 0x0f;
const FLAG_AD = 0x20;
const FLAG_CD = 0x10;
const FLAG_QR_OR_RA = 0x80;
/** The DO bit, in the flags field of an OPT record. */
const FLAG_DO = 0x8000;

/** Size of the header, and of a record's TYPE, CLASS, TTL and RDLENGTH. */
export const HEADER_BYTES = 12;
export const RECORD_FIXED_BYTES = 10;
/** Largest wire length of a name (RFC 1035 2.3.4). */
const MAX_NAME_BYTES = 255;
/** Pad responses to a multiple of this (RFC 8467 4.1). */
const PADDING_BLOCK = 468;
/** Owner name of a record: a pointer to the question, right after the header. */
export const QUESTION_POINTER = [0xc0, 12];
/** Longest time an answer is cached, and the TTL of one with no TTL to read. */
const MAX_TTL = 3600;
const DEFAULT_TTL = 30;
/** UDP payload size announced in our OPT records. */
const PAYLOAD_SIZE_RESPONSE = 1232;
const PAYLOAD_SIZE_UPSTREAM = 4096;

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
function optRecords(resp: Uint8Array): DnsRecord[] {
  return readRecords(resp).filter(
    r => r.section === 'additional' && r.type === TYPE_OPT
  );
}

/** One EDNS option inside an OPT record: offsets of its header and its end. */
interface OptOption {
  code: number;
  start: number;
  end: number;
}

/**
 * Splits the RDATA of an OPT record into options.
 * @return `exact` is false if the options do not fill the RDATA exactly.
 */
function readOptions(
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

/** The parts of a query's OPT record that the gateway uses. */
interface QueryOpt {
  flags: number;
  version: number;
  padding: boolean;
}

/**
 * Looks for the OPT record in a query.
 * @return The record (null if there is none), and whether the query is
 *     malformed in a way that RFC 6891 6.1.1 answers with FORMERR: records
 *     that do not parse, more than one OPT, an OPT not owned by the root, or
 *     options that do not fill its RDATA.
 */
function findOpt(buf: Uint8Array): {opt: QueryOpt | null; malformed: boolean} {
  try {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const found = optRecords(buf);
    if (!found.length) {
      return {opt: null, malformed: false};
    }
    const [first] = found;
    const {options, exact} = readOptions(view, first);
    return {
      opt: {
        flags: view.getUint16(first.start + 6),
        version: buf[first.start + 5],
        padding: options.some(o => o.code === OPTION_PADDING),
      },
      malformed: found.length > 1 || first.start - first.name !== 1 || !exact,
    };
  } catch {
    return {opt: null, malformed: true};
  }
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
  const isResponse = buf[2] & FLAG_QR_OR_RA;
  if (isResponse || view.getUint16(4) !== 1) {
    throw new Error('not a query');
  }

  const labels = [];
  let offset = HEADER_BYTES;
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
  if (offset - HEADER_BYTES > MAX_NAME_BYTES) {
    throw new Error('name too long'); // RFC 1035 2.3.4.
  }
  if (offset + 4 > buf.length) {
    throw new Error('truncated');
  }
  const {opt, malformed} = findOpt(buf);
  return {
    id: view.getUint16(0),
    name: lowerAscii(labels.join('.')),
    type: view.getUint16(offset),
    raw: Array.from(buf.subarray(HEADER_BYTES, offset + 4)),
    edns: opt !== null,
    dnssecOk: !!opt && (opt.flags & FLAG_DO) !== 0,
    cd: (buf[3] & FLAG_CD) !== 0,
    ad: (buf[3] & FLAG_AD) !== 0,
    rd: (buf[2] & FLAG_RD) !== 0,
    opcode: (buf[2] >> 3) & 15,
    ednsVersion: opt?.version ?? 0,
    padding: opt?.padding ?? false,
    malformed,
  };
}

/** @return The response code of a message, without the bits held in OPT. */
export function rcodeOf(resp: Uint8Array): number {
  return resp[3] & RCODE_MASK;
}

/**
 * @param protocols ALPN ids, such as `h2`.
 * @return The value of an `alpn` SvcParam: each id preceded by its length.
 */
export function alpnValue(protocols: string[]): number[] {
  return protocols.flatMap(p => [p.length, ...encoder.encode(p)]);
}

/**
 * Builds the RDATA of an SVCB or HTTPS record in service mode (RFC 9460).
 * @param target Target name; `.` means the owner name itself.
 * @param params SvcParams as [key, value]; written in increasing key order,
 *     as the RFC requires.
 */
export function svcbRdata(
  priority: number,
  target: string,
  params: Array<[number, number[]]>
): number[] {
  return [
    ...u16(priority),
    ...encodeName(target),
    ...[...params]
      .sort(([a], [b]) => a - b)
      .flatMap(([key, value]) => [...u16(key), ...u16(value.length), ...value]),
  ];
}

/**
 * Makes the question of a query that did not arrive as a DNS message (the
 * JSON API): recursion desired, no EDNS.
 * @param flags DNSSEC flags to ask the upstream with (DO and CD).
 * @param name A domain name, with or without a trailing dot.
 */
export function makeQuestion(
  name: string,
  type: number,
  flags: {dnssecOk?: boolean; cd?: boolean} = {}
): Question {
  return {
    id: 0,
    name: lowerAscii(name.replace(/\.$/, '')),
    type,
    raw: [...encodeName(name), ...u16(type), ...u16(CLASS_IN)],
    edns: false,
    dnssecOk: flags.dnssecOk ?? false,
    cd: flags.cd ?? false,
    ad: false,
    rd: true,
    opcode: 0,
    ednsVersion: 0,
    padding: false,
    malformed: false,
  };
}

/**
 * @param ttl Seconds.
 * @param owner Encoded owner name; by default a pointer to the name of the
 *     question (which starts right after the header).
 * @return A record of class IN.
 */
export function makeRecord(
  type: number,
  ttl: number,
  rdata: number[],
  owner: number[] = QUESTION_POINTER
): number[] {
  return [
    ...owner,
    ...u16(type),
    ...u16(CLASS_IN),
    ...u32(ttl),
    ...u16(rdata.length),
    ...rdata,
  ];
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
    ...u16(TYPE_OPT),
    ...u16(PAYLOAD_SIZE_UPSTREAM),
    0, // Extended RCODE.
    0, // Version.
    ...u16(dnssec ? FLAG_DO : 0),
    ...u16(option.length),
    ...option,
  ];
  const header = [
    0,
    0, // Id.
    FLAG_RD,
    (cd ? FLAG_CD : 0) | (ad ? FLAG_AD : 0),
    0,
    1, // One question.
    0,
    0,
    0,
    0,
    0,
    1, // One additional record: OPT.
  ];
  return new Uint8Array([...header, ...question, ...opt]);
}

/** An Extended DNS Error to attach to a response (RFC 8914). */
export interface Ede {
  code: number;
  text: string;
}

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
  ede?: Ede,
  additional: number[][] = []
): Uint8Array {
  return build(q, rcode, records, [], ede, additional);
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
  ede?: Ede
): Uint8Array {
  const rdata = [
    ...encodeName('dns.invalid'), // MNAME.
    ...encodeName('hostmaster.invalid'), // RNAME.
    ...u32(1), // Serial.
    ...u32(3600), // Refresh.
    ...u32(600), // Retry.
    ...u32(86400), // Expire.
    ...u32(ttl), // Minimum: the negative-caching TTL.
  ];
  return build(q, rcode, [], [makeRecord(TYPE_SOA, ttl, rdata)], ede);
}

function build(
  q: Question,
  rcode: number,
  answers: number[][],
  authority: number[][],
  ede?: Ede,
  additional: number[][] = []
): Uint8Array {
  // A query without an OPT record must get a response without one (RFC 6891).
  const opt = q.edns ? optRecord(q, rcode, ede) : [];
  const header = [
    ...u16(q.id),
    FLAG_QR_OR_RA | (q.opcode << 3) | (q.rd ? FLAG_RD : 0), // QR, opcode, RD as asked.
    FLAG_QR_OR_RA | (q.cd ? FLAG_CD : 0) | (rcode & RCODE_MASK), // RA, CD as asked, rcode.
    0,
    1, // One question.
    ...u16(answers.length),
    ...u16(authority.length),
    ...u16(additional.length + (opt.length ? 1 : 0)), // Additional + OPT.
  ];
  return new Uint8Array([
    ...header,
    ...q.raw,
    ...answers.flat(),
    ...authority.flat(),
    ...additional.flat(),
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
function optRecord(q: Question, rcode: number, ede?: Ede): number[] {
  const option = ede ? edeOption(ede.code, ede.text) : [];
  return [
    0, // Root name.
    ...u16(TYPE_OPT),
    ...u16(PAYLOAD_SIZE_RESPONSE),
    rcode >> 4, // Extended RCODE.
    0, // Version.
    ...u16(q.dnssecOk ? FLAG_DO : 0),
    ...u16(option.length),
    ...option,
  ];
}

/** Copies `resp` with `parts` of it kept, and the given counts fixed. */
function splice(
  resp: Uint8Array,
  edits: Array<{from: number; to: number; insert?: number[]}>
): Uint8Array {
  const parts: Array<Uint8Array | number[]> = [];
  let at = 0;
  for (const {from, to, insert} of edits) {
    parts.push(resp.subarray(at, from), insert ?? []);
    at = to;
  }
  parts.push(resp.subarray(at));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let pos = 0;
  for (const part of parts) {
    out.set(part, pos);
    pos += part.length;
  }
  return out;
}

/**
 * Adds an option to the OPT record of a response.
 * @return The response unchanged if it has no OPT record.
 */
export function addOptOption(resp: Uint8Array, option: number[]): Uint8Array {
  try {
    const [opt] = optRecords(resp);
    if (!opt) {
      return resp;
    }
    const out = splice(resp, [{from: opt.end, to: opt.end, insert: option}]);
    new DataView(out.buffer).setUint16(
      opt.start + 8,
      opt.length + option.length
    );
    return out;
  } catch {
    return resp; // Not a message we can edit: leave it as it is.
  }
}

/**
 * Removes every EDNS option with the given code from the OPT record.
 * @return The message unchanged if it has no such option or cannot be read.
 */
export function removeOptOption(resp: Uint8Array, code: number): Uint8Array {
  try {
    const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
    const [opt] = optRecords(resp);
    if (!opt) {
      return resp;
    }
    const unwanted = readOptions(view, opt).options.filter(
      o => o.code === code
    );
    if (!unwanted.length) {
      return resp;
    }
    const out = splice(
      resp,
      unwanted.map(o => ({from: o.start, to: o.end}))
    );
    const removed = unwanted.reduce((n, o) => n + o.end - o.start, 0);
    new DataView(out.buffer).setUint16(opt.start + 8, opt.length - removed);
    return out;
  } catch {
    return resp;
  }
}

/**
 * Removes OPT records from a response, for a client whose query had none.
 */
export function stripOpt(resp: Uint8Array): Uint8Array {
  try {
    const found = optRecords(resp);
    if (!found.length) {
      return resp;
    }
    const out = splice(
      resp,
      found.map(r => ({from: r.name, to: r.end}))
    );
    const view = new DataView(out.buffer);
    view.setUint16(10, view.getUint16(10) - found.length);
    return out;
  } catch {
    return resp;
  }
}

/**
 * Pads a response to a multiple of 468 bytes with an EDNS Padding option, for
 * a client that padded its query (RFC 7830, RFC 8467).
 */
export function padResponse(resp: Uint8Array): Uint8Array {
  const size =
    (PADDING_BLOCK - ((resp.length + 4) % PADDING_BLOCK)) % PADDING_BLOCK;
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
  if (resp.length < HEADER_BYTES || (resp[2] & FLAG_RD) === (rd ? 1 : 0)) {
    return resp;
  }
  const out = resp.slice();
  out[2] = (out[2] & ~FLAG_RD) | (rd ? FLAG_RD : 0);
  return out;
}

/**
 * @return The lower-cased CNAME targets in the answer section, without the
 *     trailing dot. Empty if the message cannot be read.
 */
export function cnameTargets(resp: Uint8Array): string[] {
  try {
    return parseAnswers(resp)
      .filter(a => a.type === TYPE_CNAME)
      .map(a => lowerAscii(readName(resp, a.data).name.replace(/\.$/, '')));
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
      return Math.min(...answers.map(a => a.ttl), MAX_TTL);
    }
    return Math.min(negativeTtl(resp) ?? DEFAULT_TTL, MAX_TTL);
  } catch {
    return DEFAULT_TTL;
  }
}

/**
 * @return How long an empty or NXDOMAIN answer may be cached (RFC 2308): the
 *     smaller of the SOA record's TTL and its MINIMUM field; null if the
 *     authority section has no SOA record.
 */
function negativeTtl(resp: Uint8Array): number | null {
  const soa = parseAuthority(resp).find(r => r.type === TYPE_SOA);
  if (!soa) {
    return null;
  }
  const view = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  return Math.min(soa.ttl, view.getUint32(soa.end - 4));
}
