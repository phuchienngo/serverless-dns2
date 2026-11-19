/**
 * @fileoverview DNS responses: building the ones the gateway makes itself,
 * and changing the ones it relays (EDNS options, padding, TTLs).
 */

import {
  CLASS_IN,
  OPTION_EDE,
  OPTION_PADDING,
  TYPE_CNAME,
  TYPE_OPT,
  TYPE_SOA,
} from './constants.js';
import {
  type DnsRecord,
  FLAG_CD,
  FLAG_DO,
  FLAG_QR_OR_RA,
  FLAG_RD,
  HEADER_BYTES,
  QUESTION_POINTER,
  RCODE_MASK,
  encodeName,
  lowerAscii,
  optRecords,
  parseAnswers,
  parseAuthority,
  readName,
  readOptions,
  u16,
  u32,
} from './wire.js';
import type {Question} from './types.js';

const encoder = new TextEncoder();

/** Pad responses to a multiple of this (RFC 8467 4.1). */
const PADDING_BLOCK = 468;

/** Longest time an answer is cached, and the TTL of one with no TTL to read. */
const MAX_TTL = 3600;
const DEFAULT_TTL = 30;

/** UDP payload size announced in our OPT records. */
const PAYLOAD_SIZE_RESPONSE = 1232;

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

/** @return An EDNS option: its code, its length and the data. */
export function ednsOption(code: number, data: ArrayLike<number>): number[] {
  return [...u16(code), ...u16(data.length), ...Array.from(data)];
}

/** An EDNS option holding an Extended DNS Error (RFC 8914). */
export function edeOption(code: number, text: string): number[] {
  return ednsOption(OPTION_EDE, [...u16(code), ...encoder.encode(text)]);
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
    return resp; // Not a message we can edit.
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
    return resp; // Not a message we can edit.
  }
}

/**
 * Pads a response to a multiple of 468 bytes with an EDNS Padding option, for
 * a client that padded its query (RFC 7830, RFC 8467).
 */
export function padResponse(resp: Uint8Array): Uint8Array {
  const size =
    (PADDING_BLOCK - ((resp.length + 4) % PADDING_BLOCK)) % PADDING_BLOCK;
  return addOptOption(
    resp,
    ednsOption(OPTION_PADDING, new Array(size).fill(0))
  );
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
 * @param answers The records of the answer section, if already read.
 * @return The lower-cased CNAME targets in the answer section, without the
 *     trailing dot. Empty if the message cannot be read.
 */
export function cnameTargets(
  resp: Uint8Array,
  answers?: DnsRecord[]
): string[] {
  try {
    return (answers ?? parseAnswers(resp))
      .filter(a => a.type === TYPE_CNAME)
      .map(a => lowerAscii(readName(resp, a.data).name.replace(/\.$/, '')));
  } catch {
    return []; // Not a message we can read: no targets.
  }
}

/**
 * @return Smallest answer TTL in seconds (at most an hour), or 30
 *     when there is no answer or the message cannot be read.
 */
export function minTtl(resp: Uint8Array): number {
  try {
    const answers = parseAnswers(resp);
    // A CNAME chain that ends in NXDOMAIN or NODATA has the SOA of the
    // negative answer too, which limits it (RFC 2308 5).
    const negative = negativeTtl(resp);
    if (answers.length) {
      return Math.min(...answers.map(a => a.ttl), negative ?? MAX_TTL, MAX_TTL);
    }
    return Math.min(negative ?? DEFAULT_TTL, MAX_TTL);
  } catch {
    return DEFAULT_TTL; // Not a message we can read.
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
