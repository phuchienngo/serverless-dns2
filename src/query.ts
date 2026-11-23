/**
 * @fileoverview DNS queries: parsing the one a client sent, and making the
 * ones the gateway sends upstream.
 */

import {MAX_QUERY} from './config.js';
import {validEcs} from './ecs.js';
import {
  CLASS_IN,
  OPTION_COOKIE,
  OPTION_ECS,
  OPTION_PADDING,
  TYPE_OPT,
} from './constants.js';
import {
  FLAG_CD,
  FLAG_AD,
  FLAG_DO,
  FLAG_QR_OR_RA,
  FLAG_RD,
  HEADER_BYTES,
  encodeName,
  latin1,
  lowerAscii,
  normalizeName,
  optRecords,
  questionCount,
  readOptions,
  u16,
} from './wire.js';
import type {Question} from './types.js';

/** Largest wire length of a name (RFC 1035 2.3.4). */
const MAX_NAME_BYTES = 255;

/** UDP payload size announced in our queries to the upstream. */
const PAYLOAD_SIZE_UPSTREAM = 4096;

/** The parts of a query's OPT record that the gateway uses. */
interface QueryOpt {
  flags: number;
  version: number;
  padding: boolean;
  cookie: number[] | null;
  ecs: Uint8Array | null;
}

/** RFC 7873 4: a client cookie of 8 bytes, then a server cookie of 8-32. */
function validCookie(length: number): boolean {
  return length === 8 || (length >= 16 && length <= 40);
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
    const cookie = options.find(o => o.code === OPTION_COOKIE);
    const cookieBytes = cookie
      ? [...buf.subarray(cookie.start + 4, cookie.end)]
      : null;
    const subnet = options.find(o => o.code === OPTION_ECS);
    const subnetData = subnet ? buf.slice(subnet.start + 4, subnet.end) : null;
    return {
      opt: {
        ecs: subnetData,
        flags: view.getUint16(first.start + 6),
        version: buf[first.start + 5],
        padding: options.some(o => o.code === OPTION_PADDING),
        cookie: cookieBytes,
      },
      // A cookie of another length is FORMERR too (RFC 7873 5.2.2).
      malformed:
        found.length > 1 ||
        first.start - first.name !== 1 ||
        !exact ||
        (cookieBytes !== null && !validCookie(cookieBytes.length)) ||
        // A subnet that is not well formed is FORMERR too (RFC 7871 6, 7.2.1).
        (subnetData !== null && !validEcs(subnetData)),
    };
  } catch {
    return {opt: null, malformed: true}; // The records do not parse.
  }
}

export class MultipleQuestionsError extends Error {}

/**
 * Parses the single question of a DNS query.
 * @throws If the message is not a well-formed single-question query.
 */
export function parseQuestion(buf: Uint8Array): Question {
  if (buf.length < HEADER_BYTES || buf.length > MAX_QUERY) {
    throw new Error('bad length');
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const isResponse = buf[2] & FLAG_QR_OR_RA;
  const opcode = (buf[2] >> 3) & 15;
  const questions = questionCount(buf);
  if (!isResponse && opcode === 0 && questions > 1) {
    throw new MultipleQuestionsError('multiple questions');
  }
  if (buf.length < HEADER_BYTES + 5) {
    throw new Error('bad length');
  }
  if (isResponse || questions !== 1) {
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
    opcode,
    ednsVersion: opt?.version ?? 0,
    padding: opt?.padding ?? false,
    cookie: opt?.cookie ?? null,
    ecs: opt?.ecs ?? null,
    malformed,
  };
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
    name: normalizeName(name),
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
    cookie: null,
    ecs: null,
    malformed: false,
  };
}

/**
 * Builds a query for the upstream resolver, with an EDNS0 OPT record.
 * @param question Question section (name, type, class).
 * @param ecs EDNS client-subnet option bytes, or null for none.
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
  const option = ecs ?? [];
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
