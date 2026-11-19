/**
 * @fileoverview Turns a DNS response message into the Google-style JSON
 * format (https://developers.google.com/speed/public-dns/docs/doh/json).
 */

import {TYPE_OPT} from './constants.js';
import {latin1, readName} from './wire.js';

const decoder = new TextDecoder();

/** One resource record in the JSON API. */
interface JsonRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

/** A DNS response in the Google JSON API format. */
export interface JsonResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{name: string; type: number}>;
  Answer?: JsonRecord[];
  Authority?: JsonRecord[];
  Additional?: JsonRecord[];
  Comment?: string;
}

/** SVCB/HTTPS parameter names by key (RFC 9460). */
const SVCB_KEYS: Record<number, string> = {
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
  7: 'dohpath',
};

/**
 * @return Lower-case hex.
 */
function toHex(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Formats 16 bytes as an IPv6 address, collapsing the longest run of zeros.
 */
function formatIpv6(b: Uint8Array, offset: number): string {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    const group = (b[offset + 2 * i] << 8) | b[offset + 2 * i + 1];
    groups.push(group.toString(16));
  }

  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') {
      i++;
      continue;
    }
    let end = i;
    while (end < 8 && groups[end] === '0') {
      end++;
    }
    if (end - i > bestLength) {
      bestStart = i;
      bestLength = end - i;
    }
    i = end;
  }

  if (bestLength < 2) {
    return groups.join(':');
  }
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

/**
 * Formats the address-list parameter of an SVCB record.
 * @param size Bytes per address (4 or 16).
 */
function formatAddressHints(value: Uint8Array, size: number): string {
  const addresses = [];
  for (let i = 0; i + size <= value.length; i += size) {
    addresses.push(
      size === 4
        ? [...value.subarray(i, i + 4)].join('.')
        : formatIpv6(value, i)
    );
  }
  return addresses.join(',');
}

/**
 * Formats the `alpn` parameter value (a list of length-prefixed ids).
 */
function formatAlpn(value: Uint8Array): string {
  const ids = [];
  for (let i = 0; i < value.length; i += 1 + value[i]) {
    ids.push(latin1(value.subarray(i + 1, i + 1 + value[i])));
  }
  return ids.join(',');
}

/**
 * Formats SVCB/HTTPS rdata in presentation format.
 */
function formatSvcb(b: Uint8Array, offset: number, end: number): string {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const target = readName(b, offset + 2);
  const parts = [String(view.getUint16(offset)), target.name];

  for (let p = target.next; p + 4 <= end;) {
    const key = view.getUint16(p);
    const length = view.getUint16(p + 2);
    const value = b.subarray(p + 4, p + 4 + length);
    p += 4 + length;

    const name = SVCB_KEYS[key] || `key${key}`;
    switch (key) {
      case 1:
        parts.push(`${name}=${formatAlpn(value)}`);
        break;
      case 2:
        parts.push(name);
        break;
      case 3:
        parts.push(`${name}=${(value[0] << 8) | value[1]}`);
        break;
      case 4:
        parts.push(`${name}=${formatAddressHints(value, 4)}`);
        break;
      case 5:
        parts.push(`${name}=${btoa(latin1(value))}`);
        break;
      case 6:
        parts.push(`${name}=${formatAddressHints(value, 16)}`);
        break;
      case 7:
        parts.push(`${name}=${decoder.decode(value)}`);
        break;
      default:
        parts.push(`${name}=${toHex(value)}`);
    }
  }
  return parts.join(' ');
}

/**
 * Formats TXT rdata: every character-string quoted, joined by spaces.
 */
function formatTxt(b: Uint8Array, offset: number, end: number): string {
  const strings = [];
  for (let i = offset; i < end; i += 1 + b[i]) {
    const text = decoder.decode(b.subarray(i + 1, i + 1 + b[i]));
    strings.push('"' + text.replace(/[\\"]/g, '\\$&') + '"');
  }
  return strings.join(' ');
}

/**
 * Formats the rdata of one record.
 * @return Null for types without a text format here.
 */
function formatRdata(
  b: Uint8Array,
  type: number,
  offset: number,
  length: number
): string | null {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const end = offset + length;
  switch (type) {
    case 1: // A
      return length === 4 ? [...b.subarray(offset, end)].join('.') : null;
    case 28: // AAAA
      return length === 16 ? formatIpv6(b, offset) : null;
    case 2: // NS
    case 5: // CNAME
    case 12: // PTR
      return readName(b, offset).name;
    case 15: // MX
      return `${view.getUint16(offset)} ${readName(b, offset + 2).name}`;
    case 16: // TXT
      return formatTxt(b, offset, end);
    case 6: {
      // SOA
      const mname = readName(b, offset);
      const rname = readName(b, mname.next);
      const numbers = [0, 4, 8, 12, 16].map(d =>
        view.getUint32(rname.next + d)
      );
      return `${mname.name} ${rname.name} ${numbers.join(' ')}`;
    }
    case 33: {
      // SRV
      const [priority, weight, port] = [0, 2, 4].map(d =>
        view.getUint16(offset + d)
      );
      return `${priority} ${weight} ${port} ${readName(b, offset + 6).name}`;
    }
    case 257: {
      // CAA
      const tagLength = b[offset + 1];
      const tag = latin1(b.subarray(offset + 2, offset + 2 + tagLength));
      const value = decoder.decode(b.subarray(offset + 2 + tagLength, end));
      return `${b[offset]} ${tag} "${value}"`;
    }
    case 64: // SVCB
    case 65: // HTTPS
      return formatSvcb(b, offset, end);
    default:
      return null;
  }
}

/**
 * Reads `count` records starting at `offset`, skipping OPT pseudo-records.
 */
function readRecords(
  b: Uint8Array,
  offset: number,
  count: number
): {records: JsonRecord[]; next: number} {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const records = [];
  for (let i = 0; i < count; i++) {
    const owner = readName(b, offset);
    const fixed = owner.next;
    if (fixed + 10 > b.length) {
      throw new Error('bad response');
    }
    const type = view.getUint16(fixed);
    const ttl = view.getUint32(fixed + 4);
    const length = view.getUint16(fixed + 8);
    const data = fixed + 10;
    if (data + length > b.length) {
      throw new Error('bad response');
    }

    if (type !== TYPE_OPT) {
      let text = null;
      try {
        text = formatRdata(b, type, data, length);
      } catch {
        // Fall through to the generic format below.
      }
      records.push({
        name: owner.name,
        type,
        TTL: ttl,
        data: text ?? `\\# ${length} ${toHex(b.subarray(data, data + length))}`,
      });
    }
    offset = data + length;
  }
  return {records, next: offset};
}

/**
 * Converts a DNS response into the JSON API format.
 * @throws If the message cannot be read.
 */
export function toJson(b: Uint8Array): JsonResponse {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const flags = view.getUint16(2);

  let offset = 12;
  const question = [];
  for (let i = 0, count = view.getUint16(4); i < count; i++) {
    const name = readName(b, offset);
    question.push({name: name.name, type: view.getUint16(name.next)});
    offset = name.next + 4;
  }

  const answer = readRecords(b, offset, view.getUint16(6));
  const authority = readRecords(b, answer.next, view.getUint16(8));
  const additional = readRecords(b, authority.next, view.getUint16(10));

  const json: JsonResponse = {
    Status: flags & 15,
    TC: !!(flags & 0x200),
    RD: !!(flags & 0x100),
    RA: !!(flags & 0x80),
    AD: !!(flags & 0x20),
    CD: !!(flags & 0x10),
    Question: question,
  };
  if (answer.records.length) {
    json.Answer = answer.records;
  }
  if (authority.records.length) {
    json.Authority = authority.records;
  }
  if (additional.records.length) {
    json.Additional = additional.records;
  }
  return json;
}
