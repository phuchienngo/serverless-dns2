/** @fileoverview EDNS Client Subnet (RFC 7871) helpers. */

import {u16} from './dns.js';

/**
 * Parses an IPv4 or IPv6 address. IPv4-mapped IPv6 becomes plain IPv4.
 * @return Family is 1 (IPv4) or 2
 *     (IPv6); null if `ip` is not a valid address.
 */
function parseIp(ip: string): {family: number; bytes: number[]} | null {
  ip = ip.trim();
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) {
    ip = mapped[1];
  }

  if (!ip.includes(':')) {
    const parts = ip.split('.');
    const valid =
      parts.length === 4 &&
      parts.every(p => /^\d{1,3}$/.test(p) && Number(p) < 256);
    return valid ? {family: 1, bytes: parts.map(Number)} : null;
  }

  const halves = ip.split('::');
  if (halves.length > 2) {
    return null;
  }
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves[1] ? halves[1].split(':') : [];
  const tooLong =
    halves.length === 1 ? head.length !== 8 : head.length + tail.length > 7;
  if (tooLong) {
    return null;
  }
  const zeros = Array(8 - head.length - tail.length).fill('0');
  const groups = [...head, ...zeros, ...tail];
  if (!groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) {
    return null;
  }
  return {family: 2, bytes: groups.flatMap(g => u16(parseInt(g, 16)))};
}

/**
 * Builds the EDNS client-subnet option.
 * @param prefix Source prefix length; defaults to /24 (IPv4) or /48
 *     (IPv6).
 * @return The option bytes, or null for an invalid input.
 */
export function makeEcs(ip: string, prefix?: number): number[] | null {
  const address = parseIp(ip);
  if (!address) {
    return null;
  }
  const maxPrefix = address.family === 1 ? 32 : 128;
  if (prefix === undefined) {
    prefix = address.family === 1 ? 24 : 48;
  }
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    return null;
  }

  const byteCount = Math.ceil(prefix / 8);
  const bytes = address.bytes.slice(0, byteCount);
  const partialBits = prefix % 8;
  if (partialBits) {
    bytes[byteCount - 1] &= (0xff << (8 - partialBits)) & 0xff; // Zero the rest.
  }
  const data = [...u16(address.family), prefix, 0, ...bytes];
  return [...u16(8), ...u16(data.length), ...data]; // Option code 8.
}

/**
 * Parses the JSON API's `edns_client_subnet` parameter.
 * @param param For example `1.2.3.4/24` or `2001:db8::/48`.
 * @return The option bytes, or null if invalid.
 */
export function parseEcsParam(param: string): number[] | null {
  const [ip, prefix, ...extra] = param.split('/');
  if (extra.length || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) {
    return null;
  }
  return makeEcs(ip, prefix === undefined ? undefined : Number(prefix));
}
