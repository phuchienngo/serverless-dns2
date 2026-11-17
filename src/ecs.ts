/** @fileoverview EDNS Client Subnet (RFC 7871) helpers. */

import {skipName, u16} from './dns.js';

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
  return buildOption(address.family, address.bytes, prefix);
}

/**
 * Encodes an ECS option, zeroing the address bits beyond `prefix`.
 */
function buildOption(family: number, address: number[], prefix: number) {
  const byteCount = Math.ceil(prefix / 8);
  const bytes = address.slice(0, byteCount);
  const partialBits = prefix % 8;
  if (partialBits) {
    bytes[byteCount - 1] &= (0xff << (8 - partialBits)) & 0xff; // Zero the rest.
  }
  const data = [...u16(family), prefix, 0, ...bytes];
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

/**
 * Reads the client's own ECS option from a DNS query (as sent by dnsproxy or
 * AdGuard Home with `edns-addr`). The subnet is clamped to /24 (IPv4) or /48
 * (IPv6) to keep the cache effective and the client's privacy.
 * @param questionLength Length of the question section (`question.raw`).
 * @return The option bytes; null if there is none, or it is empty (a privacy
 *     signal such as Firefox's `::/0`, meaning "do not locate me").
 */
export function clientEcs(
  wire: Uint8Array,
  questionLength: number
): number[] | null {
  try {
    const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    let offset = 12 + questionLength;
    const records = view.getUint16(6) + view.getUint16(8) + view.getUint16(10);
    for (let i = 0; i < records; i++) {
      offset = skipName(wire, offset);
      const type = view.getUint16(offset);
      let rdata = offset + 10;
      const end = rdata + view.getUint16(offset + 8);
      if (end > wire.length) {
        return null;
      }
      offset = end;
      if (type !== 41) {
        continue;
      }
      for (; rdata + 4 <= end;) {
        const code = view.getUint16(rdata);
        const length = view.getUint16(rdata + 2);
        const data = wire.subarray(rdata + 4, rdata + 4 + length);
        rdata += 4 + length;
        if (code !== 8 || data.length < 4) {
          continue;
        }
        const family = (data[0] << 8) | data[1];
        const source = data[2];
        const address = Array.from(data.subarray(4));
        const maxBits = family === 1 ? 32 : 128;
        const empty = source === 0 || address.every(b => b === 0);
        if (
          (family !== 1 && family !== 2) ||
          source > maxBits ||
          address.length !== Math.ceil(source / 8) ||
          empty
        ) {
          return null;
        }
        const padded = [
          ...address,
          ...Array(maxBits / 8 - address.length).fill(0),
        ];
        return buildOption(
          family,
          padded,
          Math.min(source, family === 1 ? 24 : 48)
        );
      }
    }
  } catch {
    // Malformed: behave as if the client sent no ECS.
  }
  return null;
}

/**
 * @return The `in-addr.arpa` / `ip6.arpa` name for an IP address; null if
 *     `ip` is not one.
 */
export function reverseName(ip: string): string | null {
  const address = parseIp(ip);
  if (!address) {
    return null;
  }
  if (address.family === 1) {
    return [...address.bytes].reverse().join('.') + '.in-addr.arpa';
  }
  const nibbles = address.bytes.flatMap(b => [b >> 4, b & 15]);
  return (
    nibbles
      .reverse()
      .map(n => n.toString(16))
      .join('.') + '.ip6.arpa'
  );
}
