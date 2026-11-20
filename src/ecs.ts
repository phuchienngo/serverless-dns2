/** @fileoverview EDNS Client Subnet (RFC 7871) helpers. */

import {
  ECS_FAMILIES,
  FAMILY_IPV4,
  FAMILY_IPV6,
  OPTION_ECS,
} from './constants.js';
import {ednsOption} from './response.js';
import {u16} from './wire.js';

/**
 * Parses an IPv4 or IPv6 address. IPv4-mapped IPv6 becomes plain IPv4.
 * @return The family (FAMILY_IPV4 or FAMILY_IPV6) and the address bytes; null
 *     if `ip` is not a valid address.
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
    return valid ? {family: FAMILY_IPV4, bytes: parts.map(Number)} : null;
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
  return {
    family: FAMILY_IPV6,
    bytes: groups.flatMap(g => u16(parseInt(g, 16))),
  };
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
  const {bits, prefix: defaultPrefix} = ECS_FAMILIES[address.family];
  prefix ??= defaultPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
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
  return ednsOption(OPTION_ECS, data);
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
 * Reads the client's own ECS option (as sent by dnsproxy or AdGuard Home with
 * `edns-addr`). The subnet is clamped to /24 (IPv4) or /48 (IPv6) to keep the
 * cache effective and the client's privacy.
 * @param data The data of the option, as sent; null if the query had none.
 * @return The option bytes; null if there is none or it is malformed (the
 *     connecting IP is used then). An empty one (source prefix 0 or an
 *     all-zero address: a privacy signal such as Firefox's `::/0`, "do not
 *     locate me") gives a source-prefix-0 option, which is sent upstream as it
 *     is so that no subnet is used (RFC 7871 7.1.2), and comes back with scope 0.
 */
export function clientEcs(data: Uint8Array | null): number[] | null {
  if (!data || data.length < 4) {
    return null;
  }
  const family = (data[0] << 8) | data[1];
  const source = data[2];
  const address = Array.from(data.subarray(4));
  const spec = ECS_FAMILIES[family];
  if (!spec || source > spec.bits || address.length !== Math.ceil(source / 8)) {
    return null;
  }
  if (source === 0 || address.every(b => b === 0)) {
    return buildOption(family, [], 0);
  }
  const padded = [...address, ...Array(spec.bits / 8 - address.length).fill(0)];
  return buildOption(family, padded, Math.min(source, spec.prefix));
}

/**
 * Restores the client's original ECS source prefix and address if clamped.
 * The scope is the upstream's, at most the source prefix (RFC 7871 7.2.2).
 * @return Replacement option data, or null if no change is needed.
 */
export function clientEcsReply(
  received: Uint8Array,
  sent: Uint8Array
): number[] | null {
  if (sent.length < 4 || received.length < 4 || sent[2] === received[2]) {
    return null;
  }
  return [
    ...sent.subarray(0, 3),
    Math.min(received[3], sent[2]),
    ...sent.subarray(4),
  ];
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
  if (address.family === FAMILY_IPV4) {
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
