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
 * Builds ECS from the connecting IP, capped at /24 (IPv4) or /48 (IPv6).
 * @param maxPrefix A shorter source prefix requested by the client.
 * @return The option bytes, or null for an invalid input.
 */
export function makeEcs(ip: string | null, maxPrefix = 128): number[] | null {
  const address = ip && parseIp(ip);
  if (!address) {
    return null;
  }
  if (!Number.isInteger(maxPrefix) || maxPrefix < 0 || maxPrefix > 128) {
    return null;
  }
  return buildOption(address.family, address.bytes, maxPrefix);
}

/**
 * Encodes ECS with the family's prefix cap and zeroes the remaining bits.
 */
function buildOption(
  family: number,
  address: number[] | Uint8Array,
  maxPrefix?: number
) {
  const cap = ECS_FAMILIES[family].prefix;
  const prefix = Math.min(maxPrefix ?? cap, cap);
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
 * @return The option bytes, or undefined for an invalid parameter.
 */
export function parseEcsParam(
  param: string,
  ip: string | null
): number[] | undefined {
  const [requestedIp, length, ...extra] = param.split('/');
  const address = parseIp(requestedIp);
  if (
    !address ||
    extra.length ||
    (length !== undefined && !/^\d{1,3}$/.test(length))
  ) {
    return undefined;
  }
  const prefix = length === undefined ? undefined : Number(length);
  if (prefix !== undefined && prefix > ECS_FAMILIES[address.family].bits) {
    return undefined;
  }
  return prefix === 0
    ? buildOption(address.family, [], 0)
    : (makeEcs(ip, prefix) ??
        buildOption(address.family, address.bytes, prefix));
}

/**
 * Applies the client's prefix limit to the connecting IP, with the supplied
 * subnet as a fallback. A zero prefix or all-zero address requests no location.
 * @param data The data of the option, as sent; null if the query had none.
 * @return The override to send upstream, or null to use the default.
 */
export function clientEcs(
  data: Uint8Array | null,
  ip: string | null
): number[] | null {
  if (!data || data.length < 4) {
    return null;
  }
  const family = (data[0] << 8) | data[1];
  const source = data[2];
  const address = data.subarray(4);
  const spec = ECS_FAMILIES[family];
  if (!spec || source > spec.bits || address.length !== Math.ceil(source / 8)) {
    return null;
  }
  if (source === 0 || address.every(b => b === 0)) {
    return buildOption(family, [], 0);
  }
  return makeEcs(ip, source) ?? buildOption(family, address, source);
}

/**
 * Echoes the client's ECS fields. When translated, a subnet-specific
 * answer is scoped to the query's full prefix.
 * @return Replacement option data, or null if no change is needed.
 */
export function clientEcsReply(
  received: Uint8Array,
  sent: Uint8Array
): number[] | null {
  if (
    sent.length < 4 ||
    received.length < 4 ||
    (sent.length === received.length &&
      sent.every((byte, i) => i === 3 || byte === received[i]))
  ) {
    return null;
  }
  return [
    ...sent.subarray(0, 3),
    received[3] === 0 ? 0 : sent[2],
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
