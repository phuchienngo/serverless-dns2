/**
 * @fileoverview DNS rebinding protection: a public name must not resolve to an
 * address inside the client's own network (or to the client itself), where a
 * web page could use it to reach a router, a printer or a local service.
 */

import {
  SVCPARAM_IPV4HINT,
  SVCPARAM_IPV6HINT,
  TYPE_A,
  TYPE_AAAA,
  TYPE_HTTPS,
  TYPE_SVCB,
} from './constants.js';
import {parseAnswers, type DnsRecord} from './dns.js';
import {inBlocks, type Ipv4Block} from './ipv4.js';
import {svcParams} from './svcb.js';

/**
 * IPv4 blocks that rebinding uses, as [address, prefix length]: this network,
 * private, shared (carrier-grade NAT), loopback and link-local addresses.
 */
const PRIVATE_V4: Ipv4Block[] = [
  [[0, 0, 0, 0], 8],
  [[10, 0, 0, 0], 8],
  [[100, 64, 0, 0], 10],
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16],
  [[172, 16, 0, 0], 12],
  [[192, 168, 0, 0], 16],
];

/**
 * @param a Four bytes.
 * @return Whether the address is in the client's network or on its machine.
 *     0.0.0.0 is not counted: blocklists answer it for a blocked name.
 */
export function isPrivateV4(a: ArrayLike<number>): boolean {
  if (a[0] === 0 && a[1] === 0 && a[2] === 0 && a[3] === 0) {
    return false;
  }
  return inBlocks(a, PRIVATE_V4);
}

/**
 * @param a Sixteen bytes.
 * @return Whether the address is loopback (::1), unique local (fc00::/7),
 *     link-local (fe80::/10), or an IPv4-mapped address (::ffff:0:0/96) of a
 *     private IPv4 address. `::` is not counted, like 0.0.0.0.
 */
export function isPrivateV6(a: ArrayLike<number>): boolean {
  const leading = (n: number) =>
    a.length >= n &&
    Array.from({length: n}, (_, i) => a[i]).every(b => b === 0);
  if (leading(15)) {
    return a[15] === 1; // ::1 (and :: is not).
  }
  if ((a[0] & 0xfe) === 0xfc) {
    return true;
  }
  if (a[0] === 0xfe && (a[1] & 0xc0) === 0x80) {
    return true;
  }
  const mapped = leading(10) && a[10] === 0xff && a[11] === 0xff;
  return mapped && isPrivateV4([a[12], a[13], a[14], a[15]]);
}

/** The addresses in the SvcParams `ipv4hint` and `ipv6hint` of a record. */
function hintedAddresses(
  msg: Uint8Array,
  record: DnsRecord
): Array<{v4: boolean; bytes: Uint8Array}> {
  return svcParams(msg, record).flatMap(({key, value}) => {
    const size =
      key === SVCPARAM_IPV4HINT ? 4 : key === SVCPARAM_IPV6HINT ? 16 : 0;
    const found = [];
    for (let i = 0; size && i + size <= value.length; i += size) {
      found.push({v4: size === 4, bytes: value.subarray(i, i + size)});
    }
    return found;
  });
}

/**
 * Looks for a private address in the answer section: in A and AAAA records,
 * and in the address hints of HTTPS and SVCB records, which browsers use too.
 * @param answers The records of the answer section, if already read.
 * @return The offending address (as bytes), or null if there is none or the
 *     message cannot be read.
 */
export function rebindingAddress(
  msg: Uint8Array,
  answers?: DnsRecord[]
): number[] | null {
  try {
    for (const r of answers ?? parseAnswers(msg)) {
      if (r.type === TYPE_A && r.length === 4) {
        const a = msg.subarray(r.data, r.end);
        if (isPrivateV4(a)) {
          return [...a];
        }
      } else if (r.type === TYPE_AAAA && r.length === 16) {
        const a = msg.subarray(r.data, r.end);
        if (isPrivateV6(a)) {
          return [...a];
        }
      } else if (r.type === TYPE_HTTPS || r.type === TYPE_SVCB) {
        for (const {v4, bytes} of hintedAddresses(msg, r)) {
          if (v4 ? isPrivateV4(bytes) : isPrivateV6(bytes)) {
            return [...bytes];
          }
        }
      }
    }
  } catch {
    // A message that does not parse is left to the callers that read it.
  }
  return null;
}
