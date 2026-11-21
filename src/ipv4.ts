/** @fileoverview IPv4 addresses and the blocks (CIDR ranges) they fall in. */

/** A block of addresses: the first address and the prefix length. */
export type Ipv4Block = [address: number[], prefix: number];

/** @param a Four bytes. */
function toNumber(a: ArrayLike<number>): number {
  return ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0;
}

/**
 * @param a Four bytes.
 * @return Whether the address is in one of the blocks.
 */
export function inBlocks(
  a: ArrayLike<number>,
  blocks: readonly Ipv4Block[]
): boolean {
  const n = toNumber(a);
  return blocks.some(([base, prefix]) => {
    // A shift by 32 does nothing in JavaScript, so /0 needs its own mask.
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (n & mask) >>> 0 === (toNumber(base) & mask) >>> 0;
  });
}

/**
 * @param cidrs Ranges such as `173.245.48.0/20`.
 * @throws If one is not a valid IPv4 range.
 */
export function parseCidrs(cidrs: string[]): Ipv4Block[] {
  return cidrs.map(cidr => {
    const match =
      /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
    const address = match?.slice(1, 5).map(Number);
    const prefix = Number(match?.[5]);
    if (!address || address.some(b => b > 255) || prefix > 32) {
      throw new Error(`not an IPv4 range: ${cidr}`);
    }
    return [address, prefix];
  });
}
