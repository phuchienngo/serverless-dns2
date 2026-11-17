/**
 * @fileoverview Read side of the blocklist: a character-level trie in the
 * style of Cloudflare's `trie-hard`, stored as a flat Uint32Array so it loads
 * without parsing. Written by scripts/build-blocklist.ts.
 *
 * Domains are stored reversed (`example.com` -> `moc.elpmaxe`), so a domain
 * and its subdomains share a prefix. Only the characters a-z 0-9 - _ . occur,
 * so each is a symbol 0..38 and the children of a node fit in a 64-bit mask:
 * bit `s` is set if the node has a child for symbol `s`. A node's children
 * are contiguous, so child `s` is at `firstChild + popcount(mask below s)`.
 *
 * Layout (32-bit words, little-endian): `[MAGIC, nodeCount]`, then per node
 * `[maskLow, maskHigh, firstChild]`. Node 0 is the root. Bit 63 of the mask
 * marks a node where a listed domain ends.
 */

export const MAGIC = 0x54484431;
export const HEADER_WORDS = 2;
export const NODE_WORDS = 3;
export const END_BIT = 0x80000000;

/** Symbol of each ASCII code; 255 for characters that cannot occur. */
export const SYMBOL = new Uint8Array(128).fill(255);
'-._0123456789abcdefghijklmnopqrstuvwxyz'.split('').forEach((c, i) => {
  SYMBOL[c.charCodeAt(0)] = i;
});

const DOT = 46;

/** Number of set bits. */
function popcount(x: number): number {
  x -= (x >>> 1) & 0x55555555;
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  return (Math.imul((x + (x >>> 4)) & 0x0f0f0f0f, 0x01010101) >>> 24) & 63;
}

/**
 * @param name Lower-case domain name without a trailing dot.
 * @return Whether the name, or one of its parent domains, is listed.
 */
export function isBlocked(trie: Uint32Array, name: string): boolean {
  if (trie[0] !== MAGIC) {
    return false;
  }
  let node = 0;
  for (let i = name.length - 1; i >= 0; i--) {
    const code = name.charCodeAt(i);
    const symbol = code < 128 ? SYMBOL[code] : 255;
    if (symbol === 255) {
      return false;
    }
    const base = HEADER_WORDS + node * NODE_WORDS;
    const low = trie[base];
    const high = trie[base + 1];
    let rank: number;
    if (symbol < 32) {
      if (!((low >>> symbol) & 1)) {
        return false;
      }
      rank = popcount(low & ((1 << symbol) - 1));
    } else {
      const bit = symbol - 32;
      if (!((high >>> bit) & 1)) {
        return false;
      }
      rank = popcount(low) + popcount(high & ((1 << bit) - 1));
    }
    node = trie[base + 2] + rank;

    // A listed domain ends here; it matches only at a label boundary.
    const ends = trie[HEADER_WORDS + node * NODE_WORDS + 1] & END_BIT;
    if (ends && (i === 0 || name.charCodeAt(i - 1) === DOT)) {
      return true;
    }
  }
  return false;
}
