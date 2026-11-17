/**
 * @fileoverview Read side of the blocklist: a reversed-label trie stored as a
 * flat Uint32Array, so it loads without parsing. Written by
 * scripts/build-blocklist.ts.
 *
 * Layout (32-bit words, little-endian): `[MAGIC, nodeCount]`, then 3 words
 * (12 bytes) per node, with these fields packed from the lowest bit up:
 *
 *   word 0: hashA (32)
 *   word 1: hashB (20), isEnd (1), childCount bits 0-10 (11)
 *   word 2: firstChild (24), childCount bits 11-18 (8)
 *
 * hashA and hashB together are a 52-bit hash of the label, so that an unlisted
 * name practically never collides with a listed sibling. Node 0 is the root.
 * The children of a node are contiguous and sorted by (hashA, hashB). A node
 * with `isEnd` blocks its whole subtree, so it has no children.
 */

export const MAGIC = 0x424c4b32;
export const HEADER_WORDS = 2;
export const NODE_WORDS = 3;

/** Limits of the packed fields. */
export const MAX_NODES = 1 << 24;
export const MAX_CHILDREN = 1 << 19;

const HASH_B_MASK = 0xfffff;

/**
 * Two independent hashes of a label, as [hashA (32 bits), hashB (20 bits)].
 */
export function hashLabel(label: string): [number, number] {
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = 0; i < label.length; i++) {
    const c = label.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
  }
  return [a >>> 0, (b >>> 0) & HASH_B_MASK];
}

/**
 * Packs one node into its 3 words.
 */
export function packNode(
  hash: [number, number],
  isEnd: boolean,
  firstChild: number,
  childCount: number
): [number, number, number] {
  return [
    hash[0],
    (hash[1] | ((isEnd ? 1 : 0) << 20) | ((childCount & 0x7ff) << 21)) >>> 0,
    (firstChild | ((childCount >>> 11) << 24)) >>> 0,
  ];
}

/**
 * @param name Lower-case domain name without a trailing dot.
 * @return Whether the name, or one of its parent domains, is listed.
 */
export function isBlocked(trie: Uint32Array, name: string): boolean {
  if (trie[0] !== MAGIC) {
    return false;
  }
  const labels = name.split('.');
  let node = 0;
  for (let i = labels.length - 1; i >= 0; i--) {
    const base = HEADER_WORDS + node * NODE_WORDS;
    const word1 = trie[base + 1];
    const word2 = trie[base + 2];
    const first = word2 & 0xffffff;
    const count = ((word1 >>> 21) & 0x7ff) | ((word2 >>> 24) << 11);
    const [hashA, hashB] = hashLabel(labels[i]);
    let low = 0;
    let high = count - 1;
    let found = -1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const at = HEADER_WORDS + (first + mid) * NODE_WORDS;
      const midA = trie[at];
      const midB = trie[at + 1] & HASH_B_MASK;
      if (midA === hashA && midB === hashB) {
        found = mid;
        break;
      }
      if (midA < hashA || (midA === hashA && midB < hashB)) {
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    if (found < 0) {
      return false;
    }
    node = first + found;
    if ((trie[HEADER_WORDS + node * NODE_WORDS + 1] >>> 20) & 1) {
      return true;
    }
  }
  return false;
}
