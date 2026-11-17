/**
 * @fileoverview Read side of the blocklist: a reversed-label trie stored as a
 * flat Uint32Array, so it loads without parsing. Written by
 * scripts/build-blocklist.ts.
 *
 * Layout (32-bit words, little-endian): `[MAGIC, nodeCount]`, then per node
 * `[hashHigh, hashLow, firstChild, (childCount << 1) | isEnd]`, where the two
 * hash words together are a 64-bit hash of the label (so that unlisted names
 * practically never collide with a listed sibling). Node 0 is the root.
 * The children of a node are contiguous and sorted by (hashHigh, hashLow). A node
 * with `isEnd` blocks its whole subtree, so it has no children.
 */

export const MAGIC = 0x424c4b31;
export const HEADER_WORDS = 2;
export const NODE_WORDS = 4;

/**
 * Two independent 32-bit FNV-1a hashes of a label, as [high, low].
 */
export function hashLabel(label: string): [number, number] {
  let high = 0x811c9dc5;
  let low = 0x9747b28c;
  for (let i = 0; i < label.length; i++) {
    const c = label.charCodeAt(i);
    high = Math.imul(high ^ c, 0x01000193);
    low = Math.imul(low ^ c, 0x85ebca6b) ^ (low >>> 15);
  }
  return [high >>> 0, low >>> 0];
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
    const first = trie[base + 2];
    const [hashHigh, hashLow] = hashLabel(labels[i]);
    let low = 0;
    let high = (trie[base + 3] >>> 1) - 1;
    let found = -1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const at = HEADER_WORDS + (first + mid) * NODE_WORDS;
      const midHigh = trie[at];
      const midLow = trie[at + 1];
      if (midHigh === hashHigh && midLow === hashLow) {
        found = mid;
        break;
      }
      if (midHigh < hashHigh || (midHigh === hashHigh && midLow < hashLow)) {
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    if (found < 0) {
      return false;
    }
    node = first + found;
    if (trie[HEADER_WORDS + node * NODE_WORDS + 3] & 1) {
      return true;
    }
  }
  return false;
}
