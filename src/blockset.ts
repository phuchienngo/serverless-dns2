/**
 * @fileoverview Sorted hashes of blocked domains. A query checks each suffix
 * so a blocked domain also blocks all of its subdomains.
 *
 * Layout (32-bit words, little-endian): `[MAGIC, count]`, followed by
 * `count` pairs of unsigned 32-bit hashes, sorted by the first then second.
 */

export const MAGIC = 0x424c4b33; // BLK3; rejects the previous trie asset.
export const HEADER_WORDS = 2;
export const HASH_WORDS = 2;

/** Two independent 32-bit hashes of a domain, read from right to left. */
export function hashDomain(name: string): [number, number] {
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
  }
  return [a >>> 0, b >>> 0];
}

function contains(words: Uint32Array, a: number, b: number): boolean {
  let low = 0;
  let high = words[1] - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    const at = HEADER_WORDS + mid * HASH_WORDS;
    const midA = words[at];
    const midB = words[at + 1];
    if (midA === a && midB === b) {
      return true;
    }
    if (midA < a || (midA === a && midB < b)) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return false;
}

/** Whether the name or any of its parent domains is blocked. */
export function isBlocked(words: Uint32Array, name: string): boolean {
  if (
    words[0] !== MAGIC ||
    words.length !== HEADER_WORDS + words[1] * HASH_WORDS
  ) {
    return false;
  }

  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
    if (
      (i === 0 || name.charCodeAt(i - 1) === 46) &&
      contains(words, a >>> 0, b >>> 0)
    ) {
      return true;
    }
  }
  return false;
}
