/**
 * @fileoverview The set of blocked domains, stored as a Golomb-coded set: each
 * domain is hashed to `bits` bits, the sorted hashes are stored as the gaps
 * between neighbours (Golomb-Rice coded). A query checks each suffix of the
 * name, so a blocked domain also blocks all of its subdomains.
 *
 * Hashes are truncated to `bits = ceil(log2 count) + k`, so a name that is not
 * listed is wrongly found with a probability of about 2^-k per suffix. Listed
 * names are always found.
 *
 * File layout: `MAGIC` (u32 LE), `count` (u32 LE), `k` (u8), `bits` (u8), then
 * for each sorted hash the gap to the previous one (the first gap is the hash
 * itself) as `gap >> k` in unary (that many 1 bits, then a 0 bit) followed by
 * the low `k` bits of the gap. Bits are written most significant first and the
 * last byte is padded with zeros.
 */

export const MAGIC = 0x424c4b34; // BLK4; rejects the previous formats.
export const HEADER_BYTES = 10;

/** A decoded blocklist: the sorted hashes, each `bits` bits wide. */
export interface BlockSet {
  values: Float64Array;
  bits: number;
}

/**
 * @return The hash `(a, b)` of a name cut to its low `bits` bits (at most 53,
 *     so the result is an exact number).
 */
function truncate(a: number, b: number, bits: number): number {
  a >>>= 0;
  if (bits <= 32) {
    return a % 2 ** bits;
  }
  return ((b >>> 0) % 2 ** (bits - 32)) * 2 ** 32 + a;
}

/** The `bits`-bit hash of a domain, read from right to left. */
export function hashDomain(name: string, bits: number): number {
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
  }
  return truncate(a, b, bits);
}

/**
 * Decodes a blocklist file.
 * @throws If it is not a valid blocklist.
 */
export function decodeBlockset(buffer: ArrayBuffer): BlockSet {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < HEADER_BYTES) {
    throw new Error('not a blocklist');
  }
  const view = new DataView(buffer);
  if (view.getUint32(0, true) !== MAGIC) {
    // Pages may answer a missing file with index.html; old assets are invalid.
    throw new Error('not a blocklist');
  }
  const count = view.getUint32(4, true);
  const k = bytes[8];
  const bits = bytes[9];
  if (k > 31 || bits < k || bits > 53) {
    throw new Error('bad blocklist header');
  }

  const values = new Float64Array(count);
  const end = bytes.length * 8;
  const unit = 2 ** k;
  let pos = HEADER_BYTES * 8;
  let prev = 0;
  for (let i = 0; i < count; i++) {
    let quotient = 0;
    for (;;) {
      if (pos >= end) {
        throw new Error('truncated blocklist');
      }
      const bit = (bytes[pos >> 3] >> (7 - (pos & 7))) & 1;
      pos++;
      if (!bit) {
        break;
      }
      quotient++;
    }
    if (pos + k > end) {
      throw new Error('truncated blocklist');
    }
    let remainder = 0;
    for (let j = 0; j < k; j++) {
      remainder = remainder * 2 + ((bytes[pos >> 3] >> (7 - (pos & 7))) & 1);
      pos++;
    }
    prev += quotient * unit + remainder;
    values[i] = prev;
  }
  if (end - pos >= 8) {
    throw new Error('bad blocklist length');
  }
  return {values, bits};
}

function contains(values: Float64Array, value: number): boolean {
  let low = 0;
  let high = values.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    const at = values[mid];
    if (at === value) {
      return true;
    }
    if (at < value) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return false;
}

/** Whether the name or any of its parent domains is blocked. */
export function isBlocked(set: BlockSet, name: string): boolean {
  const {values, bits} = set;
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
    if (
      (i === 0 || name.charCodeAt(i - 1) === 46) &&
      contains(values, truncate(a, b, bits))
    ) {
      return true;
    }
  }
  return false;
}
