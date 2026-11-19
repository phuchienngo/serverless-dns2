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
 * The hashes are split into blocks of `2 ** blockBits`, with an index, so that
 * a lookup decodes one block instead of the whole set: nothing is decoded when
 * the file is loaded, which matters in an isolate that starts cold.
 *
 * File layout (all integers little-endian):
 * - `MAGIC` (u32), `count` (u32), `k` (u8), `bits` (u8), `blockBits` (u8) and
 *   `streamBits` (u32), the length of the bit stream below.
 * - The index, one 12-byte entry per block: the block's first hash (low u32,
 *   high u32) and the bit offset in the stream where the rest of the block
 *   starts.
 * - The bit stream: for each hash that is not the first of its block, the gap
 *   to the previous one as `gap >> k` in unary (that many 1 bits, then a 0
 *   bit) followed by the low `k` bits of the gap. Bits are written most
 *   significant first and the last byte is padded with zeros.
 */

export const MAGIC = 0x424c4b35; // BLK5; rejects the previous formats.
export const HEADER_BYTES = 15;
/** Bytes of one index entry. */
export const INDEX_ENTRY_BYTES = 12;
/** Hashes per block, as a power of two: a lookup decodes at most this many. */
export const BLOCK_BITS = 6;

/** A loaded blocklist: its index and the bit stream of the gaps. */
export interface BlockSet {
  /** Number of hashes, each `bits` bits wide. */
  count: number;
  bits: number;
  k: number;
  blockBits: number;
  /** The first hash of each block, increasing. */
  firsts: Float64Array;
  /** Where in the stream the rest of each block starts, in bits. */
  offsets: Uint32Array;
  stream: Uint8Array;
  streamBits: number;
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
 * @return The 32 bits that start at bit `pos` of `bytes` (bits past the end
 *     read as zeros).
 */
function window(bytes: Uint8Array, pos: number): number {
  const at = pos >> 3;
  const shift = pos & 7;
  if (at + 4 >= bytes.length) {
    // Near the end: read the bytes that exist, without going past the array.
    let high = 0;
    for (let i = 0; i < 4; i++) {
      high = (high << 8) | (at + i < bytes.length ? bytes[at + i] : 0);
    }
    const next = at + 4 < bytes.length ? bytes[at + 4] : 0;
    return shift === 0
      ? high >>> 0
      : ((high << shift) | (next >>> (8 - shift))) >>> 0;
  }
  const high =
    ((bytes[at] << 24) |
      (bytes[at + 1] << 16) |
      (bytes[at + 2] << 8) |
      bytes[at + 3]) >>>
    0;
  return shift === 0
    ? high
    : ((high << shift) | (bytes[at + 4] >>> (8 - shift))) >>> 0;
}

/** Reads Golomb-Rice coded gaps one after the other from a bit position. */
export class GapReader {
  /** Where the next gap starts, in bits. */
  pos: number;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly k: number,
    pos: number
  ) {
    this.pos = pos;
  }

  /** @return The next gap. */
  next(): number {
    let quotient = 0;
    for (;;) {
      const w = window(this.bytes, this.pos);
      if (w === 0xffffffff) {
        quotient += 32;
        this.pos += 32;
        continue;
      }
      const ones = Math.clz32(~w);
      quotient += ones;
      this.pos += ones + 1;
      break;
    }
    let remainder = 0;
    if (this.k > 0) {
      remainder = window(this.bytes, this.pos) >>> (32 - this.k);
      this.pos += this.k;
    }
    return quotient * 2 ** this.k + remainder;
  }
}

/**
 * Reads a blocklist file. Only the index is read; the hashes are decoded when
 * a name is looked up (see `decodeAll` for all of them).
 * @throws If it is not a valid blocklist.
 */
export function decodeBlockset(buffer: ArrayBuffer): BlockSet {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < HEADER_BYTES) {
    throw new Error('not a blocklist');
  }
  const view = new DataView(buffer);
  if (view.getUint32(0, true) !== MAGIC) {
    // A missing asset may be answered with index.html; old assets are invalid.
    throw new Error('not a blocklist');
  }
  const count = view.getUint32(4, true);
  const k = bytes[8];
  const bits = bytes[9];
  const blockBits = bytes[10];
  const streamBits = view.getUint32(11, true);
  if (k > 31 || bits < k || bits > 53 || blockBits < 1 || blockBits > 16) {
    throw new Error('bad blocklist header');
  }

  const blocks = Math.ceil(count / 2 ** blockBits);
  const streamStart = HEADER_BYTES + blocks * INDEX_ENTRY_BYTES;
  const expected = streamStart + Math.ceil(streamBits / 8);
  if (bytes.length < expected) {
    throw new Error('truncated blocklist');
  }
  if (bytes.length !== expected) {
    throw new Error('bad blocklist length');
  }

  const firsts = new Float64Array(blocks);
  const offsets = new Uint32Array(blocks);
  for (let b = 0, at = HEADER_BYTES; b < blocks; b++, at += INDEX_ENTRY_BYTES) {
    firsts[b] =
      view.getUint32(at + 4, true) * 2 ** 32 + view.getUint32(at, true);
    offsets[b] = view.getUint32(at + 8, true);
    const ordered =
      b === 0 || (firsts[b] > firsts[b - 1] && offsets[b] >= offsets[b - 1]);
    if (!ordered || offsets[b] > streamBits || firsts[b] >= 2 ** bits) {
      throw new Error('bad blocklist index');
    }
  }
  return {
    count,
    bits,
    k,
    blockBits,
    firsts,
    offsets,
    stream: bytes.subarray(streamStart),
    streamBits,
  };
}

/** How many hashes block `b` holds. */
export function blockLength(set: BlockSet, b: number): number {
  return Math.min(2 ** set.blockBits, set.count - b * 2 ** set.blockBits);
}

/** Whether the set holds the hash: decodes the one block that could. */
function contains(set: BlockSet, value: number): boolean {
  const {firsts} = set;
  let low = 0;
  let high = firsts.length - 1;
  let block = -1; // The last block whose first hash is at most `value`.
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (firsts[mid] <= value) {
      block = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  if (block < 0) {
    return false;
  }
  let current = firsts[block];
  if (current === value) {
    return true;
  }
  // The lookup's hot loop, with the usual gap (its unary part and remainder
  // both inside one 32-bit window) read in place: a GapReader per lookup
  // cost about a third of it. A rarer, longer gap is read by a GapReader.
  const {stream, k} = set;
  const scale = 2 ** k;
  let pos = set.offsets[block];
  for (let i = blockLength(set, block) - 1; i > 0; i--) {
    const w = window(stream, pos);
    const ones = w !== 0xffffffff ? Math.clz32(~w) : 32;
    if (ones + 1 + k <= 32) {
      pos += ones + 1 + k;
      current += ones * scale + (k > 0 ? (w << (ones + 1)) >>> (32 - k) : 0);
    } else {
      const gaps = new GapReader(stream, k, pos);
      current += gaps.next();
      pos = gaps.pos;
    }
    if (current >= value) {
      return current === value;
    }
  }
  return false;
}

/** Whether the name or any of its parent domains is blocked. */
export function isBlocked(set: BlockSet, name: string): boolean {
  const {bits} = set;
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
    if (
      (i === 0 || name.charCodeAt(i - 1) === 46) &&
      contains(set, truncate(a, b, bits))
    ) {
      return true;
    }
  }
  return false;
}
