/**
 * @fileoverview The set of blocked domains, stored as a Ribbon filter (Dillinger
 * and Walzer, 2021). A query checks each suffix of the name, so a blocked
 * domain also blocks all of its subdomains.
 *
 * The filter is a table of slots, each `bits` bits wide. A name's hash gives a
 * start slot, 64 coefficient bits (the "ribbon", whose first bit is always 1)
 * and a `bits`-bit fingerprint. The build solves a linear system over GF(2) so
 * that, for every listed name, the XOR of the slots its coefficients select
 * (bit `i` selects slot `start + i`) equals its fingerprint. A name that is
 * not listed gets a random XOR, so it is wrongly found with a probability of
 * 2^-bits per suffix. Listed names are always found.
 *
 * The names are split by hash into shards of about `SHARD_KEYS`, each with its
 * own slots and hash seed: a small system needs fewer spare slots than a large
 * one (here almost none), and the build retries one shard with another seed
 * instead of everything.
 *
 * The slots are stored in columns: for each block of 32 slots, one word per
 * bit of the slot. A lookup checks one bit of the fingerprint at a time, as
 * the parity of three masked words, and stops at the first that differs: a
 * name that is not listed takes two columns on average. Nothing is decoded
 * when the file is loaded, which matters in an isolate that starts cold.
 *
 * File layout, as little-endian 32-bit words (read in place on a little-endian
 * host; a big-endian host swaps a copy once, when the file is loaded):
 * - `MAGIC`, `count`, `bits` and `shards`.
 * - The index, one word per shard: its number of slots in the low 16 bits (0
 *   for an empty shard, else at least `RIBBON_WIDTH`) and its hash seed in the
 *   high 16 bits.
 * - The slots of all shards in order, numbered from 0: for each block of 32
 *   slots (the last one padded with zeros), `bits` words; bit `i` of word `j`
 *   is bit `j` of slot `32 * block + i`.
 */

export const MAGIC = 0x424c4b36; // BLK6; rejects the previous formats.
export const HEADER_WORDS = 4;
/** Coefficient bits per name: a name touches this many consecutive slots. */
export const RIBBON_WIDTH = 64;
/** Names per shard, on average. */
export const SHARD_KEYS = 2048;
/** The most slots the index can give one shard. */
export const MAX_SHARD_SLOTS = 0xffff;
const MAX_SHARDS = 2 ** 20;

/** A loaded blocklist: where each shard's slots are, and the slots. */
export interface BlockSet {
  /** Number of listed names. */
  count: number;
  /** Bits per slot, which is also the fingerprint size. */
  bits: number;
  shards: number;
  /** The first slot of each shard, and after the last one the total. */
  starts: Uint32Array;
  /** The hash seed of each shard. */
  seeds: Uint16Array;
  /** The slots, in columns (see the file layout). */
  words: Uint32Array;
}

/** The 32-bit finalizer of MurmurHash3: every input bit affects every output bit. */
function fmix32(h: number): number {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  return (h ^ (h >>> 16)) >>> 0;
}

/** @return `floor(x * n / 2^32)`: the 32-bit `x` scaled to `[0, n)`. */
function scale(x: number, n: number): number {
  return Math.floor((x * n) / 4294967296);
}

/**
 * @return A 32-bit hash of the pair `(x, y)`; each `salt` gives another one.
 */
function mix(x: number, y: number, salt: number): number {
  return fmix32(x ^ Math.imul(y + salt, 0x9e3779b1));
}

/*
 * A name's hash is two 32-bit words `(h0, h1)`. Everything a lookup needs is
 * a `mix` of them, with salt 0 for what does not depend on the shard's seed
 * and `4 * seed + 1` to `+ 3` for what does; the build uses the same functions.
 */

/** The hash `[h0, h1]` of a domain, read from right to left. */
export function hashDomain(name: string): [number, number] {
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
  }
  const h0 = mix(a, b, 0);
  return [h0, mix(b, h0, 0)];
}

/** The shard a name belongs to. */
export function shardOf(h0: number, shards: number): number {
  return scale(h0, shards);
}

/** What the name's slots must XOR to: bit `j` for bit `j` of the slots. */
export function fingerprint(h0: number, h1: number): number {
  return mix(h0, h1, 0);
}

/** The name's first slot in a shard of `slots` slots hashed with `seed`. */
export function startOf(
  h0: number,
  h1: number,
  seed: number,
  slots: number
): number {
  return scale(mix(h0, h1, 4 * seed + 1), slots - RIBBON_WIDTH + 1);
}

/** Coefficient bits 0 to 31 (bit 0 is always set), as a signed 32-bit number. */
export function coefLow(h0: number, h1: number, seed: number): number {
  return mix(h0, h1, 4 * seed + 2) | 1;
}

/** Coefficient bits 32 to 63, as a signed 32-bit number. */
export function coefHigh(h0: number, h1: number, seed: number): number {
  return mix(h0, h1, 4 * seed + 3) | 0;
}

/**
 * @return The little-endian words of `buffer` as numbers of this host, or the
 *     other way round: the buffer itself, or on a big-endian host a swapped
 *     copy.
 */
export function littleEndianWords(
  buffer: ArrayBuffer
): Uint32Array<ArrayBuffer> {
  const words = new Uint32Array(buffer, 0, buffer.byteLength >> 2);
  if (new Uint8Array(new Uint32Array([1]).buffer)[0] === 1) {
    return words;
  }
  const view = new DataView(buffer);
  return words.map((_, i) => view.getUint32(4 * i, true));
}

/**
 * Reads a blocklist file. Only the index is read; the slots are read when a
 * name is looked up.
 * @throws If it is not a valid blocklist.
 */
export function decodeBlockset(buffer: ArrayBuffer): BlockSet {
  const file = littleEndianWords(buffer);
  // Files of an older format are invalid.
  if (file.length < HEADER_WORDS || file[0] !== MAGIC) {
    throw new Error('not a blocklist');
  }
  const [, count, bits, shards] = file;
  if (bits > 32 || shards < 1 || shards > MAX_SHARDS) {
    throw new Error('bad blocklist header');
  }
  const tableStart = HEADER_WORDS + shards;
  if (file.length < tableStart) {
    throw new Error('truncated blocklist');
  }

  const starts = new Uint32Array(shards + 1);
  const seeds = new Uint16Array(shards);
  for (let s = 0; s < shards; s++) {
    const slots = file[HEADER_WORDS + s] & MAX_SHARD_SLOTS;
    if (slots !== 0 && slots < RIBBON_WIDTH) {
      throw new Error('bad blocklist index');
    }
    seeds[s] = file[HEADER_WORDS + s] >>> 16;
    starts[s + 1] = starts[s] + slots;
  }
  const expected = 4 * (tableStart + Math.ceil(starts[shards] / 32) * bits);
  if (buffer.byteLength < expected) {
    throw new Error('truncated blocklist');
  }
  if (buffer.byteLength !== expected) {
    throw new Error('bad blocklist length');
  }
  return {count, bits, shards, starts, seeds, words: file.subarray(tableStart)};
}

/** Whether the set holds the name whose running hash state is `(a, b)`. */
function contains(set: BlockSet, a: number, b: number): boolean {
  const h0 = mix(a, b, 0);
  const shard = shardOf(h0, set.shards);
  const base = set.starts[shard];
  const slots = set.starts[shard + 1] - base;
  if (slots === 0) {
    return false;
  }
  const h1 = mix(b, h0, 0);
  const seed = set.seeds[shard];
  const first = base + startOf(h0, h1, seed, slots);
  // The coefficients as masks over the three blocks they span. Shifted right
  // in two steps, as a shift by 32 would be one by 0.
  const shift = first & 31;
  const low = coefLow(h0, h1, seed);
  const high = coefHigh(h0, h1, seed);
  const m0 = low << shift;
  const m1 = ((low >>> 1) >>> (31 - shift)) | (high << shift);
  const m2 = (high >>> 1) >>> (31 - shift);
  const {bits, words} = set;
  // Coefficients that start at a block span two: the third mask is 0, and is
  // put on the second block, as the table may end there.
  const third = shift === 0 ? bits : 2 * bits;
  const sum = fingerprint(h0, h1);
  let at = (first >>> 5) * bits;
  for (let j = 0; j < bits; j++, at++) {
    let x =
      (words[at] & m0) ^ (words[at + bits] & m1) ^ (words[at + third] & m2);
    // The parity of `x`: of its 4-bit XOR fold, from a 16-entry table.
    x ^= x >>> 16;
    x ^= x >>> 8;
    x ^= x >>> 4;
    if (((0x6996 >>> (x & 15)) ^ (sum >>> j)) & 1) {
      return false;
    }
  }
  return true;
}

/** Whether the name or any of its parent domains is blocked. */
export function isBlocked(set: BlockSet, name: string): boolean {
  let a = 0x811c9dc5;
  let b = 0x9747b28c;
  for (let i = name.length - 1; i >= 0; i--) {
    const c = name.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193);
    b = Math.imul(b ^ c, 0x85ebca6b) ^ (b >>> 15);
    if ((i === 0 || name.charCodeAt(i - 1) === 46) && contains(set, a, b)) {
      return true;
    }
  }
  return false;
}
