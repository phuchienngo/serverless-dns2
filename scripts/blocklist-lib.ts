/**
 * @fileoverview The testable parts of the blocklist build: reading list lines
 * and encoding the blocked domains (see src/blockset.ts).
 */

import {
  HEADER_WORDS,
  MAGIC,
  MAX_SHARD_SLOTS,
  RIBBON_WIDTH,
  SHARD_KEYS,
  coefHigh,
  coefLow,
  decodeBlockset,
  fingerprint,
  hashDomain,
  isBlocked,
  littleEndianWords,
  shardOf,
  startOf,
} from '../src/blockset.js';

const DOMAIN =
  /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$/;

/**
 * @return The domain of one list line, or null if it is not a plain domain
 *     rule (comments, regex, modifiers, IP addresses...).
 */
export function parseDomain(line: string): string | null {
  let s = line.trim();
  if (!s || /^[#!\[]/.test(s) || s.startsWith('@@')) {
    return null;
  }
  const comment = s.indexOf('#');
  if (comment > 0) {
    s = s.slice(0, comment).trim();
  }
  const hosts = s.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)$/);
  if (hosts) {
    s = hosts[1];
  } else if (s.startsWith('||')) {
    if (!s.endsWith('^')) {
      return null;
    }
    s = s.slice(2, -1);
  }
  s = s.replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
  return DOMAIN.test(s) ? s : null;
}

/**
 * Seeds tried for a shard before it is given one more slot: all that the
 * index can hold. Fewer seeds build faster and find a slightly larger file
 * (4096: 16 times fewer tries).
 */
const SEEDS = 2 ** 16;

/**
 * Whether the names' first slots leave a solution possible. Names that start
 * in the first slots only use those and the `RIBBON_WIDTH - 1` after them, and
 * names that start in the last ones only those up to the end: more names than
 * slots in either has no solution. Nearly every seed that fails fails here,
 * at a fraction of the cost of `solve`.
 */
function fits(
  h0s: number[],
  h1s: number[],
  seed: number,
  slots: number
): boolean {
  const last = slots - RIBBON_WIDTH;
  const starting = new Uint16Array(last + 1);
  for (let key = 0; key < h0s.length; key++) {
    starting[startOf(h0s[key], h1s[key], seed, slots)]++;
  }
  for (let at = 0, names = 0; at <= last; at++) {
    names += starting[at];
    if (names > at + RIBBON_WIDTH) {
      return false;
    }
  }
  for (let at = last, names = 0; at >= 0; at--) {
    names += starting[at];
    if (names > slots - at) {
      return false;
    }
  }
  return true;
}

/**
 * Solves one shard for one seed: finds slot values such that every name's
 * selected slots XOR to its fingerprint.
 * @return The slot values, or null if this seed has no solution.
 */
function solve(
  h0s: number[],
  h1s: number[],
  bits: number,
  seed: number,
  slots: number
): Uint32Array | null {
  if (!fits(h0s, h1s, seed, slots)) {
    return null;
  }
  const mask = 2 ** bits - 1; // The bits of a slot that are stored.
  // Row `i` of the system in echelon form: its coefficients start at slot `i`
  // (bit 0, set if the row is used) and `sums[i]` is what they must XOR to.
  const low = new Int32Array(slots);
  const high = new Int32Array(slots);
  const sums = new Uint32Array(slots);
  for (let key = 0; key < h0s.length; key++) {
    const h0 = h0s[key];
    const h1 = h1s[key];
    let at = startOf(h0, h1, seed, slots);
    let lo = coefLow(h0, h1, seed);
    let hi = coefHigh(h0, h1, seed);
    let sum = fingerprint(h0, h1);
    while (low[at] !== 0) {
      lo ^= low[at];
      hi ^= high[at];
      sum ^= sums[at];
      if (lo === 0 && hi === 0) {
        break;
      }
      // Move to the next slot the row still uses.
      while ((lo & 1) === 0) {
        lo = (lo >>> 1) | (hi << 31);
        hi >>>= 1;
        at++;
      }
    }
    if (lo !== 0) {
      low[at] = lo;
      high[at] = hi;
      sums[at] = sum;
    } else if ((sum & mask) !== 0) {
      return null; // The other names already fix a different value.
    }
  }

  // Back substitution, from the last slot; a slot no row starts at stays 0.
  const values = new Uint32Array(slots);
  for (let at = slots - 1; at >= 0; at--) {
    if (low[at] === 0) {
      continue;
    }
    let value = sums[at];
    for (let c = low[at] & ~1; c !== 0; c &= c - 1) {
      value ^= values[at + 31 - Math.clz32(c & -c)];
    }
    for (let c = high[at]; c !== 0; c &= c - 1) {
      value ^= values[at + 63 - Math.clz32(c & -c)];
    }
    values[at] = value;
  }
  return values;
}

/**
 * Solves one shard: starts with one slot per name, the least possible, and
 * adds one until some seed has a solution.
 */
export function solveShard(
  h0s: number[],
  h1s: number[],
  bits: number
): {seed: number; values: Uint32Array} {
  const n = h0s.length;
  if (n === 0) {
    return {seed: 0, values: new Uint32Array(0)};
  }
  for (let slots = Math.max(RIBBON_WIDTH, n); ; slots++) {
    if (slots > MAX_SHARD_SLOTS) {
      throw new Error('blocklist shard too large');
    }
    for (let seed = 0; seed < SEEDS; seed++) {
      const values = solve(h0s, h1s, bits, seed, slots);
      if (values) {
        return {seed, values};
      }
    }
  }
}

/** What `solveShard` returns for one shard. */
export interface SolvedShard {
  seed: number;
  values: Uint32Array;
}

function checkBits(bits: number): void {
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
    throw new Error(`precision must be 0 to 32 bits, not ${bits}`);
  }
}

/**
 * Drops the domains whose parent is listed too, and splits the rest by hash
 * into shards of about SHARD_KEYS.
 * @return The kept domains, and the two hashes of each one, per shard.
 */
export function partitionShards(
  domains: Set<string>,
  bits: number
): {kept: string[]; shards: number; h0s: number[][]; h1s: number[][]} {
  checkBits(bits);
  const kept: string[] = [];
  for (const domain of domains) {
    let covered = false;
    for (
      let dot = domain.indexOf('.');
      dot >= 0;
      dot = domain.indexOf('.', dot + 1)
    ) {
      if (domains.has(domain.slice(dot + 1))) {
        covered = true;
        break;
      }
    }
    if (!covered) {
      kept.push(domain);
    }
  }

  const shards = Math.max(1, Math.ceil(kept.length / SHARD_KEYS));
  const h0s: number[][] = Array.from({length: shards}, () => []);
  const h1s: number[][] = Array.from({length: shards}, () => []);
  for (const domain of kept) {
    const [h0, h1] = hashDomain(domain);
    const shard = shardOf(h0, shards);
    h0s[shard].push(h0);
    h1s[shard].push(h1);
  }
  return {kept, shards, h0s, h1s};
}

/**
 * Writes the file from the solved shards and checks that every domain can be
 * found in the result.
 */
export function assembleBlockset(
  kept: string[],
  solved: SolvedShard[],
  bits: number
): Uint8Array {
  const shards = solved.length;
  const slots = solved.reduce((sum, {values}) => sum + values.length, 0);

  const tableStart = HEADER_WORDS + shards;
  const file = new Uint32Array(tableStart + Math.ceil(slots / 32) * bits);
  file.set([MAGIC, kept.length, bits, shards]);
  let slot = 0;
  solved.forEach(({seed, values}, shard) => {
    file[HEADER_WORDS + shard] = values.length | (seed << 16);
    for (const value of values) {
      const at = tableStart + (slot >>> 5) * bits;
      for (let j = 0; j < bits; j++) {
        file[at + j] |= ((value >>> j) & 1) << (slot & 31);
      }
      slot++;
    }
  });
  const out = new Uint8Array(littleEndianWords(file.buffer).buffer);

  console.log('Checking that every domain decodes');
  const decoded = decodeBlockset(out.buffer);
  if (
    decoded.count !== kept.length ||
    kept.some(domain => !isBlocked(decoded, domain))
  ) {
    throw new Error('blocklist does not decode to what was encoded');
  }
  console.log(
    `${kept.length} domains -> ${slots} slots of ${bits} bits in ${shards} shards`
  );
  return out;
}

/**
 * Encodes the domains as a Ribbon filter of `bits`-bit slots (see
 * src/blockset.ts) and checks that every domain can be found in the result.
 */
export function buildBlockset(domains: Set<string>, bits: number): Uint8Array {
  const {kept, shards, h0s, h1s} = partitionShards(domains, bits);
  const solved = h0s.map((h0, shard) => {
    const result = solveShard(h0, h1s[shard], bits);
    if ((shard + 1) % 10 === 0 || shard + 1 === shards) {
      console.log(`  shard ${shard + 1}/${shards} solved`);
    }
    return result;
  });
  return assembleBlockset(kept, solved, bits);
}

/**
 * Removes the domains that `regex` already blocks. The rule must also match a
 * subdomain of the domain ("a." + domain), because a listed domain blocks its
 * subdomains too.
 * @return The number of domains removed.
 */
export function dropMatched(domains: Set<string>, regex: RegExp): number {
  let dropped = 0;
  for (const domain of domains) {
    if (regex.test(domain) && regex.test('a.' + domain)) {
      domains.delete(domain);
      dropped++;
    }
  }
  return dropped;
}
