/**
 * The blocklist file: a Ribbon filter of fingerprints (src/blockset.ts) and
 * how list lines become domains (scripts/blocklist-lib.ts).
 */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {
  buildBlockset,
  dropMatched,
  parseDomain,
} from '../scripts/blocklist-lib.js';
import {
  HEADER_WORDS,
  MAGIC,
  RIBBON_WIDTH,
  SHARD_KEYS,
  decodeBlockset,
  hashDomain,
  isBlocked,
} from '../src/blockset.js';

/** A small deterministic random generator, so that a failure can be repeated. */
function random(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomLabel(next: () => number, length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let label = '';
  for (let i = 0; i < length; i++) {
    label += chars[Math.floor(next() * chars.length)];
  }
  return label;
}

function decode(domains: string[], k = 20) {
  const file = buildBlockset(new Set(domains), k);
  return {file, set: decodeBlockset(file.buffer as ArrayBuffer)};
}

describe('blocklist file', () => {
  test('finds a listed domain and its subdomains', () => {
    const {set} = decode(['tracker.test', 'ads.example.org']);
    assert.ok(isBlocked(set, 'tracker.test'));
    assert.ok(isBlocked(set, 'a.tracker.test'));
    assert.ok(isBlocked(set, 'a.b.c.tracker.test'));
    assert.ok(isBlocked(set, 'ads.example.org'));
  });

  test('does not block the parent, siblings or look-alike names', () => {
    const {set} = decode(['ads.example.org']);
    assert.equal(isBlocked(set, 'example.org'), false, 'parent');
    assert.equal(isBlocked(set, 'www.example.org'), false, 'sibling');
    assert.equal(isBlocked(set, 'xads.example.org'), false, 'label boundary');
    assert.equal(isBlocked(set, 'ads.example.org.evil.test'), false);
    assert.equal(isBlocked(set, 'org'), false);
  });

  test('an empty list blocks nothing', () => {
    const {set} = decode([]);
    assert.equal(set.count, 0);
    assert.equal(isBlocked(set, 'anything.test'), false);
  });

  test('a single domain works', () => {
    const {set} = decode(['only.test']);
    assert.ok(isBlocked(set, 'only.test'));
    assert.equal(isBlocked(set, 'other.test'), false);
  });

  test('has the documented header', () => {
    const domains = Array.from({length: 1000}, (_, i) => `d${i}.test`);
    const {file, set} = decode(domains, 20);
    const words = new Uint32Array(file.buffer);
    assert.deepEqual(
      [...words.subarray(0, HEADER_WORDS)],
      [MAGIC, 1000, 20, 1]
    );
    const slots = words[HEADER_WORDS] & 0xffff;
    assert.ok(slots >= 1000, 'at least one slot per domain');
    assert.equal(set.starts[1], slots);
    assert.equal(set.seeds[0], words[HEADER_WORDS] >>> 16);
    assert.equal(
      words.length,
      HEADER_WORDS + 1 + Math.ceil(slots / 32) * 20,
      'header, index, 20 words per block of 32 slots'
    );
  });

  test('is little-endian whatever the host', () => {
    const {file} = decode(['a.test']);
    assert.equal(new DataView(file.buffer).getUint32(0, true), MAGIC);
  });

  test('drops a subdomain of another listed domain', () => {
    const {set} = decode([
      'tracker.test',
      'a.tracker.test',
      'b.a.tracker.test',
      'other.test',
    ]);
    assert.equal(set.count, 2);
    assert.ok(
      isBlocked(set, 'b.a.tracker.test'),
      'still blocked via the parent'
    );
  });

  test('never misses a listed domain (5000 random names)', () => {
    const next = random(1);
    const domains = Array.from(
      {length: 5000},
      () =>
        `${randomLabel(next, 4 + Math.floor(next() * 10))}.${randomLabel(next, 3)}.test`
    );
    const {set} = decode(domains);
    for (const domain of domains) {
      assert.ok(isBlocked(set, domain), domain);
      assert.ok(isBlocked(set, `sub.${domain}`), `sub.${domain}`);
    }
  });

  test('takes barely more than k bits per domain', () => {
    const next = random(2);
    const domains = Array.from(
      {length: 20000},
      () => `${randomLabel(next, 10)}.test`
    );
    const {file} = decode(domains, 20);
    assert.ok(file.length * 8 < 20000 * 20.2, `${file.length} bytes`);
  });

  test('wrongly blocks an unlisted name about 2^-k of the time', () => {
    const next = random(3);
    const k = 8;
    const domains = Array.from(
      {length: 2000},
      () => `${randomLabel(next, 12)}.test`
    );
    const {set} = decode(domains, k);
    let hits = 0;
    const trials = 200000;
    for (let i = 0; i < trials; i++) {
      // One label under an unlisted suffix: a single lookup per name.
      if (isBlocked(set, `${randomLabel(next, 16)}`)) {
        hits++;
      }
    }
    const expected = 2 ** -k;
    const observed = hits / trials;
    assert.ok(
      observed < expected * 3,
      `observed ${observed}, expected ${expected}`
    );
    assert.ok(
      observed > expected / 3,
      `observed ${observed}, expected ${expected}`
    );
  });

  test('works for the smallest and largest k', () => {
    const next = random(4);
    const domains = Array.from(
      {length: 300},
      () => `${randomLabel(next, 9)}.test`
    );
    for (const k of [1, 2, 32]) {
      const {set} = decode(domains, k);
      assert.ok(
        domains.every(d => isBlocked(set, d)),
        `k=${k}`
      );
    }
    // Without a fingerprint every name in a shard that is not empty is found.
    assert.ok(isBlocked(decode(domains, 0).set, 'unlisted.example'));
  });

  test('refuses a precision that does not fit a slot', () => {
    for (const k of [-1, 33, 1.5]) {
      assert.throws(() => buildBlockset(new Set(['a.test']), k), /precision/);
    }
  });

  test('hashDomain gives two 32-bit words', () => {
    const hash = hashDomain('example.com');
    assert.equal(hash.length, 2);
    for (const word of hash) {
      assert.ok(Number.isInteger(word) && word >= 0 && word < 2 ** 32);
    }
    assert.deepEqual(hashDomain('example.com'), hash);
    assert.notDeepEqual(hashDomain('example.org'), hash);
  });
});

describe('shards', () => {
  test('every size around the ribbon width and a shard finds all its names', () => {
    const next = random(7);
    for (const n of [
      1,
      2,
      RIBBON_WIDTH - 1,
      RIBBON_WIDTH,
      RIBBON_WIDTH + 1,
      SHARD_KEYS,
      SHARD_KEYS + 1,
      5 * SHARD_KEYS + 3,
    ]) {
      const domains = Array.from(
        {length: n},
        () => `${randomLabel(next, 11)}.test`
      );
      const {set} = decode(domains);
      assert.equal(set.count, n);
      assert.equal(set.shards, Math.ceil(n / SHARD_KEYS), `${n}: shards`);
      assert.ok(
        domains.every(d => isBlocked(set, d)),
        `${n}: found`
      );
      const slots = set.starts[set.shards];
      assert.ok(slots >= n, `${n}: a slot per name`);
      assert.ok(slots <= Math.max(RIBBON_WIDTH, n * 1.02), `${n}: ${slots}`);
    }
  });

  test('an empty shard has no slots and finds nothing', () => {
    // One name in a file of two shards: change the header to say so.
    const {file} = decode(['only.test']);
    const words = new Uint32Array(file.buffer);
    const two = new Uint32Array(words.length + 1);
    two.set(words.subarray(0, HEADER_WORDS));
    two[3] = 2;
    two.set(words.subarray(HEADER_WORDS), HEADER_WORDS + 1);
    const set = decodeBlockset(two.buffer);
    assert.deepEqual([...set.starts], [0, 0, RIBBON_WIDTH]);
    const next = random(5);
    let hits = 0;
    for (let i = 0; i < 1000; i++) {
      hits += Number(isBlocked(set, randomLabel(next, 12)));
    }
    assert.equal(hits, 0);
  });
});

describe('decodeBlockset rejects bad files', () => {
  const good = () => decode(['a.test', 'b.test', 'c.test']).file;

  test('wrong magic (for example index.html served for a missing file)', () => {
    const file = good();
    file[0] ^= 0xff;
    assert.throws(
      () => decodeBlockset(file.buffer as ArrayBuffer),
      /not a blocklist/
    );
    const html = new TextEncoder().encode('<!doctype html><html></html>');
    assert.throws(
      () => decodeBlockset(html.buffer as ArrayBuffer),
      /not a blocklist/
    );
  });

  test('too short', () => {
    assert.throws(() => decodeBlockset(new ArrayBuffer(4)), /not a blocklist/);
  });

  test('impossible parameters', () => {
    for (const [word, value] of [
      [2, 33],
      [3, 0],
      [3, 2 ** 20 + 1],
    ] as const) {
      const file = good();
      new Uint32Array(file.buffer)[word] = value; // bits, no shard, too many
      assert.throws(() => decodeBlockset(file.buffer as ArrayBuffer), /header/);
    }
  });

  test('truncated body', () => {
    const file = good();
    assert.throws(
      () =>
        decodeBlockset(file.slice(0, file.length - 1).buffer as ArrayBuffer),
      /truncated/
    );
  });

  test('a damaged index', () => {
    const tooFew = good();
    new Uint32Array(tooFew.buffer)[HEADER_WORDS] = RIBBON_WIDTH - 1;
    assert.throws(() => decodeBlockset(tooFew.buffer as ArrayBuffer), /index/);

    const more = good();
    new Uint32Array(more.buffer)[HEADER_WORDS] = RIBBON_WIDTH + 1;
    assert.throws(
      () => decodeBlockset(more.buffer as ArrayBuffer),
      /truncated/
    );
  });

  test('trailing data', () => {
    const file = good();
    const longer = new Uint8Array(file.length + 4);
    longer.set(file);
    assert.throws(() => decodeBlockset(longer.buffer as ArrayBuffer), /length/);
  });
});

describe('parseDomain (list lines)', () => {
  const cases: Array<[string, string | null]> = [
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['0.0.0.0 ads.example.com', 'ads.example.com'],
    ['127.0.0.1\ttracker.example.com', 'tracker.example.com'],
    [':: v6.example.com', 'v6.example.com'],
    ['||ads.example.com^', 'ads.example.com'],
    ['*.wild.example.com', 'wild.example.com'],
    ['dotted.example.com.', 'dotted.example.com'],
    ['with.comment.example.com # why', 'with.comment.example.com'],
    ['under_score.example.com', 'under_score.example.com'],
    // Not plain domain rules:
    ['# a comment', null],
    ['! adblock comment', null],
    ['[Adblock Plus 2.0]', null],
    ['', null],
    ['   ', null],
    ['@@||allowed.example.com^', null],
    ['||ads.example.com^$third-party', null],
    ['||ads.example.com/path', null],
    ['/regex.*/', null],
    ['1.2.3.4', null],
    ['localhost', null],
    ['has space.example.com', null],
    ['-bad-.example.com', null],
  ];
  for (const [line, expected] of cases) {
    test(JSON.stringify(line), () => assert.equal(parseDomain(line), expected));
  }

  test('rejects a name longer than 253 characters', () => {
    assert.equal(parseDomain(`${'a'.repeat(60)}.`.repeat(5) + 'com'), null);
  });
});

describe('dropMatched', () => {
  test('removes domains the regex matches, with or without a subdomain', () => {
    const domains = new Set([
      'ads.example.com',
      'ok.example.com',
      'adserver.test',
    ]);
    const dropped = dropMatched(domains, /ads/);
    assert.equal(dropped, 2);
    assert.deepEqual([...domains], ['ok.example.com']);
  });

  test('keeps a domain whose subdomains the regex would not match', () => {
    // ^ads\. matches "ads.example.com" but not "a.ads.example.com".
    const domains = new Set(['ads.example.com']);
    assert.equal(dropMatched(domains, /^ads\./), 0);
    assert.deepEqual([...domains], ['ads.example.com']);
  });
});
