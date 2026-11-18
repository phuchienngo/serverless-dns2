/**
 * The blocklist file: Golomb-coded set of truncated hashes (src/blockset.ts)
 * and how list lines become domains (scripts/blocklist-lib.ts).
 */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {
  buildBlockset,
  dropMatched,
  parseDomain,
} from '../scripts/blocklist-lib.js';
import {
  HEADER_BYTES,
  MAGIC,
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
    assert.equal(set.values.length, 0);
    assert.equal(isBlocked(set, 'anything.test'), false);
  });

  test('a single domain works', () => {
    const {set} = decode(['only.test']);
    assert.ok(isBlocked(set, 'only.test'));
    assert.equal(isBlocked(set, 'other.test'), false);
  });

  test('has the documented header', () => {
    const domains = Array.from({length: 1000}, (_, i) => `d${i}.test`);
    const {file} = decode(domains, 20);
    const view = new DataView(file.buffer);
    assert.equal(view.getUint32(0, true), MAGIC);
    assert.equal(view.getUint32(4, true), 1000);
    assert.equal(file[8], 20, 'k');
    assert.equal(file[9], 10 + 20, 'bits = ceil(log2 count) + k');
    assert.ok(file.length > HEADER_BYTES);
  });

  test('drops a subdomain of another listed domain', () => {
    const {set} = decode([
      'tracker.test',
      'a.tracker.test',
      'b.a.tracker.test',
      'other.test',
    ]);
    assert.equal(set.values.length, 2);
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

  test('is much smaller than 8 bytes per domain', () => {
    const next = random(2);
    const domains = Array.from(
      {length: 20000},
      () => `${randomLabel(next, 10)}.test`
    );
    const {file} = decode(domains, 20);
    assert.ok(file.length < 20000 * 3.2, `${file.length} bytes`);
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
    const expected = set.values.length / 2 ** set.bits;
    const observed = hits / trials;
    assert.ok(
      observed < expected * 3,
      `observed ${observed}, expected ${expected}`
    );
    assert.ok(
      observed > expected / 3,
      `observed ${observed}, expected ${expected}`
    );
    assert.ok(expected <= 2 ** -k);
  });

  test('works for the smallest and largest k', () => {
    const next = random(4);
    const domains = Array.from(
      {length: 300},
      () => `${randomLabel(next, 9)}.test`
    );
    for (const k of [0, 1, 31]) {
      const {set} = decode(domains, k);
      assert.ok(
        domains.every(d => isBlocked(set, d)),
        `k=${k}`
      );
    }
  });

  test('refuses a list too large for the precision (hash over 53 bits)', () => {
    const domains = Array.from({length: 20000}, (_, i) => `d${i}.test`);
    assert.throws(() => buildBlockset(new Set(domains), 40), /too large/);
  });

  test('hashDomain stays within the requested number of bits', () => {
    for (const bits of [1, 10, 32, 33, 38, 53]) {
      const value = hashDomain('example.com', bits);
      assert.ok(Number.isInteger(value));
      assert.ok(value >= 0 && value < 2 ** bits, `${bits} bits: ${value}`);
    }
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
    for (const [offset, value] of [
      [8, 32],
      [9, 54],
      [9, 5],
    ] as const) {
      const file = good();
      file[offset] = value; // k > 31, bits > 53, bits < k
      assert.throws(() => decodeBlockset(file.buffer as ArrayBuffer), /header/);
    }
  });

  test('truncated body', () => {
    const file = good();
    assert.throws(() =>
      decodeBlockset(file.slice(0, file.length - 3).buffer as ArrayBuffer)
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
