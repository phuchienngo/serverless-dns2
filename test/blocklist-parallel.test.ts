/**
 * @fileoverview The parallel blocklist build writes the same file as the one
 * on a single thread, byte for byte: the shards are independent, so only the
 * time changes, never the size or the precision.
 */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {buildBlockset} from '../scripts/blocklist-lib.js';
import {buildBlocksetParallel} from '../scripts/blocklist-parallel.js';
import {decodeBlockset, isBlocked} from '../src/blockset.js';

/** About 2500 names: three shards. */
function names(count: number, salt: string): Set<string> {
  const set = new Set<string>();
  for (let i = 0; i < count; i++) {
    set.add(`h${i.toString(36)}${salt}.example${i % 7}.test`);
  }
  return set;
}

const quiet = async <T>(run: () => Promise<T> | T): Promise<T> => {
  const log = console.log;
  console.log = () => {};
  try {
    return await run();
  } finally {
    console.log = log;
  }
};

describe('buildBlocksetParallel', () => {
  test(
    'writes the same bytes as the single-thread build',
    {timeout: 90_000},
    async () => {
      const domains = names(5000, 'a'); // Three shards.
      const serial = await quiet(() => buildBlockset(domains, 20));
      for (const jobs of [2, 3]) {
        const parallel = await quiet(() =>
          buildBlocksetParallel(domains, 20, jobs)
        );
        assert.deepEqual(parallel, serial, `${jobs} threads`);
      }
    }
  );

  test('finds every domain, and not others', {timeout: 90_000}, async () => {
    const domains = names(4200, 'b');
    const file = await quiet(() => buildBlocksetParallel(domains, 20, 2));
    const decoded = decodeBlockset(file.buffer as ArrayBuffer);
    assert.ok([...domains].every(d => isBlocked(decoded, d)));
    assert.ok(!isBlocked(decoded, 'not-listed.example.org'));
  });

  test(
    'one thread, or one shard, is the plain build',
    {timeout: 90_000},
    async () => {
      const domains = names(300, 'c');
      const serial = await quiet(() => buildBlockset(domains, 12));
      assert.deepEqual(
        await quiet(() => buildBlocksetParallel(domains, 12, 4)),
        serial
      );
      assert.deepEqual(
        await quiet(() => buildBlocksetParallel(names(5000, 'd'), 8, 1)),
        await quiet(() => buildBlockset(names(5000, 'd'), 8))
      );
    }
  );

  test('refuses a precision it cannot encode', async () => {
    await assert.rejects(
      buildBlocksetParallel(names(10, 'e'), 33),
      /precision must be 0 to 32 bits/
    );
  });
});
