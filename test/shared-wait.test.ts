/**
 * Work that one request starts and others wait for (coalesce in
 * src/upstream.ts, Loaded in src/loaded.ts): a request whose client went away
 * never finishes it, so the others must not wait for it for ever.
 */

import assert from 'node:assert/strict';
import {beforeEach, describe, test} from 'node:test';
import {SHARED_WAIT_MS} from '../src/config.js';
import {Loaded} from '../src/loaded.js';
import {parseQuestion} from '../src/query.js';
import {coalesce, resetUpstream} from '../src/upstream.js';
import type {Result} from '../src/types.js';
import {T, makeQuery} from './helpers.js';

const question = parseQuestion(makeQuery('shared.test', T.A));
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const never = () => new Promise<never>(() => {});
/** An answer to `question`, marked with `n` in its last byte. */
const answer = (n: number): Result => ({
  body: new Uint8Array([
    0,
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    ...question.raw,
    n,
  ]),
  ttl: 60,
});
const mark = (result: Result) => result.body[result.body.length - 1];

beforeEach(resetUpstream);

describe('coalesce', () => {
  test('callers that ask while the first is answering share its answer', async () => {
    let runs = 0;
    const task = async () => {
      runs++;
      await sleep(20);
      return answer(1);
    };
    const [a, b] = await Promise.all([
      coalesce('k', question, task),
      coalesce('k', question, task),
    ]);
    assert.equal(runs, 1);
    assert.equal(a.body.at(-1), 1);
    assert.equal(b.body.at(-1), 1);
  });

  test('a caller does not wait for ever for a request that never finishes', async () => {
    void coalesce('k', question, never); // The cancelled request.
    const started = performance.now();
    const result = await coalesce('k', question, async () => answer(2));
    assert.equal(result.body.at(-1), 2);
    assert.ok(
      performance.now() - started < SHARED_WAIT_MS + 400,
      'answered soon after the wait'
    );
  });

  test('it waits about SHARED_WAIT_MS, not less', async () => {
    void coalesce('k', question, never);
    const started = performance.now();
    await coalesce('k', question, async () => answer(2));
    assert.ok(performance.now() - started >= SHARED_WAIT_MS - 20);
  });

  test('later callers join the new request, not the one that never ends', async () => {
    let runs = 0;
    void coalesce('k', question, never);
    const second = coalesce('k', question, async () => {
      runs++;
      await sleep(60);
      return answer(3);
    });
    await sleep(SHARED_WAIT_MS + 20); // The second now runs its own task.
    const third = await coalesce('k', question, async () => {
      runs++;
      return answer(4);
    });
    assert.equal(runs, 1, 'the answer is not asked for again');
    assert.equal(mark(third), 3);
    assert.equal(mark(await second), 3);
  });

  test('a slow answer still wins when it comes before the caller’s own', async () => {
    const slow = coalesce('k', question, async () => {
      await sleep(SHARED_WAIT_MS + 60);
      return answer(5);
    });
    const joiner = coalesce('k', question, async () => {
      await sleep(500);
      return answer(6);
    });
    assert.equal(mark(await joiner), 5);
    assert.equal(mark(await slow), 5);
  });

  test('every task it starts is kept alive for the request', async () => {
    const kept: Promise<unknown>[] = [];
    const keepAlive = (work: Promise<unknown>) => void kept.push(work);
    void coalesce('k', question, never, keepAlive);
    await coalesce('k', question, async () => answer(2), keepAlive);
    assert.equal(
      kept.length,
      2,
      'the one it started, and the one it joined late'
    );
  });

  test('a caller that joins in time starts nothing to keep alive', async () => {
    const kept: Promise<unknown>[] = [];
    const keepAlive = (work: Promise<unknown>) => void kept.push(work);
    const task = async () => {
      await sleep(10);
      return answer(1);
    };
    await Promise.all([
      coalesce('k', question, task, keepAlive),
      coalesce('k', question, task, keepAlive),
    ]);
    assert.equal(kept.length, 1);
  });

  test('a failed first request leaves the caller to try on its own', async () => {
    void coalesce('k', question, async () => {
      throw new Error('down');
    }).catch(() => {});
    const result = await coalesce('k', question, async () => answer(7));
    assert.equal(result.body.at(-1), 7);
  });

  test('when both fail, the caller sees its own error', async () => {
    void coalesce('k', question, never);
    await assert.rejects(
      coalesce('k', question, async () => {
        throw new Error('own failure');
      }),
      /own failure/
    );
  });
});

describe('Loaded', () => {
  test('a caller does not wait for ever for a load that never ends', async () => {
    let loads = 0;
    const value = new Loaded(async () => {
      loads++;
      return loads === 1 ? never() : 'key';
    });
    void value.get(undefined); // The cancelled request.
    const started = performance.now();
    assert.equal(await value.get(undefined), 'key');
    assert.ok(performance.now() - started >= SHARED_WAIT_MS - 20);
    assert.ok(performance.now() - started < SHARED_WAIT_MS + 400);
    assert.equal(await value.get(undefined), 'key', 'kept');
    assert.equal(loads, 2);
  });

  test('a slow load that ends late does not replace the newer value', async () => {
    let loads = 0;
    const value = new Loaded(async () => {
      loads++;
      if (loads === 1) {
        await sleep(SHARED_WAIT_MS + 150);
        return 'old';
      }
      return 'new';
    });
    void value.get(undefined);
    assert.equal(await value.get(undefined), 'new');
    await sleep(SHARED_WAIT_MS + 250); // The first load ends meanwhile.
    assert.equal(await value.get(undefined), 'new');
  });

  test('a slow load still wins when it ends before the caller’s own', async () => {
    let loads = 0;
    const value = new Loaded(async () => {
      loads++;
      if (loads === 1) {
        await sleep(SHARED_WAIT_MS + 60);
        return 'first';
      }
      await sleep(600);
      return 'second';
    });
    void value.get(undefined);
    assert.equal(await value.get(undefined), 'first');
  });

  test('a load that it starts is kept alive for the request', async () => {
    const kept: Promise<unknown>[] = [];
    const keepAlive = (work: Promise<unknown>) => void kept.push(work);
    let loads = 0;
    const value = new Loaded(async () => {
      loads++;
      return loads === 1 ? never() : 'key';
    });
    void value.get(undefined, keepAlive);
    assert.equal(await value.get(undefined, keepAlive), 'key');
    assert.equal(kept.length, 2);
  });

  test('a load that ends in time is shared', async () => {
    let loads = 0;
    const value = new Loaded(async () => {
      loads++;
      await sleep(20);
      return 'key';
    });
    const both = await Promise.all([
      value.get(undefined),
      value.get(undefined),
    ]);
    assert.deepEqual(both, ['key', 'key']);
    assert.equal(loads, 1);
  });
});
