/** Values loaded once per isolate (src/loaded.ts). */

import assert from 'node:assert/strict';
import {afterEach, describe, test} from 'node:test';
import {Loaded} from '../src/loaded.js';
import {testClock} from './helpers.js';

afterEach(testClock.reset);

describe('Loaded', () => {
  test('loads once, and callers that ask meanwhile share the load', async () => {
    let loads = 0;
    const value = new Loaded(async (n: number) => {
      loads++;
      return n * 2;
    });
    const both = await Promise.all([value.get(21), value.get(5)]);
    assert.deepEqual(both, [42, 42]);
    assert.equal(await value.get(1), 42);
    assert.equal(loads, 1);
  });

  test('a failure (a throw or a null) gives null, and is not retried at once', async () => {
    testClock.set(1_000_000);
    let loads = 0;
    let fail: 'throw' | 'null' | null = 'throw';
    const value = new Loaded(
      async () => {
        loads++;
        if (fail === 'throw') {
          throw new Error('down');
        }
        return fail === 'null' ? null : 'ok';
      },
      Infinity,
      1000
    );
    assert.equal(await value.get(undefined), null);
    assert.equal(await value.get(undefined), null);
    assert.equal(loads, 1, 'not retried at once');
    testClock.tick(1001);
    fail = 'null';
    assert.equal(await value.get(undefined), null);
    assert.equal(loads, 2, 'retried after the delay');
    testClock.tick(1001);
    fail = null;
    assert.equal(await value.get(undefined), 'ok');
    assert.equal(await value.get(undefined), 'ok');
    assert.equal(loads, 3);
  });

  test('a value with a lifetime is loaded again when it has expired', async () => {
    testClock.set(1_000_000);
    let loads = 0;
    const value = new Loaded(async () => ++loads, 5000);
    assert.equal(await value.get(undefined), 1);
    testClock.tick(4000);
    assert.equal(await value.get(undefined), 1);
    testClock.tick(2000);
    assert.equal(await value.get(undefined), 2);
  });

  test('reset forgets the value and a failure', async () => {
    let loads = 0;
    const value = new Loaded(async () => ++loads);
    await value.get(undefined);
    value.reset();
    assert.equal(await value.get(undefined), 2);
  });
});
