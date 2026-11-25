/** Work that several requests wait for (src/wait.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {Flight, LATE} from '../src/wait.js';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const NOT_YET = Symbol('not yet');

/** @return What `promise` gives, or NOT_YET if it has not settled in `ms`. */
const settledWithin = (promise: Promise<unknown>, ms: number) =>
  Promise.race([promise, sleep(ms).then(() => NOT_YET)]);

describe('Flight', () => {
  test('a waiter gets the value of the work', async () => {
    const flight = new Flight(sleep(10).then(() => 'done'));
    assert.equal(await flight.wait().result, 'done');
    assert.equal(await flight.waitFor(500), 'done');
  });

  test('several waiters all get it', async () => {
    const flight = new Flight(sleep(10).then(() => 7));
    const all = await Promise.all([flight.wait().result, flight.wait().result]);
    assert.deepEqual(all, [7, 7]);
  });

  test('work that has already ended answers at once', async () => {
    const flight = new Flight(Promise.resolve('early'));
    await sleep(0);
    assert.equal(await settledWithin(flight.wait().result, 50), 'early');
  });

  test('a failure of the work is thrown to the waiter', async () => {
    const flight = new Flight(Promise.reject(new Error('broke')));
    await assert.rejects(flight.wait().result, /broke/);
    await assert.rejects(flight.waitFor(500), /broke/);
  });

  test('a waiter that has left is not woken', async () => {
    let finish!: () => void;
    const flight = new Flight(new Promise<void>(r => (finish = r)));
    const waiting = flight.wait();
    waiting.leave();
    finish();
    assert.equal(await settledWithin(waiting.result, 50), NOT_YET);
  });

  test('another waiter is still woken when one has left', async () => {
    let finish!: () => void;
    const flight = new Flight(
      new Promise<string>(r => (finish = () => r('ok')))
    );
    flight.wait().leave();
    const staying = flight.wait();
    finish();
    assert.equal(await staying.result, 'ok');
  });

  test('waitFor gives LATE when the work takes longer', async () => {
    const flight = new Flight(sleep(300).then(() => 'slow'));
    const started = performance.now();
    assert.equal(await flight.waitFor(40), LATE);
    const waited = performance.now() - started;
    assert.ok(waited >= 30 && waited < 200, `waited ${waited} ms`);
  });

  test('no waiter stays attached once it has what it needs', async () => {
    let finish!: () => void;
    const flight = new Flight(new Promise<void>(r => (finish = r)));
    assert.equal(await flight.waitFor(20), LATE);
    assert.equal(flight.attached, 0, 'after a wait that ran out');
    const done = flight.waitFor(500);
    assert.equal(flight.attached, 1);
    finish();
    await done;
    assert.equal(flight.attached, 0, 'after the work ended');
    const leaving = new Flight(new Promise<void>(() => {}));
    leaving.wait().leave();
    assert.equal(leaving.attached, 0, 'after leave()');
  });
});
