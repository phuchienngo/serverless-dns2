/** Which answer a request gets (firstAnswer), and the JSON of an unreadable one (readable). */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {TTL_FAILURE} from '../src/constants.js';
import {readable} from '../src/handlers.js';
import {resetLog} from '../src/log.js';
import {parseQuestion} from '../src/query.js';
import {firstAnswer} from '../src/resolve.js';
import type {Result} from '../src/types.js';
import {T, makeQuery, resetState} from './helpers.js';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const question = parseQuestion(makeQuery('answers.example.test', T.A));
const answer = (ttl: number): Result => ({body: new Uint8Array([ttl]), ttl});
const hitAfter = (ms: number, ttl: number) =>
  sleep(ms).then(() => ({result: answer(ttl), refresh: false}));
const savedError = console.error;

beforeEach(() => {
  console.error = () => {};
  resetState();
  resetLog();
});
afterEach(() => {
  console.error = savedError;
});

describe('firstAnswer', () => {
  test('the upstream answer wins over a slower cache hit', async () => {
    const result = await firstAnswer(
      hitAfter(50, 1),
      Promise.resolve(answer(2))
    );
    assert.equal(result.ttl, 2);
  });

  test('a cache hit wins over a slower upstream', async () => {
    const slow = sleep(50).then(() => answer(2));
    assert.equal((await firstAnswer(hitAfter(0, 1), slow)).ttl, 1);
  });

  test('a cache miss waits for the upstream', async () => {
    const slow = sleep(20).then(() => answer(2));
    assert.equal((await firstAnswer(Promise.resolve(null), slow)).ttl, 2);
  });

  test('a failed upstream is covered by a cache hit that comes later', async () => {
    const failed = Promise.reject(new Error('down'));
    assert.equal((await firstAnswer(hitAfter(30, 1), failed)).ttl, 1);
  });

  test('a miss and a failed upstream is the upstream error', async () => {
    const failed = Promise.reject(new Error('down'));
    await assert.rejects(firstAnswer(Promise.resolve(null), failed), /down/);
  });
});

describe('readable', () => {
  test('an answer that can be read is shown as it is', () => {
    const response = {body: makeQuery('answers.example.test', T.A), ttl: 77};
    assert.equal(readable(question, response).result, response);
  });

  test('an answer that cannot be read is shown as SERVFAIL, with its short TTL', () => {
    const garbage = {body: new Uint8Array([1, 2, 3]), ttl: 77};
    const shown = readable(question, garbage);
    assert.equal(shown.result.ttl, TTL_FAILURE);
    assert.equal((shown.json as {Status: number}).Status, 2);
  });
});
