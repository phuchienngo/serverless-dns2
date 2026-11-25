/** ECH is best effort: when adding it fails, the answer stays and a line says why. */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, test} from 'node:test';
import {RCODE_NOERROR} from '../src/constants.js';
import {loadCloudflareRanges} from '../src/cloudflare-ips.js';
import {addEch, startEchProbe} from '../src/ech.js';
import {resetLog} from '../src/log.js';
import {parseQuestion} from '../src/query.js';
import {respond} from '../src/response.js';
import {T, makeQuery, resetState} from './helpers.js';

let warnings: unknown[][];
const savedWarn = console.warn;

beforeEach(() => {
  warnings = [];
  console.warn = (...args: unknown[]) => void warnings.push(args);
  resetState();
  resetLog();
});
afterEach(() => {
  console.warn = savedWarn;
});

test('a failure keeps the answer and logs one warning with the cause', async () => {
  const question = parseQuestion(makeQuery('ech.example.test', T.HTTPS));
  const result = {body: respond(question, RCODE_NOERROR, []), ttl: 60};
  const probe = {
    cloudflare: Promise.reject(new Error('probe broke')),
    config: Promise.resolve(new Uint8Array([1, 2, 3])),
    ranges: [],
  };
  const out = await addEch(result, question, probe);
  assert.equal(out, result, 'the answer is kept as it is');
  assert.equal(warnings.length, 1);
  const [line] = warnings[0] as [Record<string, unknown>];
  assert.equal(line.event, 'ech_failed');
  assert.equal(line.message, 'ECH not added to ech.example.test: probe broke');
  assert.equal(line.cause, 'probe broke');
});

test('an answer that needs no ECH logs nothing', async () => {
  const question = parseQuestion(makeQuery('plain.example.test', T.HTTPS));
  const result = {body: respond(question, RCODE_NOERROR, []), ttl: 60};
  const probe = {
    cloudflare: Promise.resolve(false),
    config: Promise.resolve(new Uint8Array([1, 2, 3])),
    ranges: [],
  };
  assert.equal(await addEch(result, question, probe), result);
  assert.equal(warnings.length, 0);
});

test('the work a probe starts is kept alive for the request', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response('', {status: 500});
  try {
    loadCloudflareRanges({v4: ['104.16.0.0/13']});
    const question = parseQuestion(makeQuery('probe.example.test', T.HTTPS));
    const kept: Promise<unknown>[] = [];
    const probe = startEchProbe(question, null, work => void kept.push(work));
    assert.ok(probe);
    assert.equal(kept.length, 2, 'the A lookup and the key load');
    await Promise.all(kept);
  } finally {
    globalThis.fetch = original;
  }
});
