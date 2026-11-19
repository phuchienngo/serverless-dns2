/** DNS Cookies (src/cookie.ts, RFC 7873). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {cookieOption} from '../src/cookie.js';
import {parseQuestion} from '../src/dns.js';
import {T, makeQuery} from './helpers.js';

const client = [1, 2, 3, 4, 5, 6, 7, 8];
const q = (cookie?: number[]) =>
  parseQuestion(makeQuery('a.test', T.A, {cookie}));

describe('cookieOption', () => {
  test('is option 10: the client cookie, then 8 bytes of server cookie', async () => {
    const option = (await cookieOption(q(client), '192.0.2.1', 's'))!;
    assert.deepEqual(option.slice(0, 4), [0, 10, 0, 16]);
    assert.deepEqual(option.slice(4, 12), client);
    assert.equal(option.length, 4 + 16);
  });

  test('depends on the client cookie, the address and the secret', async () => {
    const make = async (c: number[], ip: string | null, secret: string) =>
      (await cookieOption(q(c), ip, secret))!.slice(12).join(',');
    const base = await make(client, '192.0.2.1', 's');
    assert.equal(await make(client, '192.0.2.1', 's'), base, 'stable');
    assert.notEqual(await make(client, '192.0.2.2', 's'), base);
    assert.notEqual(await make(client, null, 's'), base);
    assert.notEqual(await make(client, '192.0.2.1', 't'), base, 'new secret');
    assert.notEqual(
      await make([...client.slice(1), 9], '192.0.2.1', 's'),
      base
    );
  });

  test('only the first 8 bytes of a longer cookie are the client cookie', async () => {
    const withServer = [...client, ...new Array(8).fill(7)];
    const a = await cookieOption(q(withServer), 'x', 's');
    const b = await cookieOption(q(client), 'x', 's');
    assert.deepEqual(a, b);
  });

  test('is null without a cookie or without a secret', async () => {
    assert.equal(await cookieOption(q(), 'x', 's'), null);
    assert.equal(await cookieOption(q(client), 'x', undefined), null);
    assert.equal(await cookieOption(q(client), 'x', ''), null);
  });
});
