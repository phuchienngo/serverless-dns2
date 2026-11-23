/**
 * RFC 2181 8: a TTL received with the top bit set counts as zero, not as a
 * huge value that would be cached for as long as we allow.
 */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {minTtl} from '../src/response.js';
import {T, ip4, makeResponse} from './helpers.js';

const answerWith = (ttl: number) =>
  makeResponse({
    qname: 'a.test',
    qtype: T.A,
    answer: [{type: T.A, ttl, rdata: ip4('192.0.2.1')}],
  });

describe('minTtl and the top bit of a TTL', () => {
  test('a TTL with the top bit set counts as 0', () => {
    assert.equal(minTtl(answerWith(0x80000000)), 0);
    assert.equal(minTtl(answerWith(0xffffffff)), 0);
  });

  test('the largest valid TTL is limited to an hour, as before', () => {
    assert.equal(minTtl(answerWith(0x7fffffff)), 3600);
  });

  test('a record with the top bit set wins over a normal one', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [
        {type: T.A, ttl: 300, rdata: ip4('192.0.2.1')},
        {type: T.A, ttl: 0x90000000, rdata: ip4('192.0.2.2')},
      ],
    });
    assert.equal(minTtl(body), 0);
  });
});
