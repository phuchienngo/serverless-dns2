/** Answers that need no upstream (src/local.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {EDE_PRODUCED} from '../src/constants.js';
import {parseQuestion} from '../src/query.js';
import {ddrAnswer, isDdr, localAnswer, typeAnswer} from '../src/local.js';
import {T, makeQuery, parseMsg} from './helpers.js';

const q = (name: string, type: number, o = {}) =>
  parseQuestion(makeQuery(name, type, o));
const rcodeOf = (r: {body: Uint8Array} | null) => parseMsg(r!.body).rcode;

describe('localAnswer', () => {
  test('is null for an ordinary name', () => {
    assert.equal(localAnswer(q('www.example.com', T.A), 'dns.test'), null);
  });

  test('refusals come first, whatever the name', () => {
    assert.equal(
      rcodeOf(localAnswer(q('localhost', T.A, {opcode: 4}), 'h')),
      4
    );
    assert.equal(
      rcodeOf(localAnswer(q('localhost', T.A, {qclass: 3}), 'h')),
      5
    );
    assert.equal(rcodeOf(localAnswer(q('localhost', 252), 'h')), 4);
    assert.equal(rcodeOf(localAnswer(q('localhost', 0), 'h')), 1);
  });

  test('the DDR query is left to the resolver, for resolver.arpa and this host only', () => {
    for (const name of ['_dns.resolver.arpa', '_dns.dns.test']) {
      assert.equal(isDdr(q(name, T.SVCB), 'dns.test'), true, name);
      assert.equal(localAnswer(q(name, T.SVCB), 'dns.test'), null, name);
    }
    assert.equal(isDdr(q('_dns.other.example.com', T.SVCB), 'dns.test'), false);
    assert.equal(isDdr(q('_dns.resolver.arpa', T.A), 'dns.test'), false);
  });

  test('ddrAnswer names this gateway and carries the address hints', () => {
    const m = parseMsg(ddrAnswer(q('_dns.resolver.arpa', T.SVCB), 'dns.test'));
    assert.equal(m.answer[0].type, T.SVCB);
    assert.equal(m.additional.filter(r => r.type !== 41).length, 0);
  });

  test('RESINFO is an authoritative answer: a client discards one without AA (RFC 9606 3)', () => {
    const answer = localAnswer(
      q('dns.example.com', T.RESINFO),
      'dns.example.com'
    )!;
    assert.equal(parseMsg(answer.body).aa, true);
  });

  test('RESINFO for this host is answered locally (RFC 9606), for no other name', () => {
    const answer = localAnswer(
      q('dns.example.com', T.RESINFO),
      'dns.example.com'
    )!;
    const m = parseMsg(answer.body);
    assert.equal(m.answer.length, 1);
    assert.equal(m.answer[0].type, T.RESINFO);
    const rdata = m.answer[0].rdata;
    const keys: string[] = [];
    for (let i = 0; i < rdata.length; i += 1 + rdata[i]) {
      keys.push(
        Buffer.from(rdata.subarray(i + 1, i + 1 + rdata[i])).toString()
      );
    }
    assert.deepEqual(keys, ['exterr=3,15,19,23']);
    assert.equal(answer.ttl, 300);
    assert.equal(
      localAnswer(q('other.example.com', T.RESINFO), 'dns.example.com'),
      null
    );
    assert.equal(
      localAnswer(q('dns.example.com', T.A), 'dns.example.com'),
      null
    );
  });

  test('localhost, resolver.arpa and undelegated names', () => {
    assert.equal(
      parseMsg(localAnswer(q('a.localhost', T.A), 'h')!.body).answer.length,
      1
    );
    assert.equal(rcodeOf(localAnswer(q('x.resolver.arpa', T.A), 'h')), 0);
    assert.equal(rcodeOf(localAnswer(q('nas.lan', T.A), 'h')), 3);
  });
});

describe('EDE_PRODUCED', () => {
  test('is sorted, without duplicates, and is what RESINFO lists', () => {
    assert.deepEqual(
      EDE_PRODUCED,
      [...new Set(EDE_PRODUCED)].sort((a, b) => a - b)
    );
    assert.deepEqual(EDE_PRODUCED, [3, 15, 19, 23]);
  });
});

describe('typeAnswer', () => {
  test('ANY gets HINFO, other types are forwarded', () => {
    const m = parseMsg(typeAnswer(q('www.example.com', 255))!.body);
    assert.equal(m.answer[0].type, T.HINFO);
    assert.equal(typeAnswer(q('www.example.com', T.A)), null);
    assert.equal(typeAnswer(q('www.example.com', T.HTTPS)), null);
  });
});
