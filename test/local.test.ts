/** Answers that need no upstream (src/local.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {parseQuestion} from '../src/dns.js';
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

  test('localhost, resolver.arpa and undelegated names', () => {
    assert.equal(
      parseMsg(localAnswer(q('a.localhost', T.A), 'h')!.body).answer.length,
      1
    );
    assert.equal(rcodeOf(localAnswer(q('x.resolver.arpa', T.A), 'h')), 0);
    assert.equal(rcodeOf(localAnswer(q('nas.lan', T.A), 'h')), 3);
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
