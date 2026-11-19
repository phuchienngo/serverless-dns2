/** DNS64 synthesis (src/dns64.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {parseQuestion} from '../src/dns.js';
import {synthesize} from '../src/dns64.js';
import type {Question, Result} from '../src/types.js';
import {
  T,
  ip4,
  ip6,
  makeQuery,
  makeResponse,
  parseMsg,
  soaRdata,
  type QueryOptions,
} from './helpers.js';

const q = (type = T.AAAA, o: QueryOptions = {}) =>
  parseQuestion(makeQuery('a.test', type, o));

const empty = (ttl = 600, rcode = 0): Result => ({
  body: makeResponse({
    qname: 'a.test',
    qtype: T.AAAA,
    rcode,
    authority: [{type: T.SOA, ttl, rdata: soaRdata(ttl)}],
  }),
  ttl,
});

const answerA = (addresses: string[], ttl = 120): Result => ({
  body: makeResponse({
    qname: 'a.test',
    qtype: T.A,
    answer: addresses.map(a => ({type: T.A, ttl, rdata: ip4(a)})),
  }),
  ttl,
});

interface Memo {
  get: () => Result | null;
  set: (result: Result) => void;
}
const noMemo: Memo = {get: () => null, set: () => {}};

/** Runs synthesize with the given A answer; returns it and the A question asked. */
async function run(
  question: Question,
  result: Result,
  a: Result | Error,
  memo: Memo = noMemo
) {
  const asked: Question[] = [];
  const out = await synthesize(
    question,
    result,
    async lookup => {
      asked.push(lookup);
      if (a instanceof Error) {
        throw a;
      }
      return a;
    },
    memo
  );
  return {out, asked};
}

describe('synthesize (RFC 6147)', () => {
  test('embeds each A address in the /96 prefix, TTL the smaller one', async () => {
    const {out} = await run(
      q(),
      empty(600),
      answerA(['93.184.216.34', '8.8.8.8'], 120)
    );
    const m = parseMsg(out.body);
    assert.deepEqual(
      m.answer.map(r => [...r.rdata]),
      [ip6('64:ff9b::5db8:d822'), ip6('64:ff9b::808:808')]
    );
    assert.ok(m.answer.every(r => r.type === T.AAAA && r.ttl === 120));
    assert.equal(out.ttl, 120);
    const shorter = await run(q(), empty(30), answerA(['8.8.8.8'], 120));
    assert.equal(shorter.out.ttl, 30, 'not above the negative TTL');
  });

  test('asks for the A record with the same DNSSEC flags', async () => {
    const {asked} = await run(
      q(T.AAAA, {do: true, cd: true}),
      empty(),
      answerA(['8.8.8.8'])
    );
    assert.equal(asked.length, 1);
    assert.equal(asked[0].type, T.A);
    assert.equal(asked[0].name, 'a.test');
    assert.equal(asked[0].dnssecOk, true);
    assert.equal(asked[0].cd, true);
  });

  test('only for an AAAA question with an empty NOERROR answer', async () => {
    const a = answerA(['8.8.8.8']);
    const aaaa: Result = {
      body: makeResponse({
        qname: 'a.test',
        qtype: T.AAAA,
        answer: [{type: T.AAAA, ttl: 60, rdata: ip6('2001:db8::1')}],
      }),
      ttl: 60,
    };
    for (const [question, result] of [
      [q(T.A), empty()],
      [q(), aaaa],
      [q(), empty(600, 3)],
    ] as const) {
      const {out, asked} = await run(question, result, a);
      assert.equal(out, result);
      assert.equal(asked.length, 0, 'no A lookup');
    }
  });

  test('not for DO without CD (RFC 6147 5.5)', async () => {
    const result = empty();
    const {out, asked} = await run(
      q(T.AAAA, {do: true}),
      result,
      answerA(['8.8.8.8'])
    );
    assert.equal(out, result);
    assert.equal(asked.length, 0);
  });

  test('skips addresses that are not global, and keeps the others', async () => {
    const notGlobal = [
      '0.1.2.3',
      '10.0.0.1',
      '100.64.0.1',
      '127.0.0.1',
      '169.254.1.1',
      '172.16.0.1',
      '172.31.255.255',
      '192.0.0.170',
      '192.0.2.1',
      '192.168.1.1',
      '198.18.0.1',
      '198.51.100.1',
      '203.0.113.1',
      '224.0.0.1',
      '255.255.255.255',
    ];
    const result = empty();
    for (const address of notGlobal) {
      const {out} = await run(q(), result, answerA([address]));
      assert.equal(out, result, address);
    }
    for (const address of [
      '172.32.0.1',
      '100.128.0.1',
      '198.20.0.1',
      '1.1.1.1',
    ]) {
      const {out} = await run(q(), result, answerA([address]));
      assert.notEqual(out, result, address);
    }
    const {out} = await run(q(), result, answerA(['10.0.0.1', '1.1.1.1']));
    assert.equal(parseMsg(out.body).answer.length, 1, 'only the global one');
  });

  test('leaves the answer alone when the A lookup fails, is empty or an error', async () => {
    const result = empty();
    for (const a of [
      new Error('down'),
      empty(),
      {body: makeResponse({qname: 'a.test', qtype: T.A, rcode: 3}), ttl: 60},
    ]) {
      const {out} = await run(q(), result, a);
      assert.equal(out, result);
    }
  });

  test('keeps the question, id and flags, and carries stale', async () => {
    const question = q(T.AAAA, {id: 77, rd: false});
    const {out} = await run(
      question,
      {...empty(), stale: true},
      answerA(['8.8.8.8'])
    );
    const m = parseMsg(out.body);
    assert.equal(m.id, 77);
    assert.equal(m.rd, false);
    assert.equal(m.question[0].type, T.AAAA);
    assert.equal(out.stale, true);
  });

  test('uses the memo: stores what it makes, and skips the lookup on a hit', async () => {
    const stored: Result[] = [];
    const memo = {
      get: () => stored[0] ?? null,
      set: (r: Result) => void stored.push(r),
    };
    const first = await run(q(), empty(), answerA(['8.8.8.8']), memo);
    assert.equal(first.asked.length, 1);
    assert.equal(stored.length, 1);
    assert.equal(stored[0], first.out);
    const second = await run(q(), empty(), answerA(['1.1.1.1']), memo);
    assert.equal(second.asked.length, 0);
    assert.equal(second.out, stored[0]);

    const nothing: Result[] = [];
    await run(q(), empty(), answerA(['10.0.0.1']), {
      get: () => null,
      set: r => void nothing.push(r),
    });
    assert.equal(nothing.length, 0, 'nothing synthesized, nothing stored');
  });
});
