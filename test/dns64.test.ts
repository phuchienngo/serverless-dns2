/** DNS64 synthesis (src/dns64.ts). */

import assert from 'node:assert/strict';
import {beforeEach, describe, test} from 'node:test';
import {parseQuestion} from '../src/query.js';
import {ipv4onlyAnswer, withDns64} from '../src/dns64.js';
import type {Question, Result} from '../src/types.js';
import {
  T,
  ip4,
  ip6,
  makeQuery,
  makeResponse,
  nameRdata,
  parseMsg,
  resetState,
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

/**
 * Resolves `question` with DNS64 where the upstream answered `result`, and
 * `lookup` answers whatever else is asked. Starts with an empty memory.
 */
async function synthesize(
  question: Question,
  result: Result,
  lookup: (q: Question) => Promise<Result>,
  key = `https://dns.test/__cache/${nextKey++}/dns64`
): Promise<Result> {
  return withDns64(question, key, Promise.resolve(result), lookup);
}
let nextKey = 0;
beforeEach(() => resetState());

/** Runs DNS64 with the given A answer; returns the result and the questions asked. */
async function run(question: Question, result: Result, a: Result | Error) {
  const asked: Question[] = [];
  const out = await synthesize(question, result, async lookup => {
    asked.push(lookup);
    if (a instanceof Error) {
      throw a;
    }
    return a;
  });
  return {out, asked};
}

describe('withDns64 (RFC 6147)', () => {
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

  test('only synthesizes for an AAAA question with an empty NOERROR answer', async () => {
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
      assert.equal(asked.length, question.type === T.AAAA ? 1 : 0);
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

  test('keeps what it makes: the lookup is not repeated, and nothing made means nothing kept', async () => {
    const key = 'https://dns.test/__cache/kept/dns64';
    const asked: Question[] = [];
    const lookupWith = (a: Result) => async (x: Question) => {
      asked.push(x);
      return a;
    };
    const first = await synthesize(
      q(),
      empty(),
      lookupWith(answerA(['8.8.8.8'])),
      key
    );
    assert.equal(asked.length, 1);
    const second = await synthesize(
      q(),
      empty(),
      lookupWith(answerA(['1.1.1.1'])),
      key
    );
    assert.equal(asked.length, 1, 'served from memory');
    assert.deepEqual(
      [...parseMsg(second.body).answer[0].rdata],
      [...parseMsg(first.body).answer[0].rdata]
    );

    const other = 'https://dns.test/__cache/nothing/dns64';
    await synthesize(q(), empty(), lookupWith(answerA(['10.0.0.1'])), other);
    await synthesize(q(), empty(), lookupWith(answerA(['10.0.0.1'])), other);
    assert.equal(asked.length, 3, 'nothing was made, so nothing was kept');
  });

  test('DNS64 is a courtesy: if it throws, the upstream answer stands', async () => {
    const result = empty();
    // A body the synthesizer cannot read, with a rcode it accepts.
    const broken: Result = {
      body: new Uint8Array(result.body.subarray(0, 14)),
      ttl: 30,
    };
    const out = await synthesize(q(), broken, async () => {
      throw new Error('down');
    });
    assert.equal(out, broken);
  });
});

/** The ip6.arpa name of an IPv6 address given as 16 bytes. */
const reverse6 = (bytes: number[]) =>
  bytes
    .flatMap(b => [b >> 4, b & 15])
    .reverse()
    .map(n => n.toString(16))
    .join('.') + '.ip6.arpa';

const nat64 = (v4: string) => [...ip6('64:ff9b::').slice(0, 12), ...ip4(v4)];
const qPtr = (name: string, o: QueryOptions = {}) =>
  parseQuestion(makeQuery(name, T.PTR, o));

describe('ipv4onlyAnswer (RFC 7050)', () => {
  test('AAAA for ipv4only.arpa holds both addresses inside the prefix', () => {
    const question = parseQuestion(makeQuery('ipv4only.arpa', T.AAAA));
    const answer = ipv4onlyAnswer(question)!;
    const m = parseMsg(answer.body);
    assert.deepEqual(
      m.answer.map(r => [...r.rdata]),
      [ip6('64:ff9b::c000:aa'), ip6('64:ff9b::c000:ab')]
    );
    assert.ok(m.answer.every(r => r.type === T.AAAA));
  });

  test('is null for other names and types', () => {
    const ask = (name: string, type: number) =>
      ipv4onlyAnswer(parseQuestion(makeQuery(name, type)));
    assert.equal(ask('ipv4only.arpa', T.A), null);
    assert.equal(ask('a.ipv4only.arpa', T.AAAA), null);
    assert.equal(ask('example.com', T.AAAA), null);
  });
});

describe('withDns64 PTR (RFC 6147 5.3.1)', () => {
  const name = reverse6(nat64('93.184.216.34'));
  const ptrAnswer = (...hosts: string[]): Result => ({
    body: makeResponse({
      qname: '34.216.184.93.in-addr.arpa',
      qtype: T.PTR,
      answer: hosts.map(h => ({type: T.PTR, ttl: 200, rdata: nameRdata(h)})),
    }),
    ttl: 200,
  });
  const noAnswer = (rcode = 3): Result => ({
    body: makeResponse({
      qname: name,
      qtype: T.PTR,
      rcode,
      authority: [{type: T.SOA, ttl: 900, rdata: soaRdata(900)}],
    }),
    ttl: 900,
  });

  test('answers with a CNAME to the IPv4 reverse name and its PTR records', async () => {
    const asked: Question[] = [];
    const out = await synthesize(qPtr(name), noAnswer(), async lookup => {
      asked.push(lookup);
      return ptrAnswer('a.example.com.', 'b.example.com.');
    });
    assert.equal(asked.length, 1);
    assert.equal(asked[0].name, '34.216.184.93.in-addr.arpa');
    assert.equal(asked[0].type, T.PTR);
    const m = parseMsg(out.body);
    assert.equal(m.rcode, 0);
    assert.deepEqual(
      m.answer.map(r => r.type),
      [T.CNAME, T.PTR, T.PTR]
    );
    assert.deepEqual(
      [...m.answer[0].rdata],
      nameRdata('34.216.184.93.in-addr.arpa')
    );
    assert.deepEqual(
      m.answer.slice(1).map(r => r.name),
      ['34.216.184.93.in-addr.arpa.', '34.216.184.93.in-addr.arpa.']
    );
    assert.deepEqual(
      m.answer.slice(1).map(r => [...r.rdata]),
      [nameRdata('a.example.com'), nameRdata('b.example.com')]
    );
    assert.equal(out.ttl, 200);
  });

  test('also when the upstream answered NOERROR with nothing', async () => {
    const out = await synthesize(qPtr(name), noAnswer(0), async () =>
      ptrAnswer('a.example.com.')
    );
    assert.equal(parseMsg(out.body).answer.length, 2);
  });

  test('not outside the prefix, for private addresses, or for DO without CD', async () => {
    const lookup = async () => ptrAnswer('a.example.com.');
    const result = noAnswer();
    const other = reverse6(ip6('2001:db8::1'));
    const inside = (n: string) => qPtr(n);
    assert.equal(await synthesize(inside(other), result, lookup), result);
    const priv = reverse6(nat64('10.1.2.3'));
    assert.equal(await synthesize(inside(priv), result, lookup), result);
    assert.equal(
      await synthesize(qPtr(name, {do: true}), result, lookup),
      result
    );
    assert.equal(
      await synthesize(qPtr('1.0.0.127.in-addr.arpa'), result, lookup),
      result,
      'an IPv4 reverse name'
    );
    assert.equal(
      await synthesize(qPtr('x.' + name), result, lookup),
      result,
      'a name longer than an address'
    );
  });

  test('leaves the answer alone when the IPv4 name has no PTR or the lookup fails', async () => {
    const result = noAnswer();
    for (const lookup of [
      async () => ptrAnswer(),
      async () => noAnswer(),
      async (): Promise<Result> => {
        throw new Error('down');
      },
    ]) {
      assert.equal(await synthesize(qPtr(name), result, lookup), result);
    }
  });

  test('a PTR that the upstream does answer is left alone', async () => {
    const real: Result = {
      body: makeResponse({
        qname: name,
        qtype: T.PTR,
        answer: [{type: T.PTR, ttl: 60, rdata: nameRdata('real.example.com')}],
      }),
      ttl: 60,
    };
    let asked = 0;
    const out = await synthesize(
      qPtr(name),
      real,
      async () => (asked++, ptrAnswer('a.example.com.'))
    );
    assert.equal(out, real);
    assert.equal(asked, 0);
  });
});

describe('what counts as an empty AAAA answer (RFC 6147 5.1.2-5.1.4)', () => {
  const synthesizedFrom = (a: Result, result: Result) =>
    run(q(), result, a).then(({out}) => parseMsg(out.body));

  for (const [description, rcode] of [
    ['SERVFAIL', 2],
    ['REFUSED', 5],
    ['NOTIMP', 4],
    ['FORMERR', 1],
  ] as const) {
    test(`${description} is treated as an empty answer`, async () => {
      const msg = await synthesizedFrom(
        answerA(['8.8.8.8']),
        empty(600, rcode)
      );
      assert.equal(msg.rcode, 0);
      assert.equal(msg.answer.length, 1);
      assert.equal(msg.answer[0].type, T.AAAA);
    });
  }

  test('an upstream that fails on AAAA is an empty answer, with TTL at most 600', async () => {
    const out = await withDns64(
      q(),
      `https://dns.test/__cache/${nextKey++}/dns64`,
      Promise.reject(new Error('upstream down')),
      async () => answerA(['8.8.8.8'], 900)
    );
    const msg = parseMsg(out.body);
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer[0].type, T.AAAA);
    assert.equal(msg.answer[0].ttl, 600);
  });

  test('a failure stands if no A record makes an answer', async () => {
    const failure = new Error('upstream down');
    await assert.rejects(
      withDns64(
        q(),
        `https://dns.test/__cache/${nextKey++}/dns64`,
        Promise.reject(failure),
        async () => {
          throw new Error('still down');
        }
      ),
      error => error === failure
    );
  });

  test('NXDOMAIN is still returned as it is', async () => {
    const result = empty(600, 3);
    const {out} = await run(q(), result, answerA(['8.8.8.8']));
    assert.equal(out, result);
  });

  const mapped = (address: string): Result => ({
    body: makeResponse({
      qname: 'a.test',
      qtype: T.AAAA,
      answer: [{type: T.AAAA, ttl: 60, rdata: ip6(address)}],
    }),
    ttl: 60,
  });

  test('only AAAA records in ::ffff:0:0/96 are an empty answer, and are not returned', async () => {
    const msg = await synthesizedFrom(
      answerA(['8.8.8.8']),
      mapped('::ffff:c000:201')
    );
    assert.equal(msg.answer.length, 1);
    assert.equal(msg.answer[0].type, T.AAAA);
    assert.deepEqual(
      [...msg.answer[0].rdata],
      [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8]
    );
  });

  test('a usable AAAA record next to them keeps the answer as it is', async () => {
    const result: Result = {
      body: makeResponse({
        qname: 'a.test',
        qtype: T.AAAA,
        answer: [
          {type: T.AAAA, ttl: 60, rdata: ip6('::ffff:c000:201')},
          {type: T.AAAA, ttl: 60, rdata: ip6('2001:db8::1')},
        ],
      }),
      ttl: 60,
    };
    const {out} = await run(q(), result, answerA(['8.8.8.8']));
    assert.equal(out, result);
  });
});
