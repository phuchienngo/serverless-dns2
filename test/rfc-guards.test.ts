/**
 * A second angle on behaviours that one test alone guarded: each rule from an
 * RFC is checked here by another route or at its boundary.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {handle} from '../src/handlers.js';
import {ddrAnswer} from '../src/local.js';
import {withDns64} from '../src/dns64.js';
import {parseQuestion} from '../src/query.js';
import {resolve} from '../src/resolve.js';
import type {Question, Result} from '../src/types.js';
import {
  T,
  ip4,
  ip6,
  makeQuery,
  makeResponse,
  mockUpstream,
  parseMsg,
  plainOptions,
  resetState,
  type QueryOptions,
} from './helpers.js';

let upstream: ReturnType<typeof mockUpstream>;
beforeEach(() => {
  resetState();
  upstream = mockUpstream(q =>
    makeResponse({
      qname: q.question[0].name,
      qtype: q.question[0].type,
      answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.1')}],
      opt: {do: q.opt?.do},
    })
  );
});
afterEach(() => upstream.restore());

async function ask(
  name: string,
  type: number,
  query: QueryOptions = {},
  options: Record<string, unknown> = {}
) {
  const result = await resolve(
    parseQuestion(makeQuery(name, type, query)),
    plainOptions(options)
  );
  return {body: result.body, msg: parseMsg(result.body)};
}

describe('RESINFO (RFC 9606 3)', () => {
  test('the answer is authoritative, and still a plain NOERROR response', async () => {
    const {body, msg} = await ask('dns.test', T.RESINFO);
    assert.equal(body[2] & 0x04, 0x04, 'AA');
    assert.equal(body[2] & 0x80, 0x80, 'QR');
    assert.equal(body[2] & 0x02, 0, 'not truncated');
    assert.equal(body[3] & 0x80, 0x80, 'RA');
    assert.equal(msg.rcode, 0);
  });

  test('an answer from the upstream does not get AA', async () => {
    const {body} = await ask('other.example.com', T.A);
    assert.equal(body[2] & 0x04, 0);
  });
});

describe('DDR (RFC 9462)', () => {
  const record = (host: string) =>
    parseMsg(ddrAnswer(parseQuestion(makeQuery(host, T.SVCB)), host)).answer[0];

  test('priority 1, the target is the host, and the parameters are alpn and dohpath', () => {
    const r = record('dns.example.com');
    assert.deepEqual([...r.rdata.subarray(0, 2)], [0, 1], 'ServiceMode');
    const text = Buffer.from(r.rdata).toString('latin1');
    assert.ok(text.includes('\x03dns\x07example\x03com\x00'), 'target');
    assert.ok(text.includes('\x02h2'), 'alpn h2');
    assert.ok(text.includes('/dns-query{?dns}'), 'dohpath template');
  });
});

describe('names that are never forwarded', () => {
  for (const name of [
    'resolver.arpa',
    'x.resolver.arpa',
    'deep.x.resolver.arpa',
  ]) {
    test(`${name} gets an empty answer here`, async () => {
      const {msg} = await ask(name, T.A);
      assert.equal(msg.rcode, 0);
      assert.equal(msg.answer.length, 0);
      assert.equal(upstream.calls.length, 0);
    });
  }

  for (const name of ['x.alt', 'alt', 'deep.x.alt']) {
    test(`${name} is answered here`, async () => {
      const {msg} = await ask(name, T.A);
      assert.equal(msg.rcode, 3);
      assert.equal(upstream.calls.length, 0);
    });
  }

  for (const name of ['notalt', 'x.notalt', 'xresolver.arpa', 'x.alt.com']) {
    test(`${name} is not mistaken for them`, async () => {
      await ask(name, T.A);
      assert.equal(upstream.calls.length, 1);
    });
  }
});

describe('DNS Cookie lengths (RFC 7873 4)', () => {
  const cookie = (length: number) =>
    Array.from({length}, (_, i) => (i + 1) & 255);
  const valid = [8, 16, 17, 24, 39, 40];
  const invalid = [1, 7, 9, 12, 15, 41, 42, 64];

  for (const length of valid) {
    test(`${length} bytes are accepted`, async () => {
      const {msg} = await ask('c.example.com', T.A, {cookie: cookie(length)});
      assert.equal(msg.rcode, 0);
    });
  }
  for (const length of invalid) {
    test(`${length} bytes are FORMERR, without asking the upstream`, async () => {
      const {msg} = await ask('c.example.com', T.A, {cookie: cookie(length)});
      assert.equal(msg.rcode, 1);
      assert.equal(upstream.calls.length, 0);
    });
  }
});

describe('the ECS echo (RFC 7871 7.2.2, 7.3)', () => {
  const ECS = {family: 1 as const, prefix: 24, address: [192, 0, 2, 0]};
  /** Through the handler, which is what reads the client's address. */
  async function askSubnet(name: string) {
    const res = await handle(
      new Request('https://dns.test/dns-query', {
        method: 'POST',
        headers: {'content-type': 'application/dns-message'},
        body: makeQuery(name, T.A, {ecs: ECS}) as never,
      }),
      {env: {}, ip: '192.0.2.77'} as never
    );
    return {msg: parseMsg(new Uint8Array(await res.arrayBuffer()))};
  }
  const subnetOf = (msg: ReturnType<typeof parseMsg>) =>
    msg.opt?.options.find(o => o.code === 8)?.data;

  function echoing(data: number[]) {
    upstream.restore();
    upstream = mockUpstream(q =>
      makeResponse({
        qname: q.question[0].name,
        qtype: q.question[0].type,
        answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.1')}],
        opt: {options: [{code: 8, data}]},
      })
    );
  }

  test('a reply with a longer source prefix than was sent is dropped', async () => {
    echoing([0, 1, 32, 32, 192, 0, 2, 0]);
    const {msg} = await askSubnet('e1.example.com');
    assert.deepEqual([...subnetOf(msg)!], [0, 1, 24, 0, 192, 0, 2]);
  });

  test('a scope of 0 is passed on as it is', async () => {
    echoing([0, 1, 24, 0, 192, 0, 2]);
    const {msg} = await askSubnet('e2.example.com');
    assert.deepEqual([...subnetOf(msg)!], [0, 1, 24, 0, 192, 0, 2]);
  });

  test('the scope the upstream chose is passed on as it is', async () => {
    echoing([0, 1, 24, 20, 192, 0, 2]);
    const {msg} = await askSubnet('e3.example.com');
    assert.deepEqual([...subnetOf(msg)!], [0, 1, 24, 20, 192, 0, 2]);
  });
});

let nextKey = 0;

describe('what DNS64 counts as an empty AAAA answer (RFC 6147 5.1.4)', () => {
  const question = (): Question => parseQuestion(makeQuery('a.test', T.AAAA));
  const aaaa = (address: string): Result => ({
    body: makeResponse({
      qname: 'a.test',
      qtype: T.AAAA,
      answer: [{type: T.AAAA, ttl: 60, rdata: ip6(address)}],
    }),
    ttl: 60,
  });
  const a: Result = {
    body: makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 120, rdata: ip4('8.8.8.8')}],
    }),
    ttl: 120,
  };

  async function outcome(address: string) {
    const result = aaaa(address);
    const out = await withDns64(
      question(),
      `https://dns.test/__cache/${nextKey++}/dns64`,
      Promise.resolve(result),
      async () => a
    );
    return out === result ? 'kept' : 'synthesized';
  }

  // Only ::ffff:0:0/96 is the IPv4-mapped range: its neighbours are real.
  for (const [address, expected] of [
    ['::ffff:0:0', 'synthesized'],
    ['::ffff:c000:201', 'synthesized'],
    ['::ffff:ffff:ffff', 'synthesized'],
    ['::fffe:c000:201', 'kept'],
    ['::1:ffff:c000:201', 'kept'],
    ['1::ffff:c000:201', 'kept'],
    ['64:ff9b::c000:201', 'kept'],
  ] as const) {
    test(`${address}: ${expected}`, async () => {
      assert.equal(await outcome(address), expected);
    });
  }

  // Changing any one of the first 12 bytes takes an address out of the range.
  for (let byte = 0; byte < 12; byte++) {
    test(`an address that differs in byte ${byte} is a usable one`, async () => {
      const bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
      bytes[byte] = bytes[byte] ^ 0x01;
      const address = Array.from({length: 8}, (_, i) =>
        ((bytes[2 * i] << 8) | bytes[2 * i + 1]).toString(16)
      ).join(':');
      assert.equal(await outcome(address), 'kept');
    });
  }

  test('any of the last 4 bytes may be anything in the range', async () => {
    for (const tail of ['0:0', '0:1', 'ffff:ffff', '1234:5678']) {
      assert.equal(await outcome(`0:0:0:0:0:ffff:${tail}`), 'synthesized');
    }
  });

  test('a mixed answer, with the mapped record first or last, is kept', async () => {
    for (const order of [
      ['::ffff:c000:201', '2001:db8::1'],
      ['2001:db8::1', '::ffff:c000:201'],
    ]) {
      const result: Result = {
        body: makeResponse({
          qname: 'a.test',
          qtype: T.AAAA,
          answer: order.map(address => ({
            type: T.AAAA,
            ttl: 60,
            rdata: ip6(address),
          })),
        }),
        ttl: 60,
      };
      const out = await withDns64(
        question(),
        `https://dns.test/__cache/${nextKey++}/dns64`,
        Promise.resolve(result),
        async () => a
      );
      assert.equal(out, result, order.join(' '));
    }
  });

  test('a record that is not 16 bytes long is not taken for a mapped address', async () => {
    const prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    for (const rdata of [prefix, [...prefix, 192, 0, 2, 1, 9]]) {
      const result: Result = {
        body: makeResponse({
          qname: 'a.test',
          qtype: T.AAAA,
          answer: [{type: T.AAAA, ttl: 60, rdata}],
        }),
        ttl: 60,
      };
      const out = await withDns64(
        question(),
        `https://dns.test/__cache/${nextKey++}/dns64`,
        Promise.resolve(result),
        async () => a
      );
      assert.equal(out, result, `${rdata.length} bytes`);
    }
  });
});
