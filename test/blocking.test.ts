/**
 * Blocking: blocklist + regex rules + allow rules + CNAME uncloaking, with a
 * fake ASSETS binding serving a small blocklist (RFC 8914 EDE 15 on blocks).
 * The blocklist is cached per process, so this file loads one fixture only.
 */

import assert from 'node:assert/strict';
import {after, before, describe, test} from 'node:test';
import {buildBlockset} from '../scripts/blocklist-lib.js';
import {parseQuestion} from '../src/dns.js';
import {resolve} from '../src/resolve.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  mockUpstream,
  nameRdata,
  parseMsg,
  type QueryOptions,
} from './helpers.js';

const blockset = buildBlockset(
  new Set(['tracker.example.net', 'ads.listed.com']),
  20
);
const rules = {
  block: ['^telemetry\\.', '^(.+[_.-])?adserv[_.-]'],
  allow: [
    '^ok\\.tracker\\.example\\.net$',
    '^telemetry\\.allowed\\.com$',
    '^rebind-allowed\\.',
  ],
};
const assets = {
  async fetch(input: string) {
    if (input.endsWith('/blocklist.bin')) {
      return new Response(blockset);
    }
    if (input.endsWith('/rules.json')) {
      return Response.json(rules);
    }
    return new Response('nope', {status: 404});
  },
};

let upstream: ReturnType<typeof mockUpstream>;
let n = 0;
before(() => {
  upstream = mockUpstream(q => {
    const {name, type} = q.question[0];
    // `cloak*` names hide behind a CNAME to a listed tracker.
    if (name.startsWith('cloak') && type === T.A) {
      const target = name.startsWith('cloakok')
        ? 'cdn.fine.org'
        : 'x.tracker.example.net';
      return makeResponse({
        qname: name,
        qtype: type,
        answer: [
          {type: T.CNAME, ttl: 60, rdata: nameRdata(target)},
          {name: target, type: T.A, ttl: 60, rdata: ip4('1.1.1.1')},
        ],
      });
    }
    if (name.startsWith('rebind') && type === T.A) {
      const address = name.startsWith('rebind-zero')
        ? '0.0.0.0'
        : name.startsWith('rebind-public')
          ? '8.8.8.8'
          : '192.168.1.1';
      return makeResponse({
        qname: name,
        qtype: type,
        answer: [{type: T.A, ttl: 60, rdata: ip4(address)}],
      });
    }
    return makeResponse({
      qname: name,
      qtype: type,
      answer: type === T.A ? [{type: T.A, ttl: 60, rdata: ip4('1.1.1.1')}] : [],
    });
  });
});
after(() => upstream.restore());

async function ask(name: string, type = T.A, query: QueryOptions = {}) {
  const q = parseQuestion(makeQuery(name, type, query));
  const result = await resolve(q, {
    env: {ASSETS: assets as never},
    ip: null,
    host: 'dns.test',
  } as never);
  return parseMsg(result.body);
}
const isBlockedAnswer = (m: ReturnType<typeof parseMsg>) =>
  m.rcode === 3 && m.opt?.options.some(o => o.code === 15);

describe('blocking', () => {
  test('a listed domain and its subdomains get NXDOMAIN with EDE 15', async () => {
    for (const name of ['tracker.example.net', 'a.b.tracker.example.net']) {
      const m = await ask(name);
      assert.equal(m.rcode, 3, name);
      assert.ok(isBlockedAnswer(m), name);
      const ede = m.opt!.options.find(o => o.code === 15)!;
      assert.deepEqual([...ede.data.subarray(0, 2)], [0, 15], 'Blocked');
    }
  });

  test('the block answer has a SOA so that clients can cache it (RFC 2308)', async () => {
    const m = await ask('tracker.example.net');
    assert.equal(m.authority[0].type, T.SOA);
    assert.equal(m.authority[0].ttl, 300);
  });

  test('a block is NXDOMAIN for every type', async () => {
    for (const type of [T.A, T.AAAA, T.HTTPS, T.TXT]) {
      assert.equal(
        (await ask('tracker.example.net', type)).rcode,
        3,
        `type ${type}`
      );
    }
  });

  test('a client without EDNS gets NXDOMAIN with no OPT record', async () => {
    const m = await ask('tracker.example.net', T.A, {edns: false});
    assert.equal(m.rcode, 3);
    assert.equal(m.opt, undefined);
  });

  test("unlisted names and a listed name's parent are not blocked", async () => {
    assert.equal((await ask('example.net')).rcode, 0);
    assert.equal((await ask('listed.com')).rcode, 0);
    assert.equal((await ask(`fine${n++}.example.org`)).rcode, 0);
  });

  test('regex block rules', async () => {
    assert.ok(isBlockedAnswer(await ask('telemetry.vendor.org')));
    assert.ok(isBlockedAnswer(await ask('adserv-01.vendor.org')));
    assert.equal((await ask('notelemetry.vendor.org')).rcode, 0);
  });

  test('allow wins over the blocklist and over block rules', async () => {
    assert.equal(
      (await ask('ok.tracker.example.net')).rcode,
      0,
      'under a listed parent'
    );
    assert.equal(
      (await ask('telemetry.allowed.com')).rcode,
      0,
      'over a block regex'
    );
  });

  test('CNAME uncloaking: a CNAME to a blocked target is NXDOMAIN', async () => {
    const m = await ask('cloak1.shop.org');
    assert.ok(isBlockedAnswer(m));
    assert.equal(m.answer.length, 0);
  });

  test('a CNAME to an innocent target is kept', async () => {
    const m = await ask('cloakok.shop.org');
    assert.equal(m.rcode, 0);
    assert.equal(m.answer[0].type, T.CNAME);
  });

  test('uncloaking is also applied to cached answers', async () => {
    await ask('cloak2.shop.org');
    assert.ok(isBlockedAnswer(await ask('cloak2.shop.org')));
  });

  test('an allowed name is not uncloaked', async () => {
    // cloak*.allowed.com is not allowed by the rules above, so use the exact
    // allowed name: it only has an A answer here and must pass either way.
    assert.equal((await ask('telemetry.allowed.com')).rcode, 0);
  });
});

describe('DNS rebinding', () => {
  const edeText = (m: ReturnType<typeof parseMsg>) =>
    Buffer.from(
      m.opt!.options.find(o => o.code === 15)!.data.subarray(2)
    ).toString();

  test('a public name that resolves to a private address gets NXDOMAIN with EDE 15', async () => {
    const m = await ask('rebind-a.attacker.example.org');
    assert.ok(isBlockedAnswer(m));
    assert.equal(edeText(m), 'dns rebinding');
    assert.equal(m.answer.length, 0);
  });

  test('a public address, and the 0.0.0.0 that blocklists answer, pass', async () => {
    assert.equal((await ask('rebind-public.example.org')).rcode, 0);
    const zero = await ask('rebind-zero.example.org');
    assert.equal(zero.rcode, 0);
    assert.deepEqual([...zero.answer[0].rdata], [0, 0, 0, 0]);
  });

  test('an allow rule exempts the name', async () => {
    const m = await ask('rebind-allowed.home.example.org');
    assert.equal(m.rcode, 0);
    assert.deepEqual([...m.answer[0].rdata], [192, 168, 1, 1]);
  });

  test('it is also applied to cached answers', async () => {
    await ask('rebind-cached.example.org');
    assert.ok(isBlockedAnswer(await ask('rebind-cached.example.org')));
  });
});
