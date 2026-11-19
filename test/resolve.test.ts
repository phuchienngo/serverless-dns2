/**
 * resolve() without a blocklist: local answers and the forwarding path, with
 * the upstream resolver replaced by a mock (see helpers.ts).
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, mock, test} from 'node:test';
import {ECH_FRONT_DOMAIN} from '../src/config.js';
import {parseQuestion} from '../src/dns.js';
import {resolve} from '../src/resolve.js';
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
  soaRdata,
  type Msg,
  type QueryOptions,
} from './helpers.js';

let n = 0;
/** A name that no earlier test has used, so the cache starts empty. */
const fresh = (label = 'h') => `${label}${n++}.resolve.example.com`;

/** The default upstream: a public A answer for A queries, nothing otherwise. */
function answerA(query: Msg, ttl = 300) {
  const {name, type} = query.question[0];
  return makeResponse({
    qname: name,
    qtype: type,
    answer: type === T.A ? [{type: T.A, ttl, rdata: ip4('198.51.100.7')}] : [],
    opt: {do: query.opt?.do},
  });
}

let upstream: ReturnType<typeof mockUpstream>;
const useUpstream = (
  handler: Parameters<typeof mockUpstream>[0] = q => answerA(q)
) => {
  upstream = mockUpstream(handler);
  return upstream;
};
beforeEach(() => {
  resetState();
  useUpstream();
});
afterEach(() => {
  upstream.restore();
  mock.timers.reset();
  mock.restoreAll();
});

async function ask(
  name: string,
  type: number,
  query: QueryOptions = {},
  options: Record<string, unknown> = {}
) {
  const q = parseQuestion(makeQuery(name, type, query));
  const result = await resolve(q, plainOptions(options));
  return {result, msg: parseMsg(result.body)};
}

describe('answers made locally (no upstream call)', () => {
  test('DDR: SVCB for _dns.resolver.arpa names this gateway (RFC 9462)', async () => {
    const {msg} = await ask('_dns.resolver.arpa', T.SVCB);
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer.length, 1);
    const rdata = msg.answer[0].rdata;
    assert.equal(msg.answer[0].type, T.SVCB);
    assert.deepEqual(
      [...rdata.subarray(0, 2)],
      [0, 1],
      'priority 1 (service mode)'
    );
    const target = Buffer.from(
      rdata.subarray(2, 2 + 1 + 3 + 1 + 4 + 1)
    ).toString('latin1');
    assert.ok(
      target.includes('dns') && target.includes('test'),
      'target is the gateway host'
    );
    // Parameters follow the target name, with keys in increasing order.
    const keys: number[] = [];
    for (let i = 2 + 10; i + 4 <= rdata.length;) {
      keys.push((rdata[i] << 8) | rdata[i + 1]);
      i += 4 + ((rdata[i + 2] << 8) | rdata[i + 3]);
    }
    assert.deepEqual(keys, [1, 7], 'alpn then dohpath');
    assert.ok(Buffer.from(rdata).includes('/dns-query{?dns}'));
  });

  test('DDR adds the A and AAAA records of the gateway host (RFC 9462 4)', async () => {
    useUpstream(q => {
      const {name, type} = q.question[0];
      const rdata = type === T.A ? ip4('203.0.113.9') : ip6('2001:db8::9');
      return makeResponse({
        qname: name,
        qtype: type,
        answer: [{type, ttl: 3000, rdata}],
      });
    });
    const host = fresh('ddr');
    const {msg} = await ask('_dns.resolver.arpa', T.SVCB, {}, {host});
    const hints = msg.additional.filter(r => r.type !== 41);
    assert.deepEqual(hints.map(r => r.type).sort(), [T.A, T.AAAA]);
    for (const hint of hints) {
      assert.equal(hint.name, `${host}.`);
      assert.ok(hint.ttl <= 300, 'not longer than the SVCB record');
    }
    assert.deepEqual(
      [...hints.find(r => r.type === T.A)!.rdata],
      ip4('203.0.113.9')
    );
    assert.equal(msg.answer.length, 1);
  });

  test('DDR still answers when the addresses cannot be looked up', async () => {
    useUpstream(() => {
      throw new Error('down');
    });
    const host = fresh('ddr');
    const {msg} = await ask('_dns.resolver.arpa', T.SVCB, {}, {host});
    assert.equal(msg.answer[0].type, T.SVCB);
    assert.equal(msg.additional.filter(r => r.type !== 41).length, 0);
  });

  test('a DDR query that is refused gets no addresses', async () => {
    const {msg} = await ask('_dns.resolver.arpa', T.SVCB, {qclass: 3});
    assert.equal(msg.rcode, 5);
    assert.equal(upstream.calls.length, 0);
  });

  test('DDR also answers for _dns.<this host>', async () => {
    const {msg} = await ask('_dns.dns.test', T.SVCB);
    assert.equal(msg.answer[0]?.type, T.SVCB);
  });

  test('names under resolver.arpa other than DDR get NODATA, not forwarded (RFC 9462)', async () => {
    for (const [name, type] of [
      ['_dns.resolver.arpa', T.A],
      ['resolver.arpa', T.A],
      ['x.resolver.arpa', T.SVCB],
    ] as const) {
      const {msg} = await ask(name, type);
      assert.equal(msg.rcode, 0, name);
      assert.equal(msg.answer.length, 0, name);
      assert.equal(msg.authority[0].type, T.SOA, name);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('a class other than IN is REFUSED and never cached as IN', async () => {
    const name = fresh();
    const {msg} = await ask(name, T.A, {qclass: 3});
    assert.equal(msg.rcode, 5);
    assert.equal(upstream.calls.length, 0);
    await ask(name, T.A);
    assert.equal(upstream.calls.length, 1);
    assert.equal(upstream.calls[0].query.question[0].cls, 1);
  });

  test('an invalid OPT record gets FORMERR and is not forwarded', async () => {
    const base = Uint8Array.from(makeQuery(fresh(), T.A));
    base[base.length - 1] = 50; // RDLEN past the end
    const result = await resolve(parseQuestion(base), plainOptions());
    assert.equal(parseMsg(result.body).rcode, 1);
    assert.equal(upstream.calls.length, 0);
  });

  test('QTYPEs 0, OPT, TKEY and TSIG get FORMERR', async () => {
    for (const type of [0, 41, 249, 250]) {
      assert.equal((await ask(fresh(), type)).msg.rcode, 1, `type ${type}`);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('zone transfers and MAILB/MAILA get NOTIMP', async () => {
    for (const type of [251, 252, 253, 254]) {
      assert.equal((await ask(fresh(), type)).msg.rcode, 4, `type ${type}`);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('a non-QUERY opcode gets NOTIMP, with the opcode echoed', async () => {
    const {msg} = await ask(fresh(), T.A, {opcode: 4});
    assert.equal(msg.rcode, 4);
    assert.equal(msg.opcode, 4);
    assert.equal(upstream.calls.length, 0);
  });

  test('EDNS version above 0 gets BADVERS (RFC 6891 6.1.3)', async () => {
    const {msg} = await ask(fresh(), T.A, {ednsVersion: 1});
    assert.equal(msg.rcode, 16);
    assert.equal(msg.opt?.version, 0);
    assert.equal(upstream.calls.length, 0);
  });

  test('localhost names resolve to loopback (RFC 6761 6.3)', async () => {
    for (const name of ['localhost', 'app.localhost', 'a.b.localhost']) {
      const a = (await ask(name, T.A)).msg;
      assert.deepEqual([...a.answer[0].rdata], [127, 0, 0, 1], name);
      const aaaa = (await ask(name, T.AAAA)).msg;
      assert.deepEqual(
        [...aaaa.answer[0].rdata],
        [...Array(15).fill(0), 1],
        name
      );
    }
    const txt = (await ask('localhost', T.TXT)).msg;
    assert.equal(txt.rcode, 0);
    assert.equal(txt.answer.length, 0, 'no data of that type');
    assert.equal(txt.authority[0].type, T.SOA);
    assert.equal(upstream.calls.length, 0);
  });

  test('"localhost" inside a longer label is not special', async () => {
    await ask('notlocalhost.example.com', T.A);
    assert.equal(upstream.calls.length, 1);
  });

  test('private and undelegated names get NXDOMAIN with a SOA (RFC 2308)', async () => {
    for (const name of [
      'printer.lan',
      '1.0.168.192.in-addr.arpa',
      'nas.home.arpa',
    ]) {
      const {msg} = await ask(name, T.A);
      assert.equal(msg.rcode, 3, name);
      assert.equal(msg.authority[0]?.type, T.SOA, name);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('ANY gets a minimal HINFO answer (RFC 8482)', async () => {
    const {msg} = await ask(fresh(), T.ANY);
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer.length, 1);
    assert.equal(msg.answer[0].type, T.HINFO);
    assert.equal(
      Buffer.from(msg.answer[0].rdata.subarray(1, 8)).toString(),
      'RFC8482'
    );
    assert.equal(upstream.calls.length, 0);
  });

  test('local answers carry an OPT record only for clients that sent one', async () => {
    assert.ok((await ask('localhost', T.A)).msg.opt);
    assert.equal(
      (await ask('localhost', T.A, {edns: false})).msg.opt,
      undefined
    );
  });

  test('local answers copy RD and DO', async () => {
    const {msg} = await ask('localhost', T.A, {rd: false, do: true});
    assert.equal(msg.rd, false);
    assert.equal(msg.opt?.do, true);
  });
});

describe('forwarding to the upstream', () => {
  test('sends a POST of a DNS query and returns the answer for this client', async () => {
    const name = fresh();
    const {msg} = await ask(name, T.A, {id: 999});
    assert.equal(upstream.calls.length, 1);
    const call = upstream.calls[0];
    assert.equal(call.query.question[0].name, `${name}.`);
    assert.equal(call.query.question[0].type, T.A);
    assert.equal(call.query.rd, true);
    assert.equal(msg.id, 999);
    assert.deepEqual([...msg.answer[0].rdata], ip4('198.51.100.7'));
  });

  test('keeps the case of the question (0x20 encoding)', async () => {
    const name = fresh('MiXeD');
    const {msg} = await ask(name, T.A);
    assert.equal(msg.question[0].name, `${name}.`);
    assert.equal(upstream.calls[0].query.question[0].name, `${name}.`);
  });

  test('passes AAAA, PTR and HTTPS through (not blocked by default)', async () => {
    for (const type of [T.AAAA, T.PTR, T.HTTPS]) {
      const name = fresh();
      await ask(name, type);
      assert.ok(
        upstream.calls.some(
          c =>
            c.query.question[0].name === `${name}.` &&
            c.query.question[0].type === type
        ),
        `type ${type}`
      );
    }
  });

  test('the DO bit goes upstream, and RRSIGs come back (RFC 4035)', async () => {
    const name = fresh();
    useUpstream(q =>
      makeResponse({
        qname: name,
        qtype: T.A,
        ad: q.opt?.do,
        answer: [
          {type: T.A, ttl: 300, rdata: ip4('1.1.1.1')},
          ...(q.opt?.do
            ? [{type: T.RRSIG, ttl: 300, rdata: [0, 1, 2, 3]}]
            : []),
        ],
        opt: {do: q.opt?.do},
      })
    );
    const plain = await ask(name, T.A, {do: false});
    assert.equal(upstream.calls[0].query.opt?.do, false);
    assert.equal(plain.msg.answer.length, 1);

    const signed = await ask(name, T.A, {do: true});
    assert.equal(upstream.calls[1].query.opt?.do, true);
    assert.deepEqual(
      signed.msg.answer.map(r => r.type),
      [T.A, T.RRSIG]
    );
    assert.equal(signed.msg.ad, true);
    assert.equal(signed.msg.opt?.do, true);
  });

  test('CD goes upstream (RFC 4035 3.2.2)', async () => {
    await ask(fresh(), T.A, {cd: true});
    assert.equal(upstream.calls[0].query.cd, true);
  });

  test('AD without DO goes upstream (RFC 6840 5.7)', async () => {
    await ask(fresh(), T.A, {ad: true});
    assert.equal(upstream.calls[0].query.ad, true);
    await ask(fresh(), T.A);
    assert.equal(upstream.calls[1].query.ad, false);
  });

  test('answers for different DNSSEC flags are cached apart', async () => {
    const name = fresh();
    await ask(name, T.A);
    await ask(name, T.A, {do: true});
    await ask(name, T.A, {cd: true});
    await ask(name, T.A, {ad: true});
    assert.equal(upstream.calls.length, 4);
    await ask(name, T.A, {do: true});
    assert.equal(upstream.calls.length, 4, 'the same flags hit the cache');
  });

  test('a repeated question is answered from the cache', async () => {
    const name = fresh();
    const first = await ask(name, T.A);
    const second = await ask(name, T.A, {id: 7});
    assert.equal(upstream.calls.length, 1);
    assert.equal(first.result.hit, undefined);
    assert.equal(second.result.hit, true);
    assert.equal(second.msg.id, 7);
  });

  test('concurrent identical questions share one upstream call', async () => {
    const name = fresh();
    useUpstream(async q => {
      await new Promise(resolve => setTimeout(resolve, 30));
      return answerA(q);
    });
    const results = await Promise.all(
      [1, 2, 3, 4].map(id => ask(name, T.A, {id}))
    );
    assert.equal(upstream.calls.length, 1);
    assert.deepEqual(
      results.map(r => r.msg.id),
      [1, 2, 3, 4]
    );
  });

  test('SERVFAIL from the upstream is returned but not cached', async () => {
    const name = fresh();
    useUpstream(q =>
      makeResponse({qname: name, qtype: T.A, rcode: 2, opt: {do: q.opt?.do}})
    );
    assert.equal((await ask(name, T.A)).msg.rcode, 2);
    await ask(name, T.A);
    assert.equal(upstream.calls.length, 2);
  });

  test('NXDOMAIN is cached, with its SOA and a counting-down TTL', async () => {
    const name = fresh();
    useUpstream(q =>
      makeResponse({
        qname: name,
        qtype: T.A,
        rcode: 3,
        authority: [
          {name: 'example.com', type: T.SOA, ttl: 900, rdata: soaRdata(900)},
        ],
        opt: {do: q.opt?.do},
      })
    );
    await ask(name, T.A);
    const second = await ask(name, T.A);
    assert.equal(upstream.calls.length, 1);
    assert.equal(second.msg.rcode, 3);
    assert.equal(second.msg.authority[0].type, T.SOA);
    assert.ok(second.msg.authority[0].ttl <= 900);
  });

  test('a failing upstream is an error for the caller (the handler makes SERVFAIL)', async () => {
    useUpstream(() => {
      throw new Error('network down');
    });
    await assert.rejects(ask(fresh(), T.A));
  });

  test('an upstream HTTP error is an error too', async () => {
    const original = globalThis.fetch;
    upstream.restore();
    globalThis.fetch = (async () =>
      new Response('no', {status: 502})) as typeof fetch;
    try {
      await assert.rejects(ask(fresh(), T.A));
    } finally {
      globalThis.fetch = original;
    }
  });

  test('a second connection is tried when the first is slow (hedging)', async () => {
    const name = fresh();
    let calls = 0;
    useUpstream(async q => {
      if (calls++ === 0) {
        await new Promise(resolve => setTimeout(resolve, 600));
      }
      return answerA(q);
    });
    const started = Date.now();
    const {msg} = await ask(name, T.A);
    assert.ok(
      Date.now() - started < 450,
      'did not wait for the slow connection'
    );
    assert.equal(msg.answer.length, 1);
    assert.equal(upstream.calls.length, 2);
  });
});

describe('redirects (config.ts REDIRECTS)', () => {
  /** An upstream that gives voz.vn its own address and medium.com another. */
  function redirectUpstream() {
    return useUpstream(q => {
      const {name, type} = q.question[0];
      const address = name === 'voz.vn.' ? '203.0.113.50' : '192.0.2.1';
      return makeResponse({
        qname: name,
        qtype: type,
        answer:
          type === T.A ? [{type: T.A, ttl: 120, rdata: ip4(address)}] : [],
      });
    });
  }

  test('medium.com gets the addresses of voz.vn, under its own name', async () => {
    redirectUpstream();
    const {msg} = await ask('medium.com', T.A);
    assert.equal(msg.question[0].name, 'medium.com.');
    assert.equal(msg.answer.length, 1);
    assert.equal(msg.answer[0].name, 'medium.com.');
    assert.deepEqual([...msg.answer[0].rdata], ip4('203.0.113.50'));
    assert.equal(upstream.calls.length, 1);
    assert.equal(upstream.calls[0].query.question[0].name, 'voz.vn.');
  });

  test('the redirect is cached like any answer', async () => {
    redirectUpstream();
    await ask('medium.com', T.A);
    await ask('medium.com', T.A);
    assert.equal(upstream.calls.length, 1);
  });

  test('HTTPS and SVCB queries get NODATA, so the hints cannot reveal the real addresses', async () => {
    redirectUpstream();
    for (const type of [T.HTTPS, T.SVCB]) {
      const {msg} = await ask('medium.com', type);
      assert.equal(msg.rcode, 0);
      assert.equal(msg.answer.length, 0);
      assert.equal(msg.authority[0].type, T.SOA);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('other types and other names are not redirected', async () => {
    redirectUpstream();
    await ask('medium.com', T.TXT);
    await ask('www.medium.com', T.A);
    const names = upstream.calls.map(c => c.query.question[0].name);
    assert.deepEqual(names, ['medium.com.', 'www.medium.com.']);
  });

  test('AAAA is redirected too', async () => {
    redirectUpstream();
    await ask('medium.com', T.AAAA);
    assert.equal(upstream.calls[0].query.question[0].name, 'voz.vn.');
    assert.equal(upstream.calls[0].query.question[0].type, T.AAAA);
  });
});

describe('EDNS in the answer', () => {
  test('a client with EDNS gets an OPT record', async () => {
    assert.ok((await ask(fresh(), T.A)).msg.opt);
  });

  test('a client without EDNS gets none, though the upstream always sends one (RFC 6891 7)', async () => {
    const {msg} = await ask(fresh(), T.A, {edns: false});
    assert.equal(msg.optCount, 0);
    assert.equal(msg.answer.length, 1);
    assert.equal(
      upstream.calls[0].query.optCount,
      1,
      'the query to the upstream has one'
    );
  });

  test('RD is copied from the client, not from the upstream', async () => {
    assert.equal((await ask(fresh(), T.A, {rd: false})).msg.rd, false);
    assert.equal((await ask(fresh(), T.A, {rd: true})).msg.rd, true);
  });

  test('a padded query gets a response padded to a multiple of 468 bytes (RFC 8467)', async () => {
    const padded = await ask(fresh(), T.A, {padding: 30});
    assert.equal(padded.result.body.length % 468, 0);
    assert.ok(padded.msg.opt!.options.some(o => o.code === 12));
    const plain = await ask(fresh(), T.A);
    assert.notEqual(plain.result.body.length % 468, 0);
    assert.ok(!plain.msg.opt!.options.some(o => o.code === 12));
  });

  test('padding applies to local answers as well', async () => {
    const {result} = await ask('localhost', T.A, {padding: 1});
    assert.equal(result.body.length % 468, 0);
  });
});

describe('client subnet (RFC 7871)', () => {
  const ecsOf = (call: {query: Msg}) =>
    call.query.opt?.options.find(o => o.code === 8)?.data;

  test('the connecting IP is sent as /24 (IPv4)', async () => {
    await ask(fresh(), T.A, {}, {ip: '203.0.113.77'});
    assert.deepEqual(
      [...ecsOf(upstream.calls[0])!],
      [0, 1, 24, 0, 203, 0, 113]
    );
  });

  test('and as /48 for IPv6', async () => {
    await ask(fresh(), T.A, {}, {ip: '2001:db8:1:2::9'});
    assert.deepEqual(
      [...ecsOf(upstream.calls[0])!],
      [0, 2, 48, 0, 0x20, 1, 0xd, 0xb8, 0, 1]
    );
  });

  test('no IP, no subnet', async () => {
    await ask(fresh(), T.A);
    assert.equal(ecsOf(upstream.calls[0]), undefined);
  });

  test('a subnet in the options overrides the IP; null sends none', async () => {
    const option = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];
    await ask(fresh(), T.A, {}, {ip: '203.0.113.77', ecs: option});
    assert.deepEqual(
      [...ecsOf(upstream.calls[0])!],
      [0, 1, 24, 0, 198, 51, 100]
    );
    await ask(fresh(), T.A, {}, {ip: '203.0.113.77', ecs: null});
    assert.equal(ecsOf(upstream.calls[1]), undefined);
  });

  test('answers are cached per subnet', async () => {
    const name = fresh();
    await ask(name, T.A, {}, {ip: '203.0.113.1'});
    await ask(name, T.A, {}, {ip: '203.0.113.200'});
    assert.equal(upstream.calls.length, 1, 'same /24');
    await ask(name, T.A, {}, {ip: '198.51.100.1'});
    assert.equal(upstream.calls.length, 2, 'another /24');
  });

  test('an ECS option from the upstream is removed for a client that sent none (RFC 7871 7.2.2)', async () => {
    useUpstream(q =>
      makeResponse({
        qname: q.question[0].name,
        qtype: T.A,
        opt: {options: [{code: 8, data: [0, 1, 24, 24, 203, 0, 113]}]},
      })
    );
    const {msg} = await ask(fresh(), T.A, {}, {ip: '203.0.113.5'});
    assert.ok(msg.opt);
    assert.ok(!msg.opt!.options.some(o => o.code === 8));
  });

  test('but is kept when the client chose a subnet itself', async () => {
    useUpstream(q =>
      makeResponse({
        qname: q.question[0].name,
        qtype: T.A,
        opt: {options: [{code: 8, data: [0, 1, 24, 24, 198, 51, 100]}]},
      })
    );
    const option = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];
    const {msg} = await ask(fresh(), T.A, {}, {ecs: option});
    assert.ok(msg.opt!.options.some(o => o.code === 8));
  });
});

describe('serve-stale (RFC 8767)', () => {
  test('an expired answer is returned at once with a short TTL and EDE 3, and renewed', async () => {
    mock.timers.enable({apis: ['Date'], now: 1_800_000_000_000});
    const name = fresh();
    const first = await ask(name, T.A);
    assert.ok(first.msg.answer[0].ttl <= 300);
    mock.timers.tick(400_000);

    const stale = await ask(name, T.A);
    assert.equal(stale.result.stale, true);
    assert.equal(stale.msg.answer[0].ttl, 30);
    const ede = stale.msg.opt!.options.find(o => o.code === 15)!;
    assert.deepEqual([...ede.data.subarray(0, 2)], [0, 3], 'Stale Answer');

    await new Promise(resolve => setImmediate(resolve));
    assert.equal(upstream.calls.length, 2, 'renewed in the background');
    const renewed = await ask(name, T.A);
    assert.equal(renewed.result.stale, false);
    assert.equal(renewed.msg.opt!.options.length, 0);
  });

  test('a stale NXDOMAIN carries EDE 19, not 3 (RFC 8914)', async () => {
    mock.timers.enable({apis: ['Date'], now: 1_800_000_000_000});
    const name = fresh();
    useUpstream(q =>
      makeResponse({
        qname: name,
        qtype: T.A,
        rcode: 3,
        authority: [
          {name: 'example.com', type: T.SOA, ttl: 300, rdata: soaRdata(300)},
        ],
        opt: {do: q.opt?.do},
      })
    );
    await ask(name, T.A);
    mock.timers.tick(400_000);
    const stale = await ask(name, T.A);
    assert.equal(stale.result.stale, true);
    assert.equal(stale.msg.rcode, 3);
    const ede = stale.msg.opt!.options.find(o => o.code === 15)!;
    assert.deepEqual([...ede.data.subarray(0, 2)], [0, 19]);
  });

  test('a client without EDNS gets the stale answer without the option', async () => {
    mock.timers.enable({apis: ['Date'], now: 1_800_000_000_000});
    const name = fresh();
    await ask(name, T.A);
    mock.timers.tick(400_000);
    const stale = await ask(name, T.A, {edns: false});
    assert.equal(stale.msg.optCount, 0);
    assert.equal(stale.msg.answer[0].ttl, 30);
  });
});

describe('best-effort ECH for Cloudflare-hosted names', () => {
  const ECH_CONFIG = [0, 0x45, 0xfe, 0x0d, 1, 2, 3, 4];

  /** What the build writes to cloudflare-ips.json, served as an asset. */
  const assets = (status = 200, v4 = ['104.16.0.0/13', '172.64.0.0/13']) => ({
    fetch: async () =>
      new Response(JSON.stringify({v4}), {status}) as unknown as Response,
  });
  const withRanges = (extra: Record<string, unknown> = {}) => ({
    env: {ASSETS: assets()},
    ...extra,
  });

  /** An upstream where `cf*` names sit on Cloudflare and have no HTTPS record. */
  function cloudflareUpstream(
    overrides: Partial<Record<string, number[]>> = {}
  ) {
    return useUpstream(q => {
      const {name, type} = q.question[0];
      const base = {qname: name, qtype: type, opt: {do: q.opt?.do}};
      if (type === T.A) {
        const address = name.startsWith('cf') ? '104.16.0.5' : '192.0.2.5';
        return makeResponse({
          ...base,
          answer: [{type: T.A, ttl: 60, rdata: ip4(address)}],
        });
      }
      if (type === T.HTTPS && name === `${ECH_FRONT_DOMAIN}.`) {
        const rdata = [0, 1, 0, 0, 5, 0, ECH_CONFIG.length, ...ECH_CONFIG];
        return makeResponse({
          ...base,
          answer: [{type: T.HTTPS, ttl: 300, rdata}],
        });
      }
      if (type === T.HTTPS && overrides[name]) {
        return makeResponse({
          ...base,
          answer: [{type: T.HTTPS, ttl: 300, rdata: overrides[name]!}],
        });
      }
      return makeResponse(base);
    });
  }

  /** The parameter keys of an HTTPS record's rdata, in order. */
  const paramKeys = (rdata: Uint8Array) => {
    const keys: number[] = [];
    for (let i = 3; i + 4 <= rdata.length;) {
      keys.push((rdata[i] << 8) | rdata[i + 1]);
      i += 4 + ((rdata[i + 2] << 8) | rdata[i + 3]);
    }
    return keys;
  };

  test('adds the shared ECH config to an empty HTTPS answer', async () => {
    cloudflareUpstream();
    const {msg} = await ask('cf-site.example.com', T.HTTPS, {}, withRanges());
    assert.equal(msg.answer.length, 1);
    const record = msg.answer[0];
    assert.equal(record.type, T.HTTPS);
    assert.deepEqual(
      [...record.rdata.subarray(0, 3)],
      [0, 1, 0],
      'priority 1, target "."'
    );
    assert.deepEqual(
      paramKeys(record.rdata),
      [1, 5],
      'alpn, ech: keys in increasing order'
    );
    assert.ok(Buffer.from(record.rdata).includes(Buffer.from(ECH_CONFIG)));
  });

  test('adds ech to the upstream record and keeps the rest, in key order', async () => {
    const v6 = Array.from({length: 16}, (_, i) => i);
    // alpn = "h3","h2"; ipv4hint = 104.16.0.5; ipv6hint = v6.
    const alpn = [2, 0x68, 0x33, 2, 0x68, 0x32];
    const rdata = [
      ...[0, 1, 0],
      ...[0, 1, 0, alpn.length, ...alpn],
      ...[0, 4, 0, 4, 104, 16, 0, 5],
      ...[0, 6, 0, 16, ...v6],
    ];
    cloudflareUpstream({'cf-full.example.com.': rdata});
    const {msg} = await ask('cf-full.example.com', T.HTTPS, {}, withRanges());
    assert.equal(msg.answer.length, 1);
    const out = msg.answer[0].rdata;
    assert.deepEqual(paramKeys(out), [1, 4, 5, 6]);
    assert.equal(msg.answer[0].ttl, 300, 'the upstream TTL is kept');
    const bytes = Buffer.from(out);
    assert.ok(bytes.includes(Buffer.from(alpn)), 'alpn kept');
    assert.ok(bytes.includes(Buffer.from([104, 16, 0, 5])), 'ipv4hint kept');
    assert.ok(bytes.includes(Buffer.from(v6)), 'ipv6hint kept');
    assert.ok(bytes.includes(Buffer.from(ECH_CONFIG)), 'ech added');
  });

  test('a record with only alpn gets ech after it', async () => {
    cloudflareUpstream({
      'cf-alpn.example.com.': [0, 1, 0, 0, 1, 0, 3, 2, 0x68, 0x32],
    });
    const {msg} = await ask('cf-alpn.example.com', T.HTTPS, {}, withRanges());
    assert.deepEqual(paramKeys(msg.answer[0].rdata), [1, 5]);
  });

  test('an AliasMode record is left alone', async () => {
    const alias = [0, 0, 3, 0x61, 0x6c, 0x74, 0]; // priority 0, target "alt"
    cloudflareUpstream({'cf-alias.example.com.': alias});
    const {msg} = await ask('cf-alias.example.com', T.HTTPS, {}, withRanges());
    assert.equal(msg.answer.length, 1);
    assert.equal(msg.answer[0].rdata[1], 0);
    assert.ok(
      !Buffer.from(msg.answer[0].rdata).includes(Buffer.from(ECH_CONFIG))
    );
  });

  test('leaves a name that is not on Cloudflare alone', async () => {
    cloudflareUpstream();
    const {msg} = await ask(
      'other-site.example.com',
      T.HTTPS,
      {},
      withRanges()
    );
    assert.equal(msg.answer.length, 0);
  });

  test('keeps a record that already has ech', async () => {
    const own = [0, 1, 0, 0, 5, 0, 2, 9, 9];
    cloudflareUpstream({'cf-own.example.com.': own});
    const {msg} = await ask('cf-own.example.com', T.HTTPS, {}, withRanges());
    assert.deepEqual([...msg.answer[0].rdata], own);
  });

  test('is not done for a client that asks for DNSSEC records (the record would be unsigned)', async () => {
    cloudflareUpstream();
    const {msg} = await ask(
      'cf-signed.example.com',
      T.HTTPS,
      {do: true},
      withRanges()
    );
    assert.equal(msg.answer.length, 0);
    assert.equal(
      upstream.calls.filter(c => c.query.question[0].type === T.A).length,
      0,
      'no probe either'
    );
  });

  test('other query types never trigger it', async () => {
    cloudflareUpstream();
    await ask('cf-a.example.com', T.A, {}, withRanges());
    assert.equal(
      upstream.calls.filter(c => c.query.question[0].type === T.HTTPS).length,
      0
    );
  });

  test('without the ranges (no asset, bad status or bad content) the answer stays as it is', async () => {
    for (const env of [
      {},
      {ASSETS: assets(404)},
      {ASSETS: assets(200, ['not a range'])},
      {ASSETS: assets(200, [])},
    ]) {
      resetState();
      cloudflareUpstream();
      const {msg} = await ask('cf-none.example.com', T.HTTPS, {}, {env});
      assert.equal(msg.answer.length, 0);
      upstream.restore();
    }
  });

  test('the ranges are loaded once, and a failed load is not repeated at once', async () => {
    cloudflareUpstream();
    let loads = 0;
    const env = {
      ASSETS: {
        fetch: async (url: string) => {
          if (!String(url).includes('cloudflare-ips')) {
            return new Response('', {status: 404}) as unknown as Response;
          }
          loads++;
          return new Response(
            JSON.stringify({v4: ['104.16.0.0/13']})
          ) as unknown as Response;
        },
      },
    };
    await ask('cf-one.example.com', T.HTTPS, {}, {env});
    await ask('cf-two.example.com', T.HTTPS, {}, {env});
    assert.equal(loads, 1);
    resetState();
    cloudflareUpstream();
    let failed = 0;
    const broken = {
      ASSETS: {
        fetch: async (url: string) => {
          if (!String(url).includes('cloudflare-ips')) {
            return new Response('', {status: 404}) as unknown as Response;
          }
          failed++;
          throw new Error('down');
        },
      },
    };
    await ask('cf-three.example.com', T.HTTPS, {}, {env: broken});
    await ask('cf-four.example.com', T.HTTPS, {}, {env: broken});
    assert.equal(failed, 1);
  });
});

describe('resolver information (RFC 9606)', () => {
  test('RESINFO for the gateway host lists the EDE codes and an info page', async () => {
    const {msg} = await ask('dns.test', T.RESINFO);
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer[0].type, T.RESINFO);
    const strings: string[] = [];
    const rdata = msg.answer[0].rdata;
    for (let i = 0; i < rdata.length; i += 1 + rdata[i]) {
      strings.push(
        Buffer.from(rdata.subarray(i + 1, i + 1 + rdata[i])).toString()
      );
    }
    assert.deepEqual(strings, [
      'exterr=3,15,19,23',
      'infourl=https://dns.test/',
    ]);
    assert.equal(upstream.calls.length, 0);
  });

  test('RESINFO for another name is forwarded', async () => {
    await ask(fresh(), T.RESINFO);
    assert.equal(upstream.calls.length, 1);
  });
});

describe('DNS64 (RFC 6147)', () => {
  const v4 = ip4('93.184.216.34');
  const upstreamWith = (aaaa: boolean, address = v4, rcode = 0) =>
    useUpstream(q => {
      const {name, type} = q.question[0];
      const answer =
        type === T.A
          ? [{type: T.A, ttl: 120, rdata: address}]
          : type === T.AAAA && aaaa
            ? [{type: T.AAAA, ttl: 300, rdata: ip6('2001:db8::1')}]
            : [];
      return makeResponse({
        qname: name,
        qtype: type,
        rcode,
        answer,
        authority: answer.length
          ? []
          : [{type: T.SOA, ttl: 900, rdata: soaRdata(60)}],
        opt: {do: q.opt?.do},
      });
    });

  test('AAAA is made from the A record when there is none', async () => {
    upstreamWith(false);
    const {msg} = await ask(fresh(), T.AAAA, {}, {dns64: true});
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer.length, 1);
    assert.equal(msg.answer[0].type, T.AAAA);
    assert.deepEqual([...msg.answer[0].rdata], ip6('64:ff9b::5db8:d822'));
    assert.equal(
      msg.answer[0].ttl,
      60,
      'smaller of the A TTL and the SOA minimum'
    );
  });

  test('a real AAAA is left alone, and so is everything when DNS64 is off', async () => {
    upstreamWith(true);
    let {msg} = await ask(fresh(), T.AAAA, {}, {dns64: true});
    assert.deepEqual([...msg.answer[0].rdata], ip6('2001:db8::1'));
    upstreamWith(false);
    ({msg} = await ask(fresh(), T.AAAA));
    assert.equal(msg.answer.length, 0);
  });

  test('not for private addresses, nor for DO without CD', async () => {
    upstreamWith(false, ip4('10.1.2.3'));
    let {msg} = await ask(fresh(), T.AAAA, {}, {dns64: true});
    assert.equal(msg.answer.length, 0);
    upstreamWith(false);
    ({msg} = await ask(fresh(), T.AAAA, {do: true}, {dns64: true}));
    assert.equal(msg.answer.length, 0);
    ({msg} = await ask(fresh(), T.AAAA, {do: true, cd: true}, {dns64: true}));
    assert.equal(msg.answer.length, 1);
  });

  test('a failing A lookup leaves the AAAA answer as it was', async () => {
    useUpstream(q => {
      if (q.question[0].type === T.A) {
        throw new Error('down');
      }
      return makeResponse({qname: q.question[0].name, qtype: T.AAAA});
    });
    const {msg} = await ask(fresh(), T.AAAA, {}, {dns64: true});
    assert.equal(msg.rcode, 0);
    assert.equal(msg.answer.length, 0);
  });
});

describe('DNS Cookies (RFC 7873)', () => {
  const client = [1, 2, 3, 4, 5, 6, 7, 8];
  const env = {COOKIE_SECRET: 's3cret'};

  test('the client cookie comes back with a server cookie tied to the client', async () => {
    const get = async (ip: string) =>
      (
        await ask(fresh(), T.A, {cookie: client}, {env, ip})
      ).msg.opt!.options.find(o => o.code === 10)!.data;
    const one = await get('192.0.2.1');
    assert.equal(one.length, 16);
    assert.deepEqual([...one.subarray(0, 8)], client);
    assert.deepEqual([...(await get('192.0.2.1'))], [...one]);
    assert.notDeepEqual([...(await get('192.0.2.2'))], [...one]);
  });

  test('no secret, no cookie in the query or no EDNS: nothing is added', async () => {
    const cookieOf = (m: Msg) => m.opt?.options.find(o => o.code === 10);
    assert.equal(
      cookieOf((await ask(fresh(), T.A, {cookie: client})).msg),
      undefined
    );
    assert.equal(cookieOf((await ask(fresh(), T.A, {}, {env})).msg), undefined);
  });

  test('a cookie of a wrong length is FORMERR', async () => {
    const {msg} = await ask(fresh(), T.A, {cookie: [1, 2, 3]}, {env});
    assert.equal(msg.rcode, 1);
    assert.equal(upstream.calls.length, 0);
  });
});

describe('DNS64 memo', () => {
  test('the A lookup is not repeated for the same name', async () => {
    useUpstream(q => {
      const {name, type} = q.question[0];
      return makeResponse({
        qname: name,
        qtype: type,
        answer:
          type === T.A
            ? [{type: T.A, ttl: 300, rdata: ip4('93.184.216.34')}]
            : [],
        authority:
          type === T.A ? [] : [{type: T.SOA, ttl: 900, rdata: soaRdata(300)}],
      });
    });
    const name = fresh();
    const first = await ask(name, T.AAAA, {}, {dns64: true});
    const calls = upstream.calls.length;
    const second = await ask(name, T.AAAA, {}, {dns64: true});
    assert.equal(upstream.calls.length, calls, 'nothing new asked');
    assert.deepEqual(
      [...second.msg.answer[0].rdata],
      [...first.msg.answer[0].rdata]
    );
    assert.ok(second.msg.answer[0].ttl <= first.msg.answer[0].ttl);
  });
});

describe('DNS64 well-known name and PTR', () => {
  test('ipv4only.arpa AAAA is answered locally, only with dns64', async () => {
    const {msg} = await ask('ipv4only.arpa', T.AAAA, {}, {dns64: true});
    assert.equal(msg.answer.length, 2);
    assert.deepEqual([...msg.answer[0].rdata], ip6('64:ff9b::c000:aa'));
    assert.equal(upstream.calls.length, 0);
    await ask('ipv4only.arpa', T.AAAA);
    assert.equal(upstream.calls.length, 1, 'forwarded without dns64');
  });

  test('PTR of an address in the prefix follows the IPv4 reverse name', async () => {
    useUpstream(q => {
      const {name, type} = q.question[0];
      if (name === '34.216.184.93.in-addr.arpa.') {
        return makeResponse({
          qname: name,
          qtype: type,
          answer: [{type: T.PTR, ttl: 300, rdata: [3, 0x61, 0x62, 0x63, 0]}],
        });
      }
      return makeResponse({
        qname: name,
        qtype: type,
        rcode: 3,
        authority: [{type: T.SOA, ttl: 900, rdata: soaRdata(900)}],
      });
    });
    const name =
      '2.2.8.d.8.b.d.5' + '.0'.repeat(16) + '.b.9.f.f.4.6.0.0.ip6.arpa';
    const plain = await ask(name, T.PTR);
    assert.equal(plain.msg.rcode, 3, 'NXDOMAIN without dns64');
    const {msg} = await ask(name, T.PTR, {}, {dns64: true});
    assert.equal(msg.rcode, 0);
    assert.deepEqual(
      msg.answer.map(r => r.type),
      [T.CNAME, T.PTR]
    );
    assert.equal(msg.answer[1].name, '34.216.184.93.in-addr.arpa.');
  });
});
