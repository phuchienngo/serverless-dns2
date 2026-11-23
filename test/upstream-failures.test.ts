/**
 * @fileoverview What a client gets when the upstream resolver misbehaves: HTTP
 * errors, dropped connections, bodies that are not DNS messages, every rcode,
 * a slow first try, and an expired cache entry with the upstream down. The
 * table is the contract; the client always gets a DNS answer, never an HTTP
 * error.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {UPSTREAM} from '../src/config.js';
import {setEcsEnabled} from '../src/ecs.js';
import {handle, handleJson} from '../src/handlers.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  parseMsg,
  resetState,
  testClock,
  type Msg,
} from './helpers.js';

const RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
};
const EDE_STALE_ANSWER = 3;
const EDE_NETWORK_ERROR = 23;

/** What the stand-in upstream does with its nth request. */
type Behavior = (
  index: number,
  query: Msg,
  raw: Uint8Array,
  signal: AbortSignal
) => Response | Promise<Response>;

const answer = (q: Msg, spec: Record<string, unknown> = {}) =>
  makeResponse({
    qname: q.question[0].name,
    qtype: q.question[0].type,
    answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}],
    opt: {do: q.opt?.do},
    ...spec,
  });
const withRcode =
  (rcode: number): Behavior =>
  (_, q) =>
    new Response(answer(q, {answer: [], rcode}));
/** An error status that carries a good answer, so only the status is wrong. */
const httpError =
  (status: number): Behavior =>
  (_, q) =>
    new Response(answer(q), {status});
const ok: Behavior = (_, q) => new Response(answer(q));

let calls = 0;
let original: typeof fetch;
function useUpstream(behavior: Behavior): void {
  calls = 0;
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    if (String(input) !== UPSTREAM) {
      return original(input as string, init);
    }
    const raw = new Uint8Array(init!.body as Uint8Array);
    return behavior(calls++, parseMsg(raw), raw, init!.signal!);
  }) as typeof fetch;
}
beforeEach(() => {
  original = globalThis.fetch;
  resetState();
  setEcsEnabled(false); // One query per request: the counts are plain.
});
afterEach(() => {
  globalThis.fetch = original;
  testClock.reset();
});

let n = 0;
const fresh = () => `f${n++}.failures.example.com`;
const ctx = (ip: string | null = null) => ({env: {}, ip}) as never;

const post = (body: Uint8Array, ip: string | null = null) =>
  handle(
    new Request('https://dns.test/dns-query', {
      method: 'POST',
      headers: {'content-type': 'application/dns-message'},
      body: body as never,
    }),
    ctx(ip)
  );
async function ask(name: string, options = {}, ip: string | null = null) {
  const query = makeQuery(name, T.A, options);
  const res = await post(query, ip);
  const body = new Uint8Array(await res.arrayBuffer());
  return {res, query, body, msg: parseMsg(body)};
}
const edeCodes = (msg: Msg) =>
  (msg.opt?.options ?? [])
    .filter(o => o.code === 15)
    .map(o => (o.data[0] << 8) | o.data[1]);

interface Expected {
  rcode: number;
  /** Extended DNS Error carried (the client sent EDNS). */
  ede?: number;
  /** Whether a second identical query is answered without the upstream. */
  cached: boolean;
  tc?: boolean;
}

const hangs = (signal: AbortSignal) =>
  new Promise<Response>((_, reject) =>
    signal.addEventListener('abort', () => reject(new Error('aborted')))
  );
const servfail = {rcode: RCODE.SERVFAIL, ede: EDE_NETWORK_ERROR, cached: false};

const table: [string, Behavior, Expected][] = [
  // The upstream cannot be used: SERVFAIL with EDE 23, TTL kept short, not cached.
  ['HTTP 500', httpError(500), servfail],
  ['HTTP 502', httpError(502), servfail],
  ['HTTP 429', httpError(429), servfail],
  ['HTTP 404', httpError(404), servfail],
  [
    'the connection fails',
    () => {
      throw new TypeError('fetch failed');
    },
    servfail,
  ],
  ['an empty body', () => new Response(new Uint8Array(0)), servfail],
  [
    'a body shorter than a header',
    () => new Response(new Uint8Array(11)),
    servfail,
  ],
  [
    'a query echoed back (QR clear)',
    (_, __, raw) => new Response(raw),
    servfail,
  ],
  [
    'a header that counts records it does not hold',
    (_, q) => {
      const body = new Uint8Array(answer(q));
      body[7] = 9;
      return new Response(body);
    },
    servfail,
  ],

  [
    'an answer to another question',
    () =>
      new Response(
        makeResponse({
          qname: 'other.example.net',
          qtype: T.A,
          answer: [{type: T.A, ttl: 60, rdata: ip4('192.0.2.1')}],
        })
      ),
    servfail,
  ],
  [
    'an answer to the same name with another type',
    (_, q) =>
      new Response(
        makeResponse({qname: q.question[0].name, qtype: T.AAAA, answer: []})
      ),
    servfail,
  ],
  [
    'an answer to a question that is counted twice',
    (_, q) => {
      const body = new Uint8Array(answer(q));
      body[5] = 2;
      return new Response(body);
    },
    servfail,
  ],
  [
    'an answer with another id',
    (_, q) => {
      const body = new Uint8Array(answer(q));
      body[0] ^= 0xff;
      return new Response(body);
    },
    servfail,
  ],
  [
    'an answer with the name in other case is accepted',
    (_, q) =>
      new Response(answer(q, {qname: q.question[0].name.toUpperCase()})),
    {rcode: RCODE.NOERROR, cached: true},
  ],

  // The upstream answers: whatever its rcode, the client gets it. Only NOERROR
  // and NXDOMAIN are kept.
  ['NOERROR', ok, {rcode: RCODE.NOERROR, cached: true}],
  [
    'NXDOMAIN',
    withRcode(RCODE.NXDOMAIN),
    {rcode: RCODE.NXDOMAIN, cached: true},
  ],
  [
    'SERVFAIL',
    withRcode(RCODE.SERVFAIL),
    {rcode: RCODE.SERVFAIL, cached: false},
  ],
  ['REFUSED', withRcode(RCODE.REFUSED), {rcode: RCODE.REFUSED, cached: false}],
  ['NOTIMP', withRcode(RCODE.NOTIMP), {rcode: RCODE.NOTIMP, cached: false}],
  ['FORMERR', withRcode(RCODE.FORMERR), {rcode: RCODE.FORMERR, cached: false}],
  [
    'a truncated answer is passed on, not kept',
    (_, q) => {
      const body = new Uint8Array(answer(q));
      body[2] |= 2; // TC.
      return new Response(body);
    },
    {rcode: RCODE.NOERROR, cached: false, tc: true},
  ],
  [
    'the content type of the upstream is not checked',
    (_, q) => new Response(answer(q), {headers: {'content-type': 'text/html'}}),
    {rcode: RCODE.NOERROR, cached: true},
  ],

  // A slow or failing first try (hedging).
  [
    'the first try hangs, the second answers',
    (i, q, _, signal) => (i === 0 ? hangs(signal) : new Response(answer(q))),
    {rcode: RCODE.NOERROR, cached: true},
  ],
  [
    'the first try fails, the second answers',
    (i, q) =>
      i === 0 ? new Response('error', {status: 500}) : new Response(answer(q)),
    {rcode: RCODE.NOERROR, cached: true},
  ],
];

describe('the upstream resolver misbehaves', () => {
  for (const [description, behavior, e] of table) {
    test(description, async () => {
      useUpstream(behavior);
      const name = fresh();
      const first = await ask(name);
      assert.equal(first.res.status, 200, 'always a DNS answer');
      assert.equal(
        first.res.headers.get('content-type'),
        'application/dns-message'
      );
      assert.equal(first.msg.rcode, e.rcode, 'rcode');
      assert.deepEqual(
        edeCodes(first.msg),
        e.ede === undefined ? [] : [e.ede],
        'EDE'
      );
      assert.equal((first.body[2] & 2) !== 0, e.tc ?? false, 'TC');

      // The answer is the client's own: id, RD, question.
      assert.deepEqual(first.body.slice(0, 2), first.query.slice(0, 2), 'id');
      assert.equal(first.body[2] & 1, 1, 'RD');
      assert.equal(first.msg.question[0].name, `${name}.`, 'question');

      const before = calls;
      await ask(name);
      assert.equal(
        calls === before,
        e.cached,
        'a second query is served from the cache'
      );
    });
  }

  test('a failure is not remembered: the next query is answered once the upstream is back', async () => {
    const name = fresh();
    useUpstream(httpError(503));
    assert.equal((await ask(name)).msg.rcode, RCODE.SERVFAIL);
    useUpstream(ok);
    const next = await ask(name);
    assert.equal(next.msg.rcode, RCODE.NOERROR);
    assert.equal(next.msg.answer.length, 1);
  });

  test('a client without EDNS gets the failure without an OPT record', async () => {
    useUpstream(httpError(500));
    const {msg} = await ask(fresh(), {edns: false});
    assert.equal(msg.rcode, RCODE.SERVFAIL);
    assert.equal(msg.optCount, 0);
  });

  test('RD clear on the query is kept on the failure', async () => {
    useUpstream(httpError(500));
    const {body} = await ask(fresh(), {rd: false});
    assert.equal(body[2] & 1, 0);
  });

  test('the same failure over GET', async () => {
    useUpstream(httpError(500));
    const query = makeQuery(fresh(), T.A);
    const res = await handle(
      new Request(
        `https://dns.test/dns-query?dns=${Buffer.from(query).toString('base64url')}`
      ),
      ctx()
    );
    assert.equal(res.status, 200);
    assert.equal(
      parseMsg(new Uint8Array(await res.arrayBuffer())).rcode,
      RCODE.SERVFAIL
    );
  });
});

describe('the cache while the upstream is down', () => {
  test('a fresh answer is served without asking the upstream', async () => {
    const name = fresh();
    useUpstream(ok);
    await ask(name);
    useUpstream(httpError(500));
    const again = await ask(name);
    assert.equal(again.msg.rcode, RCODE.NOERROR);
    assert.equal(again.msg.answer.length, 1);
    assert.equal(calls, 0);
  });

  test('an expired answer is served stale with a short TTL and EDE 3, again and again', async () => {
    testClock.set(1_800_000_000_000);
    const name = fresh();
    useUpstream(ok);
    await ask(name);
    testClock.tick(400_000);
    useUpstream(httpError(500));
    for (let i = 0; i < 3; i++) {
      const stale = await ask(name);
      assert.equal(stale.msg.rcode, RCODE.NOERROR, 'not an error');
      assert.equal(stale.msg.answer[0].ttl, 30);
      assert.deepEqual(edeCodes(stale.msg), [EDE_STALE_ANSWER]);
      await new Promise(resolve => setImmediate(resolve)); // A failed refresh.
    }
  });

  test('past the stale period it is an error', async () => {
    testClock.set(1_800_000_000_000);
    const name = fresh();
    useUpstream(ok);
    await ask(name);
    testClock.tick(7 * 3600 * 1000);
    useUpstream(httpError(500));
    assert.equal((await ask(name)).msg.rcode, RCODE.SERVFAIL);
  });

  test('an answer that SERVFAIL replaced is not kept: stale is only of good answers', async () => {
    testClock.set(1_800_000_000_000);
    const name = fresh();
    useUpstream(ok);
    await ask(name);
    testClock.tick(400_000);
    useUpstream(withRcode(RCODE.SERVFAIL)); // The refresh gets SERVFAIL.
    await ask(name);
    await new Promise(resolve => setImmediate(resolve));
    useUpstream(httpError(500));
    const again = await ask(name);
    assert.equal(
      again.msg.rcode,
      RCODE.NOERROR,
      'the old good answer is still there'
    );
    assert.equal(again.msg.answer.length, 1);
  });
});

describe('with a client subnet (two upstream queries)', () => {
  beforeEach(() => setEcsEnabled(true));
  const IP = '203.0.113.5';
  /** The query carries a subnet with an address (not the prefix-0 one). */
  const hasSubnet = (raw: Uint8Array) => {
    const opt = parseMsg(raw).opt?.options.find(o => o.code === 8);
    return !!opt && opt.data[2] > 0;
  };
  const byQuery =
    (withSubnet: Behavior, withoutSubnet: Behavior): Behavior =>
    (i, q, raw, signal) =>
      (hasSubnet(raw) ? withSubnet : withoutSubnet)(i, q, raw, signal);

  test('both are sent, one with the subnet and one without', async () => {
    useUpstream(ok);
    await ask(fresh(), {}, IP);
    assert.equal(calls, 2);
  });

  test('REFUSED to the subnet query: the answer without it is used (RFC 7871 7.1.3)', async () => {
    useUpstream(byQuery(withRcode(RCODE.REFUSED), ok));
    const {msg} = await ask(fresh(), {}, IP);
    assert.equal(msg.rcode, RCODE.NOERROR);
    assert.equal(msg.answer.length, 1);
  });

  test('REFUSED to both: REFUSED', async () => {
    useUpstream(withRcode(RCODE.REFUSED));
    assert.equal((await ask(fresh(), {}, IP)).msg.rcode, RCODE.REFUSED);
  });

  test('another rcode to the subnet query is kept, not replaced by the other answer', async () => {
    useUpstream(byQuery(withRcode(RCODE.NXDOMAIN), ok));
    assert.equal((await ask(fresh(), {}, IP)).msg.rcode, RCODE.NXDOMAIN);
  });

  test('the query without the subnet failing does not matter if the other answers', async () => {
    useUpstream(byQuery(ok, httpError(500)));
    const {msg} = await ask(fresh(), {}, IP);
    assert.equal(msg.rcode, RCODE.NOERROR);
    assert.equal(msg.answer.length, 1);
  });

  test('the subnet query failing: the answer without it is used', async () => {
    useUpstream(byQuery(httpError(500), ok));
    const {msg} = await ask(fresh(), {}, IP);
    assert.equal(msg.rcode, RCODE.NOERROR);
    assert.equal(msg.answer.length, 1);
  });

  test('both failing is SERVFAIL', async () => {
    useUpstream(httpError(500));
    const {msg} = await ask(fresh(), {}, IP);
    assert.equal(msg.rcode, RCODE.SERVFAIL);
    assert.deepEqual(edeCodes(msg), [EDE_NETWORK_ERROR]);
  });
});

describe('the JSON API when the upstream fails', () => {
  const get = (query: string) =>
    handleJson(new Request(`https://dns.test/resolve?${query}`), ctx());

  test('Status 2 with the question', async () => {
    useUpstream(httpError(500));
    const name = fresh();
    const res = await get(`name=${name}`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      Status: number;
      Question: {name: string}[];
    };
    assert.equal(body.Status, RCODE.SERVFAIL);
    assert.equal(body.Question[0].name, `${name}.`);
  });

  test('SERVFAIL in the wire format with ct=application/dns-message', async () => {
    useUpstream(httpError(500));
    const res = await get(`name=${fresh()}&ct=application/dns-message`);
    assert.equal(res.headers.get('content-type'), 'application/dns-message');
    assert.equal(
      parseMsg(new Uint8Array(await res.arrayBuffer())).rcode,
      RCODE.SERVFAIL
    );
  });

  test('an upstream rcode is shown as its Status', async () => {
    useUpstream(withRcode(RCODE.REFUSED));
    const body = (await (await get(`name=${fresh()}`)).json()) as {
      Status: number;
    };
    assert.equal(body.Status, RCODE.REFUSED);
  });
});
