/** HTTP layer: RFC 8484 DoH (/dns-query) and the Google-style JSON API (/resolve). */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {RCODE_BADVERS, RCODE_FORMERR} from '../src/constants.js';
import {handle, handleJson, route} from '../src/handlers.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  mockUpstream,
  parseMsg,
  resetState,
} from './helpers.js';

const ctx = {env: {}, ip: null} as never;
const B = 'https://dns.test';
let upstream: ReturnType<typeof mockUpstream>;
let n = 0;
const fresh = () => `h${n++}.handlers.example.com`;

beforeEach(() => {
  resetState();
  upstream = mockUpstream(q =>
    makeResponse({
      qname: q.question[0].name,
      qtype: q.question[0].type,
      answer:
        q.question[0].type === T.A
          ? [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}]
          : [],
    })
  );
});
afterEach(() => upstream.restore());

const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const post = (body: Uint8Array | string, type = 'application/dns-message') =>
  handle(
    new Request(`${B}/dns-query`, {
      method: 'POST',
      headers: {'content-type': type},
      body: body as never,
    }),
    ctx
  );
const get = (path: string, h = handle) => h(new Request(`${B}${path}`), ctx);

describe('/dns-query (RFC 8484)', () => {
  test('truncated upstream packets get the same SERVFAIL and TTL in wire and JSON', async () => {
    upstream.restore();
    upstream = mockUpstream(q => {
      const {name, type} = q.question[0];
      const body = makeResponse({qname: name, qtype: type, opt: false});
      return body.subarray(0, body.length - 1);
    });
    const wire = await post(makeQuery(fresh(), T.A));
    assert.equal(wire.headers.get('cache-control'), 'private, max-age=5');
    const message = parseMsg(new Uint8Array(await wire.arrayBuffer()));
    assert.equal(message.rcode, 2);
    assert.equal(message.question.length, 1);

    const json = await get(`/resolve?name=${fresh()}`, handleJson);
    assert.equal(json.headers.get('cache-control'), 'private, max-age=5');
    assert.equal(((await json.json()) as {Status: number}).Status, 2);
  });

  test('POST returns application/dns-message', async () => {
    const res = await post(makeQuery(fresh(), T.A, {id: 5}));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/dns-message');
    const m = parseMsg(new Uint8Array(await res.arrayBuffer()));
    assert.equal(m.id, 5);
    assert.equal(m.answer.length, 1);
  });

  test('GET ?dns= with base64url, padded or not', async () => {
    const wire = makeQuery(fresh(), T.A);
    for (const param of [b64url(wire), b64url(wire) + '==']) {
      const res = await get(`/dns-query?dns=${param}`);
      assert.equal(res.status, 200, param);
    }
  });

  test('Cache-Control max-age is the answer TTL, and HIT is flagged', async () => {
    const wire = makeQuery(fresh(), T.A);
    const first = await post(wire);
    assert.match(first.headers.get('cache-control')!, /^private, max-age=\d+$/);
    assert.equal(first.headers.get('x-cache'), null);
    const second = await post(wire);
    assert.equal(second.headers.get('x-cache'), 'HIT');
  });

  test('Server-Timing waits for the upstream answer after a cache miss', async () => {
    upstream.restore();
    upstream = mockUpstream(async q => {
      await new Promise(resolve => setTimeout(resolve, 30));
      return makeResponse({qname: q.question[0].name, qtype: T.A});
    });
    const res = await post(makeQuery(fresh(), T.A));
    const timing = res.headers.get('server-timing');
    const duration = Number(timing?.match(/first;dur=([\d.]+)/)?.[1]);
    assert.ok(duration >= 20, `first was ${duration} ms`);
  });

  test('the same question over POST and GET share the cache', async () => {
    const wire = makeQuery(fresh(), T.A);
    await post(wire);
    const res = await get(`/dns-query?dns=${b64url(wire)}`);
    assert.equal(res.headers.get('x-cache'), 'HIT');
  });

  test('405 for other methods, with Allow', async () => {
    for (const method of ['PUT', 'DELETE', 'PATCH', 'HEAD']) {
      const res = await handle(new Request(`${B}/dns-query`, {method}), ctx);
      assert.equal(res.status, 405, method);
      assert.equal(res.headers.get('allow'), 'GET, POST');
    }
  });

  test('415 for a wrong content type, including a look-alike', async () => {
    assert.equal(
      (await post(makeQuery(fresh(), T.A), 'application/json')).status,
      415
    );
    assert.equal(
      (await post(makeQuery(fresh(), T.A), 'application/dns-messages')).status,
      415
    );
    assert.equal(
      (
        await post(
          makeQuery(fresh(), T.A),
          'application/dns-message; charset=x'
        )
      ).status,
      200
    );
  });

  test('413 for a body that is too large, 400 for garbage', async () => {
    assert.equal((await post(new Uint8Array(70000))).status, 413);
    assert.equal((await post(new Uint8Array([1, 2, 3]))).status, 400);
  });

  test('400 without dns, for bad base64, and 414 for a very long parameter', async () => {
    assert.equal((await get('/dns-query')).status, 400);
    assert.equal((await get('/dns-query?dns=***')).status, 400);
    assert.equal(
      (await get(`/dns-query?dns=${'A'.repeat(20000)}`)).status,
      414
    );
  });

  test('a QUERY with two questions returns DNS FORMERR over GET and POST', async () => {
    const first = makeQuery('first.example.com', T.A, {
      id: 0x1234,
      cd: true,
      edns: false,
    });
    const second = makeQuery('second.example.com', T.AAAA, {edns: false});
    const wire = Uint8Array.from([...first, ...second.subarray(12)]);
    new DataView(wire.buffer).setUint16(4, 2);

    for (const res of [
      await get(`/dns-query?dns=${b64url(wire)}`),
      await post(wire),
    ]) {
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/dns-message');
      assert.equal(res.headers.get('cache-control'), 'private, max-age=0');
      const reply = parseMsg(new Uint8Array(await res.arrayBuffer()));
      assert.equal(reply.id, 0x1234);
      assert.equal(reply.qr, true);
      assert.equal(reply.rd, true);
      assert.equal(reply.cd, true);
      assert.equal(reply.rcode, RCODE_FORMERR);
      assert.equal(reply.size, 12);
    }
    assert.equal(upstream.calls.length, 0);
  });

  test('/dns-query without dns still reports it missing', async () => {
    const res = await get('/dns-query');
    assert.equal(res.status, 400);
  });

  test('an upstream failure becomes SERVFAIL, not an HTTP error', async () => {
    upstream.restore();
    upstream = mockUpstream(() => {
      throw new Error('down');
    });
    const res = await post(makeQuery(fresh(), T.A));
    assert.equal(res.status, 200);
    const m = parseMsg(new Uint8Array(await res.arrayBuffer()));
    assert.equal(m.rcode, 2);
    const ede = m.opt!.options.find(o => o.code === 15)!;
    assert.deepEqual([...ede.data.subarray(0, 2)], [0, 23], 'Network Error');
    assert.equal(res.headers.get('cache-control'), 'private, max-age=5');
  });

  test('a SERVFAIL for a client without EDNS has no OPT record', async () => {
    upstream.restore();
    upstream = mockUpstream(() => {
      throw new Error('down');
    });
    const res = await post(makeQuery(fresh(), T.A, {edns: false}));
    const m = parseMsg(new Uint8Array(await res.arrayBuffer()));
    assert.equal(m.rcode, 2);
    assert.equal(m.opt, undefined);
  });

  test('DO, CD and a client subnet reach the upstream', async () => {
    const wire = makeQuery(fresh(), T.A, {
      do: true,
      cd: true,
      ecs: {family: 1, prefix: 24, address: [198, 51, 100]},
    });
    await post(wire);
    const sent = upstream.calls[0].query;
    assert.equal(sent.opt?.do, true);
    assert.equal(sent.cd, true);
    assert.deepEqual(
      [...sent.opt!.options.find(o => o.code === 8)!.data],
      [0, 1, 24, 0, 198, 51, 100]
    );
  });
});

describe('a client that asks not to be located (ECS source prefix 0)', () => {
  const located = {env: {}, ip: '203.0.113.77'} as never;
  const send = (ecs?: {family: 1 | 2; prefix: number; address: number[]}) =>
    handle(
      new Request(`${B}/dns-query`, {
        method: 'POST',
        headers: {'content-type': 'application/dns-message'},
        body: makeQuery(fresh(), T.A, {ecs}) as never,
      }),
      located
    );
  const subnetsSent = () =>
    upstream.calls.map(({query}) => [
      ...(query.opt?.options.find(o => o.code === 8)?.data ?? []),
    ]);

  test('no subnet of the connecting IP goes upstream: source prefix 0 does', async () => {
    await send({family: 2, prefix: 0, address: []});
    assert.deepEqual(subnetsSent(), [[0, 2, 0, 0], []]);
  });

  test('a query with no ECS still gets its connecting IP as /24', async () => {
    await send();
    assert.deepEqual(subnetsSent(), [[0, 1, 24, 0, 203, 0, 113], []]);
  });
});

/* eslint-disable @typescript-eslint/no-explicit-any */
describe('/resolve (Google JSON API)', () => {
  const json = async (path: string) => {
    const res = await get(path, handleJson);
    return {
      res,
      body: (res.status === 200 ? await res.json() : await res.text()) as any,
    };
  };

  test('returns Google-style JSON', async () => {
    const name = fresh();
    const {res, body} = await json(`/resolve?name=${name}&type=A`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type')!, /^application\/json/);
    assert.equal(body.Status, 0);
    assert.equal(body.Answer[0].data, '192.0.2.9');
    assert.deepEqual(body.Question, [{name: `${name}.`, type: 1}]);
  });

  test('type may be a name or a number; the default is A', async () => {
    const name = fresh();
    assert.equal(
      (await json(`/resolve?name=${name}&type=aaaa`)).body.Question[0].type,
      28
    );
    assert.equal(
      (await json(`/resolve?name=${name}&type=28`)).body.Question[0].type,
      28
    );
    assert.equal(
      (await json(`/resolve?name=${name}`)).body.Question[0].type,
      1
    );
  });

  test('400 for a bad name, type or subnet', async () => {
    assert.equal((await json('/resolve')).res.status, 400);
    assert.equal(
      (await json(`/resolve?name=${'a'.repeat(64)}.com`)).res.status,
      400
    );
    assert.equal((await json('/resolve?name=a..com')).res.status, 400);
    assert.equal((await json('/resolve?name=a.com&type=0')).res.status, 400);
    assert.equal((await json('/resolve?name=a.com&type=NOPE')).res.status, 400);
    assert.equal(
      (await json('/resolve?name=a.com&type=70000')).res.status,
      400
    );
    assert.equal(
      (await json(`/resolve?name=${fresh()}&edns_client_subnet=xyz`)).res
        .status,
      400
    );
  });

  test('only GET is implemented; HEAD is a bad request', async () => {
    const post = await handleJson(
      new Request(`${B}/resolve?name=a.com`, {method: 'POST'}),
      ctx
    );
    assert.equal(post.status, 501);
    const head = await handleJson(
      new Request(`${B}/resolve?name=a.com`, {method: 'HEAD'}),
      ctx
    );
    assert.equal(head.status, 400);
  });

  test('do=1 asks the upstream for DNSSEC, cd=1 disables checking', async () => {
    await json(`/resolve?name=${fresh()}&do=1&cd=true`);
    assert.equal(upstream.calls[0].query.opt?.do, true);
    assert.equal(upstream.calls[0].query.cd, true);
  });

  test('edns_client_subnet is sent upstream', async () => {
    await json(`/resolve?name=${fresh()}&edns_client_subnet=203.0.113.0/24`);
    const option = upstream.calls[0].query.opt!.options.find(
      o => o.code === 8
    )!;
    assert.deepEqual([...option.data], [0, 1, 24, 0, 203, 0, 113]);
  });

  test('type PTR with an IP converts it to the reverse name', async () => {
    const {body} = await json('/resolve?name=203.0.113.9&type=PTR');
    assert.equal(body.Question[0].name, '9.113.0.203.in-addr.arpa.');
  });

  test('ct=application/dns-message returns the wire format', async () => {
    const res = await get(
      `/resolve?name=${fresh()}&ct=application/dns-message`,
      handleJson
    );
    assert.equal(res.headers.get('content-type'), 'application/dns-message');
  });

  test('an upstream failure is Status 2 (SERVFAIL)', async () => {
    upstream.restore();
    upstream = mockUpstream(() => {
      throw new Error('down');
    });
    const {body} = await json(`/resolve?name=${fresh()}`);
    assert.equal(body.Status, 2);
  });
});

describe('dns64 parameter', () => {
  test('Server-Timing includes the A lookup when the original AAAA is cached', async () => {
    upstream.restore();
    upstream = mockUpstream(async q => {
      const {name, type} = q.question[0];
      if (type !== T.A) return makeResponse({qname: name, qtype: type});
      await new Promise(resolve => setTimeout(resolve, 30));
      return makeResponse({
        qname: name,
        qtype: type,
        answer: [{type, ttl: 120, rdata: ip4('93.184.216.34')}],
      });
    });
    const url = `/resolve?name=${fresh()}&type=AAAA`;
    await get(url, handleJson);
    const res = await get(`${url}&dns64=1`, handleJson);
    const answer = (await res.json()) as {Answer?: unknown[]};
    assert.equal(answer.Answer?.length, 1);
    const timing = res.headers.get('server-timing');
    const duration = Number(timing?.match(/first;dur=([\d.]+)/)?.[1]);
    assert.ok(duration >= 20, `first was ${duration} ms`);
  });

  test('ipv4only.arpa still rejects unsupported EDNS versions with DNS64 on', async () => {
    const wire = makeQuery('ipv4only.arpa', T.AAAA, {ednsVersion: 1});
    const res = await get(`/dns-query?dns=${b64url(wire)}&dns64=1`);
    const msg = parseMsg(new Uint8Array(await res.arrayBuffer()));
    assert.equal(res.status, 200);
    assert.equal(msg.rcode, RCODE_BADVERS);
    assert.equal(msg.answer.length, 0);
    assert.equal(upstream.calls.length, 0);
  });

  const aaaa = async (query: string) => {
    upstream.restore();
    upstream = mockUpstream(q =>
      makeResponse({
        qname: q.question[0].name,
        qtype: q.question[0].type,
        answer:
          q.question[0].type === T.A
            ? [{type: T.A, ttl: 120, rdata: ip4('93.184.216.34')}]
            : [],
      })
    );
    const res = await get(
      `/resolve?name=${fresh()}&type=AAAA${query}`,
      handleJson
    );
    return ((await res.json()) as {Answer?: unknown[]}).Answer?.length ?? 0;
  };

  test('dns64=1 and dns64=true turn it on, like do and cd', async () => {
    assert.equal(await aaaa('&dns64=1'), 1);
    assert.equal(await aaaa('&dns64=true'), 1);
    assert.equal(await aaaa('&dns64=TRUE'), 1);
  });

  test('anything else, or no parameter, leaves it off', async () => {
    for (const query of [
      '',
      '&dns64',
      '&dns64=0',
      '&dns64=false',
      '&dns64=yes',
    ]) {
      assert.equal(await aaaa(query), 0, query || 'no parameter');
    }
  });
});

describe('routing', () => {
  const via = (path: string, init?: RequestInit) =>
    route(new Request(`${B}${path}`, init), ctx);

  test('/dns-query?name= and /resolve answer the JSON API', async () => {
    for (const path of ['/dns-query', '/resolve']) {
      const res = await via(`${path}?name=${fresh()}`);
      assert.match(res.headers.get('content-type')!, /json/, path);
    }
  });

  test('a trailing slash is ignored; other paths are 404', async () => {
    assert.equal((await via(`/resolve/?name=${fresh()}`)).status, 200);
    assert.equal((await via('/other')).status, 404);
  });

  test('a POST with a name parameter is still a DoH POST', async () => {
    const res = await via(`/dns-query?name=${fresh()}`, {
      method: 'POST',
      headers: {'content-type': 'application/dns-message'},
      body: makeQuery(fresh(), T.A),
    });
    assert.match(res.headers.get('content-type')!, /dns-message/);
  });
});
