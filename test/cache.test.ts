/**
 * The answer cache (src/cache.ts): TTL countdown (RFC 1035, 2181), negative
 * caching (RFC 2308), serve-stale (RFC 8767) and the two tiers.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, mock, test} from 'node:test';
import {
  LOCAL_CACHE_SIZE,
  MIN_CACHE_TTL,
  REFRESH_EARLY_MS,
  STALE_MAX_S,
  STALE_TTL,
} from '../src/config.js';
import {lookupLocal, lookupShared, store} from '../src/cache.js';
import {parseQuestion} from '../src/query.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  mxRdata,
  parseMsg,
  resetState,
  soaRdata,
} from './helpers.js';

const START = 1_700_000_000_000;
let counter = 0;
const uniqueKey = () => `https://dns.test/__cache/${counter++}`;
const question = (name = 'a.test', o = {}) =>
  parseQuestion(makeQuery(name, T.A, o));
const answer = (ttl: number, name = 'a.test') =>
  makeResponse({
    qname: name,
    qtype: T.A,
    answer: [{type: T.A, ttl, rdata: ip4('1.2.3.4')}],
  });
const ttlOf = (body: Uint8Array) => parseMsg(body).answer[0].ttl;

beforeEach(() => {
  resetState();
  mock.timers.enable({apis: ['Date'], now: START});
});
afterEach(() => {
  mock.timers.reset();
  mock.restoreAll();
});
const tick = (seconds: number) => mock.timers.tick(seconds * 1000);

describe('local cache', () => {
  test('resetState empties it', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    assert.ok(lookupLocal(key, question()));
    resetState();
    assert.equal(lookupLocal(key, question()), null);
  });

  test('misses until something is stored', () => {
    assert.equal(lookupLocal(uniqueKey(), question()), null);
  });

  test('a hit is a copy for this client: id and case of the question', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    const q = question('A.TeSt', {id: 4242});
    const hit = lookupLocal(key, q)!;
    const m = parseMsg(hit.result.body);
    assert.equal(m.id, 4242);
    assert.equal(m.question[0].name, 'A.TeSt.');
    assert.equal(hit.result.hit, true);
  });

  test('answer TTLs count down (RFC 1035 3.2.1)', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    assert.equal(ttlOf(lookupLocal(key, question())!.result.body), 300);
    tick(100);
    const hit = lookupLocal(key, question())!;
    assert.equal(ttlOf(hit.result.body), 200);
    assert.equal(hit.result.ttl, 200);
    assert.equal(hit.refresh, false);
    assert.equal(hit.result.stale, false);
  });

  test('every answer record gets the remaining TTL', () => {
    const key = uniqueKey();
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [
        {type: T.A, ttl: 300, rdata: ip4('1.1.1.1')},
        {type: T.A, ttl: 120, rdata: ip4('2.2.2.2')},
      ],
    });
    store(undefined, key, {body, ttl: 120});
    tick(20);
    const m = parseMsg(lookupLocal(key, question())!.result.body);
    assert.deepEqual(
      m.answer.map(r => r.ttl),
      [100, 100]
    );
  });

  test('authority TTLs count down too, so negative answers expire on time', () => {
    const key = uniqueKey();
    const body = makeResponse({
      qname: 'gone.test',
      qtype: T.A,
      rcode: 3,
      authority: [{name: 'test', type: T.SOA, ttl: 900, rdata: soaRdata(900)}],
    });
    store(undefined, key, {body, ttl: 900});
    tick(300);
    const m = parseMsg(lookupLocal(key, question('gone.test'))!.result.body);
    assert.equal(m.rcode, 3);
    assert.equal(m.authority[0].ttl, 600);
  });

  test('additional-section TTLs count down too', () => {
    const key = uniqueKey();
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.MX,
      answer: [{type: T.MX, ttl: 300, rdata: mxRdata(10, 'mail.a.test')}],
      additional: [
        {name: 'mail.a.test', type: T.A, ttl: 600, rdata: ip4('5.6.7.8')},
      ],
    });
    store(undefined, key, {body, ttl: 300});
    tick(100);
    const m = parseMsg(lookupLocal(key, question())!.result.body);
    assert.equal(m.answer[0].ttl, 200);
    assert.equal(m.additional.find(r => r.type === T.A)!.ttl, 200);
  });

  test('the OPT record is not rewritten as if it had a TTL', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    tick(10);
    assert.equal(
      parseMsg(lookupLocal(key, question())!.result.body).opt?.extRcode,
      0
    );
  });

  test('a TTL below the minimum is kept for MIN_CACHE_TTL (a deliberate choice)', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(5), ttl: 5});
    tick(MIN_CACHE_TTL - 10);
    const hit = lookupLocal(key, question())!;
    assert.equal(hit.result.stale, false);
    assert.equal(ttlOf(hit.result.body), 10);
  });

  test('refreshes early, on a fraction of the lookups near expiry', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    tick(300 - REFRESH_EARLY_MS / 2000);
    mock.method(Math, 'random', () => 0);
    assert.equal(lookupLocal(key, question())!.refresh, true);
    mock.method(Math, 'random', () => 0.9);
    assert.equal(lookupLocal(key, question())!.refresh, false);
  });

  test('does not refresh early while the entry is young', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    mock.method(Math, 'random', () => 0);
    assert.equal(lookupLocal(key, question())!.refresh, false);
  });

  test('past its TTL it is served stale with a short TTL (RFC 8767)', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    tick(301);
    const hit = lookupLocal(key, question())!;
    assert.equal(hit.result.stale, true);
    assert.equal(hit.refresh, true);
    assert.equal(hit.result.ttl, STALE_TTL);
    assert.equal(ttlOf(hit.result.body), STALE_TTL);
    assert.equal(STALE_TTL, 30, 'RFC 8767 suggests 30 seconds');
  });

  test('is dropped after the stale period', () => {
    const key = uniqueKey();
    store(undefined, key, {body: answer(300), ttl: 300});
    tick(300 + STALE_MAX_S - 1);
    assert.ok(lookupLocal(key, question()));
    tick(2);
    assert.equal(lookupLocal(key, question()), null);
  });

  test('stores NOERROR and NXDOMAIN, but not SERVFAIL, REFUSED or truncated', () => {
    for (const [rcode, tc, stored] of [
      [0, false, true],
      [3, false, true],
      [2, false, false],
      [5, false, false],
      [0, true, false],
    ] as const) {
      const key = uniqueKey();
      store(undefined, key, {
        body: makeResponse({qname: 'a.test', qtype: T.A, rcode, tc}),
        ttl: 60,
      });
      assert.equal(
        lookupLocal(key, question()) !== null,
        stored,
        `rcode ${rcode} tc ${tc}`
      );
    }
  });

  test('ignores an entry too short for the question', () => {
    const key = uniqueKey();
    store(undefined, key, {body: new Uint8Array(14), ttl: 60});
    assert.equal(lookupLocal(key, question()), null);
  });

  test('keeps at most LOCAL_CACHE_SIZE entries, dropping the least recently used', () => {
    const prefix = uniqueKey();
    const body = answer(300);
    for (let i = 0; i < LOCAL_CACHE_SIZE; i++) {
      store(undefined, `${prefix}/${i}`, {body, ttl: 300});
    }
    assert.ok(lookupLocal(`${prefix}/0`, question()), 'touch the oldest');
    store(undefined, `${prefix}/new`, {body, ttl: 300});
    assert.ok(lookupLocal(`${prefix}/0`, question()), 'recently used survives');
    assert.equal(
      lookupLocal(`${prefix}/1`, question()),
      null,
      'the next oldest goes'
    );
    assert.ok(lookupLocal(`${prefix}/new`, question()));
  });
});

/** The parts of the Cache API that the code uses. */
class FakeCache {
  readonly entries = new Map<string, Response>();
  async match(request: Request) {
    return this.entries.get(request.url)?.clone();
  }
  async put(request: Request, response: Response) {
    this.entries.set(request.url, response);
  }
}

describe('shared cache (Cache API)', () => {
  test('without a Cache API there is nothing to find', async () => {
    assert.equal(await lookupShared(undefined, uniqueKey(), question()), null);
  });

  test('store writes through to it, and lookupShared reads it back', async () => {
    const cache = new FakeCache();
    const key = uniqueKey();
    const pending: Promise<unknown>[] = [];
    store(cache as unknown as Cache, key, {body: answer(300), ttl: 300}, p =>
      pending.push(p)
    );
    await Promise.all(pending);
    assert.equal(pending.length, 1, 'the write is handed to waitUntil');

    const stored = cache.entries.get(new Request(key).url)!;
    assert.equal(stored.headers.get('x-ttl'), '300');
    assert.equal(stored.headers.get('x-t'), String(START / 1000));
    // Kept past its TTL so it can be served stale.
    assert.equal(
      stored.headers.get('cache-control'),
      `public, max-age=${300 + STALE_MAX_S}`
    );

    tick(60);
    const hit = (await lookupShared(
      cache as unknown as Cache,
      key,
      question()
    ))!;
    assert.equal(ttlOf(hit.result.body), 240);
  });

  test('a shared hit is copied into the local cache', async () => {
    const cache = new FakeCache();
    const key = uniqueKey();
    cache.entries.set(
      new Request(key).url,
      new Response(answer(300), {
        headers: {'x-t': String(START / 1000), 'x-ttl': '300'},
      })
    );
    assert.equal(lookupLocal(key, question()), null);
    assert.ok(await lookupShared(cache as unknown as Cache, key, question()));
    assert.ok(lookupLocal(key, question()));
  });

  test('ignores an entry without its timestamps', async () => {
    const cache = new FakeCache();
    const key = uniqueKey();
    cache.entries.set(new Request(key).url, new Response(answer(300)));
    assert.equal(
      await lookupShared(cache as unknown as Cache, key, question()),
      null
    );
  });

  test('does not store what the local cache would not', async () => {
    const cache = new FakeCache();
    store(cache as unknown as Cache, uniqueKey(), {
      body: makeResponse({qname: 'a.test', qtype: T.A, rcode: 2}),
      ttl: 5,
    });
    assert.equal(cache.entries.size, 0);
  });
});
