/**
 * @fileoverview The log lines: only what goes wrong, one JSON object each, and
 * no more than one of a kind every few seconds.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {UPSTREAM} from '../src/config.js';
import {handle} from '../src/handlers.js';
import {describeError, logEvent, resetLog, setLogLevel} from '../src/log.js';
import {T, makeQuery, resetState} from './helpers.js';

let lines: {
  level: string;
  json: Record<string, unknown>;
  error?: unknown;
}[];
let realNow: typeof Date.now;
let clock: number;
const saved = {error: console.error, warn: console.warn};
let original: typeof fetch;

beforeEach(() => {
  lines = [];
  for (const level of ['error', 'warn'] as const) {
    console[level] = (entry: Record<string, unknown>, error?: unknown) =>
      void lines.push({level, json: entry, error});
  }
  realNow = Date.now;
  clock = 1_000_000;
  Date.now = () => clock;
  original = globalThis.fetch;
  resetState();
  resetLog();
});
afterEach(() => {
  console.error = saved.error;
  console.warn = saved.warn;
  Date.now = realNow;
  globalThis.fetch = original;
});

describe('logEvent', () => {
  test('writes the event and its fields as one object, not a string', () => {
    logEvent('error', 'boom', 'It broke', {name: 'a.example', type: 1});
    assert.equal(lines.length, 1);
    assert.equal(lines[0].level, 'error');
    assert.equal(typeof lines[0].json, 'object');
    assert.deepEqual(lines[0].json, {
      event: 'boom',
      message: 'It broke',
      name: 'a.example',
      type: 1,
    });
    assert.equal(lines[0].error, undefined);
  });

  test('passes the caught error beside the line, for Workers Issues', () => {
    const cause = new Error('upstream 500');
    logEvent('error', 'boom', 'm', {}, cause);
    assert.equal(lines[0].error, cause);
    logEvent('error', 'other', 'm', {}, 'not an Error object');
    assert.equal(lines[1].error, undefined);
  });

  test('holds back the same kind for 10 s, then says how many', () => {
    logEvent('error', 'boom', 'm', {});
    clock += 9_999;
    logEvent('error', 'boom', 'm', {});
    logEvent('error', 'boom', 'm', {});
    assert.equal(lines.length, 1);
    clock += 1;
    logEvent('error', 'boom', 'm', {});
    assert.equal(lines.length, 2);
    assert.equal(lines[1].json.held, 2);
    clock += 10_000;
    logEvent('error', 'boom', 'm', {});
    assert.equal(lines[2].json.held, undefined);
  });

  test('keeps a separate gap for each kind', () => {
    logEvent('error', 'one', 'm', {});
    logEvent('warn', 'two', 'm', {});
    assert.deepEqual(
      lines.map(l => l.level),
      ['error', 'warn']
    );
  });
});

/** Posts a query that the stand-in upstream answers after `delay` ms. */
async function slowAnswer(name: string, delay: number): Promise<void> {
  const {makeResponse, ip4, parseMsg} = await import('./helpers.js');
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    if (String(input) !== UPSTREAM) {
      return original(input as string, init);
    }
    await new Promise(resolve => setTimeout(resolve, delay));
    const q = parseMsg(new Uint8Array(init!.body as Uint8Array));
    return new Response(
      makeResponse({
        qname: q.question[0].name,
        qtype: q.question[0].type,
        answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}],
      })
    );
  }) as typeof fetch;
  await handle(
    new Request('https://dns.test/dns-query', {
      method: 'POST',
      headers: {'content-type': 'application/dns-message'},
      body: makeQuery(name, T.A) as never,
    }),
    {env: {}, ip: null} as never
  );
}

describe('the log level', () => {
  test('warn writes both kinds, error only failures, off nothing', () => {
    setLogLevel('warn');
    logEvent('error', 'a', 'm', {});
    logEvent('warn', 'b', 'm', {});
    assert.equal(lines.length, 2);
    resetLog();
    setLogLevel('error');
    logEvent('error', 'a', 'm', {});
    logEvent('warn', 'b', 'm', {});
    assert.deepEqual(
      lines.slice(2).map(l => l.json.event),
      ['a']
    );
    resetLog();
    setLogLevel('off');
    logEvent('error', 'a', 'm', {});
    logEvent('warn', 'b', 'm', {});
    assert.equal(lines.length, 3);
  });

  test('a line the level drops is not counted as held back', () => {
    setLogLevel('error');
    logEvent('warn', 'slow', 'm', {});
    logEvent('warn', 'slow', 'm', {});
    setLogLevel('warn');
    logEvent('warn', 'slow', 'm', {});
    assert.equal(lines.length, 1);
    assert.equal(lines[0].json.held, undefined);
  });

  test('a slow upstream answer is a warning, and only at level warn', async () => {
    for (const [value, expected] of [
      ['warn', 1],
      ['error', 0],
    ] as const) {
      lines.length = 0;
      resetLog();
      setLogLevel(value);
      await slowAnswer(`slow-${value}.log.example.com`, 350);
      const slow = lines.filter(l => l.json.event === 'slow_upstream');
      assert.equal(slow.length, expected);
      if (expected) {
        assert.match(
          String(slow[0].json.message),
          new RegExp(`^${new URL(UPSTREAM).host} answered in \\d+ ms$`)
        );
        assert.ok(Number(slow[0].json.ms) >= 300);
      }
    }
    const slow = lines.length ? lines[0] : null;
    assert.equal(slow, null);
  });

  test('an answer under 300 ms is not logged', async () => {
    await slowAnswer('quick.log.example.com', 0);
    assert.deepEqual(lines, []);
    await slowAnswer('almost.log.example.com', 200);
    assert.deepEqual(lines, []);
  });
});

describe('describeError', () => {
  test('says what each kind of failure was', () => {
    assert.equal(describeError(new Error('upstream 500')), 'upstream 500');
    const abort = new Error('x');
    abort.name = 'AbortError';
    assert.equal(describeError(abort), 'timeout');
    assert.equal(
      describeError(
        new AggregateError([
          new Error('upstream 502'),
          new Error('upstream 502'),
        ])
      ),
      'upstream 502'
    );
    assert.equal(describeError('odd'), 'odd');
  });
});

const post = (name: string) =>
  handle(
    new Request('https://dns.test/dns-query', {
      method: 'POST',
      headers: {'content-type': 'application/dns-message'},
      body: makeQuery(name, T.A) as never,
    }),
    {env: {}, ip: null} as never
  );
const upstreamReturns = (status: number) => {
  globalThis.fetch = (async (input: unknown, init?: RequestInit) =>
    String(input) === UPSTREAM
      ? new Response(new Uint8Array(0), {status})
      : original(input as string, init)) as typeof fetch;
};

describe('what the gateway logs', () => {
  test('a failing upstream gives the cause, then the SERVFAIL with the name', async () => {
    upstreamReturns(500);
    await post('down.log.example.com');
    const events = lines.map(l => l.json.event);
    assert.ok(events.includes('upstream_failed'));
    assert.ok(events.includes('servfail'));
    const failed = lines.find(l => l.json.event === 'upstream_failed')!;
    assert.match(String(failed.json.cause), /upstream 500/);
    assert.equal(failed.json.host, new URL(UPSTREAM).host);
    const servfail = lines.find(l => l.json.event === 'servfail')!;
    assert.equal(servfail.level, 'error');
    assert.equal(servfail.json.name, 'down.log.example.com');
    assert.equal(servfail.json.type, T.A);
    assert.equal(
      servfail.json.message,
      'SERVFAIL for A down.log.example.com: upstream 500'
    );
    assert.equal(
      failed.json.message,
      `${new URL(UPSTREAM).host} failed: upstream 500`
    );
    assert.ok(servfail.error instanceof Error, 'the error rides along');
    assert.ok(failed.error instanceof Error);
  });

  test('many failures in a row give one line of each kind', async () => {
    upstreamReturns(502);
    for (let i = 0; i < 20; i++) {
      await post(`n${i}.log.example.com`);
    }
    assert.equal(lines.filter(l => l.json.event === 'servfail').length, 1);
    assert.equal(
      lines.filter(l => l.json.event === 'upstream_failed').length,
      1
    );
  });

  test('an answer that works logs nothing', async () => {
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      if (String(input) !== UPSTREAM) {
        return original(input as string, init);
      }
      const {makeResponse, ip4, parseMsg} = await import('./helpers.js');
      const q = parseMsg(new Uint8Array(init!.body as Uint8Array));
      return new Response(
        makeResponse({
          qname: q.question[0].name,
          qtype: q.question[0].type,
          answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}],
        })
      );
    }) as typeof fetch;
    const res = await post('fine.log.example.com');
    assert.equal(res.status, 200);
    assert.deepEqual(lines, []);
  });
});
