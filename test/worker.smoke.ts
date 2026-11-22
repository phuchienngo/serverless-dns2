import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {test} from 'node:test';
import type {JsonResponse} from '../src/format.js';
import {ip4, makeQuery, parseMsg, T} from './helpers.js';

test('the Worker serves DNS over JSON and wire in workerd', async () => {
  const state = await mkdtemp(join(tmpdir(), 'dns-worker-smoke-'));
  const worker = spawn(
    process.execPath,
    [
      'x',
      '--no-install',
      'wrangler',
      'dev',
      '--local',
      '--ip',
      '127.0.0.1',
      '--port',
      '0',
      '--persist-to',
      state,
      '--no-show-interactive-dev-session',
    ],
    {
      stdio: ['ignore', 'pipe', 'inherit'],
      env: {...process.env, WRANGLER_SEND_METRICS: 'false'},
    }
  );
  const closed = once(worker, 'close');
  void closed.catch(() => {});
  worker.stdout.pipe(process.stdout);
  const startup = setTimeout(() => worker.kill(), 10_000);
  try {
    let origin: string | undefined;
    const logs = createInterface({input: worker.stdout});
    for await (const line of logs) {
      origin = line.match(/Ready on (http:\/\/127\.0\.0\.1:\d+)/)?.[1];
      if (origin) break;
    }
    clearTimeout(startup);
    assert.ok(origin, 'Wrangler exited or timed out before reporting a local URL');

    const json = await fetch(`${origin}/resolve?name=localhost&type=A`, {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(json.status, 200);
    const result = (await json.json()) as JsonResponse;
    assert.equal(result.Status, 0);
    assert.equal(result.Answer?.[0]?.data, '127.0.0.1');

    const query = Buffer.from(makeQuery('localhost', T.A)).toString('base64url');
    const wire = await fetch(`${origin}/dns-query?dns=${query}`, {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(wire.status, 200);
    assert.equal(wire.headers.get('content-type'), 'application/dns-message');
    const answer = parseMsg(new Uint8Array(await wire.arrayBuffer()));
    assert.equal(answer.id, 0x1234);
    assert.equal(answer.rcode, 0);
    assert.equal(answer.answer.length, 1);
    assert.deepEqual([...answer.answer[0].rdata], ip4('127.0.0.1'));
  } finally {
    clearTimeout(startup);
    worker.kill();
    await closed.finally(() => rm(state, {recursive: true, force: true}));
  }
});
