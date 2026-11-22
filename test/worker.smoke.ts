import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createTestHarness} from 'wrangler';
import type {JsonResponse} from '../src/format.js';

test('the Worker serves DNS over JSON and wire in workerd', async () => {
  const worker = createTestHarness({workers: [{configPath: 'wrangler.jsonc'}]});
  try {
    await worker.listen();

    const json = await worker.fetch('/resolve?name=localhost&type=A');
    assert.equal(json.status, 200);
    const result = (await json.json()) as JsonResponse;
    assert.equal(result.Status, 0);
    assert.equal(result.Answer?.[0]?.data, '127.0.0.1');

    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1234);
    header[2] = 1;
    header[5] = 1;
    const name = Buffer.from('localhost');
    const question = Buffer.from([name.length, ...name, 0, 0, 1, 0, 1]);
    const query = Buffer.concat([header, question]).toString('base64url');
    const wire = await worker.fetch(`/dns-query?dns=${query}`);
    assert.equal(wire.status, 200);
    assert.equal(wire.headers.get('content-type'), 'application/dns-message');
    const answer = Buffer.from(await wire.arrayBuffer());
    assert.equal(answer.readUInt16BE(0), 0x1234);
    assert.equal(answer[3] & 15, 0);
    assert.equal(answer.readUInt16BE(6), 1);
    assert.deepEqual([...answer.subarray(-4)], [127, 0, 0, 1]);
  } finally {
    await worker.close();
  }
});
