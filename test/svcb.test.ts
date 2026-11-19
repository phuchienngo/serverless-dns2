/** SVCB and HTTPS records (src/svcb.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {parseAnswers} from '../src/wire.js';
import {
  addSvcParam,
  alpnValue,
  isAliasMode,
  svcParam,
  svcParams,
  svcbRdata,
} from '../src/svcb.js';
import {T, makeResponse} from './helpers.js';

/** A message with one HTTPS record of the given RDATA, and that record. */
function withRecord(rdata: number[]) {
  const msg = makeResponse({
    qname: 'a.test',
    qtype: T.HTTPS,
    answer: [{type: T.HTTPS, ttl: 60, rdata}],
  });
  return {msg, record: parseAnswers(msg)[0]};
}

describe('svcbRdata and alpnValue', () => {
  test('alpn ids are written with their lengths', () => {
    assert.deepEqual(alpnValue(['h2', 'h3']), [2, 0x68, 0x32, 2, 0x68, 0x33]);
  });

  test('parameters are written in increasing key order', () => {
    const rdata = svcbRdata(1, '.', [
      [5, [9]],
      [1, [7, 7]],
    ]);
    assert.deepEqual(rdata, [0, 1, 0, 0, 1, 0, 2, 7, 7, 0, 5, 0, 1, 9]);
  });
});

describe('reading parameters', () => {
  const rdata = svcbRdata(1, '.', [
    [1, [2, 0x68, 0x32]],
    [4, [1, 2, 3, 4]],
  ]);

  test('svcParams lists them in order, with their start', () => {
    const {msg, record} = withRecord(rdata);
    const params = svcParams(msg, record);
    assert.deepEqual(
      params.map(p => [p.key, [...p.value]]),
      [
        [1, [2, 0x68, 0x32]],
        [4, [1, 2, 3, 4]],
      ]
    );
    assert.equal(params[0].start, record.data + 3);
  });

  test('svcParam finds one, or gives null', () => {
    const {msg, record} = withRecord(rdata);
    assert.deepEqual([...svcParam(msg, record, 4)!], [1, 2, 3, 4]);
    assert.equal(svcParam(msg, record, 5), null);
  });

  test('a parameter that claims more than the record has is cut at its end', () => {
    const damaged = [...rdata];
    damaged[damaged.length - 5] = 0xff; // Length of the last: far too long.
    const {msg, record} = withRecord(damaged);
    assert.deepEqual([...svcParams(msg, record)[1].value], [1, 2, 3, 4]);
  });

  test('a record may have no parameters, and AliasMode is told by priority 0', () => {
    const alias = withRecord([0, 0, 0]);
    assert.deepEqual(svcParams(alias.msg, alias.record), []);
    assert.equal(isAliasMode(alias.msg, alias.record), true);
    const service = withRecord(rdata);
    assert.equal(isAliasMode(service.msg, service.record), false);
  });
});

describe('addSvcParam', () => {
  const keys = (msg: Uint8Array) =>
    svcParams(msg, parseAnswers(msg)[0]).map(p => p.key);

  test('puts the parameter among the others in key order, and fixes the length', () => {
    const {msg, record} = withRecord(
      svcbRdata(1, '.', [
        [1, [1]],
        [4, [1, 2, 3, 4]],
        [6, [0, 0]],
      ])
    );
    const out = addSvcParam(msg, record, 5, [9, 9, 9]);
    assert.deepEqual(keys(out), [1, 4, 5, 6]);
    const changed = parseAnswers(out)[0];
    assert.equal(changed.length, record.length + 7);
    assert.deepEqual([...svcParam(out, changed, 5)!], [9, 9, 9]);
    assert.deepEqual([...svcParam(out, changed, 6)!], [0, 0]);
  });

  test('goes first or last when it belongs there', () => {
    const {msg, record} = withRecord(svcbRdata(1, '.', [[4, [1, 2, 3, 4]]]));
    assert.deepEqual(keys(addSvcParam(msg, record, 1, [1])), [1, 4]);
    assert.deepEqual(keys(addSvcParam(msg, record, 6, [1])), [4, 6]);
    const empty = withRecord([0, 1, 0]);
    assert.deepEqual(keys(addSvcParam(empty.msg, empty.record, 5, [1])), [5]);
  });

  test('the rest of the message is kept, and the input is not changed', () => {
    const {msg, record} = withRecord(svcbRdata(1, '.', [[1, [1]]]));
    const before = msg.slice();
    const out = addSvcParam(msg, record, 5, [1, 2]);
    assert.deepEqual(msg, before);
    assert.deepEqual(
      [...out.subarray(0, record.data - 2)],
      [...msg.subarray(0, record.data - 2)]
    );
    assert.equal(out.length, msg.length + 6);
  });
});
