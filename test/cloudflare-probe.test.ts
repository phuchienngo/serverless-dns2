import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {sampleAddresses} from '../scripts/cloudflare-probe.js';

describe('sampleAddresses', () => {
  test('spreads eight addresses over the range', () => {
    assert.deepEqual(sampleAddresses('172.64.0.0/13'), [
      '172.64.0.1',
      '172.65.0.1',
      '172.66.0.1',
      '172.67.0.1',
      '172.68.0.1',
      '172.69.0.1',
      '172.70.0.1',
      '172.71.0.1',
    ]);
  });

  test('a small range keeps every address inside it', () => {
    assert.deepEqual(sampleAddresses('103.21.244.0/30'), [
      '103.21.244.1',
      '103.21.244.2',
    ]);
  });
});
