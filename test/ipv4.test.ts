/** IPv4 blocks (src/ipv4.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {inBlocks, type Ipv4Block} from '../src/ipv4.js';
import {ip4} from './helpers.js';

describe('inBlocks', () => {
  const blocks: Ipv4Block[] = [
    [[10, 0, 0, 0], 8],
    [[172, 16, 0, 0], 12],
    [[100, 64, 0, 0], 10],
    [[192, 0, 2, 7], 32],
    [[224, 0, 0, 0], 3],
  ];

  test('includes the first and last address of each block', () => {
    for (const a of [
      '10.0.0.0',
      '10.255.255.255',
      '172.16.0.0',
      '172.31.255.255',
      '100.64.0.0',
      '100.127.255.255',
      '192.0.2.7',
      '224.0.0.0',
      '255.255.255.255',
    ]) {
      assert.equal(inBlocks(ip4(a), blocks), true, a);
    }
  });

  test('excludes the addresses next to a block', () => {
    for (const a of [
      '9.255.255.255',
      '11.0.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '100.63.255.255',
      '100.128.0.0',
      '192.0.2.6',
      '192.0.2.8',
      '223.255.255.255',
      '8.8.8.8',
    ]) {
      assert.equal(inBlocks(ip4(a), blocks), false, a);
    }
  });

  test('handles /0 (everything), /32 (one address) and an empty list', () => {
    assert.equal(inBlocks(ip4('1.2.3.4'), [[[0, 0, 0, 0], 0]]), true);
    assert.equal(inBlocks(ip4('1.2.3.4'), [[[1, 2, 3, 4], 32]]), true);
    assert.equal(inBlocks(ip4('1.2.3.5'), [[[1, 2, 3, 4], 32]]), false);
    assert.equal(inBlocks(ip4('1.2.3.4'), []), false);
  });
});
