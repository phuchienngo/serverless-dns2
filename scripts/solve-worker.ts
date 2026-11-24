/**
 * @fileoverview A worker thread of the blocklist build: solves the shards it
 * is sent (see blocklist-parallel.ts).
 */

import {parentPort} from 'node:worker_threads';
import {solveShard} from './blocklist-lib.js';

parentPort!.on(
  'message',
  ({
    shard,
    h0s,
    h1s,
    bits,
  }: {
    shard: number;
    h0s: number[];
    h1s: number[];
    bits: number;
  }) => {
    parentPort!.postMessage({shard, result: solveShard(h0s, h1s, bits)});
  }
);
