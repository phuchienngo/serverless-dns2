/**
 * @fileoverview The blocklist build on several threads. The shards are
 * independent, so each one is solved by whichever worker is free; the file is
 * the same, byte for byte, as `buildBlockset` writes.
 */

import {availableParallelism} from 'node:os';
import {Worker} from 'node:worker_threads';
import {
  assembleBlockset,
  buildBlockset,
  partitionShards,
  type SolvedShard,
} from './blocklist-lib.js';

/**
 * Same as `buildBlockset`, with the shards solved on `jobs` threads.
 * @param jobs Defaults to the number of CPUs.
 */
export async function buildBlocksetParallel(
  domains: Set<string>,
  bits: number,
  jobs = availableParallelism()
): Promise<Uint8Array> {
  const {kept, shards, h0s, h1s} = partitionShards(domains, bits);
  const threads = Math.min(jobs, shards);
  if (threads < 2) {
    return buildBlockset(domains, bits);
  }
  console.log(`Solving ${shards} shards on ${threads} threads`);
  const solved: SolvedShard[] = new Array(shards);
  let next = 0;
  let done = 0;
  const workers: Worker[] = [];
  try {
    await Promise.all(
      Array.from(
        {length: threads},
        () =>
          new Promise<void>((resolve, reject) => {
            const worker = new Worker(
              decodeURIComponent(
                new URL('./solve-worker.ts', import.meta.url).pathname
              )
            );
            workers.push(worker);
            const send = () => {
              if (next >= shards) {
                resolve();
                return;
              }
              const shard = next++;
              worker.postMessage({
                shard,
                h0s: h0s[shard],
                h1s: h1s[shard],
                bits,
              });
            };
            worker.on('message', ({shard, result}) => {
              solved[shard] = result;
              if (++done % 10 === 0 || done === shards) {
                console.log(`  shard ${done}/${shards} solved`);
              }
              send();
            });
            worker.on('error', reject);
            send();
          })
      )
    );
  } finally {
    await Promise.all(workers.map(worker => worker.terminate()));
  }
  return assembleBlockset(kept, solved, bits);
}
