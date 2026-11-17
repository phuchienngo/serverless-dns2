/**
 * @fileoverview Loads the prebuilt blocklist (`/blocklist.bin`, a static asset)
 * into the isolate's memory on first use.
 */

import {BLOCKLIST_PATH} from './config.js';
import {HASH_WORDS, HEADER_WORDS, MAGIC} from './blockset.js';
import type {Env} from './types.js';

const RETRY_DELAY_MS = 60 * 1000;

let hashes: Uint32Array | null = null;
let loading: Promise<Uint32Array | null> | null = null;
let retryAt = 0;
/** Durations of the most recent load, in ms. */
let lastLoad = {asset: 0, body: 0};

async function fetchBlockset(
  env: Env,
  host: string
): Promise<Uint32Array | null> {
  try {
    const t0 = performance.now();
    const response = await env.ASSETS!.fetch(
      `https://${host}${BLOCKLIST_PATH}`
    );
    const t1 = performance.now();
    if (!response.ok) {
      throw new Error(`blocklist ${response.status}`);
    }
    const buffer = await response.arrayBuffer();
    lastLoad = {asset: t1 - t0, body: performance.now() - t1};
    if (buffer.byteLength % 4 !== 0) {
      throw new Error('bad blocklist length');
    }
    const words = new Uint32Array(buffer);
    if (
      words[0] !== MAGIC ||
      words.length !== HEADER_WORDS + words[1] * HASH_WORDS
    ) {
      // Pages may answer a missing file with index.html; old assets are invalid.
      throw new Error('not a blocklist');
    }
    return words;
  } catch {
    retryAt = Date.now() + RETRY_DELAY_MS;
    return null;
  }
}

/**
 * @return The blocklist if this isolate has already loaded it.
 */
export function peekBlocklist(): Uint32Array | null {
  return hashes;
}

/**
 * @return The blocklist, or null if there is none (or it failed to load; a
 *     failed load is retried after a minute).
 */
export async function getBlocklist(
  env: Env,
  host: string,
  timing?: Record<string, number>
): Promise<Uint32Array | null> {
  if (hashes) {
    return hashes;
  }
  if (!env.ASSETS || Date.now() < retryAt) {
    return null;
  }
  const start = performance.now();
  loading ??= fetchBlockset(env, host).finally(() => {
    loading = null;
  });
  hashes = await loading;
  if (timing) {
    timing.cold = 1;
    timing.block = performance.now() - start;
    timing.asset = lastLoad.asset;
    timing.body = lastLoad.body;
  }
  return hashes;
}
