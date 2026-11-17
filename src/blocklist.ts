/**
 * @fileoverview Loads the prebuilt blocklist (`/blocklist.bin`, a static asset)
 * into the isolate's memory on first use.
 */

import {BLOCKLIST_PATH} from './config.js';
import type {Env} from './types.js';

const RETRY_DELAY_MS = 60 * 1000;

let trie: Uint32Array | null = null;
let loading: Promise<Uint32Array | null> | null = null;
let retryAt = 0;

async function fetchTrie(env: Env, host: string): Promise<Uint32Array | null> {
  try {
    const response = await env.ASSETS!.fetch(
      `https://${host}${BLOCKLIST_PATH}`
    );
    if (!response.ok) {
      throw new Error(`blocklist ${response.status}`);
    }
    const buffer = await response.arrayBuffer();
    return new Uint32Array(buffer, 0, buffer.byteLength >> 2);
  } catch {
    retryAt = Date.now() + RETRY_DELAY_MS;
    return null;
  }
}

/**
 * @return The blocklist, or null if there is none (or it failed to load; a
 *     failed load is retried after a minute).
 */
export async function getBlocklist(
  env: Env,
  host: string
): Promise<Uint32Array | null> {
  if (trie) {
    return trie;
  }
  if (!env.ASSETS || Date.now() < retryAt) {
    return null;
  }
  loading ??= fetchTrie(env, host).finally(() => {
    loading = null;
  });
  trie = await loading;
  return trie;
}
