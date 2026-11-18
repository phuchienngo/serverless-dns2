/**
 * @fileoverview Loads the prebuilt blocklist (`/blocklist.bin`, a static asset)
 * into the isolate's memory on first use.
 */

import {BLOCKLIST_PATH, RULES_PATH} from './config.js';
import {compilePatterns} from './regexlist.js';
import {HASH_WORDS, HEADER_WORDS, MAGIC} from './blockset.js';
import type {Env} from './types.js';

/** Compiled regex rules; `allow` always wins over `block` and the blocklist. */
export interface Rules {
  block: RegExp | null;
  allow: RegExp | null;
}

const RETRY_DELAY_MS = 60 * 1000;

let hashes: Uint32Array | null = null;
let rules: Rules = {block: null, allow: null};
/** True once both files loaded; until then each request retries (rate-limited). */
let ready = false;
let loading: Promise<void> | null = null;
let retryAt = 0;
/** Durations of the most recent load, in ms. */
let lastLoad = {asset: 0, body: 0};

/** Loads the regex rules; null if they could not be loaded. */
async function fetchRules(env: Env, host: string): Promise<Rules | null> {
  try {
    const response = await env.ASSETS!.fetch(`https://${host}${RULES_PATH}`);
    if (!response.ok) {
      throw new Error(`rules ${response.status}`);
    }
    const {block, allow} = (await response.json()) as {
      block?: string[];
      allow?: string[];
    };
    return {
      block: compilePatterns(block ?? []),
      allow: compilePatterns(allow ?? []),
    };
  } catch {
    return null;
  }
}

/** Loads the hash blocklist; null if it could not be loaded. */
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
    return null;
  }
}

/** Loads both files. Whatever loaded is used; a failure is retried later. */
async function load(env: Env, host: string): Promise<void> {
  const [words, loaded] = await Promise.all([
    fetchBlockset(env, host),
    fetchRules(env, host),
  ]);
  hashes = words ?? hashes;
  rules = loaded ?? rules;
  ready = !!(words && loaded);
  if (!ready) {
    retryAt = Date.now() + RETRY_DELAY_MS;
  }
}

/**
 * @return Whether the blocklist and the rules are loaded in this isolate.
 */
export function isReady(): boolean {
  return ready;
}

/**
 * @return What is loaded so far: the hash blocklist (null if none) and the
 *     regex rules.
 */
export function peekBlocklist(): Uint32Array | null {
  return hashes;
}

export function peekRules(): Rules {
  return rules;
}

/**
 * Loads the blocklist and rules if this isolate has not yet. A failed load
 * is retried after a minute; meanwhile whatever did load is used.
 */
export async function getBlocklist(
  env: Env,
  host: string,
  timing?: Record<string, number>
): Promise<void> {
  if (ready || !env.ASSETS || Date.now() < retryAt) {
    return;
  }
  const start = performance.now();
  loading ??= load(env, host).finally(() => {
    loading = null;
  });
  await loading;
  if (timing) {
    timing.cold = 1;
    timing.block = performance.now() - start;
    timing.asset = lastLoad.asset;
    timing.body = lastLoad.body;
  }
}
