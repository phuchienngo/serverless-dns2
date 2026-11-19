/**
 * @fileoverview Cloudflare's published IPv4 ranges, which ech.ts uses to tell
 * names served by Cloudflare. `npm run build-lists` downloads the list
 * (CLOUDFLARE_IPS_URL) into a static asset; each isolate loads it on first use.
 */

import {CLOUDFLARE_IPS_PATH} from './config.js';
import {parseCidrs, type Ipv4Block} from './ipv4.js';
import type {Env} from './types.js';

const RETRY_DELAY_MS = 60 * 1000;

let ranges: Ipv4Block[] | null = null;
let loading: Promise<Ipv4Block[] | null> | null = null;
let retryAt = 0;

/** Forgets the loaded ranges (for tests). */
export function resetCloudflareRanges(): void {
  ranges = null;
  loading = null;
  retryAt = 0;
}

async function load(env: Env, host: string): Promise<Ipv4Block[] | null> {
  try {
    const response = await env.ASSETS!.fetch(
      `https://${host}${CLOUDFLARE_IPS_PATH}`
    );
    if (!response.ok) {
      throw new Error(`cloudflare ips ${response.status}`);
    }
    const {v4} = (await response.json()) as {v4?: string[]};
    const loaded = parseCidrs(v4 ?? []);
    if (!loaded.length) {
      throw new Error('no cloudflare ranges');
    }
    ranges = loaded;
    return loaded;
  } catch {
    retryAt = Date.now() + RETRY_DELAY_MS; // Not loaded: tried again later.
    return null;
  }
}

/**
 * @return Cloudflare's IPv4 ranges, loaded once per isolate; null if they
 *     cannot be had (a failed load is retried after a minute).
 */
export function getCloudflareRanges(
  env: Env,
  host: string
): Promise<Ipv4Block[] | null> {
  if (ranges) {
    return Promise.resolve(ranges);
  }
  if (!env.ASSETS || Date.now() < retryAt) {
    return Promise.resolve(null);
  }
  loading ??= load(env, host).finally(() => {
    loading = null;
  });
  return loading;
}
