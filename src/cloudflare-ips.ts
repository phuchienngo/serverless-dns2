/**
 * @fileoverview Cloudflare's published IPv4 ranges, which ech.ts uses to tell
 * names served by Cloudflare. `npm run build-lists` downloads the list
 * (CLOUDFLARE_IPS_URL) into a static asset; each isolate loads it on first use.
 */

import {fetchAsset} from './assets.js';
import {CLOUDFLARE_IPS_PATH} from './config.js';
import {parseCidrs, type Ipv4Block} from './ipv4.js';
import {Loaded} from './loaded.js';
import type {Env} from './types.js';

const ranges = new Loaded(async ({env, host}: {env: Env; host: string}) => {
  const response = await fetchAsset(env, host, CLOUDFLARE_IPS_PATH);
  const {v4} = (await response.json()) as {v4?: string[]};
  const blocks = parseCidrs(v4 ?? []);
  return blocks.length ? blocks : null;
});

/**
 * @return Cloudflare's IPv4 ranges, loaded once per isolate; null if they
 *     cannot be had (a failed load is retried after a minute).
 */
export function getCloudflareRanges(
  env: Env,
  host: string
): Promise<Ipv4Block[] | null> {
  return env.ASSETS ? ranges.get({env, host}) : Promise.resolve(null);
}

/** Forgets the loaded ranges (for tests). */
export function resetCloudflareRanges(): void {
  ranges.reset();
}
