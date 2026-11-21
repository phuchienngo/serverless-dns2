/**
 * @fileoverview Cloudflare's published IPv4 ranges, which ech.ts uses to tell
 * names served by Cloudflare. `bun run build-lists` downloads the list
 * (CLOUDFLARE_IPS_URL); worker.ts bundles it and hands it to
 * `loadCloudflareRanges` when the isolate starts.
 */

import {parseCidrs, type Ipv4Block} from './ipv4.js';

let blocks: Ipv4Block[] = [];

/**
 * Sets the ranges.
 * @param v4 CIDR strings.
 * @throws If one is not a valid IPv4 range.
 */
export function loadCloudflareRanges(v4: string[]): void {
  blocks = parseCidrs(v4);
}

/** @return Cloudflare's IPv4 ranges. */
export function getCloudflareRanges(): readonly Ipv4Block[] {
  return blocks;
}

/** Forgets the ranges (for tests). */
export function resetCloudflareRanges(): void {
  blocks = [];
}
