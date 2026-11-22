/**
 * @fileoverview Cloudflare's published IPv4 ranges, which ech.ts uses to tell
 * names served by Cloudflare. `bun run build-lists` downloads the list
 * (CLOUDFLARE_IPS_URL); worker.ts bundles it and hands it to
 * `loadCloudflareRanges` when the isolate starts. It also holds the ranges
 * that answered for this domain when the build tried them (the profile page
 * offers addresses from those).
 */

import {parseCidrs, type Ipv4Block} from './ipv4.js';

let blocks: Ipv4Block[] = [];
let pinnable: string[] = [];
let prefix6: string | null = null;

/**
 * Sets the ranges.
 * @param v4 CIDR strings.
 * @param answering The ones among them that answer for this domain.
 * @param v6prefix The first three groups of the domain's own IPv6 addresses.
 * @throws If one is not a valid IPv4 range.
 */
export function loadCloudflareRanges(
  v4: string[],
  answering: string[] = [],
  v6prefix: string | null = null
): void {
  blocks = parseCidrs(v4);
  pinnable = answering.filter(cidr => v4.includes(cidr));
  prefix6 = v6prefix;
}

/** @return The IPv6 prefix of this domain's addresses, if known. */
export function getV6Prefix(): string | null {
  return prefix6;
}

/** @return The ranges that answered for this domain at build time. */
export function getPinnableRanges(): readonly string[] {
  return pinnable;
}

/** @return Cloudflare's IPv4 ranges. */
export function getCloudflareRanges(): readonly Ipv4Block[] {
  return blocks;
}

/** Forgets the ranges (for tests). */
export function resetCloudflareRanges(): void {
  blocks = [];
  pinnable = [];
  prefix6 = null;
}
