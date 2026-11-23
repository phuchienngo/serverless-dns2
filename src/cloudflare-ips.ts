/**
 * @fileoverview What the build learned about Cloudflare's network
 * (`build/cloudflare-ips.json`, see scripts/cloudflare-probe.ts): its published
 * IPv4 ranges, which ech.ts uses to tell names served by Cloudflare, and what
 * the profile page (profile.ts) needs to offer addresses. worker.ts bundles the
 * file and hands it to `loadCloudflareRanges` when the isolate starts.
 */

import {parseCidrs, type Ipv4Block} from './ipv4.js';

export interface CloudflareIps {
  /** The ranges Cloudflare publishes (CLOUDFLARE_IPS_URL). */
  v4: string[];
  /** The ones among them that answered for this domain at build time. */
  pinnable: string[];
  /** The first three groups of the domain's own IPv6 addresses, if known. */
  v6prefix: string | null;
}

let blocks: Ipv4Block[] = [];
let pinning = {
  pinnable: [] as readonly string[],
  v6prefix: null as string | null,
};

/**
 * Sets what is known.
 * @param ips Missing parts are empty.
 * @throws If a published range is not a valid IPv4 range.
 */
export function loadCloudflareRanges(ips: Partial<CloudflareIps>): void {
  blocks = parseCidrs(ips.v4 ?? []);
  pinning = {pinnable: ips.pinnable ?? [], v6prefix: ips.v6prefix ?? null};
}

/** @return Cloudflare's published IPv4 ranges. */
export function getCloudflareRanges(): readonly Ipv4Block[] {
  return blocks;
}

/** @return The ranges that answer for this domain, and its IPv6 prefix. */
export function getPinning(): typeof pinning {
  return pinning;
}

/** Forgets it all (for tests). */
export function resetCloudflareRanges(): void {
  loadCloudflareRanges({});
}
