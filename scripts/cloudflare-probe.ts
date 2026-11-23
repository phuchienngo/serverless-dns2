/**
 * @fileoverview Finds which of Cloudflare's published ranges answer for this
 * domain when connected to by address, so the profile page (src/profile.ts)
 * only offers addresses that work. Cloudflare does not document this: some
 * ranges answer 403 or nothing.
 */

import {resolve6} from 'node:dns/promises';
import {request} from 'node:https';
import type {CloudflareIps} from '../src/cloudflare-ips.js';

/** Longest wait for one address, in ms. */
const TIMEOUT_MS = 5000;

/**
 * @param cidr A range such as `172.64.0.0/13`.
 * @return Eight addresses spread evenly over the range (a range answers in
 *     some places and not in others, so a few at the start are not enough).
 */
export function sampleAddresses(cidr: string): string[] {
  const [base, prefix] = cidr.split('/');
  const size = 2 ** (32 - Number(prefix));
  const start = base
    .split('.')
    .reduce((sum, part) => sum * 256 + Number(part), 0);
  const at = (n: number) =>
    [24, 16, 8, 0].map(shift => Math.floor(n / 2 ** shift) % 256).join('.');
  const offsets = Array.from(
    {length: 8},
    (_, i) => Math.floor((i * size) / 8) + 1
  );
  return [...new Set(offsets)]
    .filter(o => o < size - 1)
    .map(o => at(start + o));
}

/** @return Whether `host` answers 200 on `/cdn-cgi/trace` at this address. */
function answers(address: string, host: string): Promise<boolean> {
  return new Promise(resolve => {
    const req = request(
      {
        hostname: address,
        servername: host,
        headers: {host},
        path: '/cdn-cgi/trace',
        timeout: TIMEOUT_MS,
      },
      res => {
        res.resume();
        resolve(res.statusCode === 200);
      }
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end();
  });
}

/**
 * @param ranges CIDR ranges to try.
 * @param host The domain to ask for.
 * @return The ranges where at least one sample address answered 200.
 */
async function pinnableRanges(
  ranges: string[],
  host: string
): Promise<string[]> {
  const results = await Promise.all(
    ranges.map(async cidr => {
      const found = await Promise.all(
        sampleAddresses(cidr).map(address => answers(address, host))
      );
      const answered = found.filter(Boolean).length;
      console.log(`${cidr}: ${answered}/${found.length} addresses answered`);
      return answered > 0;
    })
  );
  return ranges.filter((_, i) => results[i]);
}

/**
 * Cloudflare serves a domain at `<prefix>::<an IPv4 address in two hex groups>`
 * for every IPv4 address that serves it (checked by hand, undocumented). The
 * prefix is that of the domain's own AAAA records.
 * @param aaaa The domain's AAAA records, as the resolver writes them.
 * @return The first three groups of the first record, or null if it has none
 *     written as `a:b:c::...`.
 */
export function v6Prefix(aaaa: string[]): string | null {
  const match = /^([0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4})::/i.exec(
    aaaa[0] ?? ''
  );
  return match ? match[1].toLowerCase() : null;
}

/**
 * Learns what the profile page needs: which of the published ranges answer for
 * `host`, and its IPv6 prefix (a DNS lookup, so no IPv6 is needed here, which
 * a GitHub runner does not have).
 * @throws If no range answers.
 */
export async function describeCloudflare(
  published: string[],
  host: string
): Promise<CloudflareIps> {
  console.log(`Trying ${published.length} Cloudflare ranges for ${host}`);
  const pinnable = await pinnableRanges(published, host);
  console.log(`${pinnable.length} answer: ${pinnable.join(' ')}`);
  if (!pinnable.length) {
    throw new Error(`no Cloudflare range answered for ${host}`);
  }
  const v6prefix = v6Prefix(await resolve6(host).catch(() => []));
  console.log(
    v6prefix
      ? `IPv6 prefix of ${host}: ${v6prefix}`
      : `no IPv6 prefix for ${host}: the profile page will offer IPv4 only`
  );
  return {v4: published, pinnable, v6prefix};
}
