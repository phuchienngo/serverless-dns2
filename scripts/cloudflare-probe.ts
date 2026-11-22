/**
 * @fileoverview Finds which of Cloudflare's published ranges answer for this
 * domain when connected to by address, so the profile page (src/profile.ts)
 * only offers addresses that work. Cloudflare does not document this: some
 * ranges answer 403 or nothing.
 */

import {request} from 'node:https';

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
export async function pinnableRanges(
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
