/**
 * @fileoverview The testable parts of the blocklist build: reading list lines
 * and encoding the blocked domains (see src/blockset.ts).
 */

import {
  HEADER_BYTES,
  MAGIC,
  decodeBlockset,
  hashDomain,
  isBlocked,
} from '../src/blockset.js';

const DOMAIN =
  /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$/;

/**
 * @return The domain of one list line, or null if it is not a plain domain
 *     rule (comments, regex, modifiers, IP addresses...).
 */
export function parseDomain(line: string): string | null {
  let s = line.trim();
  if (!s || /^[#!\[]/.test(s) || s.startsWith('@@')) {
    return null;
  }
  const comment = s.indexOf('#');
  if (comment > 0) {
    s = s.slice(0, comment).trim();
  }
  const hosts = s.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)$/);
  if (hosts) {
    s = hosts[1];
  } else if (s.startsWith('||')) {
    if (!s.endsWith('^')) {
      return null;
    }
    s = s.slice(2, -1);
  }
  s = s.replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
  return DOMAIN.test(s) ? s : null;
}

/**
 * Encodes the domains as a Golomb-coded set (see src/blockset.ts) and checks
 * that every domain can be found in the decoded result.
 */
export function buildBlockset(domains: Set<string>, k: number): Uint8Array {
  const kept: string[] = [];
  for (const domain of domains) {
    let covered = false;
    for (
      let dot = domain.indexOf('.');
      dot >= 0;
      dot = domain.indexOf('.', dot + 1)
    ) {
      if (domains.has(domain.slice(dot + 1))) {
        covered = true;
        break;
      }
    }
    if (!covered) {
      kept.push(domain);
    }
  }
  const bits = Math.ceil(Math.log2(Math.max(kept.length, 1))) + k;
  if (bits > 53) {
    throw new Error(`blocklist too large for ${k} precision bits`);
  }
  const values = [...new Set(kept.map(d => hashDomain(d, bits)))].sort(
    (x, y) => x - y
  );

  const header = new Uint8Array(HEADER_BYTES);
  const view = new DataView(header.buffer);
  view.setUint32(0, MAGIC, true);
  view.setUint32(4, values.length, true);
  header[8] = k;
  header[9] = bits;
  const body: number[] = [];
  let current = 0;
  let filled = 0;
  const put = (bit: number) => {
    current = (current << 1) | bit;
    if (++filled === 8) {
      body.push(current);
      current = 0;
      filled = 0;
    }
  };
  let prev = 0;
  for (const value of values) {
    const gap = value - prev;
    prev = value;
    const quotient = Math.floor(gap / 2 ** k);
    const remainder = gap - quotient * 2 ** k;
    for (let i = 0; i < quotient; i++) {
      put(1);
    }
    put(0);
    for (let i = k - 1; i >= 0; i--) {
      put(Math.floor(remainder / 2 ** i) % 2);
    }
  }
  while (filled !== 0) {
    put(0);
  }
  const out = new Uint8Array(HEADER_BYTES + body.length);
  out.set(header);
  out.set(body, HEADER_BYTES);

  const decoded = decodeBlockset(out.buffer);
  if (
    decoded.bits !== bits ||
    decoded.values.length !== values.length ||
    values.some((v, i) => decoded.values[i] !== v) ||
    kept.some(domain => !isBlocked(decoded, domain))
  ) {
    throw new Error('blocklist does not decode to what was encoded');
  }
  console.log(
    `${kept.length} domains -> ${values.length} hashes of ${bits} bits`
  );
  return out;
}

/**
 * Removes the domains that `regex` already blocks. The rule must also match a
 * subdomain of the domain ("a." + domain), because a listed domain blocks its
 * subdomains too.
 * @return The number of domains removed.
 */
export function dropMatched(domains: Set<string>, regex: RegExp): number {
  let dropped = 0;
  for (const domain of domains) {
    if (regex.test(domain) && regex.test('a.' + domain)) {
      domains.delete(domain);
      dropped++;
    }
  }
  return dropped;
}
