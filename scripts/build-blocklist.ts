/**
 * Builds public/blocklist.bin from blocklists.yaml.
 * Usage: tsx scripts/build-blocklist.ts [config.yaml] [out.bin]
 */

import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {dirname, join} from 'node:path';
import {parse} from 'yaml';
import {
  HEADER_BYTES,
  MAGIC,
  decodeBlockset,
  hashDomain,
  isBlocked,
} from '../src/blockset.js';
import {BLOCKLIST_PRECISION_BITS} from '../src/config.js';
import {
  checkPattern,
  compilePatterns,
  domainPattern,
  splitRules,
} from '../src/regexlist.js';

const DOMAIN =
  /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$/;

interface Config {
  lists?: string[];
  allow?: string[];
  block?: string[];
}

/**
 * @return The domain of one list line, or null if it is not a plain domain
 *     rule (comments, regex, modifiers, IP addresses...).
 */
function parseDomain(line: string): string | null {
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

async function readSource(source: string): Promise<string> {
  if (!/^https?:\/\//.test(source)) {
    return readFile(source, 'utf8');
  }
  const response = await fetch(source, {signal: AbortSignal.timeout(60000)});
  if (!response.ok) {
    throw new Error(`${source}: HTTP ${response.status}`);
  }
  return response.text();
}

/**
 * Encodes the domains as a Golomb-coded set (see src/blockset.ts) and checks
 * that every domain can be found in the decoded result.
 */
function buildBlockset(domains: Set<string>, k: number): Uint8Array {
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

async function main() {
  const [configPath = 'blocklists.yaml', outPath = 'public/blocklist.bin'] =
    process.argv.slice(2);
  const config: Config = parse(await readFile(configPath, 'utf8')) ?? {};

  // `block` and `allow` entries are domains or /regex/ rules.
  const block = splitRules(config.block ?? []);
  const allow = splitRules(config.allow ?? []);
  for (const pattern of [...block.patterns, ...allow.patterns]) {
    const problem = checkPattern(pattern);
    if (problem) {
      throw new Error(`regex ${pattern}: ${problem}`);
    }
  }
  // An allowed domain also allows its subdomains, and wins over every block
  // rule at query time, so it becomes a regex rule too.
  const allowPatterns = [
    ...allow.patterns,
    ...allow.domains.map(domainPattern),
  ];
  // The runtime joins the patterns of each group into one regex, so check
  // that the joined regex compiles (e.g. no duplicate named groups).
  for (const group of [block.patterns, allowPatterns]) {
    try {
      compilePatterns(group);
    } catch (error) {
      throw new Error(
        `regex rules do not combine: ${(error as Error).message}`
      );
    }
  }
  console.log(
    `${block.patterns.length} block regex, ${allowPatterns.length} allow rules`
  );

  const domains = new Set<string>();
  for (const source of config.lists ?? []) {
    const before = domains.size;
    let total = 0;
    for (const line of (await readSource(source)).split(/\r?\n/)) {
      const domain = parseDomain(line);
      if (domain) {
        total++;
        domains.add(domain);
      }
    }
    console.log(`${source}: ${total} domains, ${domains.size - before} new`);
  }
  for (const domain of block.domains) {
    domains.add(domain);
  }
  // A domain the regex rules already block does not need a hash. The rule must
  // also match a subdomain of it ("a." + domain), because a listed domain
  // blocks its subdomains too.
  const regex = compilePatterns(block.patterns);
  if (regex) {
    let dropped = 0;
    for (const domain of domains) {
      if (regex.test(domain) && regex.test('a.' + domain)) {
        domains.delete(domain);
        dropped++;
      }
    }
    console.log(`${dropped} domains dropped, already matched by regex`);
  }
  if (!domains.size) {
    console.warn('warning: no domains; the blocklist will be empty');
  }

  const blockset = buildBlockset(domains, BLOCKLIST_PRECISION_BITS);
  // Written last, so a failed source leaves the previous files untouched.
  await mkdir(dirname(outPath), {recursive: true});
  await writeFile(
    join(dirname(outPath), 'rules.json'),
    JSON.stringify({block: block.patterns, allow: allowPatterns})
  );
  await writeFile(outPath, blockset);
  console.log(`${blockset.byteLength} bytes -> ${outPath}`);
}

main().catch(error => {
  console.error(error.message);
  process.exit(1); // A failed source must not ship a partial list.
});
