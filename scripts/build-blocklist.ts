/**
 * Builds build/blocklist.bin from the sources and rules in src/config.ts.
 * Usage: bun scripts/build-blocklist.ts [out.bin]
 */

import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {dirname, join} from 'node:path';
import {buildBlockset, dropMatched, parseDomain} from './blocklist-lib.js';
import {parseCidrs} from '../src/ipv4.js';
import {pinnableRanges} from './cloudflare-probe.js';
import {
  BLOCKLIST,
  BLOCKLIST_PRECISION_BITS,
  CLOUDFLARE_IPS_URL,
  PROBE_HOST,
} from '../src/config.js';
import {
  checkPattern,
  compilePatterns,
  domainPattern,
  splitRules,
} from '../src/regexlist.js';

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

async function main() {
  const outPath = process.argv[2] ?? 'build/blocklist.bin';

  // `block` and `allow` entries are domains or /regex/ rules.
  const block = splitRules(BLOCKLIST.block);
  const allow = splitRules(BLOCKLIST.allow);
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
  for (const source of BLOCKLIST.lists) {
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
  // A domain the regex rules already block does not need a hash.
  const regex = compilePatterns(block.patterns);
  if (regex) {
    console.log(
      `${dropMatched(domains, regex)} domains dropped, already matched by regex`
    );
  }
  if (!domains.size) {
    console.warn('warning: no domains; the blocklist will be empty');
  }

  // Cloudflare's IPv4 ranges, for ech.ts. Fails the build if unusable.
  const cloudflare = (await readSource(CLOUDFLARE_IPS_URL))
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean);
  parseCidrs(cloudflare);
  console.log(
    `Trying ${cloudflare.length} Cloudflare ranges for ${PROBE_HOST}`
  );
  const pinnable = await pinnableRanges(cloudflare, PROBE_HOST);
  console.log(
    `${cloudflare.length} Cloudflare IPv4 ranges, ${pinnable.length} answer for ${PROBE_HOST}: ${pinnable.join(' ')}`
  );
  if (!pinnable.length) {
    throw new Error(`no Cloudflare range answered for ${PROBE_HOST}`);
  }

  console.log(`Encoding ${domains.size} domains`);
  const blockset = buildBlockset(domains, BLOCKLIST_PRECISION_BITS);
  // Written last, so a failed source leaves the previous files untouched.
  await mkdir(dirname(outPath), {recursive: true});
  await writeFile(
    join(dirname(outPath), 'rules.json'),
    JSON.stringify({block: block.patterns, allow: allowPatterns})
  );
  await writeFile(
    join(dirname(outPath), 'cloudflare-ips.json'),
    JSON.stringify({v4: cloudflare, pinnable})
  );
  await writeFile(outPath, blockset);
  console.log(`${blockset.byteLength} bytes -> ${outPath}`);
}

main().catch(error => {
  console.error(error.message);
  process.exit(1); // A failed source must not ship a partial list.
});
