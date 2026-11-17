/**
 * Builds public/blocklist.bin from blocklists.yaml.
 * Usage: tsx scripts/build-blocklist.ts [config.yaml] [out.bin]
 */

import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {dirname} from 'node:path';
import {parse} from 'yaml';
import {HEADER_WORDS, HASH_WORDS, MAGIC, hashDomain} from '../src/blockset.js';

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

/** True if `name` is `parent` or one of its subdomains. */
function isUnder(name: string, parent: string): boolean {
  return name === parent || name.endsWith('.' + parent);
}

function buildHashes(domains: Set<string>): Uint32Array {
  const entries: Array<{name: string; hash: [number, number]}> = [];
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
      entries.push({name: domain, hash: hashDomain(domain)});
    }
  }
  entries.sort((a, b) => a.hash[0] - b.hash[0] || a.hash[1] - b.hash[1]);
  const words = new Uint32Array(HEADER_WORDS + entries.length * HASH_WORDS);
  words[0] = MAGIC;
  words[1] = entries.length;
  entries.forEach((entry, i) => {
    if (
      i > 0 &&
      entry.hash[0] === entries[i - 1].hash[0] &&
      entry.hash[1] === entries[i - 1].hash[1]
    ) {
      throw new Error(`hash collision: ${entries[i - 1].name}, ${entry.name}`);
    }
    words.set(entry.hash, HEADER_WORDS + i * HASH_WORDS);
  });
  return words;
}

async function main() {
  const [configPath = 'blocklists.yaml', outPath = 'public/blocklist.bin'] =
    process.argv.slice(2);
  const config: Config = parse(await readFile(configPath, 'utf8')) ?? {};
  const lists = config.lists ?? [];
  const allow = (config.allow ?? []).map(d => d.trim().toLowerCase());

  const domains = new Set<string>();
  for (const source of lists) {
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
  for (const domain of config.block ?? []) {
    domains.add(domain.trim().toLowerCase());
  }
  for (const domain of domains) {
    if (allow.some(parent => isUnder(domain, parent))) {
      domains.delete(domain);
    }
  }
  if (!domains.size) {
    console.warn('warning: no domains; the blocklist will be empty');
  }

  const hashes = buildHashes(domains);
  await mkdir(dirname(outPath), {recursive: true});
  await writeFile(outPath, new Uint8Array(hashes.buffer));
  console.log(
    `${domains.size} domains -> ${hashes[1]} hashes, ${hashes.byteLength} bytes -> ${outPath}`
  );
}

main().catch(error => {
  console.error(error.message);
  process.exit(1); // A failed source must not ship a partial list.
});
