/**
 * Builds public/blocklist.bin from blocklists.yaml.
 * Usage: tsx scripts/build-blocklist.ts [config.yaml] [out.bin]
 */

import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {dirname} from 'node:path';
import {parse} from 'yaml';
import {END_BIT, HEADER_WORDS, MAGIC, NODE_WORDS, SYMBOL} from '../src/trie.js';

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

/**
 * Builds the trie (see src/trie.ts) breadth-first from the sorted, reversed
 * domains: each node covers a range of keys sharing a prefix.
 */
function buildTrie(domains: Iterable<string>): Uint32Array {
  const keys = [...domains].map(d => [...d].reverse().join('')).sort();
  if (!keys.length) {
    return new Uint32Array([MAGIC, 1, 0, 0, 0]);
  }
  const from = [0];
  const to = [keys.length];
  const depth = [0];
  const nodes: number[] = [];
  for (let i = 0; i < from.length; i++) {
    let start = from[i];
    const d = depth[i];
    const ends = keys[start].length === d; // The shortest key sorts first.
    if (ends) {
      start++;
    }
    let low = 0;
    let high = ends ? END_BIT : 0;
    const firstChild = from.length;
    for (let s = start; s < to[i];) {
      const code = keys[s].charCodeAt(d);
      let e = s + 1;
      while (e < to[i] && keys[e].charCodeAt(d) === code) {
        e++;
      }
      if (!(ends && code === 46)) {
        // A listed parent already blocks its subdomains.
        const symbol = SYMBOL[code];
        if (symbol < 32) {
          low |= 1 << symbol;
        } else {
          high |= 1 << (symbol - 32);
        }
        from.push(s);
        to.push(e);
        depth.push(d + 1);
      }
      s = e;
    }
    nodes.push(low >>> 0, high >>> 0, firstChild);
  }
  const words = new Uint32Array(HEADER_WORDS + nodes.length);
  words[0] = MAGIC;
  words[1] = nodes.length / NODE_WORDS;
  words.set(nodes, HEADER_WORDS);
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

  const trie = buildTrie(domains);
  await mkdir(dirname(outPath), {recursive: true});
  await writeFile(outPath, new Uint8Array(trie.buffer));
  console.log(
    `${domains.size} domains -> ${trie[1]} nodes, ${trie.byteLength} bytes -> ${outPath}`
  );
}

main().catch(error => {
  console.error(error.message);
  process.exit(1); // A failed source must not ship a partial list.
});
