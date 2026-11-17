/**
 * Builds public/blocklist.bin from blocklists.yaml.
 * Usage: tsx scripts/build-blocklist.ts [config.yaml] [out.bin]
 */

import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {dirname} from 'node:path';
import {parse} from 'yaml';
import {HEADER_WORDS, MAGIC, NODE_WORDS, hashLabel} from '../src/trie.js';

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

interface TrieNode {
  hash: [number, number];
  end: boolean;
  children: Map<string, TrieNode>;
}

function buildTrie(domains: Iterable<string>): Uint32Array {
  const root: TrieNode = {hash: [0, 0], end: false, children: new Map()};
  for (const domain of domains) {
    let node = root;
    let covered = false;
    for (const label of domain.split('.').reverse()) {
      if (node.end) {
        covered = true; // A parent domain is already blocked.
        break;
      }
      const hash = hashLabel(label);
      const key = `${hash[0]}:${hash[1]}`;
      let child = node.children.get(key);
      if (!child) {
        child = {hash, end: false, children: new Map()};
        node.children.set(key, child);
      }
      node = child;
    }
    if (!covered) {
      node.end = true;
      node.children.clear(); // The parent now covers all of them.
    }
  }

  // Breadth-first, so the children of a node are contiguous.
  const order = [root];
  const firstChild: number[] = [];
  for (let i = 0; i < order.length; i++) {
    firstChild[i] = order.length;
    const kids = [...order[i].children.values()].sort(
      (a, b) => a.hash[0] - b.hash[0] || a.hash[1] - b.hash[1]
    );
    order.push(...kids);
  }
  const words = new Uint32Array(HEADER_WORDS + order.length * NODE_WORDS);
  words[0] = MAGIC;
  words[1] = order.length;
  order.forEach((node, i) => {
    const base = HEADER_WORDS + i * NODE_WORDS;
    words[base] = node.hash[0];
    words[base + 1] = node.hash[1];
    words[base + 2] = firstChild[i];
    words[base + 3] = (node.children.size << 1) | (node.end ? 1 : 0);
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
