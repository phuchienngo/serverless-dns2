/**
 * Shows how the `block:` / `allow:` rules of blocklists.yaml treat names.
 * The downloaded lists are not checked. Usage: bun scripts/match-regex.ts name...
 */

import {readFile} from 'node:fs/promises';
import {parse} from 'yaml';
import {checkPattern, domainPattern, splitRules} from '../src/regexlist.js';

async function main() {
  const config = parse(await readFile('blocklists.yaml', 'utf8')) ?? {};
  const block = splitRules(config.block ?? []);
  const allow = splitRules(config.allow ?? []);
  const allowPatterns = [
    ...allow.patterns,
    ...allow.domains.map(domainPattern),
  ];
  for (const pattern of [...block.patterns, ...allowPatterns]) {
    const problem = checkPattern(pattern);
    if (problem) {
      throw new Error(`regex ${pattern}: ${problem}`);
    }
  }
  const matching = (patterns: string[], name: string) =>
    patterns.filter(p => new RegExp(p).test(name));
  for (const name of process.argv.slice(2)) {
    const allowed = matching(allowPatterns, name);
    const blocked = [
      ...matching(block.patterns, name),
      ...block.domains
        .filter(
          d => domainPattern(d) && new RegExp(domainPattern(d)).test(name)
        )
        .map(d => `domain ${d}`),
    ];
    const verdict = allowed.length
      ? `allowed by ${allowed.join('  ')}`
      : blocked.length
        ? `blocked by ${blocked.join('  ')}`
        : 'no match (the downloaded lists are not checked)';
    console.log(`${name}: ${verdict}`);
  }
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
