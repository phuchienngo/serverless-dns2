/**
 * Shows how the block and allow rules in src/config.ts treat names.
 * The downloaded lists are not checked. Usage: bun scripts/match-regex.ts name...
 */

import {BLOCKLIST} from '../src/config.js';
import {checkPattern, domainPattern, splitRules} from '../src/regexlist.js';

function main() {
  const block = splitRules(BLOCKLIST.block);
  const allow = splitRules(BLOCKLIST.allow);
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

try {
  main();
} catch (error) {
  console.error((error as Error).message);
  process.exit(1);
}
