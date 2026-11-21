/**
 * Shows how the block and allow rules in src/config.ts treat names.
 * The downloaded lists are not checked. Usage: bun scripts/match-regex.ts name...
 */

import {BLOCKLIST} from '../src/config.js';
import {checkPattern, domainPattern, splitRules} from '../src/regexlist.js';
import {normalizeName} from '../src/wire.js';

function compileRule(pattern: string, label = pattern) {
  return {regex: new RegExp(pattern), label};
}

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
  const allowRules = allowPatterns.map(pattern => compileRule(pattern));
  const blockRules = [
    ...block.patterns.map(pattern => compileRule(pattern)),
    ...block.domains.map(domain =>
      compileRule(domainPattern(domain), `domain ${domain}`)
    ),
  ];
  const matching = (rules: ReturnType<typeof compileRule>[], name: string) =>
    rules.filter(({regex}) => regex.test(name)).map(({label}) => label);
  for (const input of process.argv.slice(2)) {
    const name = normalizeName(input);
    const allowed = matching(allowRules, name);
    const blocked = matching(blockRules, name);
    const verdict = allowed.length
      ? `allowed by ${allowed.join('  ')}`
      : blocked.length
        ? `blocked by ${blocked.join('  ')}`
        : 'no match (the downloaded lists are not checked)';
    console.log(`${input}: ${verdict}`);
  }
}

try {
  main();
} catch (error) {
  console.error((error as Error).message);
  process.exit(1);
}
