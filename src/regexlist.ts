/**
 * @fileoverview Regex blocking rules (`regex:` in blocklists.yaml).
 *
 * JavaScript regexes backtrack, so a bad pattern can take exponential time.
 * Patterns are limited to a safe subset (no lookaround, no backreferences, no
 * nested quantifiers) which makes matching a short domain name linear in
 * practice. The build rejects anything else.
 */

const UNSAFE: Array<[RegExp, string]> = [
  [/\(\?<?[=!]/, 'lookaround'],
  [/\\[1-9]|\\k</, 'backreference'],
  // A group that ends in a quantifier and is itself quantified: (a+)+ (a*)* ...
  [/\((?:[^()\\]|\\.)*[+*}]\)[+*{]/, 'nested quantifier'],
];

/**
 * @return Why the pattern is not allowed, or null if it is fine.
 */
export function checkPattern(pattern: string): string | null {
  for (const [bad, reason] of UNSAFE) {
    if (bad.test(pattern)) {
      return reason;
    }
  }
  try {
    new RegExp(pattern);
  } catch (error) {
    return (error as Error).message;
  }
  return null;
}

/**
 * Splits `block:` / `allow:` entries: `/pattern/` is a regex, anything else is
 * a domain (which also covers its subdomains).
 */
export function splitRules(entries: string[]): {
  domains: string[];
  patterns: string[];
} {
  const domains: string[] = [];
  const patterns: string[] = [];
  for (const raw of entries) {
    const entry = raw.trim();
    if (entry.length > 2 && entry.startsWith('/') && entry.endsWith('/')) {
      patterns.push(entry.slice(1, -1));
    } else if (entry) {
      domains.push(entry.toLowerCase());
    }
  }
  return {domains, patterns};
}

/** @return A pattern matching `domain` and its subdomains. */
export function domainPattern(domain: string): string {
  return `(^|\\.)${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`;
}

/**
 * @return One regex matching any of the patterns, or null if there are none.
 */
export function compilePatterns(patterns: string[]): RegExp | null {
  if (!patterns.length) {
    return null;
  }
  return new RegExp(patterns.map(p => `(?:${p})`).join('|'));
}
