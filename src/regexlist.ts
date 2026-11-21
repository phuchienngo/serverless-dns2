/** @fileoverview Regex allow and block rules. */

const UNSAFE: Array<[RegExp, string]> = [
  [/\(\?<?[=!]/, 'lookaround'],
  [/\\[1-9]|\\k</, 'backreference'],
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
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === '\\') {
      i++;
    } else if (char === '[') {
      inClass = true;
    } else if (char === ']') {
      inClass = false;
    } else if (
      !inClass &&
      char === ')' &&
      /[+*{]/.test(pattern.charAt(i + 1))
    ) {
      return 'repeated group';
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
export function splitRules(entries: readonly string[]): {
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
