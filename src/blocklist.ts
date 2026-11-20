/**
 * @fileoverview The blocklist and the regex rules built by `bun run
 * build-lists`. worker.ts bundles them with the Worker and hands them to
 * `loadBlocklist` when the isolate starts, so a request never waits for them.
 */

import {compilePatterns} from './regexlist.js';
import {decodeBlockset, type BlockSet} from './blockset.js';

/** Compiled regex rules; `allow` always wins over `block` and the blocklist. */
export interface Rules {
  block: RegExp | null;
  allow: RegExp | null;
}

let hashes: BlockSet | null = null;
let rules: Rules = {block: null, allow: null};

/**
 * Sets the blocklist and the rules in use.
 * @param buffer The contents of `blocklist.bin`.
 * @param patterns The contents of `rules.json`.
 * @throws If `buffer` is not a valid blocklist.
 */
export function loadBlocklist(
  buffer: ArrayBuffer,
  patterns: {block?: string[]; allow?: string[]}
): void {
  hashes = decodeBlockset(buffer);
  rules = {
    block: compilePatterns(patterns.block ?? []),
    allow: compilePatterns(patterns.allow ?? []),
  };
}

/** Unloads the blocklist and the rules (for tests). */
export function resetBlocklist(): void {
  hashes = null;
  rules = {block: null, allow: null};
}

/** @return The hash blocklist; null if none is loaded. */
export function peekBlocklist(): BlockSet | null {
  return hashes;
}

/** @return The regex rules. */
export function peekRules(): Rules {
  return rules;
}
