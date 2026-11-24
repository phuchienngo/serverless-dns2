/**
 * @fileoverview Log lines for what goes wrong, never for what works: one
 * object per line (not a string), so Workers Logs indexes and filters on its
 * fields. A failure also passes the error itself, so that Workers Issues
 * groups it with its stack. Each kind of line
 * is written at most once every MIN_GAP_MS in an isolate, with a count of the
 * ones held back, so an upstream that is down gives a few lines, not one per
 * request. Nothing about a request that succeeded is logged, and no client
 * address.
 */

import {LOG_LEVEL} from './config.js';

/** How much each LOG_LEVEL lets through. */
const RANK = {off: 0, error: 1, warn: 2};

/** The level a line needs to be written. */
const SEVERITY = {error: 1, warn: 2};

let level: keyof typeof RANK = LOG_LEVEL;

/** Sets the log level (for tests). */
export function setLogLevel(value: keyof typeof RANK): void {
  level = value;
}

/** Shortest time between two lines of the same kind, in ms. */
const MIN_GAP_MS = 10_000;

/** When each kind was last written, and how many were held back since. */
const kinds = new Map<string, {at: number; held: number}>();

/** Forgets what was logged (for tests). */
export function resetLog(): void {
  kinds.clear();
  level = LOG_LEVEL;
}

/**
 * @return What went wrong, in a few words: the messages of the failed tries of
 *     an `AggregateError`, `timeout` for an abort, else the error's message.
 */
export function describeError(error: unknown): string {
  if (error instanceof AggregateError) {
    return [...new Set(error.errors.map(describeError))].join('; ');
  }
  if (error instanceof Error) {
    return error.name === 'AbortError' ? 'timeout' : error.message;
  }
  return String(error);
}

/**
 * Writes one line, unless one of the same kind was written less than
 * MIN_GAP_MS ago.
 * @param severity `error` for what fails a request, `warn` for what is only
 *     slow.
 * @param error The error that was caught, if any: logged beside the line.
 */
export function logEvent(
  severity: 'error' | 'warn',
  event: string,
  fields: Record<string, string | number | boolean>,
  error?: unknown
): void {
  if (RANK[level] < SEVERITY[severity]) {
    return; // Not wanted: not counted as held back either.
  }
  const now = Date.now();
  const kind = kinds.get(event);
  if (kind && now - kind.at < MIN_GAP_MS) {
    kind.held++;
    return;
  }
  const held = kind?.held ?? 0;
  kinds.set(event, {at: now, held: 0});
  const line = {event, ...fields, ...(held ? {held} : {})};
  if (error instanceof Error) {
    console[severity](line, error);
  } else {
    console[severity](line);
  }
}
