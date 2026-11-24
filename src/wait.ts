/** @fileoverview Waiting for a promise, but not for ever. */

/** What `within` gives when the time was up first. */
export const LATE = Symbol('late');

/**
 * @return What `promise` gives, or LATE if it has not settled within `ms`; a
 *     rejection of `promise` is thrown. The timer is cleared either way, and
 *     while it runs the runtime knows the request can still make progress.
 */
export async function within<T>(
  promise: Promise<T>,
  ms: number
): Promise<T | typeof LATE> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const patience = new Promise<typeof LATE>(resolve => {
    timer = setTimeout(resolve, ms, LATE);
  });
  try {
    return await Promise.race([promise, patience]);
  } finally {
    clearTimeout(timer);
  }
}
