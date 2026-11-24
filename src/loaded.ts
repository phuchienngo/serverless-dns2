/**
 * @fileoverview A value loaded on first use and kept in the isolate's memory:
 * callers that ask while it loads share one load, and a failed load is not
 * retried at once. A caller does not wait long for a load that another request
 * started: that request may be gone, and then the load never ends.
 */

import {SHARED_WAIT_MS} from './config.js';
import {LATE, within} from './wait.js';

export const RETRY_DELAY_MS = 60 * 1000;

export class Loaded<Arg, Value> {
  private value: Value | null = null;
  private expires = Infinity;
  private loading: Promise<Value | null> | null = null;
  private retryAt = 0;

  /**
   * @param load Loads the value; a throw or a null is a failure.
   * @param ttlMs How long the value is kept; for ever by default.
   * @param retryMs How long to wait after a failure before loading again.
   */
  constructor(
    private readonly load: (arg: Arg) => Promise<Value | null>,
    private readonly ttlMs = Infinity,
    private readonly retryMs = RETRY_DELAY_MS
  ) {}

  /** Starts a load; its result is kept unless another load took its place. */
  private start(arg: Arg): Promise<Value | null> {
    const loading: Promise<Value | null> = this.load(arg)
      .catch(() => null)
      .then(loaded => {
        if (this.loading === loading) {
          this.value = loaded;
          this.expires = Date.now() + this.ttlMs;
          this.retryAt = loaded === null ? Date.now() + this.retryMs : 0;
        }
        return loaded;
      })
      .finally(() => {
        if (this.loading === loading) {
          this.loading = null;
        }
      });
    this.loading = loading;
    return loading;
  }

  /** @return The value; null if it cannot be had (yet). */
  get(arg: Arg): Promise<Value | null> {
    const now = Date.now();
    if (this.value !== null && now < this.expires) {
      return Promise.resolve(this.value);
    }
    if (now < this.retryAt) {
      return Promise.resolve(null);
    }
    const loading = this.loading;
    return loading ? this.join(loading, arg) : this.start(arg);
  }

  /**
   * Waits for a load that is under way, at most SHARED_WAIT_MS; after that
   * loads again (this load becomes the one others join) and takes whichever
   * ends first.
   */
  private async join(
    loading: Promise<Value | null>,
    arg: Arg
  ): Promise<Value | null> {
    const loaded = await within(loading, SHARED_WAIT_MS);
    if (loaded !== LATE) {
      return loaded;
    }
    return Promise.race([loading, this.start(arg)]);
  }

  /** Forgets the value and any failure (for tests). */
  reset(): void {
    this.value = null;
    this.expires = Infinity;
    this.loading = null;
    this.retryAt = 0;
  }
}
