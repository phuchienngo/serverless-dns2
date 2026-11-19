/**
 * @fileoverview A value loaded on first use and kept in the isolate's memory:
 * callers that ask while it loads share one load, and a failed load is not
 * retried at once.
 */

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

  /** @return The value; null if it cannot be had (yet). */
  get(arg: Arg): Promise<Value | null> {
    const now = Date.now();
    if (this.value !== null && now < this.expires) {
      return Promise.resolve(this.value);
    }
    if (now < this.retryAt) {
      return Promise.resolve(null);
    }
    this.loading ??= this.load(arg)
      .catch(() => null)
      .then(loaded => {
        this.value = loaded;
        this.expires = Date.now() + this.ttlMs;
        this.retryAt = loaded === null ? Date.now() + this.retryMs : 0;
        return loaded;
      })
      .finally(() => {
        this.loading = null;
      });
    return this.loading;
  }

  /** Forgets the value and any failure (for tests). */
  reset(): void {
    this.value = null;
    this.expires = Infinity;
    this.loading = null;
    this.retryAt = 0;
  }
}
