/**
 * @fileoverview A value loaded on first use and kept in the isolate's memory:
 * callers that ask while it loads share one load, and a failed load is not
 * retried at once. A caller does not wait long for a load that another request
 * started: that request may be gone, and then the load never ends.
 */

import {SHARED_WAIT_MS} from './config.js';
import {Flight, LATE} from './wait.js';

export const RETRY_DELAY_MS = 60 * 1000;

export class Loaded<Arg, Value> {
  private value: Value | null = null;
  private expires = Infinity;
  private flight: Flight<Value | null> | null = null;
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

  /**
   * Starts a load; its result is kept unless another load took its place.
   * @param keepAlive Keeps the request running until the load is done: other
   *     requests wait for it.
   */
  private start(
    arg: Arg,
    keepAlive?: (work: Promise<unknown>) => void
  ): Promise<Value | null> {
    const loading: Promise<Value | null> = this.load(arg)
      .catch(() => null)
      .then(loaded => {
        if (this.flight === flight) {
          this.value = loaded;
          this.expires = Date.now() + this.ttlMs;
          this.retryAt = loaded === null ? Date.now() + this.retryMs : 0;
        }
        return loaded;
      })
      .finally(() => {
        if (this.flight === flight) {
          this.flight = null;
        }
      });
    const flight = new Flight(loading);
    this.flight = flight;
    keepAlive?.(loading);
    return loading;
  }

  /**
   * @param keepAlive Keeps the request running until a load that this call
   *     starts is done.
   * @return The value; null if it cannot be had (yet).
   */
  get(
    arg: Arg,
    keepAlive?: (work: Promise<unknown>) => void
  ): Promise<Value | null> {
    const now = Date.now();
    if (this.value !== null && now < this.expires) {
      return Promise.resolve(this.value);
    }
    if (now < this.retryAt) {
      return Promise.resolve(null);
    }
    const flight = this.flight;
    return flight
      ? this.join(flight, arg, keepAlive)
      : this.start(arg, keepAlive);
  }

  /**
   * Waits for a load that is under way, at most SHARED_WAIT_MS; after that
   * loads again (this load becomes the one others join) and takes whichever
   * ends first.
   */
  private async join(
    flight: Flight<Value | null>,
    arg: Arg,
    keepAlive?: (work: Promise<unknown>) => void
  ): Promise<Value | null> {
    const loaded = await flight.waitFor(SHARED_WAIT_MS);
    if (loaded !== LATE) {
      return loaded;
    }
    const own = this.start(arg, keepAlive);
    const waiting = flight.wait();
    try {
      return await Promise.race([waiting.result, own]);
    } finally {
      waiting.leave();
    }
  }

  /** Forgets the value and any failure (for tests). */
  reset(): void {
    this.value = null;
    this.expires = Infinity;
    this.flight = null;
    this.retryAt = 0;
  }
}
