/**
 * @fileoverview Work that several requests wait for. The runtime warns, and
 * drops what it queued, when work belonging to one request settles a promise
 * of another request that has been cancelled or has ended: a client that
 * leaves would leave such a promise behind. So the work only records its
 * outcome in a plain field, and each waiter looks at it with a timer of its
 * own, which goes away with the request: nothing crosses from one request to
 * the other.
 */

/** What `Flight.waitFor` gives when the time was up first. */
export const LATE = Symbol('late');

/** How often a waiter looks at the work, in ms. */
export const POLL_MS = 2;

/** A timer, or none yet. */
type Timer = ReturnType<typeof setTimeout> | null;

/** Stops a timer that may be running. */
const cancel = (timer: Timer) => clearTimeout(timer as number | null);

type Outcome<T> = {value: T} | {error: unknown};

/** A waiter that can leave. */
export interface Waiting<T> {
  /** Settles like the work does; never if the waiter has left. */
  result: Promise<T>;
  /** Stops the waiter looking at the work. */
  leave(): void;
}

export class Flight<T> {
  private outcome: Outcome<T> | null = null;
  private watching = 0;

  constructor(work: Promise<T>) {
    work.then(
      value => void (this.outcome = {value}),
      error => void (this.outcome = {error})
    );
  }

  /** How many waiters are still looking at the work (for tests). */
  get attached(): number {
    return this.watching;
  }

  /** @return A waiter for the work's outcome. */
  wait(): Waiting<T> {
    let timer: Timer = null;
    let looking = true;
    const stop = () => {
      if (looking) {
        looking = false;
        this.watching--;
      }
      cancel(timer);
    };
    this.watching++;
    const result = new Promise<T>((resolve, reject) => {
      const look = () => {
        const outcome = this.outcome;
        if (!outcome) {
          timer = setTimeout(look, POLL_MS);
          return;
        }
        stop();
        if ('error' in outcome) {
          reject(outcome.error);
        } else {
          resolve(outcome.value);
        }
      };
      look();
    });
    return {result, leave: stop};
  }

  /**
   * @return What the work gives, or LATE if it has not settled within `ms`; a
   *     failure of the work is thrown. The waiter has left by then, either way.
   */
  async waitFor(ms: number): Promise<T | typeof LATE> {
    const waiting = this.wait();
    let timer: Timer = null;
    const patience = new Promise<typeof LATE>(resolve => {
      timer = setTimeout(resolve, ms, LATE);
    });
    try {
      return await Promise.race([waiting.result, patience]);
    } finally {
      cancel(timer);
      waiting.leave();
    }
  }
}
