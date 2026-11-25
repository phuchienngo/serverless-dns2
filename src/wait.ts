/**
 * @fileoverview Work that several requests wait for. The runtime warns, and
 * cancels the continuation, when a promise that a request is waiting on is
 * settled after that request has ended. So a waiter registers with the work
 * and, when it has what it needs, takes its name off again: nothing of it is
 * left attached to work that belongs to another request.
 */

/** What `Flight.waitFor` gives when the time was up first. */
export const LATE = Symbol('late');

type Outcome<T> = {value: T} | {error: unknown};

/** A waiter that can leave. */
export interface Waiting<T> {
  /** Settles like the work does; never if the waiter has left. */
  result: Promise<T>;
  /** Takes the waiter off the work. */
  leave(): void;
}

export class Flight<T> {
  private outcome: Outcome<T> | null = null;
  private readonly waiters = new Set<(outcome: Outcome<T>) => void>();

  constructor(work: Promise<T>) {
    const settle = (outcome: Outcome<T>) => {
      this.outcome = outcome;
      for (const wake of this.waiters) {
        wake(outcome);
      }
      this.waiters.clear();
    };
    work.then(
      value => settle({value}),
      error => settle({error})
    );
  }

  /** How many waiters are attached to the work (for tests). */
  get attached(): number {
    return this.waiters.size;
  }

  /** @return A waiter for the work's outcome. */
  wait(): Waiting<T> {
    let leave = () => {};
    const result = new Promise<T>((resolve, reject) => {
      const wake = (outcome: Outcome<T>) => {
        if ('error' in outcome) {
          reject(outcome.error);
        } else {
          resolve(outcome.value);
        }
      };
      leave = () => void this.waiters.delete(wake);
      if (this.outcome) {
        wake(this.outcome);
      } else {
        this.waiters.add(wake);
      }
    });
    return {result, leave: () => leave()};
  }

  /**
   * @return What the work gives, or LATE if it has not settled within `ms`; a
   *     failure of the work is thrown. The waiter has left by then, either way.
   */
  async waitFor(ms: number): Promise<T | typeof LATE> {
    const waiting = this.wait();
    let timer: ReturnType<typeof setTimeout> | null = null;
    const patience = new Promise<typeof LATE>(resolve => {
      timer = setTimeout(resolve, ms, LATE);
    });
    try {
      return await Promise.race([waiting.result, patience]);
    } finally {
      clearTimeout(timer);
      waiting.leave();
    }
  }
}
