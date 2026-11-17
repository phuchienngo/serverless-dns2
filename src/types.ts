/** @fileoverview Types shared by the gateway's modules. */

/**
 * A parsed DNS question. `name` is lower-cased for lookups, while `raw` keeps
 * the original question bytes (name, type, class) so the client's 0x20 case
 * survives.
 */
export interface Question {
  id: number;
  name: string;
  type: number;
  raw: number[];
}

/** An answer ready to send back to the client. */
export interface Result {
  body: Uint8Array;
  ttl: number;
  hit?: boolean;
}

export interface Env {
  /** URL of the upstream DoH resolver. */
  UPSTREAM: string;
}

/** Per-request values supplied by the platform adapter. */
export interface Context {
  env: Env;
  ip: string | null;
  cache?: Cache;
  waitUntil?: (promise: Promise<unknown>) => void;
}

export interface ResolveOptions extends Context {
  host: string;
  /** Overrides the subnet derived from `ip`; null sends none. */
  ecs?: number[] | null;
  dnssec?: boolean;
  cd?: boolean;
}
