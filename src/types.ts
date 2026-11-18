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
  /** Whether the query carried an EDNS (OPT) record. */
  edns: boolean;
  /** The DO bit of that record: the client wants DNSSEC records. */
  dnssecOk: boolean;
  /** The CD (checking disabled) flag of the query. */
  cd: boolean;
  /** The AD flag of the query: the client wants to know if answers validated. */
  ad: boolean;
  /** The RD flag, which a response copies. */
  rd: boolean;
  opcode: number;
  /** EDNS version of the query's OPT record (0 if there is none). */
  ednsVersion: number;
  /** Whether the query has an EDNS Padding option (RFC 7830). */
  padding: boolean;
}

/** An answer ready to send back to the client. */
export interface Result {
  body: Uint8Array;
  ttl: number;
  hit?: boolean;
  /** Served past its TTL (RFC 8767). */
  stale?: boolean;
}

export interface Env {
  /** Static assets of the Pages project; holds the blocklist. */
  ASSETS?: Fetcher;
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
  /** Ask for the AD flag even without DO (RFC 6840 5.7). */
  ad?: boolean;
  /** Filled with durations in ms (see `serverTiming`). */
  timing?: Record<string, number>;
}
