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
  /** The EDNS Cookie option (RFC 7873): client cookie, then server cookie. */
  cookie: number[] | null;
  /** The data of the EDNS Client Subnet option (RFC 7871), as sent. */
  ecs: Uint8Array | null;
  /** The OPT record is invalid (RFC 6891 6.1.1): answer FORMERR. */
  malformed: boolean;
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
  /** Static assets of the Worker; holds the blocklist. */
  ASSETS?: Fetcher;
  /** Secret for DNS Cookies (RFC 7873); without it cookies are ignored. */
  COOKIE_SECRET?: string;
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
  /**
   * Overrides the subnet derived from `ip`; null sends none. An option with
   * source prefix 0 is the client asking not to be located.
   */
  ecs?: number[] | null;
  /** Synthesize AAAA records from A records (DNS64, RFC 6147). */
  dns64?: boolean;
  /** Filled with durations in ms (see `serverTiming`). */
  timing?: Record<string, number>;
}
