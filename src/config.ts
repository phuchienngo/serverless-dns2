/** @fileoverview Tunable constants for the DoH gateway. */

/** Whether to attach the client's subnet (EDNS Client Subnet) to queries. */
export const ECS_ENABLED = true;

/** Largest DNS message accepted, in bytes (same limit as Google). */
export const MAX_QUERY = 512;

/** Longest `dns=` parameter accepted (base64url of 512 bytes is 683 chars). */
export const MAX_DNS_PARAM = 700;

/** How long to wait for the upstream resolver. */
export const UPSTREAM_TIMEOUT_MS = 4000;

/** Answers kept in the isolate's memory, in front of the Cache API. */
export const LOCAL_CACHE_SIZE = 500;

/** Cached answers live at least this long, in seconds. */
export const MIN_CACHE_TTL = 30;

/**
 * An entry this close to expiring is refreshed early on 1 in 6 lookups, so
 * popular names are renewed gradually instead of all at once.
 */
export const REFRESH_EARLY_MS = 10000;

/** Answer NXDOMAIN locally for private and undelegated names. */
export const BLOCK_UNDELEGATED = true;

/**
 * CDN redirects: the key resolves to the A/AAAA answers of the value.
 *
 */
export const REDIRECTS: Record<string, string> = {
  'www.bilibili.tv': 'www.bilibili.tv.w.cdngslb.com',
};

/**
 * Record type names accepted by the JSON API.
 *
 */
export const RECORD_TYPES: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  SVCB: 64,
  HTTPS: 65,
  ANY: 255,
  CAA: 257,
};

/** DNS record types used by name in the code. */
export const TYPE_A = 1;
export const TYPE_AAAA = 28;
export const TYPE_OPT = 41;
export const TYPE_SVCB = 64;
export const TYPE_HTTPS = 65;
