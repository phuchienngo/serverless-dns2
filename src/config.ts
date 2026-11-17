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
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAP: 22,
  'NSAP-PTR': 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  SRV: 33,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38,
  DNAME: 39,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  TKEY: 249,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  ANY: 255,
  ALL: 255,
  URI: 256,
  CAA: 257,
  AVC: 258,
  DOA: 259,
  AMTRELAY: 260,
  RESINFO: 261,
  WALLET: 262,
  TA: 32768,
  DLV: 32769,
};

/** DNS record types used by name in the code. */
export const TYPE_A = 1;
export const TYPE_AAAA = 28;
export const TYPE_OPT = 41;
export const TYPE_SVCB = 64;
export const TYPE_HTTPS = 65;

/**
 * Query types answered with an empty NODATA right away, saving an upstream
 * call. ANY is safe to refuse (RFC 8482); the others are off by default
 * because blocking them breaks things (IPv6, ECH and service hints).
 */
export const BLOCK_ANY = true;
export const BLOCK_AAAA = false;
export const BLOCK_PTR = false;
export const BLOCK_HTTPS = false;

/** Best-effort ECH for Cloudflare-hosted sites (see ech.ts). */
export const ECH_ENABLED = true;
/** Name whose HTTPS record carries Cloudflare's shared ECH key. */
export const ECH_FRONT_DOMAIN = 'cloudflare-ech.com';
