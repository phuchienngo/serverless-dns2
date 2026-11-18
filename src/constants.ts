/**
 * @fileoverview Protocol constants: record types, response codes, EDNS option
 * codes and Extended DNS Error codes. Tunable settings are in config.ts.
 */

/** Record type names accepted by the JSON API (IANA DNS parameters). */
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

/** Record types used by number in the code. */
export const TYPE_A = RECORD_TYPES.A;
export const TYPE_NS = RECORD_TYPES.NS;
export const TYPE_CNAME = RECORD_TYPES.CNAME;
export const TYPE_SOA = RECORD_TYPES.SOA;
export const TYPE_PTR = RECORD_TYPES.PTR;
export const TYPE_HINFO = RECORD_TYPES.HINFO;
export const TYPE_AAAA = RECORD_TYPES.AAAA;
export const TYPE_NAPTR = RECORD_TYPES.NAPTR;
export const TYPE_OPT = RECORD_TYPES.OPT;
export const TYPE_SVCB = RECORD_TYPES.SVCB;
export const TYPE_HTTPS = RECORD_TYPES.HTTPS;
export const TYPE_ANY = RECORD_TYPES.ANY;

/** Query types that no recursive resolver answers (RFC 6895, 6891, 8945). */
export const TYPES_FORMERR = [
  0,
  RECORD_TYPES.OPT,
  RECORD_TYPES.TKEY,
  RECORD_TYPES.TSIG,
];
/** Zone transfers (RFC 1995, 5936) and the obsolete MAILB/MAILA. */
export const TYPES_NOTIMP = [
  RECORD_TYPES.IXFR,
  RECORD_TYPES.AXFR,
  RECORD_TYPES.MAILB,
  RECORD_TYPES.MAILA,
];

export const CLASS_IN = 1;

/** Response codes (RFC 1035, RFC 6891 for BADVERS). */
export const RCODE_NOERROR = 0;
export const RCODE_FORMERR = 1;
export const RCODE_SERVFAIL = 2;
export const RCODE_NXDOMAIN = 3;
export const RCODE_NOTIMP = 4;
export const RCODE_REFUSED = 5;
export const RCODE_BADVERS = 16;

/** EDNS option codes. */
export const OPTION_ECS = 8; // RFC 7871.
export const OPTION_PADDING = 12; // RFC 7830.
export const OPTION_EDE = 15; // RFC 8914.
export const ECH_PARAM = 5; // SvcParamKey `ech` (RFC 9460).

/** Extended DNS Error info codes (RFC 8914) that are used. */
export const EDE_STALE_ANSWER = 3;
export const EDE_BLOCKED = 15;

/**
 * TTLs, in seconds, of answers made locally (also the negative-caching TTL
 * of their SOA, RFC 2308).
 */
export const TTL_LOCAL = 3600; // Loopback, undelegated names, ANY.
export const TTL_BLOCKED = 300; // Blocked names.
export const TTL_DDR = 300;
export const TTL_SHORT = 60;
