/** @fileoverview Tunable constants for the DoH gateway. */

/** Whether to attach the client's subnet (EDNS Client Subnet) to queries. */
export const ECS_ENABLED = true;

/** Largest DNS message accepted, in bytes (same limit as Google). */
export const MAX_QUERY = 512;

/** Longest `dns=` parameter accepted (base64url of 512 bytes is 683 chars). */
export const MAX_DNS_PARAM = 700;

/** How long to wait for the upstream resolver. */
export const UPSTREAM_TIMEOUT_MS = 4000;
/** Upstream DoH resolver, and an optional second one for hedged queries. */
export const UPSTREAM = 'https://ayr25cp79f.cloudflare-gateway.com/dns-query';
export const UPSTREAM_BACKUP = '';

/** Answers kept in the isolate's memory, in front of the Cache API. */
export const LOCAL_CACHE_SIZE = 5000;

/** Cached answers live at least this long, in seconds. */
export const MIN_CACHE_TTL = 60;

/**
 * An entry this close to expiring is refreshed early on 1 in 6 lookups, so
 * popular names are renewed gradually instead of all at once.
 */
export const REFRESH_EARLY_MS = 10000;

/** How long past its TTL an answer may still be served while it is refreshed. */
export const STALE_MAX_S = 6 * 3600;
/** TTL given to clients for such a stale answer. */
export const STALE_TTL = 30;

/**
 * Send the query to a second connection if the first has not answered after
 * three times the recent average latency, but not sooner or later than these.
 */
export const HEDGE_MIN_MS = 40;
export const HEDGE_MAX_MS = 150;

/** Answer NXDOMAIN locally for private and undelegated names. */
export const BLOCK_UNDELEGATED = true;

/**
 * CDN redirects: the key resolves to the A/AAAA answers of the value.
 *
 */
export const REDIRECTS: Record<string, string> = {};

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

/** Domain blocklist built by `npm run build-lists` (see blocklist.ts). */
export const BLOCKLIST_ENABLED = true;
export const BLOCKLIST_PATH = '/blocklist.bin';
/**
 * Build time: a name that is not listed is wrongly blocked with a probability
 * of about 2^-this per suffix looked up. Each extra bit costs about one more
 * bit per listed domain in the file.
 */
export const BLOCKLIST_PRECISION_BITS = 20;
/** Regex block/allow rules built from blocklists.yaml (see regexlist.ts). */
export const RULES_PATH = '/rules.json';

/**
 * Also check every CNAME target in an answer against the blocklist, so a
 * tracker hidden behind a first-party subdomain is blocked (CNAME uncloaking).
 */
export const CNAME_UNCLOAK = true;
