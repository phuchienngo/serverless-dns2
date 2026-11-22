/** @fileoverview Tunable constants for the DoH gateway. */

/** Largest DNS message accepted, in bytes (same limit as Google). */
export const MAX_QUERY = 512;

/** Longest `dns=` parameter accepted (base64url of 512 bytes is 683 chars). */
export const MAX_DNS_PARAM = 700;

/** How long to wait for the upstream resolver. */
export const UPSTREAM_TIMEOUT_MS = 4000;
/** Upstream DoH resolver, and an optional second one for hedged queries. */
export const UPSTREAM = 'https://dns.google/dns-query';
export const UPSTREAM_BACKUP: string | null = null;

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
 * Send the query again if the first try has not answered after three times
 * the recent average latency, but not sooner or later than these. Without an
 * UPSTREAM_BACKUP the second try goes to the same host, and so usually shares
 * the open connection: no new handshake, but it only helps against a slow
 * request, not a slow connection.
 */
export const HEDGE_MIN_MS = 20;
export const HEDGE_MAX_MS = 80;

/** Answer NXDOMAIN locally for private and undelegated names. */
export const BLOCK_UNDELEGATED = true;

/**
 * Redirects: the exact name on the left is answered with the A/AAAA records of
 * the name on the right (SVCB/HTTPS answer NODATA, other types are forwarded
 * unchanged). Subdomains are not redirected.
 */
export const REDIRECTS: Record<string, string> = {
  'medium.com': 'voz.vn',
};

/**
 * DNS64 (RFC 6147), which a request asks for with `?dns64`: the NAT64 prefix
 * (a /96, RFC 6052) that A records are embedded in. Default: well-known prefix.
 */
export const DNS64_PREFIX = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/** Answer ANY with a minimal HINFO, saving an upstream call (RFC 8482). */
export const BLOCK_ANY = true;

/** Name whose HTTPS record carries Cloudflare's shared ECH key. */
export const ECH_FRONT_DOMAIN = 'cloudflare-ech.com';

export const BLOCKLIST = {
  lists: [
    'https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/output/doh/doh_adblock.txt',
    'https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/output/doh/doh_privacy.txt',
    'https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/output/doh/doh_malware.txt',
  ],
  allow: [],
  block: [
    '/^ad([sxv]?[0-9]*|system)[_.-][^.]+\\.|[_.-]ad([sxv]?[0-9]*|system)[_.-]/',
    '/^(.+[_.-])?(?:adse?rv(er?|ice)?s?[0-9]*|telemetry)[_.-]/',
    '/^adim(age|g)s?[0-9]*[_.-]/',
    '/^adtrack(er|ing)?[0-9]*[_.-]/',
    '/^advert(s|is(ing|ements?))?[0-9]*[_.-]/',
    '/^aff(iliat(es?|ion))?[_.-]/',
    '/^analytics?[_.-]/',
    '/^banners?[_.-]/',
    '/^beacons?[0-9]*[_.-]/',
    '/^count(ers?)?[0-9]*[_.-]/',
    '/^mads\\./',
    '/^pixels?[-.]/',
    '/^stat(s|istics)?[0-9]*[_.-]/',
    '/^(ads|logs|cloudservices).roku.com$/',
    '/^track(ers?|ing)?[0-9]*[_.-]/',
    '/^traff(ic)?[-.]/',
    'thodia.mservice.io',
    'merchant.momocdn.net',
    'social.momocdn.net',
    'socialhub.mservice.com.vn',
    'socialhub.momo.vn',
  ],
} as const;

/**
 * Build time: a name that is not listed is wrongly blocked with a probability
 * of about 2^-this per suffix looked up. Each extra bit costs about one more
 * bit per listed domain in the file.
 */
export const BLOCKLIST_PRECISION_BITS = 20;

/**
 * DNS rebinding protection: a name whose answer holds a private, loopback or
 * link-local address (or one in an HTTPS/SVCB hint) gets NXDOMAIN. A rule in
 * `BLOCKLIST.allow` exempts a name, such as one for a service at home.
 */
export const BLOCK_REBINDING = true;

/**
 * Also check every CNAME target in an answer against the blocklist, so a
 * tracker hidden behind a first-party subdomain is blocked (CNAME uncloaking).
 */
export const CNAME_UNCLOAK = true;

/** Cloudflare's published IPv4 ranges, which `bun run build-lists` downloads (see cloudflare-ips.ts). */
export const CLOUDFLARE_IPS_URL = 'https://www.cloudflare.com/ips-v4';
