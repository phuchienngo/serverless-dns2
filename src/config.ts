/** @fileoverview Tunable constants for the DoH gateway. */

/** Largest DNS message accepted, in bytes (same limit as Google). */
export const MAX_QUERY = 512;

/** Longest `dns=` parameter accepted (base64url of 512 bytes is 683 chars). */
export const MAX_DNS_PARAM = 700;

/** How long to wait for the upstream resolver. */
export const UPSTREAM_TIMEOUT_MS = 4000;
/** Upstream DoH resolver, and an optional second one for hedged queries. */
export const UPSTREAM = 'https://dns11.quad9.net/dns-query';
export const UPSTREAM_BACKUP: string | null = null;

/**
 * Send the client's subnet to the upstream (EDNS Client Subnet, RFC 7871), so
 * that a CDN answers with a server near the client. Turn it off for a resolver
 * that does not pass it on (Cloudflare's 1.1.1.1 does not; Gateway, Google and
 * Quad9's dns11 do): the query then carries no ECS, one query is made instead
 * of two, and the cache keeps one answer for every client.
 */
export const ECS_ENABLED = true;

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
export const HEDGE_MIN_MS = 15;
export const HEDGE_MAX_MS = 50;

/**
 * How long a request waits for work that another request started (the same
 * query in flight, the ECH key being loaded) before it does the work itself.
 * The other request may be gone (its client disconnected), and then its work
 * never finishes; a request left waiting for it would be cancelled as hung.
 */
export const SHARED_WAIT_MS = 50;

/**
 * What `src/log.ts` writes: `warn` is failures and slow upstream answers,
 * `error` is failures only, `off` is nothing.
 */
export const LOG_LEVEL: 'off' | 'error' | 'warn' = 'warn';

/** An upstream answer slower than this (ms) is logged as a warning. */
export const SLOW_UPSTREAM_MS = 300;

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

/**
 * Build time: the domain asked for at addresses in Cloudflare's published
 * ranges. The ranges that answer 200 are the ones the profile page offers
 * (see scripts/cloudflare-probe.ts).
 */
export const PROBE_HOST = 'dns.phuchien.me';

export const BLOCKLIST = {
  lists: [
    // HaGeZi Multi ULTIMATE: Pro plus the most aggressive rules; it can break
    // apps and sites, so put what breaks in `allow`.
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt',
    // HaGeZi Threat Intelligence Feeds, medium: malware, phishing, scams.
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt',
    // HaGeZi referral domains (affiliate and tracking links). The project advises
    // against blocking them: some search result links and unsubscribe links
    // go through them.
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/blocklist-referral-onlydomains.txt',
  ],
  // Names that break apps or sites when blocked. An entry covers its subdomains.
  allow: [
    'js.monitor.azure.com', // Parts of Microsoft services and Azure reports.
    'c.office.com', // Office forms with a timer cannot start.
    'measure.office.com', // Office connectivity check (sdwan.measure.office.com).
    'click.discord.com', // Discord login and verification.
    'za.zalo.me', // Links in Zalo PC.
    'cdn.cookielaw.org', // Cookie notices; sites break without it.
    'wsapi.master.live', // Nimo TV app.
    'html-load.com', // Ad-block detection checks (dictionary.cambridge.org...).
    'content-loader.com', // Same as html-load.com.
    'dd.garena.com', // Garena login.
    'l.facebook.com', // Facebook's outbound link redirector.
    'api.ipify.org', // Public IP lookup API.
  ],
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
    'connect.facebook.net', // Facebook tracking embedded in other sites, and the Connect button.
    'connect.facebook.com',
    '/^ep[0-9]+\\.facebook\\.com$/', // ep1, ep2, ep3...: Facebook's newer tracking hosts.
    'dns.ladipage.com', // CNAME used by ad campaigns and by scams.
    'dns.webcake.io',
    'dns.storecake.io',
    'invl.io', // Marketing links inserted in video players.
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
