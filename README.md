# DoH gateway (Cloudflare Pages)

- `/dns-query` — RFC 8484 DoH (GET `?dns=`, POST `application/dns-message`). Status codes follow Google Public DNS.
- `/resolve` — Google-style JSON API (GET): `name`, `type`, `do`, `cd`, `ct`, `edns_client_subnet`.
  (`/dns-query?name=...` also returns JSON.)

Config: no secrets. The upstream DoH URL (`UPSTREAM`, optional `UPSTREAM_BACKUP`) and the other knobs are in `src/config.ts`.

Layout: `src/` (TypeScript logic; entry `core.ts`), `functions/dns-query.ts` and `functions/resolve.ts` (Pages adapters).

Dev: `npm install`, `npm run check` (tsc), `npm run format` (Prettier, Google/gts style).

Deploy: `npx wrangler pages deploy --branch main` (or push to `main`).

DDR (Android 16+ Private DNS): add in your zone
`_dns.dns.example.com  SVCB  1 dns.example.com. alpn="h2,h3" dohpath="/dns-query{?dns}"`
then set `dns_ddr_version 1` and `networkmonitor_async_privdns_resolution 1` via `adb shell device_config put connectivity ...`.

## Extras

- Honours a client-supplied ECS (dnsproxy / AdGuard Home `edns-addr`); empty subnets such as `::/0` are ignored.
- `BLOCK_ANY/AAAA/PTR/HTTPS` in `src/config.ts` answer those query types with NODATA locally.
- `/resolve?name=8.8.8.8&type=PTR` converts an IP to its reverse name.
- Best-effort ECH: for Cloudflare-hosted names the HTTPS answer gets Cloudflare's shared `ech` key (`src/ech.ts`).

## Blocklist

1. Put your sources in `blocklists.yaml` (`lists`, plus optional `allow` and `block` rules).
2. `npm run build-lists` downloads them, keeps plain domains only and writes `public/blocklist.bin`
   (a Golomb-coded set: sorted hashes of the blocked domains, truncated to `ceil(log2 N) + BLOCKLIST_PRECISION_BITS`
   bits and stored as gaps, about 21.6 bits per domain; blocking a domain blocks its subdomains).
   A name that is not listed is wrongly blocked with a probability of about 2^-20 per suffix looked up (set
   `BLOCKLIST_PRECISION_BITS` in `src/config.ts`; listed names are never missed). If a source fails, nothing is
   written and the build fails.
3. The file is not committed. Cloudflare Pages builds it on every push: in the project's
   Settings -> Builds, set **Build command** to `npm run build-lists` and **Build output directory**
   to `public`. `npm run deploy` builds it locally and uploads.

Rules: `block:` and `allow:` in `blocklists.yaml` take domains (which also cover their subdomains) or `/regex/` rules,
matched against the lower-case name without a trailing dot (anchor with `^`/`$` yourself). The build rejects lookaround,
backreferences and the common nested-quantifier forms such as `(a+)+` (not every slow pattern: keep rules simple). `allow` wins over the lists and the block rules,
so an allowed subdomain works even under a blocked parent. Domains already matched by a block regex are left out of the
hash list. Try rules with `npx tsx scripts/match-regex.ts name...` (checks the regex and allow rules only).

CNAME uncloaking (`CNAME_UNCLOAK` in `src/config.ts`): every CNAME target in an answer is also checked against the
blocklist, so a tracker hidden behind a first-party subdomain (`metrics.site.com -> x.tracker.net`) gets NXDOMAIN.

Blocked names get NXDOMAIN. Each isolate loads the file once into memory.

## Latency

- Serve-stale: an expired answer (up to 6 h past its TTL) is returned at once with TTL 30 and renewed in the background.
- The Cache API lookup and the upstream call run in parallel; the first answer wins and the upstream call always renews the cache.
- Hedging: if the upstream has not answered after 100 ms the query is also sent on a second connection, to the optional
  `UPSTREAM_BACKUP` (a second DoH URL) or else to `UPSTREAM` again. The first answer wins.
- `Server-Timing` on the `/resolve` and `/dns-query` responses shows `cache`, `upstream` and, on a cold isolate, `block`/`asset`.

Daily rebuild: `.github/workflows/rebuild.yml` prunes old deployments (keeps the newest 10) and then calls a Pages
Deploy Hook (also runnable from the Actions tab). Setup, once:
- Pages -> Settings -> Builds -> Deploy hooks: add a hook for `main`; store its URL as the GitHub secret `PAGES_DEPLOY_HOOK`.
- Cloudflare API token with permission "Account -> Cloudflare Pages -> Edit"; store it as `CLOUDFLARE_API_TOKEN`,
  and your account id as `CLOUDFLARE_ACCOUNT_ID`.

A failed build leaves the previous deployment serving.
