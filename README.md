# DoH gateway (Cloudflare Pages)

- `/dns-query` — RFC 8484 DoH (GET `?dns=`, POST `application/dns-message`). Status codes follow Google Public DNS.
- `/resolve` — Google-style JSON API (GET): `name`, `type`, `do`, `cd`, `ct`, `edns_client_subnet`.
  (`/dns-query?name=...` also returns JSON.)

Config: the only secret is the optional `COOKIE_SECRET` (see DNS Cookies below). The upstream DoH URL (`UPSTREAM`, optional `UPSTREAM_BACKUP`) and the other knobs are in `src/config.ts`.

Layout: `src/` (TypeScript logic; entry `core.ts`), `functions/dns-query.ts` and `functions/resolve.ts` (Pages adapters).

Dev: `npm install`, `npm run check` (tsc), `npm run format` (Prettier, Google/gts style).

Deploy: `npx wrangler pages deploy --branch main` (or push to `main`).

DDR (Android 16+ Private DNS): add in your zone
`_dns.dns.example.com  SVCB  1 dns.example.com. alpn="h2,h3" dohpath="/dns-query{?dns}"`
then set `dns_ddr_version 1` and `networkmonitor_async_privdns_resolution 1` via `adb shell device_config put connectivity ...`.

## Extras

- Honours a client-supplied ECS (dnsproxy / AdGuard Home `edns-addr`); an empty one (source prefix 0, such as Firefox's `::/0`) means "do not locate me": it is sent upstream as it is, so no subnet of the connecting IP is used (RFC 7871 7.1.2).
- `ANY` queries get a minimal HINFO locally (`BLOCK_ANY`); `REDIRECTS` in `src/config.ts` answers a name with another name's A/AAAA records (now `medium.com` -> `voz.vn`); not for a query with DO, since what is made here carries no signature.
- `/resolve?name=8.8.8.8&type=PTR` converts an IP to its reverse name.
- The DO and CD bits of a query are passed to the upstream (DNSSEC records and `AD` come back as asked; a query with AD but no DO also gets `AD`). Answers made
  locally (blocked names, NODATA) carry a made-up SOA so clients can cache them (RFC 2308), and an OPT record only if the
  query had one (RFC 6891); an OPT record from the upstream is dropped for a client that sent none.
- Padding (RFC 8467): a query with an EDNS Padding option gets its response padded to a multiple of 468 bytes. Stale
  answers carry EDE 3 (RFC 8767). `localhost` and `*.localhost` answer 127.0.0.1 / ::1 (RFC 6761), `ANY` gets a minimal
  HINFO (RFC 8482), non-QUERY opcodes get NOTIMP and EDNS versions above 0 get BADVERS. RD and the opcode are echoed.
- Best-effort ECH: for Cloudflare-hosted names the HTTPS answer gets Cloudflare's shared `ech` key (`src/ech.ts`), added to the record the upstream sent (hints and the rest stay) or, if it sent none, as a new one; the Cloudflare IPv4 ranges it uses to recognise those names are downloaded from https://www.cloudflare.com/ips-v4 by `npm run build-lists` (the build fails if that fails), so the daily rebuild keeps them current. Not done for queries with DO, as the changed record would carry no signature.

## Standards extras

Three optional features, none of which touches the caches or their TTLs.

- **DNS64** (RFC 6147), off unless a request has `dns64=1` (or `true`), like the `do` and `cd` parameters (`/dns-query?dns=...&dns64=1` or
  `/resolve?name=...&type=AAAA&dns64=1`). When an AAAA answer has no AAAA record but the name has A records, the response carries
  AAAA records made from them: the IPv4 address inside the NAT64 prefix `DNS64_PREFIX` in `src/config.ts` (default `64:ff9b::/96`).
  The TTL is the smaller of the A record's and the AAAA answer's (RFC 6147 5.1.7). Not done for a query with DO and no CD
  (it could not validate), nor for private, loopback, documentation, multicast and other non-global addresses. A CNAME chain
  is flattened: the new records are owned by the name asked. It costs one more lookup of the A record (itself cached), and
  the result is kept in the isolate's memory. Needs a NAT64 gateway on the client's network.
  Also with `?dns64`: `AAAA ipv4only.arpa` is answered locally with the two well-known addresses inside the prefix, which is
  how clients discover it (RFC 7050); and a PTR for an address inside the prefix, which the upstream cannot answer, gets a
  CNAME to the reverse name of the embedded IPv4 address followed by that name's PTR records (RFC 6147 5.3.1).
- **Resolver information** (RFC 9606): `RESINFO` for this gateway's host name answers locally with `exterr=3,15,19,23`
  (the Extended DNS Errors it produces) and `infourl=https://<host>/`. Clients that found the gateway through DDR can ask for it.
- **DNS Cookies** (RFC 7873): set the secret with `npx wrangler pages secret put COOKIE_SECRET --project-name serverless-dns2`
  (for example from `openssl rand -hex 32`) and redeploy. A query with a Cookie option then gets the client cookie back with
  a server cookie (first 8 bytes of HMAC-SHA256 of the client cookie and the client IP). Cookies are never enforced, since HTTPS
  already stops spoofing, so a query without one, or with a stale one, is answered normally; a cookie of an invalid length is FORMERR.
  Without `COOKIE_SECRET` cookies are ignored.

Not done on purpose: QNAME minimisation (RFC 9156) and the root-related RFCs (8109, 8806) apply to a recursive resolver, and
this gateway forwards to one. Aggressive NSEC caching (8198) and NXDOMAIN cut (8020) would answer without asking the upstream
from data this gateway does not validate.

## Blocklist

1. Put your sources in `blocklists.yaml` (`lists`, plus optional `allow` and `block` rules).
2. `npm run build-lists` downloads them, keeps plain domains only and writes `public/blocklist.bin`
   (a Golomb-coded set: sorted hashes of the blocked domains, truncated to `ceil(log2 N) + BLOCKLIST_PRECISION_BITS`
   bits and stored as gaps, about 22.8 bits per domain; blocking a domain blocks its subdomains). The hashes are
   split into blocks of 64 with an index, so a cold isolate only reads the index and a lookup decodes one block (the
   whole set used to be decoded on load, about 10 ms of CPU).
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

DNS rebinding protection (`BLOCK_REBINDING` in `src/config.ts`): if the answer for a name holds a private, shared (100.64/10),
loopback or link-local address (A, AAAA, IPv4-mapped, or the `ipv4hint`/`ipv6hint` of an HTTPS/SVCB record), the name gets
NXDOMAIN with EDE 15 ("dns rebinding"), so a web page cannot reach your router or local services through a public name. `0.0.0.0`
and `::` (what blocklists answer) pass. Like uncloaking it is checked on every response, also cached ones. A name that must resolve to a
private address (a service at home) goes in `allow:` in `blocklists.yaml`.

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
