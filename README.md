# DoH gateway (Cloudflare Workers)

- `/dns-query` — RFC 8484 DoH (GET `?dns=`, POST `application/dns-message`). Status codes follow Google Public DNS.
- `/resolve` — Google-style JSON API (GET): `name`, `type`, `do`, `cd`, `ct`, `edns_client_subnet`.
  (`/dns-query?name=...` also returns JSON.)
- `/apple` — a page that makes an Apple DNS profile (see below); `/cloudflare-ips.json` — the Cloudflare ranges it measures.

Config: the only secret is the optional `COOKIE_SECRET` (see DNS Cookies below). The upstream DoH URL (`UPSTREAM`, optional `UPSTREAM_BACKUP`) and the other knobs are in `src/config.ts`.

`src/worker.ts` hands each request to `route()` in `src/handlers.ts`, which sends `/dns-query` and `/resolve` to their handlers, `/apple` and `/cloudflare-ips.json` to `src/profile.ts`, and returns HTTP 404 for other paths. `bun run build-lists` writes the lists to `build/` for bundling into the Worker.

Dev (with [Bun](https://bun.sh)): `bun install`, `bun run check` (tsc), `bun test` (the tests with a table of inputs and what each must give back are `test/inputs.test.ts`, `json-inputs.test.ts` and `upstream-failures.test.ts`), `bun run format` (Prettier, Google/gts style).

Deploy: push to `main` (GitHub Actions builds the lists and runs `wrangler deploy`), or `bun run deploy` from your machine.

Apple DNS profile: open `https://<host>/apple` in a browser, press Measure, and the page tries addresses of Cloudflare's network from where you are, ticks the ones that answer fastest with the fewest lost packets, and makes a `.mobileconfig` that connects to them (`ServerAddresses`). Which addresses are offered is decided by `bun run build-lists`, which asks for the domain (`PROBE_HOST` in `src/config.ts`) at addresses spread over each range Cloudflare publishes, and keeps the ranges that answer 200. For each IPv4 address it tries it also tries the IPv6 one at `<prefix>::<the IPv4 address in two hex groups>`, where the prefix is that of the domain's own AAAA records (found by the build); Cloudflare serves the domain at both, and an address that cannot be reached (no IPv6 on your network) is simply dropped. Installing the profile is still done by hand in System Settings. Connecting to a Cloudflare address other than the zone's own is not a documented feature, so it may stop working.

DDR (Android 16+ Private DNS): add in your zone
`_dns.dns.example.com  SVCB  1 dns.example.com. alpn="h2,h3" dohpath="/dns-query{?dns}"`
then set `dns_ddr_version 1` and `networkmonitor_async_privdns_resolution 1` via `adb shell device_config put connectivity ...`.

## Extras

- ECS is on (`ECS_ENABLED` in `src/config.ts`) and the upstream is Quad9's `dns11` resolver (the one with ECS), which passes the client subnet on (Google's does too). For one that does not, set `ECS_ENABLED` to false: no ECS is then sent or kept, so one upstream query is made and one answer is cached for every client. The rest of this item is about the case where it is on.
- Honours a client-supplied ECS (dnsproxy / AdGuard Home `edns-addr`). Source prefix 0, such as Firefox's `::/0`, is sent as supplied (RFC 7871 7.1.2). Otherwise the subnet is the client's address from `CF-Connecting-IP` (/24, /48). A query with no subnet is still sent with ECS source prefix 0, because Google would otherwise make one up from the Worker's own Cloudflare address. When the query has a subnet, one query with ECS and one without are sent in parallel; the ECS answer is used unless it is REFUSED (RFC 7871 7.1.3; Akamai refuses ECS from Google) or fails, then the other one is. The one that loses is not cancelled. A client's own subnet option that is malformed (unknown family, wrong number of address octets, bits past the prefix) is FORMERR (RFC 7871 6, 7.2.1).
- `ANY` queries get a minimal HINFO locally (`BLOCK_ANY`; not with DO, which the upstream answers with signatures, RFC 8482 4.2); `REDIRECTS` in `src/config.ts` answers a name with another name's A/AAAA records (now `medium.com` -> `voz.vn`); not for a query with DO, since what is made here carries no signature.
- `/resolve?name=8.8.8.8&type=PTR` converts an IP to its reverse name.
- The DO and CD bits of a query are passed to the upstream (DNSSEC records and `AD` come back as asked; a query with AD but no DO also gets `AD`). Answers made
  locally (blocked names, NODATA) carry a made-up SOA so clients can cache them (RFC 2308), and an OPT record only if the
  query had one (RFC 6891); an OPT record from the upstream is dropped for a client that sent none.
- Padding (RFC 8467): a query with an EDNS Padding option gets its response padded to a multiple of 468 bytes. Stale
  answers carry EDE 3 (RFC 8767). `localhost` and `*.localhost` answer 127.0.0.1 / ::1 (RFC 6761), `ANY` gets a minimal
  HINFO (RFC 8482), non-QUERY opcodes get NOTIMP and EDNS versions above 0 get BADVERS. RD and the opcode are echoed.
- When the upstream fails (HTTP error, no connection, a body that is not a DNS message, or a reply with another id or question) the client gets SERVFAIL with EDE 23, which is not cached. An expired answer still in the cache is served at once instead, whatever the upstream does. Other rcodes of the upstream are passed on, and only NOERROR and NXDOMAIN are cached.
- Best-effort ECH: for Cloudflare-hosted names the HTTPS answer gets Cloudflare's shared `ech` key (`src/ech.ts`), added to the record the upstream sent (hints and the rest stay) or, if it sent none, as a new one; the Cloudflare IPv4 ranges it uses to recognise those names are downloaded from https://www.cloudflare.com/ips-v4 by `bun run build-lists` (the build fails if that fails), so the daily rebuild keeps them current. Not done for queries with DO, as the changed record would carry no signature.

## Standards extras

Three optional features, none of which touches the caches or their TTLs.

- **DNS64** (RFC 6147), off unless a request has `dns64=1` (or `true`), like the `do` and `cd` parameters (`/dns-query?dns=...&dns64=1` or
  `/resolve?name=...&type=AAAA&dns64=1`). When an AAAA answer has no AAAA record but the name has A records, the response carries
  AAAA records made from them: the IPv4 address inside the NAT64 prefix `DNS64_PREFIX` in `src/config.ts` (default `64:ff9b::/96`).
  The TTL is the smaller of the A record's and the AAAA answer's (RFC 6147 5.1.7). Not done for a query with DO and no CD
  (it could not validate), nor for private, loopback, documentation, multicast and other non-global addresses. A CNAME chain
  is flattened: the new records are owned by the name asked. The A lookup can run alongside AAAA (RFC 6147 5.1.8), and
  the result is kept in the isolate's memory. Needs a NAT64 gateway on the client's network.
  Also with `?dns64`: `AAAA ipv4only.arpa` is answered locally with the two well-known addresses inside the prefix, which is
  how clients discover it (RFC 7050); and a PTR for an address inside the prefix, which the upstream cannot answer, gets a
  CNAME to the reverse name of the embedded IPv4 address followed by that name's PTR records (RFC 6147 5.3.1).
- **Resolver information** (RFC 9606): `RESINFO` for this gateway's host name answers locally with `exterr=3,15,19,23`
  (the Extended DNS Errors it produces). Clients that found the gateway through DDR can ask for it.
- **DNS Cookies** (RFC 7873): set the secret with `bunx wrangler secret put COOKIE_SECRET`
  (for example from `openssl rand -hex 32`) and redeploy. A query with a Cookie option then gets the client cookie back with
  a server cookie (first 8 bytes of HMAC-SHA256 of the client cookie and the client IP). Cookies are never enforced, since HTTPS
  already stops spoofing, so a query without one, or with a stale one, is answered normally; a cookie of an invalid length is FORMERR.
  Without `COOKIE_SECRET` cookies are ignored.

Not done on purpose: QNAME minimisation (RFC 9156) and the root-related RFCs (8109, 8806) apply to a recursive resolver, and
this gateway forwards to one. Aggressive NSEC caching (8198) and NXDOMAIN cut (8020) would answer without asking the upstream
from data this gateway does not validate.

## Logs

Workers Logs is on, but the automatic line per request is off (`invocation_logs: false` in `wrangler.jsonc`). The gateway writes a log object (with a `message` sentence for the Message column) only when something goes wrong (`src/log.ts`): `upstream_failed` (which upstream, and why: `upstream 500`, `timeout`, `bad upstream response`), `servfail` (the name and type a client got SERVFAIL for) and `slow_upstream` (an answer slower than `SLOW_UPSTREAM_MS`, 300 ms). `LOG_LEVEL` in `src/config.ts` picks what is written: `warn` (all), `error` (failures only) or `off`. At most one line of each kind every 10 s per isolate; `held` says how many were skipped. Answers that work are not logged, and no client address is. The line is an object, so each field can be filtered on in the dashboard, and a failure carries its `Error`, so Workers Issues can group it.

## Blocklist

1. Put your sources in `BLOCKLIST.lists` in `src/config.ts`, with any `allow` and `block` rules.
2. `bun run build-lists` downloads them, keeps plain domains only and writes `build/blocklist.bin` (with `rules.json` and `cloudflare-ips.json`, the published ranges and the ones that answer for the domain, beside it)
   (a Ribbon filter: each domain's hash selects some of 64 consecutive slots of `BLOCKLIST_PRECISION_BITS` bits, and
   the build solves for slot values that XOR to the domain's fingerprint; about 20.02 bits per domain at 20 bits, where
   20 is the least possible; blocking a domain blocks its subdomains). The domains are split into shards of about
   2048, each solved on its own with the fewest slots that work, which takes a minute or two. The file is bundled with the Worker
   and read in place: a new isolate only reads the small shard index. The slots are stored bit by bit in columns, so a lookup compares one fingerprint bit
   at a time and stops at the first that differs: about two steps for a name that is not listed.
   A name that is not listed is wrongly blocked with a probability of 2^-20 per suffix looked up (set
   `BLOCKLIST_PRECISION_BITS` in `src/config.ts`; listed names are never missed). If a source fails, nothing is
   written and the build fails.
3. The file is not committed. The GitHub workflow builds it on every push to `main` and deploys the Worker with it
   (see below); `bun run deploy` does the same from your machine.

`BLOCKLIST.block` and `BLOCKLIST.allow` take domains (which also cover their subdomains) or `/regex/` rules as strings,
matched against the lower-case name without a trailing dot (anchor with `^`/`$` yourself). The build rejects lookaround,
backreferences, and `*`, `+`, or `{...}` after a group. Groups can still be optional with `?`. Keep patterns simple to limit
backtracking. `allow` wins over the lists and the block rules, so an allowed subdomain works even under a blocked
parent. Domains already matched by a block regex are left out of the hash list. Try rules with
`bun scripts/match-regex.ts name...` (checks the regex and allow rules only).

CNAME uncloaking (`CNAME_UNCLOAK` in `src/config.ts`): every CNAME target in an answer is also checked against the
blocklist, so a tracker hidden behind a first-party subdomain (`metrics.site.com -> x.tracker.net`) gets NXDOMAIN.

DNS rebinding protection (`BLOCK_REBINDING` in `src/config.ts`): if the answer for a name holds a private, shared (100.64/10),
loopback or link-local address (A, AAAA, IPv4-mapped, or the `ipv4hint`/`ipv6hint` of an HTTPS/SVCB record), the name gets
NXDOMAIN with EDE 15 ("dns rebinding"), so a web page cannot reach your router or local services through a public name. `0.0.0.0`
and `::` (what blocklists answer) pass. Like uncloaking it is checked on every response, also cached ones. A name that must resolve to a
private address (a service at home) goes in `BLOCKLIST.allow` in `src/config.ts`.

Blocked names get NXDOMAIN. The lists are part of the Worker bundle, so nothing is fetched at run time.

## Latency

- Serve-stale: an expired answer (up to 6 h past its TTL) is returned at once with TTL 30 and renewed in the background.
- The Cache API lookup and the upstream call run in parallel; the first answer wins and the upstream call always renews the cache.
- Every upstream query (the ECS one and the one without) is hedged: it waits three times the recent average upstream latency, bounded to 20–80 ms. If the query is still pending,
  it sends a second request to `UPSTREAM_BACKUP` if set, or to `UPSTREAM` again, usually on the same connection.
  The first answer wins.
- These speed-ups cost the upstream extra queries (every cache miss in the isolate's memory asks it, a slow query is sent twice, and with ECS on every query is sent twice): see "Trade-offs" in `FEATURES.md`.
- `Server-Timing` on `/resolve` and `/dns-query` reports how long it took to prepare the DNS answer (`first`), including any DNS64 or DDR lookups needed for it.

Build and deploy: `.github/workflows/rebuild.yml` runs `bun run build-lists` and `wrangler deploy` on every push to
`main`, every day (so the lists stay current) and from the Actions tab. Setup, once: a Cloudflare API token with the
permission "Account -> Workers Scripts -> Edit" stored as the GitHub secret `CLOUDFLARE_API_TOKEN`, and your account id
as `CLOUDFLARE_ACCOUNT_ID`. The domain is attached to the Worker in the dashboard (Workers & Pages -> the Worker ->
Settings -> Domains & Routes).

A failed build stops before the deploy, so the previous version keeps serving.
