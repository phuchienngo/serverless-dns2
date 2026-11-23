# Features, standards and tests

Code layout: `constants.ts` (record types, rcodes, option codes, EDE, local TTLs), `config.ts` (tunable settings only), the DNS messages in `wire.ts` (numbers, names, `readRecords`, the base of every record reader and editor), `query.ts` (parsing a client's query, making upstream queries) and `response.ts` (making responses, editing relayed ones, TTLs), with `svcb.ts` for SVCB/HTTPS parameters. `handlers.ts` (DoH and JSON handlers and `route()`, which `worker.ts` calls for every request), `profile.ts` (the `/apple` page and `/cloudflare-ips.json`), `loaded.ts` memoizes what is fetched once per isolate (the ECH key); the lists built by `build-lists` (the blocklist, rules and Cloudflare ranges) are bundled into the Worker (`worker.ts`). `ipv4.ts` and `cloudflare-ips.ts` hold IPv4 ranges. `resolve.ts` orders the steps (local answer, blocking, cache, upstream) and finishes the response; `local.ts` (answers without upstream), `redirects.ts` (REDIRECTS), `blocking.ts` (blocklist, rules, and the checks of an answer: CNAME uncloaking, rebinding) and `upstream.ts` (hedging, request sharing) hold the steps.

Every feature, the standard it follows, where it lives and which test covers it.
`bun test` runs all tests (written for `node:test`, upstream mocked); `bun run check` also typechecks them.
"Deliberate deviation" marks a place where performance or privacy wins over the RFC.

| Feature | Standard | Code | Tests |
|---|---|---|---|
| DoH GET/POST, status codes (405/413/414/415/400) | RFC 8484 | `handlers.ts` | `handlers.test.ts` |
| `QUERY` with `QDCOUNT > 1` gets DNS FORMERR | RFC 9619 | `handlers.ts`, `response.ts` | `handlers.test.ts` |
| JSON API `/resolve` (name, type, do, cd, ct, subnet, PTR from IP) | Google DoH JSON | `handlers.ts`, `format.ts` | `handlers.test.ts`, `format.test.ts` |
| Message parsing and building (names up to 255 octets, CD echoed), case kept (0x20) | RFC 1035, 4343 | `wire.ts`, `query.ts`, `response.ts` | `dns.test.ts` |
| EDNS0: OPT only if the query had one, DO echoed, BADVERS, extended rcode | RFC 6891 | `query.ts`, `response.ts`, `resolve.ts` | `dns.test.ts`, `resolve.test.ts` |
| DNSSEC passthrough: DO, CD, AD | RFC 3225, 4035, 6840 5.7 | `resolve.ts`, `query.ts` | `resolve.test.ts` |
| Negative answers carry a SOA, minimum TTL | RFC 2308 | `response.ts` | `dns.test.ts`, `resolve.test.ts` |
| Padding of responses to 468 bytes | RFC 7830, 8467 | `response.ts` | `dns.test.ts`, `resolve.test.ts` |
| Extended DNS Errors (15 blocked, 3 stale answer, 19 stale NXDOMAIN, 23 upstream unreachable) | RFC 8914 | `response.ts`, `resolve.ts` | `dns.test.ts`, `blocking.test.ts`, `resolve.test.ts` |
| Client subnet, only with `ECS_ENABLED` (off by default: Cloudflare's resolver ignores it; off = no ECS option, one query, one cache entry for all): /24 and /48 from `CF-Connecting-IP`, client-chosen subnet, source prefix 0 = not located (also sent when there is no subnet, so the upstream makes none up), per-subnet cache, no ECS in responses to queries without one; with a subnet, queries with and without ECS run in parallel and the ECS answer wins unless REFUSED | RFC 7871 | `ecs.ts`, `resolve.ts`, `upstream.ts`, `query.ts` | `ecs.test.ts`, `resolve.test.ts`, `handlers.test.ts` |
| Cache: TTL countdown (answer, authority, additional), LRU, Cache API, early refresh | RFC 1035, 2181 | `cache.ts` | `cache.test.ts`, `resolve.test.ts` |
| Serve-stale with TTL 30 and EDE 3 | RFC 8767 (deliberate deviation: served at once, not after a failed refresh) | `cache.ts`, `resolve.ts` | `cache.test.ts`, `resolve.test.ts` |
| Minimum cache TTL 60 s | none (deliberate deviation) | `cache.ts` | `cache.test.ts` |
| Request coalescing, hedged upstream queries (every one, with or without ECS) | none | `upstream.ts`, `resolve.ts` | `upstream.test.ts`, `resolve.test.ts` |
| `localhost` answers | RFC 6761 | `resolve.ts` | `resolve.test.ts` |
| Undelegated names, private reverse zones, `.alt` | RFC 6761, 6303, 8375, 9476 | `undelegated.ts` | `undelegated.test.ts`, `resolve.test.ts` |
| ANY gets HINFO | RFC 8482 | `resolve.ts` | `resolve.test.ts` |
| NOTIMP for other opcodes, AXFR/IXFR/MAILB/MAILA; FORMERR for QTYPE 0/OPT/TKEY/TSIG; REFUSED for classes other than IN | RFC 1035, 5936, 6895 | `resolve.ts` | `resolve.test.ts` |
| FORMERR for an invalid OPT (two OPTs, non-root owner, bad length) | RFC 6891 6.1.1 | `query.ts`, `resolve.ts` | `dns.test.ts`, `resolve.test.ts` |
| DDR (`_dns.resolver.arpa` SVCB, with the host's A/AAAA in additional); other `resolver.arpa` names get NODATA | RFC 9462, 9460 | `resolve.ts` | `resolve.test.ts` |
| Resolver information: RESINFO for the gateway host (`exterr`) | RFC 9606 | `local.ts` | `local.test.ts`, `resolve.test.ts` |
| DNS64, on request with `dns64=1` (prefix in `config.ts`; not for DO without CD, nor private addresses): AAAA from A, PTR for the prefix, `ipv4only.arpa` | RFC 6147, 6052, 7050 | `dns64.ts`, `resolve.ts` | `dns64.test.ts`, `resolve.test.ts` |
| DNS Cookies, only with the `COOKIE_SECRET` setting; never enforced (HTTPS already stops spoofing); wrong length is FORMERR | RFC 7873 | `cookie.ts`, `query.ts` | `cookie.test.ts`, `dns.test.ts`, `resolve.test.ts` |
| Best-effort ECH key for Cloudflare names (skipped with DO) | RFC 9460 (ECH draft) | `ech.ts`, `cloudflare-ips.ts` | `resolve.test.ts` |
| Redirects: a name answered with another name's A/AAAA (`medium.com` -> `voz.vn`), HTTPS/SVCB NODATA | none | `config.ts`, `upstream.ts`, `local.ts` | `resolve.test.ts` |
| Routing: `/dns-query`, `/resolve`, `/apple`, `/cloudflare-ips.json`, 404 otherwise | none | `handlers.ts` | `handlers.test.ts` |
| Apple DNS profile page: measures Cloudflare addresses in the browser, plain profile or one with `ServerAddresses` | Apple `com.apple.dnsSettings.managed` | `profile.ts` | `handlers.test.ts` |
| Ranges offered by that page: the published Cloudflare ranges that answer for the domain, found by the build, and the IPv6 prefix of the domain's AAAA records, with which the page makes an IPv6 address from each IPv4 one (undocumented, checked by hand) | none | `scripts/cloudflare-probe.ts`, `scripts/build-blocklist.ts`, `cloudflare-ips.ts`, `profile.ts` | `cloudflare-probe.test.ts`, `handlers.test.ts` |
| Blocklist (Ribbon filter in shards, subdomains covered) | none | `blockset.ts`, `blocklist.ts` | `blockset.test.ts`, `blocking.test.ts` |
| Blocklist build: list parsing, dedupe, regex drop | hosts / adblock syntax | `scripts/blocklist-lib.ts` | `blockset.test.ts` |
| Regex block/allow rules (allow wins), safety checks | none | `regexlist.ts` | `rules.test.ts`, `blocking.test.ts` |
| DNS rebinding protection: private, loopback, link-local and shared addresses (also in HTTPS/SVCB hints) get NXDOMAIN with EDE 15; `allow` rules exempt | none (as dnsmasq `stop-dns-rebind`, Unbound `private-address`) | `rebinding.ts`, `blocking.ts` | `rebinding.test.ts`, `blocking.test.ts` |
| CNAME uncloaking | none | `resolve.ts` | `blocking.test.ts` |
| JSON/RFC 3597 record text, AAAA compression | RFC 3597, 5952 | `format.ts` | `format.test.ts` |

## Known gaps

- Not covered by unit tests: the browser side of `/apple` beyond parsing and the plain button (probing and ranking run only in a real browser), and the probe's network calls (`scripts/cloudflare-probe.ts` is tested for its sampling only).
- A DNSSEC-validating client sees a blocked name's NXDOMAIN as unsigned (inherent to filtering).
