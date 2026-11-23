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
| Client subnet, only with `ECS_ENABLED` (off by default: Cloudflare's resolver ignores it; off = no ECS option, one query, one cache entry for all): /24 and /48 from `CF-Connecting-IP`, client-chosen subnet, source prefix 0 = not located (also sent when there is no subnet, so the upstream makes none up), per-subnet cache, no ECS in responses to queries without one; with a subnet, queries with and without ECS run in parallel and the ECS answer wins unless it is REFUSED or fails; a malformed client subnet is FORMERR; a reply whose subnet is not the one sent is dropped (7.3), and a client that sent one always gets one back, with scope 0 if the upstream sent none (7.2.2) | RFC 7871 | `ecs.ts`, `resolve.ts`, `upstream.ts`, `query.ts` | `ecs.test.ts`, `resolve.test.ts`, `handlers.test.ts` |
| Cache: TTL countdown (answer, authority, additional), LRU, Cache API, early refresh | RFC 1035, 2181 | `cache.ts` | `cache.test.ts`, `resolve.test.ts` |
| Serve-stale with TTL 30 and EDE 3 | RFC 8767 (deliberate deviation: served at once, not after a failed refresh) | `cache.ts`, `resolve.ts` | `cache.test.ts`, `resolve.test.ts` |
| Minimum cache TTL 60 s (also for TTL 0, which RFC 1035 and 8767 say not to cache) | none (deliberate deviation) | `cache.ts` | `cache.test.ts` |
| Request coalescing, hedged upstream queries (every one, with or without ECS) | none | `upstream.ts`, `resolve.ts` | `upstream.test.ts`, `resolve.test.ts`, `upstream-failures.test.ts` |
| `localhost` answers | RFC 6761 | `resolve.ts` | `resolve.test.ts` |
| Undelegated names, private reverse zones, `.alt`; `home.arpa` is not forwarded, except a DS query with DO (it must prove the absence) | RFC 6761, 6303, 8375, 9476 | `undelegated.ts` | `undelegated.test.ts`, `resolve.test.ts` |
| ANY gets HINFO (`RFC8482`), but not with DO: that needs an RRSIG for a signed zone (MUST), so the upstream answers. Deviation: a name that has a CNAME gets HINFO too (RFC 8482 4.2 allows it only where there is none; this cannot be known without asking) | RFC 8482 | `local.ts` | `resolve.test.ts`, `inputs.test.ts` |
| NOTIMP for other opcodes, AXFR/IXFR/MAILB/MAILA; FORMERR for QTYPE 0/OPT/TKEY/TSIG; REFUSED for classes other than IN (these rcodes are this gateway's choice: the RFCs do not fix them) | RFC 1035, 5936, 6895 | `resolve.ts` | `resolve.test.ts` |
| FORMERR for an invalid OPT (two OPTs, non-root owner, bad length) | RFC 6891 6.1.1 | `query.ts`, `resolve.ts` | `dns.test.ts`, `resolve.test.ts` |
| DDR (`_dns.resolver.arpa` SVCB, with the host's A/AAAA in additional); other `resolver.arpa` names get NODATA | RFC 9462, 9460 | `resolve.ts` | `resolve.test.ts` |
| Resolver information: RESINFO for the gateway host (`exterr`), with the AA flag, without which a client discards it | RFC 9606 | `local.ts` | `local.test.ts`, `resolve.test.ts` |
| DNS64, on request with `dns64=1` (prefix in `config.ts`; not for DO without CD, nor private addresses): AAAA from A, PTR for the prefix, `ipv4only.arpa`; an AAAA lookup that fails, gets any rcode but NXDOMAIN, or holds only `::ffff:0:0/96` addresses counts as empty (5.1.2-5.1.4) | RFC 6147, 6052, 7050 | `dns64.ts`, `resolve.ts` | `dns64.test.ts`, `resolve.test.ts` |
| DNS Cookies, only with the `COOKIE_SECRET` setting; never enforced (HTTPS already stops spoofing); wrong length is FORMERR | RFC 7873 | `cookie.ts`, `query.ts` | `cookie.test.ts`, `dns.test.ts`, `resolve.test.ts` |
| Best-effort ECH key for Cloudflare names (skipped with DO) | RFC 9460 (ECH draft) | `ech.ts`, `cloudflare-ips.ts` | `resolve.test.ts` |
| Redirects: a name answered with another name's A/AAAA (`medium.com` -> `voz.vn`), HTTPS/SVCB NODATA | none | `config.ts`, `upstream.ts`, `local.ts` | `resolve.test.ts` |
| Behaviour per kind of input: header flags, opcodes, QDCOUNT/ANCOUNT/ARCOUNT, QTYPE and QCLASS, names (root, 63-octet label, 253 characters, mixed case, odd bytes, compression), EDNS versions and flags, malformed OPT, cookies of each length, ECS variants (a client ECS with an unknown family, a wrong number of address octets or bits past its prefix is FORMERR; a scope in a query is accepted); and a query cut at every byte (400 before the question ends, FORMERR inside the OPT record) | RFC 1035, 2181, 4343, 6891, 7871 (6, 7.2.1), 7873, 8482, 9619 | `query.ts`, `local.ts`, `handlers.ts` | `inputs.test.ts` |
| Behaviour per kind of request on the JSON API `/resolve`: methods, names (length limits, case kept, punycode only), types (names, numbers, 0 and 65536 refused, ANY/AXFR/OPT locally), reverse names for PTR/NAPTR of an IP, `do`/`cd`/`ct`, `edns_client_subnet` (valid, /0, invalid), repeated and unknown parameters | Google DNS-over-HTTPS JSON API | `handlers.ts` | `json-inputs.test.ts` |
| Behaviour when the upstream misbehaves: HTTP errors, dropped connections, bodies that are not DNS messages or answer another question or id (all SERVFAIL with EDE 23, not cached), each rcode passed on (only NOERROR and NXDOMAIN kept), a slow or failing first try (hedging), a stale answer served while it is down, REFUSED to, or failure of, the subnet query (RFC 7871 7.1.3: the answer without the subnet is used), and the JSON API | RFC 2308, 7871, 8767, 8914 | `upstream.ts`, `resolve.ts`, `cache.ts` | `upstream-failures.test.ts` |
| Routing: `/dns-query`, `/resolve`, `/apple`, `/cloudflare-ips.json`, 404 otherwise | none | `handlers.ts` | `handlers.test.ts` |
| Apple DNS profile page: measures Cloudflare addresses in the browser, plain profile or one with `ServerAddresses` | Apple `com.apple.dnsSettings.managed` | `profile.ts` | `handlers.test.ts` |
| Ranges offered by that page: the published Cloudflare ranges that answer for the domain, found by the build, and the IPv6 prefix of the domain's AAAA records, with which the page makes an IPv6 address from each IPv4 one (undocumented, checked by hand) | none | `scripts/cloudflare-probe.ts`, `scripts/build-blocklist.ts`, `cloudflare-ips.ts`, `profile.ts` | `cloudflare-probe.test.ts`, `handlers.test.ts` |
| Blocklist (Ribbon filter in shards, subdomains covered) | none | `blockset.ts`, `blocklist.ts` | `blockset.test.ts`, `blocking.test.ts` |
| Blocklist build: list parsing, dedupe, regex drop | hosts / adblock syntax | `scripts/blocklist-lib.ts` | `blockset.test.ts` |
| Regex block/allow rules (allow wins), safety checks | none | `regexlist.ts` | `rules.test.ts`, `blocking.test.ts` |
| DNS rebinding protection: private, loopback, link-local and shared addresses (also in HTTPS/SVCB hints) get NXDOMAIN with EDE 15; `allow` rules exempt | none (as dnsmasq `stop-dns-rebind`, Unbound `private-address`) | `rebinding.ts`, `blocking.ts` | `rebinding.test.ts`, `blocking.test.ts` |
| CNAME uncloaking | none | `resolve.ts` | `blocking.test.ts` |
| JSON/RFC 3597 record text, AAAA compression | RFC 3597, 5952 | `format.ts` | `format.test.ts` |

## Trade-offs

Where this gateway spends the upstream's capacity (or a client's privacy) to save latency. Accepted, because the upstream is a public resolver built for this load and the gateway serves a handful of clients; revisit them if the traffic grows or the upstream changes.

| Choice | What it costs | Why it is accepted |
|---|---|---|
| Every miss in the isolate's memory asks the upstream, even when the Cache API holds the answer (the two race, the first wins, the upstream call renews the cache) | One upstream query per such request: the Cache API saves latency, not upstream load. The largest of the costs here, and the one that grows with traffic | The answer comes at the speed of the faster one, and the cache is always renewed, so nothing served from it is far out of date. Skipping the upstream when the Cache API entry is fresh would cut the load but add latency on those requests; load is not a goal here, latency is, so it is kept as it is |
| Hedging: a query still pending after 3x the recent average latency (20-80 ms) is sent again, to the same or the backup upstream | At most one extra query, only for a slow one: few when the upstream is healthy (not measured), up to twice the queries while it is slow or failing | The tail of the latency (p90, max) is where most of the delay is; the extra query often shares the open connection |
| With ECS on and a subnet, one query with it and one without, in parallel (`ECS_ENABLED`, off by default) | Twice the upstream queries, each also hedged: up to four per request | The one without the subnet is the fallback for a resolver that refuses ECS (RFC 7871 7.1.3) and for one that fails on it; off, which suits Cloudflare's resolver, costs none of this |
| Early refresh: an entry with under 10 s left is renewed on 1 in 6 lookups | A few queries just before an entry expires, for names that are asked often | Popular names are renewed gradually, so a client rarely waits for an expired one |
| Serve-stale: an expired answer (up to 6 h) is returned at once and renewed in the background | One background query for the first request after it expires | The client never waits; if the upstream is down the stale answer is still served |
| Minimum cache TTL of 60 s | Answers can be up to 60 s older than their TTL says (RFC deviation) | Short TTLs of CDNs would otherwise bring a query on almost every request |
| Coalescing: identical concurrent queries share one upstream call | None; it saves queries | If that call fails the others try on their own once |
| HTTPS queries for Cloudflare-hosted names do an extra A lookup (to recognise them for the ECH key), and DNS64 does an A lookup beside AAAA | One more upstream query for those requests only, and for DNS64 only on request | Both are optional best-effort features; the lookup runs alongside the main one |
| A query with no subnet is sent with ECS source prefix 0 (when ECS is on) | None; it is a privacy choice | Google would otherwise invent a subnet from the Worker's own address |
| The client's address is sent upstream as a /24 (/48) subnet (when ECS is on) | Reveals the neighbourhood of a client to the upstream | The point of ECS is that a CDN answers with a server near the client; a client can send prefix 0 to refuse it |
| The upstream is trusted: its answer is checked only for id and question, not validated | A wrong but well-formed answer from it would be served and cached | It is reached over HTTPS and chosen by the operator; validating DNSSEC is left to the client |

## Checked against the RFC texts

The rules that bind a server were read in the text of each RFC (not recalled from memory), and the code fixed where it differed: 7871 (ECS), 6891 (EDNS), 8484 (DoH), 7873 (cookies), 9619, 8482 (ANY), 8767 (serve-stale), 8914 (EDE), 7830/8467 (padding), 6761/6303/8375 (special names), 9462 (DDR), 9606 (RESINFO), 6147 (DNS64), 5952 (AAAA text). Not read line by line: 1035, 2181, 2308, 3225, 3597, 4035, 4343, 5936, 6052, 6840, 6895, 7050, 9460, 9476, and 8914's registry beyond the codes used.

## Known gaps

- DNS Cookies, RFC 7873 5.4: a query with no question and a COOKIE option (to fetch a server cookie) is answered with HTTP 400, as any query without a question is. The RFC asks a server with cookies enabled to answer it; over HTTPS a cookie protects nothing, so it is not done.
- DNS64, RFC 6147 5.1.4: an AAAA answer with `::ffff:0:0/96` records next to usable ones is passed on as it is (the RFC says to drop the former); removing records from a message with name compression is not done.
- Answers made here (blocked names, undelegated names, `localhost`, HINFO) carry no signatures, so a validating client that asks with DO sees an unsigned negative answer for them, apart from the forwarded cases above.

- Not covered by unit tests: the browser side of `/apple` beyond parsing and the plain button (probing and ranking run only in a real browser), and the probe's network calls (`scripts/cloudflare-probe.ts` is tested for its sampling only).
- A DNSSEC-validating client sees a blocked name's NXDOMAIN as unsigned (inherent to filtering).
