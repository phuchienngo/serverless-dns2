# Features, standards and tests

Every feature, the standard it follows, where it lives and which test covers it.
`npm test` runs all tests (`node:test` via tsx, upstream mocked); `npm run check` also typechecks them.
"Deliberate deviation" marks a place where performance or privacy wins over the RFC.

| Feature | Standard | Code | Tests |
|---|---|---|---|
| DoH GET/POST, status codes (405/413/414/415/400) | RFC 8484 | `handlers.ts` | `handlers.test.ts` |
| JSON API `/resolve` (name, type, do, cd, ct, subnet, PTR from IP) | Google DoH JSON | `handlers.ts`, `format.ts` | `handlers.test.ts`, `format.test.ts` |
| Message parsing and building, case kept (0x20) | RFC 1035, 4343 | `dns.ts` | `dns.test.ts` |
| EDNS0: OPT only if the query had one, DO echoed, BADVERS, extended rcode | RFC 6891 | `dns.ts`, `resolve.ts` | `dns.test.ts`, `resolve.test.ts` |
| DNSSEC passthrough: DO, CD, AD | RFC 3225, 4035, 6840 5.7 | `resolve.ts`, `dns.ts` | `resolve.test.ts` |
| Negative answers carry a SOA, minimum TTL | RFC 2308 | `dns.ts` | `dns.test.ts`, `resolve.test.ts` |
| Padding of responses to 468 bytes | RFC 7830, 8467 | `dns.ts` | `dns.test.ts`, `resolve.test.ts` |
| Extended DNS Errors (15 blocked, 3 stale) | RFC 8914 | `dns.ts`, `resolve.ts` | `dns.test.ts`, `blocking.test.ts`, `resolve.test.ts` |
| Client subnet: /24 and /48, client-chosen subnet, per-subnet cache, no ECS in responses to queries without one | RFC 7871 | `ecs.ts`, `resolve.ts` | `ecs.test.ts`, `resolve.test.ts` |
| Cache: TTL countdown (answer, authority, additional), LRU, Cache API, early refresh | RFC 1035, 2181 | `cache.ts` | `cache.test.ts`, `resolve.test.ts` |
| Serve-stale with TTL 30 and EDE 3 | RFC 8767 (deliberate deviation: served at once, not after a failed refresh) | `cache.ts`, `resolve.ts` | `cache.test.ts`, `resolve.test.ts` |
| Minimum cache TTL 60 s | none (deliberate deviation) | `cache.ts` | `cache.test.ts` |
| Request coalescing, hedged upstream queries | none | `resolve.ts` | `resolve.test.ts` |
| `localhost` answers | RFC 6761 | `resolve.ts` | `resolve.test.ts` |
| Undelegated names, private reverse zones, `.alt` | RFC 6761, 6303, 8375, 9476 | `undelegated.ts` | `undelegated.test.ts`, `resolve.test.ts` |
| ANY gets HINFO | RFC 8482 | `resolve.ts` | `resolve.test.ts` |
| NOTIMP for other opcodes, AXFR/IXFR/MAILB/MAILA; FORMERR for QTYPE 0/OPT/TKEY/TSIG; REFUSED for classes other than IN | RFC 1035, 5936, 6895 |
| FORMERR for an invalid OPT (two OPTs, non-root owner, bad length) | RFC 6891 6.1.1 | `dns.ts`, `resolve.ts` | `dns.test.ts`, `resolve.test.ts` | `resolve.ts` | `resolve.test.ts` |
| DDR (`_dns.resolver.arpa` SVCB); other `resolver.arpa` names get NODATA | RFC 9462, 9460 | `resolve.ts` | `resolve.test.ts` |
| Best-effort ECH key for Cloudflare names (skipped with DO) | RFC 9460 (ECH draft) | `ech.ts` | `resolve.test.ts` |
| Blocklist (Golomb-coded set, subdomains covered) | none | `blockset.ts`, `blocklist.ts` | `blockset.test.ts`, `blocking.test.ts` |
| Blocklist build: list parsing, dedupe, regex drop | hosts / adblock syntax | `scripts/blocklist-lib.ts` | `blockset.test.ts` |
| Regex block/allow rules (allow wins), safety checks | none | `regexlist.ts` | `rules.test.ts`, `blocking.test.ts` |
| CNAME uncloaking | none | `resolve.ts` | `blocking.test.ts` |
| JSON/RFC 3597 record text, AAAA compression | RFC 3597, 5952 | `format.ts` | `format.test.ts` |

## Known gaps

- `checkPattern` does not detect catastrophic patterns such as `^(a|aa)+$` (3 `todo` tests).
- Not covered by unit tests: `functions/*.ts` adapters, `Server-Timing`, retry of a failed blocklist load.
- A DNSSEC-validating client sees a blocked name's NXDOMAIN as unsigned (inherent to filtering).
