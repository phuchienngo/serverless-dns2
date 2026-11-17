# DoH gateway (Cloudflare Pages)

- `/dns-query` — RFC 8484 DoH (GET `?dns=`, POST `application/dns-message`). Status codes follow Google Public DNS.
- `/resolve` — Google-style JSON API (GET): `name`, `type`, `do`, `cd`, `ct`, `edns_client_subnet`.
  (`/dns-query?name=...` also returns JSON.)

Config: secret `UPSTREAM` (upstream DoH URL, blocklist lives there):
`wrangler pages secret put UPSTREAM --project-name serverless-dns2`.
`REDIRECTS` (CDN source -> target) and other knobs are in `src/config.ts`.

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

## Blocklist (manual)

1. Put your sources in `blocklists.yaml` (`lists`, plus optional `allow` and `block` domains).
2. `npm run build-lists` downloads them, keeps plain domains only and writes `public/blocklist.bin`
   (a flat character-level trie in the style of Cloudflare trie-hard; blocking a domain blocks its subdomains).
   If a source fails, nothing is written.
3. Commit `public/blocklist.bin` and push (or `npm run deploy`). Blocked names get NXDOMAIN.

Each isolate loads the file once into memory. `allow` cannot punch a hole into a blocked parent domain.
