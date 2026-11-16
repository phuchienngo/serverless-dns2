# DoH gateway (Cloudflare Pages)
1. Edit `UPSTREAM` and `REDIRECTS` in `functions/dns-query.js`.
2. Deploy: `npx wrangler pages deploy public --project-name serverless-dns2`, add a custom domain (e.g. doh.example.com).
3. DDR (Android 16 Private DNS): add DNS record in your zone
   `_dns.doh.example.com  SVCB  1 doh.example.com. alpn="h2,h3" dohpath="/dns-query{?dns}"`
   then run the two `adb shell device_config put connectivity ...` flags from the loophole README.
