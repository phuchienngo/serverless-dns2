/** Files that wrangler bundles into the Worker (see worker.ts). */
declare module '*.bin' {
  const data: ArrayBuffer;
  export default data;
}
declare module '*/rules.json' {
  const rules: {block?: string[]; allow?: string[]};
  export default rules;
}
declare module '*/cloudflare-ips.json' {
  const ranges: Partial<import('./cloudflare-ips.js').CloudflareIps>;
  export default ranges;
}
