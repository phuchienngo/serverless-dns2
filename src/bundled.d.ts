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
  const ranges: {v4?: string[]; pinnable?: string[]; v6prefix?: string | null};
  export default ranges;
}
