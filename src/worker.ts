/** @fileoverview Cloudflare Workers entry point for `/dns-query` and `/resolve`. */

import blocklist from '../build/blocklist.bin';
import cloudflareIps from '../build/cloudflare-ips.json';
import rules from '../build/rules.json';
import {loadBlocklist} from './blocklist.js';
import {loadCloudflareRanges} from './cloudflare-ips.js';
import {route} from './handlers.js';
import type {Env} from './types.js';

// The lists built by `bun run build-lists` are bundled with the Worker, so a
// new isolate answers its first request without fetching them.
loadBlocklist(blocklist, rules);
loadCloudflareRanges(cloudflareIps);

export default {
  fetch(
    request: Request,
    env: Env,
    ctx: {waitUntil(promise: Promise<unknown>): void}
  ): Promise<Response> | Response {
    return route(request, {
      env,
      ip: request.headers.get('CF-Connecting-IP'),
      cache: caches.default,
      waitUntil: (promise: Promise<unknown>) => ctx.waitUntil(promise),
    });
  },
};
