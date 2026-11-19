/**
 * @fileoverview Cloudflare Workers entry point: sends `/dns-query` and
 * `/resolve` to the gateway. Everything else is served from the static assets
 * (see `assets` in wrangler.jsonc), so this is only run for those two paths.
 */

import {handle, handleJson} from './core.js';
import type {Env} from './types.js';

export default {
  fetch(
    request: Request,
    env: Env,
    ctx: {waitUntil(promise: Promise<unknown>): void}
  ): Promise<Response> | Response {
    const context = {
      env,
      ip: request.headers.get('CF-Connecting-IP'),
      cache: caches.default,
      waitUntil: (promise: Promise<unknown>) => ctx.waitUntil(promise),
    };
    const path = new URL(request.url).pathname.replace(/\/+$/, '');
    if (path === '/dns-query') {
      return handle(request, context);
    }
    if (path === '/resolve') {
      return handleJson(request, context);
    }
    return env.ASSETS
      ? env.ASSETS.fetch(request)
      : new Response('not found', {status: 404});
  },
};
