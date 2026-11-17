/** @fileoverview Cloudflare Pages adapter for `/dns-query`. */

import {handle} from '../src/core.js';
import type {Env} from '../src/types.js';

export const onRequest: PagesFunction<Env> = ({request, env, waitUntil}) =>
  handle(request, {
    env,
    ip: request.headers.get('CF-Connecting-IP'),
    cache: caches.default,
    waitUntil,
  });
