/**
 * @fileoverview Cloudflare Pages adapter for `/resolve`, the Google-style
 * JSON API.
 */

import {handleJson} from '../src/core.js';
import type {Env} from '../src/types.js';

export const onRequest: PagesFunction<Env> = ({request, env, waitUntil}) =>
  handleJson(request, {
    env,
    ip: request.headers.get('CF-Connecting-IP'),
    cache: caches.default,
    waitUntil,
  });
