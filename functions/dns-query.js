// Cloudflare Pages adapter
import { handle } from "../src/core.js";

export function onRequest({ request, env, waitUntil }) {
  return handle(request, {
    env,
    ip: request.headers.get("CF-Connecting-IP"),
    cache: caches.default,
    waitUntil,
  });
}
