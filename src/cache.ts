/**
 * @fileoverview Two-tier answer cache, after RethinkDNS: a small LRU in the
 * isolate's memory (free to read) in front of the Cloudflare Cache API (shared
 * by all isolates in a data center, but each read costs a few milliseconds).
 */

import {LOCAL_CACHE_SIZE, MIN_CACHE_TTL, REFRESH_EARLY_MS} from './config.js';
import {parseAnswers, u16} from './dns.js';
import type {Question, Result} from './types.js';

/** A cached response. `storedAt` is in milliseconds, `ttl` in seconds. */
interface Entry {
  body: Uint8Array;
  storedAt: number;
  ttl: number;
}

/** Least-recently-used cache backed by a Map (which keeps insert order). */
class LruCache {
  private readonly entries = new Map<string, Entry>();

  constructor(private readonly capacity: number) {}

  /**
   */
  get(key: string): Entry | undefined {
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.entries.set(key, entry); // Now the most recently used.
    }
    return entry;
  }

  /**
   */
  put(key: string, entry: Entry): void {
    this.entries.delete(key);
    this.entries.set(key, entry);
    if (this.entries.size > this.capacity) {
      const oldest = this.entries.keys().next();
      if (!oldest.done) {
        this.entries.delete(oldest.value);
      }
    }
  }
}

const localCache = new LruCache(LOCAL_CACHE_SIZE);

/**
 * @param now Milliseconds.
 * @return Whether the entry may still be served.
 */
function isFresh(entry: Entry, now: number): boolean {
  const remaining = entry.storedAt + entry.ttl * 1000 - now;
  if (remaining <= 0) {
    return false;
  }
  return !(remaining < REFRESH_EARLY_MS && Math.random() < 1 / 6);
}

/**
 * Turns an entry into a response for `q`, with every answer TTL set to the
 * time left in the cache.
 * @param now Milliseconds.
 */
function serve(entry: Entry, q: Question, now: number): Result | null {
  const body = entry.body.slice();
  if (body.length < 12 + q.raw.length) {
    return null;
  }
  const remaining = Math.max(
    1,
    Math.ceil((entry.storedAt + entry.ttl * 1000 - now) / 1000)
  );
  body.set(u16(q.id), 0);
  body.set(q.raw, 12); // Same length as stored; restores the client's case.
  try {
    const view = new DataView(body.buffer);
    for (const answer of parseAnswers(body)) {
      view.setUint32(answer.start + 4, remaining);
    }
  } catch {
    return null;
  }
  return {body, ttl: remaining, hit: true};
}

/**
 * Looks an answer up: memory first, then the Cache API.
 */
export async function lookup(
  cache: Cache | undefined,
  key: string,
  q: Question
): Promise<Result | null> {
  const local = localCache.get(key);
  if (local && isFresh(local, Date.now())) {
    const result = serve(local, q, Date.now());
    if (result) {
      return result;
    }
  }
  if (!cache) {
    return null;
  }

  const hit = await cache.match(new Request(key));
  if (!hit) {
    return null;
  }
  const entry = {
    body: new Uint8Array(await hit.arrayBuffer()),
    storedAt: Number(hit.headers.get('x-t')) * 1000,
    ttl: Number(hit.headers.get('x-ttl')),
  };
  if (!(entry.storedAt > 0 && entry.ttl > 0) || !isFresh(entry, Date.now())) {
    return null;
  }
  localCache.put(key, entry); // Write-through to the faster tier.
  return serve(entry, q, Date.now());
}

/**
 * Stores a response in both tiers, unless it is an error or truncated.
 */
export function store(
  cache: Cache | undefined,
  key: string,
  {body, ttl}: Result,
  waitUntil?: (promise: Promise<unknown>) => void
): void {
  const rcode = body[3] & 15;
  const truncated = body[2] & 2;
  if ((rcode !== 0 && rcode !== 3) || truncated) {
    return;
  }

  const entry = {
    body,
    storedAt: Date.now(),
    ttl: Math.max(ttl, MIN_CACHE_TTL),
  };
  localCache.put(key, entry);
  if (!cache) {
    return;
  }

  const stored = cache.put(
    new Request(key),
    new Response(body, {
      headers: {
        'cache-control': `public, max-age=${entry.ttl}`,
        'x-t': String(Math.floor(entry.storedAt / 1000)),
        'x-ttl': String(entry.ttl),
      },
    })
  );
  if (waitUntil) {
    waitUntil(stored);
  }
}
