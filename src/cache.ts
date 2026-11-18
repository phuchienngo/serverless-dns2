/**
 * @fileoverview Two-tier answer cache, after RethinkDNS: a small LRU in the
 * isolate's memory (free to read) in front of the Cloudflare Cache API (shared
 * by all isolates in a data center, but each read costs a few milliseconds).
 */

import {
  LOCAL_CACHE_SIZE,
  MIN_CACHE_TTL,
  REFRESH_EARLY_MS,
  STALE_MAX_S,
  STALE_TTL,
} from './config.js';
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

/** A cached answer for a question; `refresh` asks the caller to renew it. */
export interface Hit {
  result: Result;
  refresh: boolean;
}

type Freshness = 'fresh' | 'early' | 'stale' | 'expired';

/**
 * @param now Milliseconds.
 * @return `early` is a fresh entry about to expire (renewed with a small
 *     chance on each use, so that clients rarely wait); `stale` is expired but
 *     still servable.
 */
function classify(entry: Entry, now: number): Freshness {
  const remaining = entry.storedAt + entry.ttl * 1000 - now;
  if (remaining <= -STALE_MAX_S * 1000) {
    return 'expired';
  }
  if (remaining <= 0) {
    return 'stale';
  }
  return remaining < REFRESH_EARLY_MS && Math.random() < 1 / 6
    ? 'early'
    : 'fresh';
}

/**
 * Turns an entry into a hit for `q`, with every answer TTL set to the time
 * left in the cache (or a short one for a stale answer).
 * @param now Milliseconds.
 */
function serve(entry: Entry, q: Question, now: number): Hit | null {
  const freshness = classify(entry, now);
  if (freshness === 'expired' || entry.body.length < 12 + q.raw.length) {
    return null;
  }
  const body = entry.body.slice();
  const remaining =
    freshness === 'stale'
      ? STALE_TTL
      : Math.max(
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
  return {
    result: {
      body,
      ttl: remaining,
      hit: true,
      stale: freshness === 'stale',
    },
    refresh: freshness !== 'fresh',
  };
}

/**
 * Looks an answer up in the isolate's memory (instant).
 */
export function lookupLocal(key: string, q: Question): Hit | null {
  const entry = localCache.get(key);
  return entry ? serve(entry, q, Date.now()) : null;
}

/**
 * Looks an answer up in the Cache API (shared by the data center).
 */
export async function lookupShared(
  cache: Cache | undefined,
  key: string,
  q: Question
): Promise<Hit | null> {
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
  if (!(entry.storedAt > 0 && entry.ttl > 0)) {
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
        // Kept past its TTL so that it can be served stale.
        'cache-control': `public, max-age=${entry.ttl + STALE_MAX_S}`,
        'x-t': String(Math.floor(entry.storedAt / 1000)),
        'x-ttl': String(entry.ttl),
      },
    })
  );
  if (waitUntil) {
    waitUntil(stored);
  }
}
