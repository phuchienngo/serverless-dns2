/**
 * @fileoverview Resolves one question: local answers, blocking, the caches and
 * the upstream resolver. Shared by the `/dns-query` and `/resolve` endpoints.
 */

import {lookupLocal, lookupShared, store} from './cache.js';
import {blockReason, nxdomain, screen} from './blocking.js';
import {
  EDE_NETWORK_ERROR,
  EDE_STALE_ANSWER,
  EDE_STALE_NXDOMAIN,
  OPTION_ECS,
  RCODE_NXDOMAIN,
  RCODE_SERVFAIL,
  TTL_DISCOVERY,
  TTL_FAILURE,
  TYPE_A,
  TYPE_AAAA,
} from './constants.js';
import {
  makeRecord,
  copyRd,
  edeOption,
  respond,
  rewriteOpt,
  stripOpt,
} from './response.js';
import {encodeName, parseAnswers, rcodeOf} from './wire.js';
import {makeQuestion} from './query.js';
import {cookieOption} from './cookie.js';
import {ipv4onlyAnswer, withDns64} from './dns64.js';
import {getCloudflareRanges} from './cloudflare-ips.js';
import {addEch, startEchProbe} from './ech.js';
import {clientEcsReply, makeEcs} from './ecs.js';
import {ddrAnswer, isDdr, localAnswer, typeAnswer} from './local.js';
import type {Question, ResolveOptions, Result} from './types.js';
import {askUpstream, coalesce, forward, queryFlags} from './upstream.js';

/** Names that need no escaping in a URL (the usual case: faster to test). */
const SAFE_NAME = /^[a-z0-9.-]+$/;

/**
 * Cache key: name, type, client subnet and DNSSEC flags.
 * @return A URL, as the Cache API only accepts requests as keys.
 */
function cacheKey(host: string, q: Question, ecs: number[] | null): string {
  const subnet = ecs ? ecs.slice(4).join('-') : 'none';
  const {dnssec, cd, ad} = queryFlags(q);
  const flags = `${+dnssec}${+cd}${+ad}`;
  const name = SAFE_NAME.test(q.name) ? q.name : encodeURIComponent(q.name);
  return `https://${host}/__cache/${name}/${q.type}/${subnet}/${flags}`;
}

/** Where DNS64 keeps what it makes: the cache key, in a space of its own. */
function dns64Key(q: Question, options: ResolveOptions): string {
  return `${cacheKey(options.host, q, ecsOf(options))}/dns64`;
}

/** The client subnet to send: the one chosen by the client, else its IP's. */
function ecsOf(options: ResolveOptions): number[] | null {
  if (options.ecs !== undefined) {
    return options.ecs;
  }
  return options.ip ? makeEcs(options.ip) : null;
}

/**
 * The DDR answer (RFC 9462 4): the SVCB record naming this gateway, and the
 * A and AAAA records of its host name in the additional section, which save
 * the client a round trip. The addresses are left out if they cannot be had.
 */
async function ddrResult(
  q: Question,
  options: ResolveOptions
): Promise<Result> {
  const {host} = options;
  const owner = encodeName(host);
  const lookups = await Promise.allSettled(
    [TYPE_A, TYPE_AAAA].map(type =>
      // Same options for both, and no subnet, so that they share cache entries.
      answer(makeQuestion(host, type), {...options, ecs: null})
    )
  );
  const hints = lookups.flatMap(lookup => {
    if (lookup.status !== 'fulfilled') {
      return [];
    }
    const {body} = lookup.value;
    return parseAnswers(body)
      .filter(r => r.type === TYPE_A || r.type === TYPE_AAAA)
      .map(r => {
        return makeRecord(
          r.type,
          Math.min(r.ttl, TTL_DISCOVERY),
          [...body.subarray(r.data, r.end)],
          owner
        );
      });
  });
  return {body: ddrAnswer(q, host, hints), ttl: TTL_DISCOVERY};
}

/**
 * Resolves a question.
 * @throws If the upstream resolver fails.
 */
export async function resolve(
  q: Question,
  options: ResolveOptions
): Promise<Result> {
  const result = await resolveQuestion(q, options);
  return {...result, body: await shape(q, result, options)};
}

/**
 * Shapes an answer for the client that asked: its RD flag, the EDNS parts
 * (an OPT record only if it sent one, ECS as it sent it, EDE for a stale
 * answer, a cookie, padding last so that the size is final).
 */
async function shape(
  q: Question,
  result: Result,
  options: ResolveOptions
): Promise<Uint8Array> {
  const body = copyRd(result.body, q.rd);
  if (!q.edns) {
    // The upstream always sends an OPT record; a client that sent none must
    // not get one (RFC 6891).
    return stripOpt(body);
  }
  const added: number[][] = [];
  if (result.stale) {
    const code =
      rcodeOf(body) === RCODE_NXDOMAIN ? EDE_STALE_NXDOMAIN : EDE_STALE_ANSWER;
    added.push(edeOption(code, ''));
  }
  const cookie = await cookieOption(q, options.ip, options.env.COOKIE_SECRET);
  if (cookie) {
    added.push(cookie);
  }
  const {ecs} = q;
  return rewriteOpt(body, {
    remove: options.ecs ? undefined : OPTION_ECS,
    replace:
      options.ecs && ecs
        ? {code: OPTION_ECS, withData: data => clientEcsReply(data, ecs)}
        : undefined,
    add: added,
    pad: q.padding,
  });
}

async function resolveQuestion(
  q: Question,
  options: ResolveOptions
): Promise<Result> {
  const {host} = options;

  const special =
    localAnswer(q, host) ?? (options.dns64 ? ipv4onlyAnswer(q) : null);
  if (special) {
    return special;
  }
  if (isDdr(q, host)) {
    return ddrResult(q, options);
  }

  const reason = blockReason(q.name);
  const result = reason
    ? nxdomain(q, reason)
    : screen(q, await answer(q, options));
  return options.dns64
    ? withDns64(q, dns64Key(q, options), result, a =>
        resolveQuestion(a, {...options, dns64: false})
      )
    : result;
}

/**
 * Answers a question that is neither special nor blocked: local rules, then
 * the caches and the upstream resolver.
 */
async function answer(q: Question, options: ResolveOptions): Promise<Result> {
  const {host, cache, waitUntil} = options;
  const flags = queryFlags(q);

  const typed = typeAnswer(q);
  if (typed) {
    return typed;
  }

  const ecs = ecsOf(options);

  const key = cacheKey(host, q, ecs);
  const fetchFresh = async () => {
    const result = await coalesce(key, q, async () => {
      // ECH replaces the HTTPS record with an unsigned one, which a client that
      // validates DNSSEC (DO) would reject; give those the real record.
      const probe = flags.dnssec
        ? null
        : startEchProbe(q, ecs, forward, getCloudflareRanges);
      return addEch(await askUpstream(q, ecs, flags), q, probe);
    });
    store(cache, key, result, waitUntil);
    return result;
  };
  const refreshInBackground = () => {
    // A failed refresh leaves the old entry to be served; nobody waits for it.
    const refreshing = fetchFresh().catch(() => {});
    waitUntil?.(refreshing);
  };

  // 1. Memory: instant. A stale or expiring answer is served at once and
  //    renewed in the background.
  const local = lookupLocal(key, q);
  if (local) {
    if (local.refresh) {
      refreshInBackground();
    }
    return local.result;
  }

  // 2. The Cache API and the upstream resolver race: whichever answers first
  //    wins (reading the Cache API can take longer than asking the upstream).
  //    The upstream call always finishes, so it renews the cache either way.
  const started = performance.now();
  const fetching = fetchFresh();
  waitUntil?.(fetching.catch(() => {})); // Failure is handled where it is awaited.
  const shared = lookupShared(cache, key, q).catch(() => null); // A miss.
  const first = await Promise.race([
    shared.then(hit => hit?.result ?? null),
    fetching.catch(() => null),
  ]);
  if (options.timing) {
    options.timing.first = performance.now() - started;
  }
  if (first) {
    return first;
  }
  // The Cache API had nothing, or the upstream failed: use what is left.
  const hit = await shared;
  return hit ? hit.result : fetching;
}

/**
 * The answer when the upstream resolver cannot be reached: SERVFAIL with an
 * Extended DNS Error (RFC 8914) saying why, kept in clients' caches briefly.
 */
export function upstreamFailure(q: Question): Result {
  return {
    body: respond(q, RCODE_SERVFAIL, [], {
      code: EDE_NETWORK_ERROR,
      text: 'upstream unreachable',
    }),
    ttl: TTL_FAILURE,
  };
}
