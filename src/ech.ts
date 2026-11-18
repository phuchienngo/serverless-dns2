/**
 * @fileoverview Best-effort Encrypted Client Hello. Cloudflare-hosted sites
 * share one ECH key, but many resolvers do not return it. For an HTTPS query
 * that came back empty, we check whether the name's IPv4 addresses belong to
 * Cloudflare and, if so, answer with an HTTPS record carrying that key.
 */

import {CLOUDFLARE_V4, ECH_FRONT_DOMAIN} from './config.js';
import {
  ALPN_HTTP,
  RCODE_NOERROR,
  SVCPARAM_ALPN,
  SVCPARAM_ECH,
  SVCPARAM_IPV4HINT,
  TYPE_A,
  TYPE_HTTPS,
} from './constants.js';
import {
  alpnValue,
  buildQuery,
  encodeName,
  makeRecord,
  rcodeOf,
  parseAnswers,
  readName,
  respond,
  svcbRdata,
  u16,
} from './dns.js';
import type {Question, Result} from './types.js';

const ECH_CONFIG_TTL_MS = 3600 * 1000;
const SYNTHETIC_TTL = 300;

/** Asks the upstream resolver; supplied by resolve.ts to avoid a cycle. */
export type Ask = (wire: Uint8Array) => Promise<Uint8Array>;

function toInt(bytes: ArrayLike<number>): number {
  return (
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0
  );
}

const RANGES = CLOUDFLARE_V4.map(([base, bits]) => ({
  base: toInt(base.split('.').map(Number)),
  mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0,
}));

function isCloudflare(ip: ArrayLike<number>): boolean {
  const n = toInt(ip);
  return RANGES.some(r => (n & r.mask) >>> 0 === r.base);
}

/**
 * @return The value of SvcParam `key` of an HTTPS record's RDATA, or null.
 */
function svcParam(resp: Uint8Array, rdata: number, end: number, key: number) {
  let offset = readName(resp, rdata + 2).next; // Skip priority and target.
  while (offset + 4 <= end) {
    const k = (resp[offset] << 8) | resp[offset + 1];
    const length = (resp[offset + 2] << 8) | resp[offset + 3];
    if (k === key) {
      return resp.slice(offset + 4, offset + 4 + length);
    }
    offset += 4 + length;
  }
  return null;
}

let echConfig: {value: Uint8Array; expires: number} | null = null;
let echConfigLoading: Promise<Uint8Array | null> | null = null;

/** Forgets the memoized ECH key (for tests). */
export function resetEch(): void {
  echConfig = null;
  echConfigLoading = null;
}

async function loadEchConfig(ask: Ask): Promise<Uint8Array | null> {
  const question = [...encodeName(ECH_FRONT_DOMAIN), ...u16(TYPE_HTTPS), 0, 1];
  const resp = await ask(buildQuery(question, null));
  for (const a of parseAnswers(resp)) {
    if (a.type !== TYPE_HTTPS) {
      continue;
    }
    const rdata = a.data;
    const value = svcParam(resp, rdata, rdata + a.length, SVCPARAM_ECH);
    if (value) {
      echConfig = {value, expires: Date.now() + ECH_CONFIG_TTL_MS};
      return value;
    }
  }
  return null;
}

/**
 * @return The shared Cloudflare ECHConfigList (memoized for an hour; queries
 *     that need it at the same time share one request).
 */
function getEchConfig(ask: Ask): Promise<Uint8Array | null> {
  if (echConfig && echConfig.expires > Date.now()) {
    return Promise.resolve(echConfig.value);
  }
  echConfigLoading ??= loadEchConfig(ask).finally(() => {
    echConfigLoading = null;
  });
  return echConfigLoading;
}

/** @return Whether any of the name's A records is a Cloudflare address. */
async function behindCloudflare(
  name: string,
  ecs: number[] | null,
  ask: Ask
): Promise<boolean> {
  const question = [...encodeName(name), ...u16(TYPE_A), 0, 1];
  const resp = await ask(buildQuery(question, ecs));
  return parseAnswers(resp).some(
    a =>
      a.type === TYPE_A &&
      a.length === 4 &&
      isCloudflare(resp.subarray(a.data, a.data + 4))
  );
}

/**
 * Work that may be needed to add ECH, started alongside the HTTPS query so
 * that it does not add to the wait.
 */
export interface EchProbe {
  cloudflare: Promise<boolean>;
  config: Promise<Uint8Array | null>;
}

/**
 * Starts the lookups addEch may need: is the name on Cloudflare (an A query),
 * and the ECH key (usually already memoized).
 * @return null if `q` is not an HTTPS query.
 */
export function startEchProbe(
  q: Question,
  ecs: number[] | null,
  ask: Ask
): EchProbe | null {
  if (q.type !== TYPE_HTTPS) {
    return null;
  }
  return {
    cloudflare: behindCloudflare(q.name, ecs, ask).catch(() => false),
    config: getEchConfig(ask).catch(() => null),
  };
}

/**
 * Replaces the HTTPS answer with one carrying ECH when `result` has none and the
 * name is served by Cloudflare. The IPv4 hints of the answer, if it has any,
 * tell whether the name is on Cloudflare; otherwise the probe's A query does.
 * Returns `result` unchanged otherwise, or if anything fails.
 */
export async function addEch(
  result: Result,
  q: Question,
  probe: EchProbe | null
): Promise<Result> {
  if (!probe || rcodeOf(result.body) !== RCODE_NOERROR) {
    return result;
  }
  try {
    let hinted: boolean | null = null;
    for (const a of parseAnswers(result.body)) {
      if (a.type !== TYPE_HTTPS) {
        continue;
      }
      const rdata = a.data;
      const end = rdata + a.length;
      if (svcParam(result.body, rdata, end, SVCPARAM_ECH)) {
        return result; // Already has ECH.
      }
      const hints = svcParam(result.body, rdata, end, SVCPARAM_IPV4HINT);
      for (let i = 0; hints && i + 4 <= hints.length; i += 4) {
        hinted = (hinted ?? false) || isCloudflare(hints.subarray(i, i + 4));
      }
    }
    if (!(hinted ?? (await probe.cloudflare))) {
      return result;
    }
    const config = await probe.config;
    if (!config) {
      return result;
    }
    const rdata = svcbRdata(1, '.', [
      [SVCPARAM_ALPN, alpnValue(ALPN_HTTP)],
      [SVCPARAM_ECH, [...config]],
    ]);
    const record = makeRecord(TYPE_HTTPS, SYNTHETIC_TTL, rdata);
    return {body: respond(q, RCODE_NOERROR, [record]), ttl: SYNTHETIC_TTL};
  } catch {
    return result; // ECH is best effort: keep the answer as it is.
  }
}
