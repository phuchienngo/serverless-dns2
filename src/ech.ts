/**
 * @fileoverview Best-effort Encrypted Client Hello. Cloudflare-hosted sites
 * share one ECH key, but many resolvers do not return it. For an HTTPS query
 * that came back empty, we check whether the name's IPv4 addresses belong to
 * Cloudflare and, if so, answer with an HTTPS record carrying that key.
 */

import {ECH_ENABLED, ECH_FRONT_DOMAIN, TYPE_A, TYPE_HTTPS} from './config.js';
import {
  buildQuery,
  encodeName,
  parseAnswers,
  readName,
  respond,
  u16,
} from './dns.js';
import type {Question, Result} from './types.js';

/** Cloudflare's published IPv4 ranges: [first address, prefix length]. */
const CLOUDFLARE_V4: Array<[string, number]> = [
  ['173.245.48.0', 20],
  ['103.21.244.0', 22],
  ['103.22.200.0', 22],
  ['103.31.4.0', 22],
  ['141.101.64.0', 18],
  ['108.162.192.0', 18],
  ['190.93.240.0', 20],
  ['188.114.96.0', 20],
  ['197.234.240.0', 22],
  ['198.41.128.0', 17],
  ['162.158.0.0', 15],
  ['104.16.0.0', 13],
  ['104.24.0.0', 14],
  ['172.64.0.0', 13],
  ['131.0.72.0', 22],
];

const ECH_PARAM = 5;
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

/**
 * @return The shared Cloudflare ECHConfigList (memoized for an hour).
 */
async function getEchConfig(ask: Ask): Promise<Uint8Array | null> {
  if (echConfig && echConfig.expires > Date.now()) {
    return echConfig.value;
  }
  const question = [...encodeName(ECH_FRONT_DOMAIN), ...u16(TYPE_HTTPS), 0, 1];
  const resp = await ask(buildQuery(question, null));
  for (const a of parseAnswers(resp)) {
    if (a.type !== TYPE_HTTPS) {
      continue;
    }
    const rdata = a.start + 10;
    const value = svcParam(resp, rdata, rdata + a.length, ECH_PARAM);
    if (value) {
      echConfig = {value, expires: Date.now() + ECH_CONFIG_TTL_MS};
      return value;
    }
  }
  return null;
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
      isCloudflare(resp.subarray(a.start + 10, a.start + 14))
  );
}

/**
 * Replaces the HTTPS answer with one carrying ECH when `result` has none and the
 * name is served by Cloudflare. Returns `result` unchanged otherwise, or if
 * anything fails.
 */
export async function addEch(
  q: Question,
  result: Result,
  ecs: number[] | null,
  ask: Ask
): Promise<Result> {
  if (!ECH_ENABLED || q.type !== TYPE_HTTPS || (result.body[3] & 15) !== 0) {
    return result;
  }
  try {
    const hasEch = parseAnswers(result.body).some(a => {
      const rdata = a.start + 10;
      return (
        a.type === TYPE_HTTPS &&
        svcParam(result.body, rdata, rdata + a.length, ECH_PARAM) !== null
      );
    });
    if (hasEch) {
      return result;
    }
    if (!(await behindCloudflare(q.name, ecs, ask))) {
      return result;
    }
    const config = await getEchConfig(ask);
    if (!config) {
      return result;
    }
    const rdata = [
      0,
      1, // Priority 1 (service mode).
      0, // Target: the name itself.
      0,
      1,
      0,
      6,
      2,
      104,
      50,
      2,
      104,
      51, // alpn: h2, h3.
      ...u16(ECH_PARAM),
      ...u16(config.length),
      ...config,
    ];
    const record = [
      0xc0,
      12,
      ...u16(TYPE_HTTPS),
      0,
      1,
      0,
      0,
      1,
      44,
      ...u16(rdata.length),
      ...rdata,
    ];
    return {body: respond(q, 0, [record]), ttl: SYNTHETIC_TTL};
  } catch {
    return result;
  }
}
