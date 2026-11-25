/**
 * @fileoverview Best-effort Encrypted Client Hello. Cloudflare-hosted sites
 * share one ECH key, but many resolvers do not return it. For an HTTPS query
 * whose answer has no `ech`, we check whether the name is on Cloudflare (its
 * IPv4 hints, or else its A records, are in Cloudflare's ranges) and, if so,
 * add the key to the record the upstream sent, or answer with a new record
 * when there was none.
 */

import {ECH_FRONT_DOMAIN} from './config.js';
import {getCloudflareRanges} from './cloudflare-ips.js';
import {
  ALPN_HTTP,
  RCODE_NOERROR,
  SVCPARAM_ALPN,
  SVCPARAM_ECH,
  SVCPARAM_IPV4HINT,
  TYPE_A,
  TYPE_HTTPS,
} from './constants.js';
import {FLAG_AD, encodeName, parseAnswers, rcodeOf, u16} from './wire.js';
import {makeRecord, respond} from './response.js';
import {inBlocks, type Ipv4Block} from './ipv4.js';
import {Loaded} from './loaded.js';
import {describeError, logEvent} from './log.js';
import {
  addSvcParam,
  alpnValue,
  isAliasMode,
  svcParam,
  svcbRdata,
} from './svcb.js';
import type {Question, Result} from './types.js';
import {queryUpstream} from './upstream.js';

const ECH_CONFIG_TTL_MS = 3600 * 1000;
const SYNTHETIC_TTL = 300;

/** The shared Cloudflare ECHConfigList, asked for at most once an hour. */
const echConfig = new Loaded<void, Uint8Array>(async () => {
  const question = [...encodeName(ECH_FRONT_DOMAIN), ...u16(TYPE_HTTPS), 0, 1];
  const {body, records} = await queryUpstream(question, null);
  for (const record of records) {
    const value =
      record.section === 'answer' &&
      record.type === TYPE_HTTPS &&
      svcParam(body, record, SVCPARAM_ECH);
    if (value) {
      return value.slice();
    }
  }
  return null;
}, ECH_CONFIG_TTL_MS);

/** Forgets the memoized ECH key (for tests). */
export function resetEch(): void {
  echConfig.reset();
}

/** @return Whether any of the name's A records is a Cloudflare address. */
async function behindCloudflare(
  name: string,
  ecs: number[] | null,
  ranges: readonly Ipv4Block[]
): Promise<boolean> {
  const question = [...encodeName(name), ...u16(TYPE_A), 0, 1];
  const {body, records} = await queryUpstream(question, ecs);
  return records.some(
    a =>
      a.section === 'answer' &&
      a.type === TYPE_A &&
      a.length === 4 &&
      inBlocks(body.subarray(a.data, a.end), ranges)
  );
}

/**
 * Work that may be needed to add ECH, started alongside the HTTPS query so
 * that it does not add to the wait.
 */
interface EchProbe {
  cloudflare: Promise<boolean>;
  config: Promise<Uint8Array | null>;
  ranges: readonly Ipv4Block[];
}

/**
 * Starts the A lookup and ECH config lookup for an HTTPS query.
 * @param keepAlive Keeps the request running until the work is done (the
 *     `waitUntil` of the request): the answer may be ready first, and other
 *     requests share the key's load, which must not belong to a request that
 *     has ended.
 * @return null for other types or if the client requests DNSSEC records.
 */
export function startEchProbe(
  q: Question,
  ecs: number[] | null,
  keepAlive?: (work: Promise<unknown>) => void
): EchProbe | null {
  if (q.type !== TYPE_HTTPS || q.dnssecOk) {
    return null;
  }
  const ranges = getCloudflareRanges();
  if (!ranges.length) {
    return null;
  }
  const probe = {
    cloudflare: behindCloudflare(q.name, ecs, ranges).catch(() => false),
    config: echConfig.get(undefined, keepAlive),
    ranges,
  };
  keepAlive?.(probe.cloudflare);
  return probe;
}

/**
 * @return Whether the answer's IPv4 hints are in Cloudflare's ranges; null if
 *     it has none.
 */
function hintedCloudflare(
  body: Uint8Array,
  records: ReturnType<typeof parseAnswers>,
  blocks: readonly Ipv4Block[]
): boolean | null {
  let hinted: boolean | null = null;
  for (const record of records) {
    const hints = svcParam(body, record, SVCPARAM_IPV4HINT);
    for (let i = 0; hints && i + 4 <= hints.length; i += 4) {
      hinted = (hinted ?? false) || inBlocks(hints.subarray(i, i + 4), blocks);
    }
  }
  return hinted;
}

/**
 * @return A new HTTPS record that carries only the ECH key, as an answer to
 *     a name for which the upstream sent none.
 */
function synthesizeHttps(q: Question, config: Uint8Array): Result {
  const rdata = svcbRdata(1, '.', [
    [SVCPARAM_ALPN, alpnValue(ALPN_HTTP)],
    [SVCPARAM_ECH, [...config]],
  ]);
  const record = makeRecord(TYPE_HTTPS, SYNTHETIC_TTL, rdata);
  return {body: respond(q, RCODE_NOERROR, [record]), ttl: SYNTHETIC_TTL};
}

/** @return `result` with the ECH key added to each of the `services` records. */
function addToServices(
  result: Result,
  services: ReturnType<typeof parseAnswers>,
  config: Uint8Array
): Result {
  // From the last record to the first, so that the offsets still hold.
  const changed = [...services]
    .reverse()
    .reduce((msg, r) => addSvcParam(msg, r, SVCPARAM_ECH, config), result.body);
  // The records are no longer what was validated: AD must not claim it
  // (RFC 4035 3.2.3; a query with AD but no DO gets it from the upstream).
  changed[3] &= ~FLAG_AD;
  return {body: changed, ttl: result.ttl};
}

/**
 * @return The answer with ECH added, or null if it needs none or the name is
 *     not served by Cloudflare. The IPv4 hints of the answer, if it has any,
 *     tell whether the name is on Cloudflare; otherwise the probe's A query
 *     does.
 */
async function withEch(
  result: Result,
  q: Question,
  probe: EchProbe
): Promise<Result | null> {
  const {body} = result;
  const records = parseAnswers(body).filter(r => r.type === TYPE_HTTPS);
  if (records.some(r => svcParam(body, r, SVCPARAM_ECH))) {
    return null; // Already has ECH.
  }
  // AliasMode records have no parameters to add the key to.
  const services = records.filter(r => !isAliasMode(body, r));
  if (records.length && !services.length) {
    return null;
  }
  const onCloudflare =
    hintedCloudflare(body, records, probe.ranges) ?? (await probe.cloudflare);
  const config = onCloudflare ? await probe.config : null;
  if (!config) {
    return null;
  }
  return services.length
    ? addToServices(result, services, config)
    : synthesizeHttps(q, config);
}

/**
 * Adds ECH to the HTTPS answer when `result` has none and the name is served
 * by Cloudflare: to the records the upstream sent, or, when it sent no HTTPS
 * record, as a new one. Returns `result` unchanged otherwise. ECH is best
 * effort: a failure is logged and the answer is kept as it is.
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
    return (await withEch(result, q, probe)) ?? result;
  } catch (error) {
    const cause = describeError(error);
    logEvent(
      'warn',
      'ech_failed',
      `ECH not added to ${q.name}: ${cause}`,
      {name: q.name, cause},
      error
    );
    return result;
  }
}
