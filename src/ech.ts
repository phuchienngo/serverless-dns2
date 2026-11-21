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
import {encodeName, parseAnswers, rcodeOf, u16} from './wire.js';
import {makeRecord, respond} from './response.js';
import {inBlocks, type Ipv4Block} from './ipv4.js';
import {Loaded} from './loaded.js';
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
  const resp = await queryUpstream(question, null);
  for (const record of parseAnswers(resp)) {
    const value =
      record.type === TYPE_HTTPS && svcParam(resp, record, SVCPARAM_ECH);
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
  ranges: Promise<Ipv4Block[] | null>
): Promise<boolean> {
  const question = [...encodeName(name), ...u16(TYPE_A), 0, 1];
  const [resp, blocks] = await Promise.all([
    queryUpstream(question, ecs),
    ranges,
  ]);
  return (
    !!blocks &&
    parseAnswers(resp).some(
      a =>
        a.type === TYPE_A &&
        a.length === 4 &&
        inBlocks(resp.subarray(a.data, a.data + 4), blocks)
    )
  );
}

/**
 * Work that may be needed to add ECH, started alongside the HTTPS query so
 * that it does not add to the wait.
 */
interface EchProbe {
  cloudflare: Promise<boolean>;
  config: Promise<Uint8Array | null>;
  ranges: Promise<Ipv4Block[] | null>;
}

/**
 * Starts the lookups addEch may need: is the name on Cloudflare (an A query),
 * the ECH key (usually already memoized) and Cloudflare's ranges (loaded
 * only for an HTTPS query).
 * @return null for other types or if the client requests DNSSEC records.
 */
export function startEchProbe(
  q: Question,
  ecs: number[] | null
): EchProbe | null {
  if (q.type !== TYPE_HTTPS || q.dnssecOk) {
    return null;
  }
  const loaded = getCloudflareRanges().catch(() => null);
  return {
    cloudflare: behindCloudflare(q.name, ecs, loaded).catch(() => false),
    config: echConfig.get(),
    ranges: loaded,
  };
}

/**
 * @return Whether the answer's IPv4 hints are in Cloudflare's ranges; null if
 *     it has none.
 */
function hintedCloudflare(
  body: Uint8Array,
  records: ReturnType<typeof parseAnswers>,
  blocks: Ipv4Block[]
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
 * Adds ECH to the HTTPS answer when `result` has none and the name is served
 * by Cloudflare: to the records the upstream sent (AliasMode ones have no
 * parameters to add it to), or, when it sent no HTTPS record, as a new one.
 * The IPv4 hints of the answer, if it has any, tell whether the name is on
 * Cloudflare; otherwise the probe's A query does.
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
    const blocks = await probe.ranges;
    if (!blocks) {
      return result;
    }
    const {body} = result;
    const records = parseAnswers(body).filter(r => r.type === TYPE_HTTPS);
    if (records.some(r => svcParam(body, r, SVCPARAM_ECH))) {
      return result; // Already has ECH.
    }
    const services = records.filter(r => !isAliasMode(body, r));
    if (records.length && !services.length) {
      return result;
    }
    const onCloudflare =
      hintedCloudflare(body, records, blocks) ?? (await probe.cloudflare);
    const config = onCloudflare ? await probe.config : null;
    if (!config) {
      return result;
    }
    if (!services.length) {
      const rdata = svcbRdata(1, '.', [
        [SVCPARAM_ALPN, alpnValue(ALPN_HTTP)],
        [SVCPARAM_ECH, [...config]],
      ]);
      const record = makeRecord(TYPE_HTTPS, SYNTHETIC_TTL, rdata);
      return {body: respond(q, RCODE_NOERROR, [record]), ttl: SYNTHETIC_TTL};
    }
    // From the last record to the first, so that the offsets still hold.
    const changed = [...services]
      .reverse()
      .reduce((msg, r) => addSvcParam(msg, r, SVCPARAM_ECH, config), body);
    return {body: changed, ttl: result.ttl};
  } catch {
    return result; // ECH is best effort: keep the answer as it is.
  }
}
