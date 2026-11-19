/**
 * @fileoverview Test helpers: build DNS messages and read them back. The
 * reader is written independently of src/ so that a test does not check the
 * code with itself.
 */

import {mock} from 'node:test';
import {UPSTREAM} from '../src/config.js';
import {resetBlocklist} from '../src/blocklist.js';
import {resetCache} from '../src/cache.js';
import {resetCloudflareRanges} from '../src/cloudflare-ips.js';
import {resetEch} from '../src/ech.js';
import {resetUpstream} from '../src/upstream.js';

export const T = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  HINFO: 13,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  OPT: 41,
  DS: 43,
  RRSIG: 46,
  SVCB: 64,
  HTTPS: 65,
  ANY: 255,
  RESINFO: 261,
};

/** A name in wire format (no compression). */
export function nameBytes(name: string): number[] {
  const out: number[] = [];
  for (const label of name.replace(/\.$/, '').split('.').filter(Boolean)) {
    out.push(label.length, ...Buffer.from(label, 'latin1'));
  }
  out.push(0);
  return out;
}

const u16 = (n: number) => [(n >> 8) & 255, n & 255];
const u32 = (n: number) => [
  (n >>> 24) & 255,
  (n >>> 16) & 255,
  (n >>> 8) & 255,
  n & 255,
];

export interface QueryOptions {
  id?: number;
  rd?: boolean;
  opcode?: number;
  /** Send an OPT record (default true). */
  edns?: boolean;
  ednsVersion?: number;
  do?: boolean;
  cd?: boolean;
  ad?: boolean;
  /** Bytes of EDNS Padding. */
  padding?: number;
  /** ECS option: source prefix length and the address bytes. */
  ecs?: {family: 1 | 2; prefix: number; address: number[]};
  qclass?: number;
  /** Raw bytes of an EDNS Cookie option. */
  cookie?: number[];
}

/** Builds a DNS query message. */
export function makeQuery(
  name: string,
  type: number,
  o: QueryOptions = {}
): Uint8Array {
  const edns = o.edns ?? true;
  const flags =
    ((o.opcode ?? 0) << 11) |
    ((o.rd ?? true) ? 0x100 : 0) |
    (o.ad ? 0x20 : 0) |
    (o.cd ? 0x10 : 0);
  let options: number[] = [];
  if (o.ecs) {
    const bytes = o.ecs.address.slice(0, Math.ceil(o.ecs.prefix / 8));
    options.push(
      ...u16(8),
      ...u16(4 + bytes.length),
      ...u16(o.ecs.family),
      o.ecs.prefix,
      0,
      ...bytes
    );
  }
  if (o.cookie) {
    options.push(...u16(10), ...u16(o.cookie.length), ...o.cookie);
  }
  if (o.padding !== undefined) {
    options.push(
      ...u16(12),
      ...u16(o.padding),
      ...new Array(o.padding).fill(0)
    );
  }
  const opt = edns
    ? [
        0,
        ...u16(T.OPT),
        ...u16(4096),
        0,
        o.ednsVersion ?? 0,
        o.do ? 0x80 : 0,
        0,
        ...u16(options.length),
        ...options,
      ]
    : [];
  return new Uint8Array([
    ...u16(o.id ?? 0x1234),
    ...u16(flags),
    ...u16(1),
    ...u16(0),
    ...u16(0),
    ...u16(edns ? 1 : 0),
    ...nameBytes(name),
    ...u16(type),
    ...u16(o.qclass ?? 1),
    ...opt,
  ]);
}

export interface Rr {
  name: string;
  type: number;
  cls: number;
  ttl: number;
  rdata: Uint8Array;
  /** Offset of the TYPE field, for patching the message. */
  start: number;
}

export interface OptInfo {
  udp: number;
  extRcode: number;
  version: number;
  do: boolean;
  options: Array<{code: number; data: Uint8Array}>;
}

export interface Msg {
  size: number;
  id: number;
  qr: boolean;
  opcode: number;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  cd: boolean;
  rcode: number;
  question: Array<{name: string; type: number; cls: number}>;
  answer: Rr[];
  authority: Rr[];
  additional: Rr[];
  /** The OPT record of the additional section, if any. */
  opt?: OptInfo;
  optCount: number;
}

function readName(b: Uint8Array, offset: number): {name: string; next: number} {
  const labels: string[] = [];
  let next = -1;
  for (let jumps = 0; jumps < 64;) {
    const length = b[offset];
    if (length === undefined) {
      throw new Error('name runs past the message');
    }
    if (length === 0) {
      return {name: labels.join('.') + '.', next: next < 0 ? offset + 1 : next};
    }
    if ((length & 0xc0) === 0xc0) {
      if (next < 0) {
        next = offset + 2;
      }
      offset = ((length & 0x3f) << 8) | b[offset + 1];
      jumps++;
      continue;
    }
    labels.push(
      Buffer.from(b.subarray(offset + 1, offset + 1 + length)).toString(
        'latin1'
      )
    );
    offset += 1 + length;
  }
  throw new Error('name loop');
}

/** Parses a DNS message; throws if it is malformed. */
export function parseMsg(b: Uint8Array): Msg {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const flags = v.getUint16(2);
  const counts = [4, 6, 8, 10].map(o => v.getUint16(o));
  let offset = 12;
  const question = [];
  for (let i = 0; i < counts[0]; i++) {
    const n = readName(b, offset);
    question.push({
      name: n.name,
      type: v.getUint16(n.next),
      cls: v.getUint16(n.next + 2),
    });
    offset = n.next + 4;
  }
  const sections: Rr[][] = [];
  for (const count of counts.slice(1)) {
    const records: Rr[] = [];
    for (let i = 0; i < count; i++) {
      const n = readName(b, offset);
      const length = v.getUint16(n.next + 8);
      if (n.next + 10 + length > b.length) {
        throw new Error('record runs past the message');
      }
      records.push({
        name: n.name,
        type: v.getUint16(n.next),
        cls: v.getUint16(n.next + 2),
        ttl: v.getUint32(n.next + 4),
        rdata: b.slice(n.next + 10, n.next + 10 + length),
        start: n.next,
      });
      offset = n.next + 10 + length;
    }
    sections.push(records);
  }
  if (offset !== b.length) {
    throw new Error(`${b.length - offset} trailing bytes`);
  }
  const [answer, authority, additional] = sections;
  const opts = additional.filter(r => r.type === T.OPT);
  let opt: OptInfo | undefined;
  if (opts.length) {
    const r = opts[0];
    const options = [];
    for (let i = 0; i + 4 <= r.rdata.length;) {
      const length = (r.rdata[i + 2] << 8) | r.rdata[i + 3];
      options.push({
        code: (r.rdata[i] << 8) | r.rdata[i + 1],
        data: r.rdata.slice(i + 4, i + 4 + length),
      });
      i += 4 + length;
    }
    opt = {
      udp: r.cls,
      extRcode: r.ttl >>> 24,
      version: (r.ttl >>> 16) & 255,
      do: (r.ttl & 0x8000) !== 0,
      options,
    };
  }
  return {
    size: b.length,
    id: v.getUint16(0),
    qr: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 15,
    aa: (flags & 0x400) !== 0,
    tc: (flags & 0x200) !== 0,
    rd: (flags & 0x100) !== 0,
    ra: (flags & 0x80) !== 0,
    ad: (flags & 0x20) !== 0,
    cd: (flags & 0x10) !== 0,
    rcode: ((opt?.extRcode ?? 0) << 4) | (flags & 15),
    question,
    answer,
    authority,
    additional,
    opt,
    optCount: opts.length,
  };
}

// --- rdata builders -------------------------------------------------------

export const ip4 = (s: string) => s.split('.').map(Number);

export function ip6(s: string): number[] {
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return groups.flatMap(g => u16(parseInt(g, 16)));
}

export const nameRdata = (n: string) => nameBytes(n);

export function soaRdata(minimum: number): number[] {
  return [
    ...nameBytes('ns.example.'),
    ...nameBytes('hostmaster.example.'),
    ...u32(1),
    ...u32(7200),
    ...u32(900),
    ...u32(1209600),
    ...u32(minimum),
  ];
}

export function txtRdata(...strings: string[]): number[] {
  return strings.flatMap(s => [s.length, ...Buffer.from(s)]);
}

export const mxRdata = (pref: number, name: string) => [
  ...u16(pref),
  ...nameBytes(name),
];

export interface RrSpec {
  /** Owner name; omitted means a pointer to the question name. */
  name?: string;
  type: number;
  ttl: number;
  rdata: number[] | Uint8Array;
  cls?: number;
}

export interface ResponseSpec {
  id?: number;
  qname: string;
  qtype: number;
  rcode?: number;
  rd?: boolean;
  ad?: boolean;
  aa?: boolean;
  tc?: boolean;
  answer?: RrSpec[];
  authority?: RrSpec[];
  /** Additional records other than OPT. */
  additional?: RrSpec[];
  /** The OPT record; false leaves it out. */
  opt?: false | {do?: boolean; options?: Array<{code: number; data: number[]}>};
}

function rrBytes(r: RrSpec): number[] {
  return [
    ...(r.name === undefined ? [0xc0, 12] : nameBytes(r.name)),
    ...u16(r.type),
    ...u16(r.cls ?? 1),
    ...u32(r.ttl),
    ...u16(r.rdata.length),
    ...r.rdata,
  ];
}

/** Builds a response like a resolver would send it. */
export function makeResponse(s: ResponseSpec): Uint8Array {
  const opt =
    s.opt === false
      ? []
      : (() => {
          const options = (s.opt?.options ?? []).flatMap(o => [
            ...u16(o.code),
            ...u16(o.data.length),
            ...o.data,
          ]);
          return [
            0,
            ...u16(T.OPT),
            ...u16(1232),
            0,
            0,
            s.opt?.do ? 0x80 : 0,
            0,
            ...u16(options.length),
            ...options,
          ];
        })();
  const flags =
    0x8000 |
    (s.aa ? 0x400 : 0) |
    (s.tc ? 0x200 : 0) |
    ((s.rd ?? true) ? 0x100 : 0) |
    0x80 |
    (s.ad ? 0x20 : 0) |
    ((s.rcode ?? 0) & 15);
  return new Uint8Array([
    ...u16(s.id ?? 0),
    ...u16(flags),
    ...u16(1),
    ...u16(s.answer?.length ?? 0),
    ...u16(s.authority?.length ?? 0),
    ...u16((s.additional?.length ?? 0) + (opt.length ? 1 : 0)),
    ...nameBytes(s.qname),
    ...u16(s.qtype),
    ...u16(1),
    ...(s.answer ?? []).flatMap(rrBytes),
    ...(s.authority ?? []).flatMap(rrBytes),
    ...(s.additional ?? []).flatMap(rrBytes),
    ...opt,
  ]);
}

// --- upstream mock --------------------------------------------------------

export interface UpstreamCall {
  /** The query the gateway sent, parsed. */
  query: Msg;
  raw: Uint8Array;
  url: string;
}

/**
 * Replaces `fetch` so that the gateway's upstream queries go to `handler`.
 * The handler returns a response message (its id is set to the query's) or
 * throws to simulate a failure.
 * @return The calls seen so far; restore with `restore()`.
 */
export function mockUpstream(
  handler: (query: Msg, call: UpstreamCall) => Uint8Array | Promise<Uint8Array>
): {calls: UpstreamCall[]; restore: () => void} {
  const calls: UpstreamCall[] = [];
  const original = globalThis.fetch;
  const fake = mock.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (url !== UPSTREAM) {
      return original(input as string, init);
    }
    const raw = new Uint8Array(init!.body as Uint8Array);
    const call = {query: parseMsg(raw), raw, url};
    calls.push(call);
    const body = new Uint8Array(await handler(call.query, call));
    body[0] = raw[0];
    body[1] = raw[1];
    return new Response(body, {
      headers: {'content-type': 'application/dns-message'},
    });
  });
  globalThis.fetch = fake as unknown as typeof fetch;
  return {calls, restore: () => void (globalThis.fetch = original)};
}

/** Request options for `resolve()` with no assets and no client IP. */
export function plainOptions(extra: Record<string, unknown> = {}) {
  return {env: {}, ip: null, host: 'dns.test', ...extra} as never;
}

/** Forgets everything that the gateway keeps in memory between requests. */
export function resetState(): void {
  resetCache();
  resetUpstream();
  resetEch();
  resetCloudflareRanges();
  resetBlocklist();
}
