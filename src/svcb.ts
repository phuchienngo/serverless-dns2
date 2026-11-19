/**
 * @fileoverview SVCB and HTTPS records (RFC 9460): building the RDATA, and
 * reading and extending the SvcParams of a record in a message.
 */

import {readName, encodeName, u16, type DnsRecord} from './dns.js';

const encoder = new TextEncoder();

/**
 * @param protocols ALPN ids, such as `h2`.
 * @return The value of an `alpn` SvcParam: each id preceded by its length.
 */
export function alpnValue(protocols: string[]): number[] {
  return protocols.flatMap(p => [p.length, ...encoder.encode(p)]);
}

/**
 * Builds the RDATA of an SVCB or HTTPS record in service mode.
 * @param target Target name; `.` means the owner name itself.
 * @param params SvcParams as [key, value]; written in increasing key order,
 *     as the RFC requires.
 */
export function svcbRdata(
  priority: number,
  target: string,
  params: Array<[number, number[]]>
): number[] {
  return [
    ...u16(priority),
    ...encodeName(target),
    ...[...params]
      .sort(([a], [b]) => a - b)
      .flatMap(([key, value]) => [...u16(key), ...u16(value.length), ...value]),
  ];
}

/** A SvcParam of a record: its key, its value, and where it starts. */
export interface SvcParam {
  key: number;
  value: Uint8Array;
  /** Offset of the key. */
  start: number;
}

/** @return Whether the record is in AliasMode (priority 0, no parameters). */
export function isAliasMode(msg: Uint8Array, record: DnsRecord): boolean {
  return ((msg[record.data] << 8) | msg[record.data + 1]) === 0;
}

/**
 * @return The SvcParams of an SVCB or HTTPS record, in the order they are
 *     written. A parameter that claims more than the record has is cut at
 *     its end, so that nothing beyond the record is read.
 */
export function svcParams(msg: Uint8Array, record: DnsRecord): SvcParam[] {
  const end = record.data + record.length;
  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const params: SvcParam[] = [];
  let at = readName(msg, record.data + 2).next; // After priority and target.
  while (at + 4 <= end) {
    const length = view.getUint16(at + 2);
    params.push({
      key: view.getUint16(at),
      value: msg.subarray(at + 4, Math.min(at + 4 + length, end)),
      start: at,
    });
    at += 4 + length;
  }
  return params;
}

/** @return The value of SvcParam `key` of the record, or null. */
export function svcParam(
  msg: Uint8Array,
  record: DnsRecord,
  key: number
): Uint8Array | null {
  return svcParams(msg, record).find(p => p.key === key)?.value ?? null;
}

/**
 * @return A copy of `msg` where the record also has the parameter, placed
 *     among the others in increasing key order, with its length fixed. The
 *     rest of the message is kept. The record must not have the key yet.
 */
export function addSvcParam(
  msg: Uint8Array,
  record: DnsRecord,
  key: number,
  value: ArrayLike<number>
): Uint8Array {
  const end = record.data + record.length;
  const at = svcParams(msg, record).find(p => p.key > key)?.start ?? end;
  const param = [...u16(key), ...u16(value.length), ...Array.from(value)];
  const out = new Uint8Array(msg.length + param.length);
  out.set(msg.subarray(0, record.data - 2));
  out.set(u16(record.length + param.length), record.data - 2);
  out.set(msg.subarray(record.data, at), record.data);
  out.set(param, at);
  out.set(msg.subarray(at), at + param.length);
  return out;
}
