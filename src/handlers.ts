/**
 * @fileoverview HTTP handlers: `/dns-query` (RFC 8484) and `/resolve` (the
 * Google-style JSON API). Status codes follow Google Public DNS:
 * https://developers.google.com/speed/public-dns/docs/doh
 */

import {MAX_DNS_PARAM, MAX_QUERY} from './config.js';
import {RECORD_TYPES, TYPE_NAPTR, TYPE_PTR} from './constants.js';
import {makeQuestion, parseQuestion} from './dns.js';
import {clientEcs, echoClientEcs, parseEcsParam, reverseName} from './ecs.js';
import {toJson} from './format.js';
import {resolve, upstreamFailure} from './resolve.js';
import type {Context, Question, ResolveOptions, Result} from './types.js';

function textResponse(
  message: string,
  status: number,
  headers?: Record<string, string>
): Response {
  return new Response(message, {status, headers});
}

/**
 * @return A Server-Timing header value for the durations in `timing`.
 */
function formatTiming(timing?: Record<string, number>): string {
  return Object.entries(timing ?? {})
    .map(([name, ms]) => `${name};dur=${ms.toFixed(1)}`)
    .join(', ');
}

/**
 * @return A `application/dns-message` response.
 */
function wireResponse(
  result: Result,
  timing?: Record<string, number>
): Response {
  const headers: Record<string, string> = {
    'content-type': 'application/dns-message',
    'cache-control': `private, max-age=${result.ttl}`,
  };
  if (result.hit) {
    headers['x-cache'] = 'HIT';
  }
  const serverTiming = formatTiming(timing);
  if (serverTiming) {
    headers['server-timing'] = serverTiming;
  }
  return new Response(result.body, {headers});
}

/** The options for resolving a request to `url`, with room for Server-Timing. */
function makeOptions(url: URL, ctx: Context): ResolveOptions {
  return {
    ...ctx,
    host: url.hostname,
    timing: {},
    dns64: flag(url.searchParams, 'dns64'),
  };
}

/**
 * Resolves a question; if the upstream resolver cannot be reached the answer
 * is a SERVFAIL, not an HTTP error.
 */
async function resolveOrFail(
  question: Question,
  options: ResolveOptions
): Promise<Result> {
  try {
    return await resolve(question, options);
  } catch {
    return upstreamFailure(question); // Upstream down, timed out or unreadable.
  }
}

/**
 * Decodes the `dns` query parameter of a GET request.
 * @param param base64url, with or without padding.
 */
function decodeDnsParam(param: string): Uint8Array {
  const base64 = param.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

/**
 * Handles `/dns-query`: GET `?dns=<base64url>` or POST of a DNS message.
 */
export async function handle(
  request: Request,
  ctx: Context
): Promise<Response> {
  const url = new URL(request.url);

  const method = request.method;
  if (method !== 'GET' && method !== 'POST') {
    return textResponse('method not allowed', 405, {allow: 'GET, POST'});
  }

  let wire;
  try {
    if (method === 'POST') {
      const contentType = request.headers.get('content-type') || '';
      if (!/^application\/dns-message\s*(;|$)/i.test(contentType)) {
        return textResponse('unsupported media type', 415);
      }
      wire = new Uint8Array(await request.arrayBuffer());
      if (wire.length > MAX_QUERY) {
        return textResponse('payload too large', 413);
      }
    } else {
      const param = url.searchParams.get('dns');
      if (param === null) {
        // Convenience: the JSON API also answers on this path.
        return url.searchParams.has('name')
          ? handleJson(request, ctx)
          : textResponse('missing dns parameter', 400);
      }
      if (param.length > MAX_DNS_PARAM) {
        return textResponse('uri too long', 414);
      }
      wire = decodeDnsParam(param);
    }
  } catch {
    // A body that cannot be read, or a `dns` parameter that is not base64url.
    return textResponse('bad request', 400);
  }

  let question: Question;
  try {
    question = parseQuestion(wire);
  } catch {
    // Not a well-formed single-question query.
    return textResponse('bad dns message', 400);
  }

  // Honour a subnet the client chose itself; an empty one (privacy signal)
  // is ignored, so the connecting IP is used.
  const options = makeOptions(url, ctx);
  const ecs = clientEcs(wire);
  if (ecs) {
    options.ecs = ecs;
  }
  const result = await resolveOrFail(question, options);
  if (ecs) {
    // The response repeats the subnet as the client sent it, not as clamped.
    result.body = echoClientEcs(result.body, wire);
  }
  return wireResponse(result, options.timing);
}

/**
 * @return Whether `name` is a valid ASCII domain name (RFC 1035
 *     length limits; non-ASCII names must be punycoded).
 */
function isValidName(name: string): boolean {
  name = name.replace(/\.$/, '');
  return (
    name.length >= 1 &&
    name.length <= 253 &&
    /^[\x21-\x7e]+$/.test(name) &&
    name.split('.').every(label => label.length >= 1 && label.length <= 63)
  );
}

/**
 * @param param A number (1-65535) or a record type name.
 * @return The type, or NaN if invalid. Defaults to A.
 */
function parseType(param: string | null): number {
  if (!param) {
    return RECORD_TYPES.A;
  }
  const type = /^\d+$/.test(param)
    ? Number(param)
    : RECORD_TYPES[param.toUpperCase()];
  return type >= 1 && type <= 65535 ? type : NaN;
}

/**
 * @return Whether the boolean parameter is `1` or `true`.
 */
function flag(params: URLSearchParams, key: string): boolean {
  return ['1', 'true'].includes((params.get(key) || '').toLowerCase());
}

/**
 * Handles `/resolve`: the Google-style JSON API (GET only).
 * Parameters: name, type, do, cd, ct, edns_client_subnet.
 */
export async function handleJson(
  request: Request,
  ctx: Context
): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;
  if (request.method === 'HEAD') {
    return textResponse('bad request', 400, {allow: 'GET'});
  }
  if (request.method !== 'GET') {
    return textResponse('not implemented', 501, {allow: 'GET'});
  }

  let name = params.get('name') || '';
  const type = parseType(params.get('type'));
  if (Number.isNaN(type)) {
    return textResponse('invalid type', 400);
  }
  // PTR/NAPTR for an IP address: look up its reverse-DNS name instead.
  if (type === TYPE_PTR || type === TYPE_NAPTR) {
    name = reverseName(name.replace(/\.$/, '')) ?? name;
  }
  if (!isValidName(name)) {
    return textResponse('invalid name', 400);
  }

  const options = makeOptions(url, ctx);
  const subnet = params.get('edns_client_subnet');
  if (subnet) {
    options.ecs = parseEcsParam(subnet);
    if (!options.ecs) {
      return textResponse('invalid edns_client_subnet', 400);
    }
  }

  const question = makeQuestion(name, type, {
    dnssecOk: flag(params, 'do'),
    cd: flag(params, 'cd'),
  });

  const result = await resolveOrFail(question, options);
  if (params.get('ct') === 'application/dns-message') {
    return wireResponse(result, options.timing);
  }

  let json;
  try {
    json = toJson(result.body);
  } catch {
    // The upstream sent something that does not parse.
    json = {
      Status: 2,
      TC: false,
      RD: true,
      RA: true,
      AD: false,
      CD: false,
      Question: [{name: name.replace(/\.$/, '') + '.', type}],
      Comment: 'bad upstream response',
    };
  }
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=UTF-8',
    'cache-control': `private, max-age=${result.ttl}`,
  };
  const serverTiming = formatTiming(options.timing);
  if (serverTiming) {
    headers['server-timing'] = serverTiming;
  }
  if (result.hit) {
    headers['x-cache'] = 'HIT';
  }
  return new Response(JSON.stringify(json), {headers});
}
