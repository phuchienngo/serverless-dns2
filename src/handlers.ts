/**
 * @fileoverview HTTP handlers: `/dns-query` (RFC 8484) and `/resolve` (the
 * Google-style JSON API). Status codes follow Google Public DNS:
 * https://developers.google.com/speed/public-dns/docs/doh
 */

import {MAX_DNS_PARAM, MAX_QUERY, RECORD_TYPES} from './config.js';
import {encodeName, lowerAscii, parseQuestion, respond, u16} from './dns.js';
import {parseEcsParam} from './ecs.js';
import {toJson} from './format.js';
import {resolve} from './resolve.js';
import type {Context, Question, ResolveOptions, Result} from './types.js';

function textResponse(
  message: string,
  status: number,
  headers?: Record<string, string>
): Response {
  return new Response(message, {status, headers});
}

/**
 * @return A `application/dns-message` response.
 */
function wireResponse(result: Result): Response {
  const headers: Record<string, string> = {
    'content-type': 'application/dns-message',
    'cache-control': `private, max-age=${result.ttl}`,
  };
  if (result.hit) {
    headers['x-cache'] = 'HIT';
  }
  return new Response(result.body, {headers});
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
  if (!ctx.env.UPSTREAM) {
    return textResponse('UPSTREAM not configured', 500);
  }

  const method = request.method;
  if (method === 'HEAD') {
    return textResponse('bad request', 400);
  }
  if (method !== 'GET' && method !== 'POST') {
    return textResponse('not implemented', 501, {allow: 'GET, POST'});
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
    return textResponse('bad request', 400);
  }

  let question: Question;
  try {
    question = parseQuestion(wire);
  } catch {
    return textResponse('bad dns message', 400);
  }

  try {
    return wireResponse(await resolve(question, {...ctx, host: url.hostname}));
  } catch {
    return wireResponse({body: respond(question, 2, []), ttl: 5}); // SERVFAIL.
  }
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
  if (!ctx.env.UPSTREAM) {
    return textResponse('UPSTREAM not configured', 500);
  }
  if (request.method === 'HEAD') {
    return textResponse('bad request', 400, {allow: 'GET'});
  }
  if (request.method !== 'GET') {
    return textResponse('not implemented', 501, {allow: 'GET'});
  }

  const name = params.get('name') || '';
  if (!isValidName(name)) {
    return textResponse('invalid name', 400);
  }
  const type = parseType(params.get('type'));
  if (Number.isNaN(type)) {
    return textResponse('invalid type', 400);
  }

  const options: ResolveOptions = {
    ...ctx,
    host: url.hostname,
    dnssec: flag(params, 'do'),
    cd: flag(params, 'cd'),
  };
  const subnet = params.get('edns_client_subnet');
  if (subnet) {
    options.ecs = parseEcsParam(subnet);
    if (!options.ecs) {
      return textResponse('invalid edns_client_subnet', 400);
    }
  }

  const question: Question = {
    id: 0,
    name: lowerAscii(name.replace(/\.$/, '')),
    type,
    raw: [...encodeName(name), ...u16(type), 0, 1],
  };

  let result;
  try {
    result = await resolve(question, options);
  } catch {
    result = {body: respond(question, 2, []), ttl: 5}; // SERVFAIL.
  }
  if (params.get('ct') === 'application/dns-message') {
    return wireResponse(result);
  }

  let json;
  try {
    json = toJson(result.body);
  } catch {
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
  if (result.hit) {
    headers['x-cache'] = 'HIT';
  }
  return new Response(JSON.stringify(json), {headers});
}
