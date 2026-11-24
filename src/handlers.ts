/**
 * @fileoverview HTTP handlers: `/dns-query` (RFC 8484) and `/resolve` (the
 * Google-style JSON API). Status codes follow Google Public DNS:
 * https://developers.google.com/speed/public-dns/docs/doh
 */

import {MAX_DNS_PARAM, MAX_QUERY} from './config.js';
import {RECORD_TYPES, TTL_UNCACHED, TYPE_NAPTR, TYPE_PTR} from './constants.js';
import {makeQuestion, MultipleQuestionsError, parseQuestion} from './query.js';
import {clientEcs, parseEcsParam, reverseName} from './ecs.js';
import {toJson} from './format.js';
import {describeError, logEvent} from './log.js';
import {formErrorHeader} from './response.js';
import {profileResponse, rangesResponse} from './profile.js';
import {resolve, upstreamFailure} from './resolve.js';
import type {Context, Question, ResolveOptions, Result} from './types.js';

/** @return The name of a record type (`AAAA`), or its number if unknown. */
function typeName(type: number): string {
  return (
    Object.keys(RECORD_TYPES).find(k => RECORD_TYPES[k] === type) ?? `${type}`
  );
}

function textResponse(
  message: string,
  status: number,
  headers?: Record<string, string>
): Response {
  return new Response(message, {status, headers});
}

/**
 * @return The headers of a response: its type, how long a client may keep it,
 *     whether the gateway had it cached, and Server-Timing.
 */
function responseHeaders(
  contentType: string,
  result: Result,
  first?: number
): Record<string, string> {
  const headers: Record<string, string> = {
    'content-type': contentType,
    'cache-control': `private, max-age=${result.ttl}`,
  };
  if (result.hit) {
    headers['x-cache'] = 'HIT';
  }
  if (first !== undefined) {
    headers['server-timing'] = `first;dur=${first.toFixed(1)}`;
  }
  return headers;
}

/**
 * @return A `application/dns-message` response.
 */
function wireResponse(result: Result, first?: number): Response {
  return new Response(result.body, {
    headers: responseHeaders('application/dns-message', result, first),
  });
}

/** The options for resolving a request to `url`. */
function makeOptions(url: URL, ctx: Context): ResolveOptions {
  return {
    ...ctx,
    host: url.hostname,
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
): Promise<{result: Result; first: number}> {
  const started = performance.now();
  let result: Result;
  try {
    result = await resolve(question, options);
  } catch (error) {
    const cause = describeError(error);
    logEvent(
      'error',
      'servfail',
      `SERVFAIL for ${typeName(question.type)} ${question.name}: ${cause}`,
      {name: question.name, type: question.type, cause},
      error
    );
    result = upstreamFailure(question);
  }
  return {result, first: performance.now() - started};
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
        return textResponse('missing dns parameter', 400);
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
  } catch (error) {
    if (error instanceof MultipleQuestionsError) {
      return wireResponse({body: formErrorHeader(wire), ttl: TTL_UNCACHED});
    }
    return textResponse('bad dns message', 400);
  }

  const options = makeOptions(url, ctx);
  const ecs = clientEcs(question.ecs);
  if (ecs) {
    options.ecs = ecs;
  }
  const {result, first} = await resolveOrFail(question, options);
  return wireResponse(result, first);
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

  const {result, first} = await resolveOrFail(question, options);
  return params.get('ct') === 'application/dns-message'
    ? wireResponse(result, first)
    : jsonResponse(question, result, first);
}

/**
 * @return The JSON form of an answer, and the answer it was made from: SERVFAIL
 *     if the answer cannot be read.
 */
export function readable(
  question: Question,
  result: Result
): {json: ReturnType<typeof toJson>; result: Result} {
  try {
    return {json: toJson(result.body), result};
  } catch (error) {
    const cause = describeError(error);
    logEvent(
      'error',
      'json_unreadable',
      `Answer for ${typeName(question.type)} ${question.name} is not readable: ${cause}`,
      {name: question.name, type: question.type, cause},
      error
    );
    const failure = upstreamFailure(question);
    return {json: toJson(failure.body), result: failure};
  }
}

/** @return The JSON response to a question, with its headers. */
function jsonResponse(
  question: Question,
  answer: Result,
  first: number
): Response {
  const {json, result} = readable(question, answer);
  const headers = responseHeaders(
    'application/json; charset=UTF-8',
    result,
    first
  );
  return new Response(JSON.stringify(json), {headers});
}

/**
 * Routes a request by its path: `/dns-query` (a GET with `name` and no `dns`
 * is the JSON API too) and `/resolve`.
 */
export function route(
  request: Request,
  ctx: Context
): Promise<Response> | Response {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');
  const params = url.searchParams;
  if (path === '/resolve') {
    return handleJson(request, ctx);
  }
  if (path === '/apple') {
    return profileResponse();
  }
  if (path === '/cloudflare-ips.json') {
    return rangesResponse();
  }
  if (path !== '/dns-query') {
    return textResponse('not found', 404);
  }
  const json =
    request.method === 'GET' && !params.has('dns') && params.has('name');
  return json ? handleJson(request, ctx) : handle(request, ctx);
}
