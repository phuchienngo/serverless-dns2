/**
 * @fileoverview DNS Cookies (RFC 7873). A client that sends a cookie gets it
 * back with a server cookie. The cookie is never enforced: requests arrive
 * over HTTPS, which already stops spoofing, so nothing is refused for lacking
 * one. Needs the COOKIE_SECRET setting; without it cookies are ignored.
 */

import {OPTION_COOKIE} from './constants.js';
import {u16} from './dns.js';
import type {Question} from './types.js';

const encoder = new TextEncoder();

/** The HMAC key of the last secret seen, so that it is imported only once. */
let imported: {secret: string; key: Promise<CryptoKey>} | null = null;

function hmacKey(secret: string): Promise<CryptoKey> {
  if (imported?.secret !== secret) {
    imported = {
      secret,
      key: crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        {name: 'HMAC', hash: 'SHA-256'},
        false,
        ['sign']
      ),
    };
  }
  return imported.key;
}

/**
 * @return The EDNS option to add to the response, or null if the query had
 *     no cookie or there is no secret.
 *     Server cookie: the first 8 bytes of HMAC-SHA256(secret, client cookie,
 *     client address), so it cannot be forged without the secret.
 */
export async function cookieOption(
  q: Question,
  ip: string | null,
  secret: string | undefined
): Promise<number[] | null> {
  if (!q.cookie || !secret) {
    return null;
  }
  const client = q.cookie.slice(0, 8);
  const key = await hmacKey(secret);
  const input = new Uint8Array([...client, ...encoder.encode(ip ?? '')]);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
  const data = [...client, ...mac.subarray(0, 8)];
  return [...u16(OPTION_COOKIE), ...u16(data.length), ...data];
}
