/**
 * @fileoverview DNS Cookies (RFC 7873). A client that sends a cookie gets it
 * back with a server cookie. The cookie is never enforced: requests arrive
 * over HTTPS, which already stops spoofing, so nothing is refused for lacking
 * one. Needs the COOKIE_SECRET setting; without it cookies are ignored.
 */

import {OPTION_COOKIE} from './constants.js';
import {ednsOption} from './response.js';
import {utf8} from './wire.js';
import type {Question} from './types.js';

/** The HMAC key of the last secret seen, so that it is imported only once. */
let imported: {secret: string; key: Promise<CryptoKey>} | null = null;

function hmacKey(secret: string): Promise<CryptoKey> {
  if (imported?.secret !== secret) {
    imported = {
      secret,
      key: crypto.subtle.importKey(
        'raw',
        new Uint8Array(utf8(secret)),
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
 *     no cookie, there is no secret, or the cookie could not be made.
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
  try {
    const client = q.cookie.slice(0, 8);
    const key = await hmacKey(secret);
    const input = new Uint8Array([...client, ...utf8(ip ?? '')]);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
    const data = [...client, ...mac.subarray(0, 8)];
    return ednsOption(OPTION_COOKIE, data);
  } catch {
    imported = null; // Try the key again next time.
    return null; // A cookie is a courtesy: the answer goes out without one.
  }
}
