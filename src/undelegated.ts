/**
 * @fileoverview Names that can never resolve on the public Internet. Answering
 * NXDOMAIN locally saves the round trip to the upstream resolver (the list
 * follows dnscrypt-proxy's `plugin_block_undelegated`, as used by RethinkDNS).
 */

/** Top-level labels reserved for private or special use. */
const PRIVATE_TLDS = new Set([
  'corp',
  'example',
  'home',
  'internal',
  'intranet',
  'invalid',
  'lan',
  'local',
  'localdomain',
  'localhost',
  'localnet',
  'modem',
  'onion',
  'private',
  'router',
  'test',
]);

/** Reverse zones of private, loopback, link-local and CGNAT addresses. */
const PRIVATE_REVERSE = [
  /(^|\.)10\.in-addr\.arpa$/,
  /(^|\.)127\.in-addr\.arpa$/,
  /(^|\.)0\.in-addr\.arpa$/,
  /(^|\.)168\.192\.in-addr\.arpa$/,
  /(^|\.)254\.169\.in-addr\.arpa$/,
  /(^|\.)(1[6-9]|2\d|3[01])\.172\.in-addr\.arpa$/,
  /(^|\.)(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.100\.in-addr\.arpa$/,
  /(^|\.)[89ab]\.e\.f\.ip6\.arpa$/, // fe80::/10
  /(^|\.)[cd]\.f\.ip6\.arpa$/, // fc00::/7
];

/**
 * @param name Lower-case domain name without the trailing dot.
 */
export function isUndelegated(name: string): boolean {
  const tld = name.slice(name.lastIndexOf('.') + 1);
  return (
    PRIVATE_TLDS.has(tld) ||
    name === 'home.arpa' ||
    name.endsWith('.home.arpa') ||
    PRIVATE_REVERSE.some(pattern => pattern.test(name))
  );
}
