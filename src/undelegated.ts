/**
 * @fileoverview Names that can never resolve on the public Internet. Answering
 * NXDOMAIN locally saves the round trip to the upstream resolver (the list
 * follows dnscrypt-proxy's `plugin_block_undelegated`, as used by RethinkDNS).
 */

/** Top-level labels reserved for private or special use. */
const PRIVATE_TLDS = new Set([
  'alt', // RFC 9476.
  'corp',
  'example',
  'home',
  'internal',
  'intranet',
  'invalid',
  'lan',
  'local',
  'localdomain',
  'localnet',
  'modem',
  'onion',
  'private',
  'router',
  'test',
]);

/**
 * Reverse zones of private, loopback, link-local, CGNAT and documentation
 * addresses (RFC 6303).
 */
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
  /(^|\.)2\.0\.192\.in-addr\.arpa$/, // 192.0.2.0/24
  /(^|\.)100\.51\.198\.in-addr\.arpa$/, // 198.51.100.0/24
  /(^|\.)113\.0\.203\.in-addr\.arpa$/, // 203.0.113.0/24
  /(^|\.)255\.255\.255\.255\.in-addr\.arpa$/,
  /(^|\.)8\.b\.d\.0\.1\.0\.0\.2\.ip6\.arpa$/, // 2001:db8::/32
  /^1(\.0){31}\.ip6\.arpa$/, // ::1
  /^0(\.0){31}\.ip6\.arpa$/, // ::
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
