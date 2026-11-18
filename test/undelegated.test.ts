/** Names answered with NXDOMAIN locally (RFC 6761, 6303, 8375, 9476, 7686). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {isUndelegated} from '../src/undelegated.js';

const yes = (...names: string[]) =>
  names.forEach(n => assert.equal(isUndelegated(n), true, n));
const no = (...names: string[]) =>
  names.forEach(n => assert.equal(isUndelegated(n), false, n));

describe('isUndelegated', () => {
  test('special-use and private top-level names', () => {
    yes('foo.test', 'foo.example', 'x.invalid', 'printer.local', 'a.b.lan');
    yes('x.onion', 'x.internal', 'x.corp', 'x.home', 'x.alt', 'x.router');
  });

  test('home.arpa (RFC 8375)', () => {
    yes('home.arpa', 'printer.home.arpa');
    no('foo.arpa', 'myhome.arpa');
  });

  test('private IPv4 reverse zones', () => {
    yes('1.0.0.10.in-addr.arpa', '10.in-addr.arpa');
    yes(
      '1.1.168.192.in-addr.arpa',
      '1.0.0.127.in-addr.arpa',
      '5.0.0.0.in-addr.arpa'
    );
    yes('1.1.254.169.in-addr.arpa');
  });

  test('172.16/12 and 100.64/10 stop at their edges', () => {
    yes('1.1.16.172.in-addr.arpa', '1.1.31.172.in-addr.arpa');
    no('1.1.15.172.in-addr.arpa', '1.1.32.172.in-addr.arpa');
    yes('1.1.64.100.in-addr.arpa', '1.1.127.100.in-addr.arpa');
    no('1.1.63.100.in-addr.arpa', '1.1.128.100.in-addr.arpa');
  });

  test('documentation and broadcast reverse zones (RFC 6303)', () => {
    yes(
      '7.2.0.192.in-addr.arpa',
      '7.100.51.198.in-addr.arpa',
      '7.113.0.203.in-addr.arpa'
    );
    yes('255.255.255.255.in-addr.arpa');
    no('7.1.0.192.in-addr.arpa', '8.8.8.8.in-addr.arpa');
  });

  test('IPv6 reverse zones', () => {
    const nibbles = (n: string) => n.split('').join('.');
    yes(
      `${nibbles('1'.padStart(32, '0').split('').reverse().join(''))}.ip6.arpa`
    );
    yes(`${nibbles('0'.repeat(32))}.ip6.arpa`);
    yes('1.8.b.d.0.1.0.0.2.ip6.arpa', 'x.8.b.d.0.1.0.0.2.ip6.arpa');
    yes('a.e.f.ip6.arpa', 'c.f.ip6.arpa', 'd.f.ip6.arpa');
    no('1.0.0.2.ip6.arpa', 'x.0.0.0.0.ip6.arpa');
  });

  test('ordinary names are not undelegated', () => {
    no('example.com', 'www.google.com', 'tester.org', 'localhost');
  });
});
