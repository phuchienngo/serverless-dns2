/** EDNS Client Subnet (RFC 7871): src/ecs.ts. */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {clientEcs, makeEcs, parseEcsParam, reverseName} from '../src/ecs.js';
import {T, ip4, makeQuery} from './helpers.js';

/** The ECS option: code 8, length, family, source prefix, scope, address. */
const option = (family: number, prefix: number, address: number[]) => [
  0,
  8,
  0,
  4 + address.length,
  0,
  family,
  prefix,
  0,
  ...address,
];

describe('makeEcs', () => {
  test('IPv4 defaults to /24 and sends only those three bytes', () => {
    assert.deepEqual(makeEcs('203.0.113.77'), option(1, 24, [203, 0, 113]));
  });

  test('IPv6 defaults to /48', () => {
    assert.deepEqual(
      makeEcs('2001:db8:1:2:3:4:5:6'),
      option(2, 48, [0x20, 0x01, 0x0d, 0xb8, 0, 1])
    );
  });

  test('zeroes the address bits beyond the prefix', () => {
    assert.deepEqual(
      makeEcs('255.255.255.255', 20),
      option(1, 20, [255, 255, 240])
    );
    assert.deepEqual(makeEcs('255.255.255.255', 0), option(1, 0, []));
    assert.deepEqual(makeEcs('1.2.3.4', 32), option(1, 32, [1, 2, 3, 4]));
  });

  test('understands every form of an IPv6 address', () => {
    assert.deepEqual(makeEcs('::1', 128)?.slice(-16), [
      ...Array(15).fill(0),
      1,
    ]);
    assert.deepEqual(makeEcs('::', 128)?.slice(-16), Array(16).fill(0));
    assert.deepEqual(makeEcs('2001:db8::1', 128)?.slice(-4), [0, 0, 0, 1]);
    assert.deepEqual(
      makeEcs('2001:DB8::', 32),
      option(2, 32, [0x20, 0x01, 0x0d, 0xb8])
    );
  });

  test('turns an IPv4-mapped IPv6 address into IPv4', () => {
    assert.deepEqual(makeEcs('::ffff:1.2.3.4'), makeEcs('1.2.3.4'));
  });

  test('rejects invalid input', () => {
    for (const ip of [
      '',
      'abc',
      '1.2.3',
      '1.2.3.4.5',
      '256.1.1.1',
      ':::',
      '1::2::3',
      '12345::',
      'g::1',
    ]) {
      assert.equal(makeEcs(ip), null, ip);
    }
    assert.equal(makeEcs('1.2.3.4', 33), null);
    assert.equal(makeEcs('::1', 129), null);
    assert.equal(makeEcs('1.2.3.4', -1), null);
    assert.equal(makeEcs('1.2.3.4', 1.5), null);
  });
});

describe('parseEcsParam (the JSON API parameter)', () => {
  test('reads an address with or without a prefix', () => {
    assert.deepEqual(parseEcsParam('1.2.3.4/24'), option(1, 24, [1, 2, 3]));
    assert.deepEqual(parseEcsParam('1.2.3.4'), makeEcs('1.2.3.4'));
    assert.deepEqual(parseEcsParam('2001:db8::/48'), makeEcs('2001:db8::', 48));
  });

  test('rejects garbage', () => {
    for (const p of [
      '1.2.3.4/abc',
      '1.2.3.4/24/1',
      '1.2.3.4/',
      'x/24',
      '1.2.3.4/999',
    ]) {
      assert.equal(parseEcsParam(p), null, p);
    }
  });
});

describe('clientEcs (an ECS option sent by the client)', () => {
  const read = (opts: Parameters<typeof makeQuery>[2]) => {
    const wire = makeQuery('a.test', T.A, opts);
    return clientEcs(wire);
  };

  test('honours the client subnet', () => {
    assert.deepEqual(
      read({ecs: {family: 1, prefix: 24, address: [198, 51, 100]}}),
      option(1, 24, [198, 51, 100])
    );
    assert.deepEqual(
      read({ecs: {family: 1, prefix: 16, address: [198, 51]}}),
      option(1, 16, [198, 51])
    );
  });

  test('clamps a more specific subnet to /24 (IPv4) and /48 (IPv6)', () => {
    assert.deepEqual(
      read({ecs: {family: 1, prefix: 32, address: [198, 51, 100, 9]}}),
      option(1, 24, [198, 51, 100])
    );
    assert.deepEqual(
      read({
        ecs: {family: 2, prefix: 64, address: [0x20, 1, 0xd, 0xb8, 0, 1, 0, 2]},
      }),
      option(2, 48, [0x20, 1, 0xd, 0xb8, 0, 1])
    );
  });

  test('an empty subnet (source prefix 0 or an all-zero address) asks not to be located: a source prefix 0 option', () => {
    assert.deepEqual(
      read({ecs: {family: 2, prefix: 0, address: []}}),
      option(2, 0, [])
    );
    assert.deepEqual(
      read({ecs: {family: 1, prefix: 24, address: [0, 0, 0]}}),
      option(1, 0, [])
    );
  });

  test('returns null without an ECS option, or without EDNS', () => {
    assert.equal(read({}), null);
    assert.equal(read({edns: false}), null);
    assert.equal(read({padding: 10}), null);
  });

  test('ignores a malformed option', () => {
    // Family 3 does not exist.
    assert.equal(
      read({ecs: {family: 3 as 1, prefix: 24, address: [1, 2, 3]}}),
      null
    );
    // Prefix longer than the address of that family.
    assert.equal(
      read({ecs: {family: 1, prefix: 40, address: [1, 2, 3, 4, 5]}}),
      null
    );
    // Address shorter than the prefix says.
    const wire = Uint8Array.from(
      makeQuery('a.test', T.A, {
        ecs: {family: 1, prefix: 24, address: [1, 2, 3]},
      })
    );
    wire[wire.length - 5] = 32; // source prefix 32, but only three bytes follow
    assert.equal(clientEcs(wire), null);
  });

  test('copes with a damaged message', () => {
    const wire = makeQuery('a.test', T.A);
    assert.equal(clientEcs(wire.subarray(0, wire.length - 6)), null);
  });
});

describe('reverseName', () => {
  test('IPv4', () => {
    assert.equal(reverseName('1.2.3.4'), '4.3.2.1.in-addr.arpa');
    assert.equal(reverseName(ip4('9.9.9.9').join('.')), '9.9.9.9.in-addr.arpa');
  });

  test('IPv6 is 32 nibbles, lowest first', () => {
    const name = reverseName('2001:db8::1')!;
    assert.ok(name.endsWith('.ip6.arpa'));
    assert.equal(
      name,
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
    );
  });

  test('is null for something that is not an IP address', () => {
    assert.equal(reverseName('example.com'), null);
    assert.equal(reverseName(''), null);
  });
});
