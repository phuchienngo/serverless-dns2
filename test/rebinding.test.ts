/** DNS rebinding protection (src/rebinding.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {isPrivateV4, isPrivateV6, rebindingAddress} from '../src/rebinding.js';
import {T, ip4, ip6, makeResponse, nameBytes} from './helpers.js';

describe('isPrivateV4', () => {
  test('private, shared, loopback, link-local and "this network" blocks', () => {
    for (const a of [
      '10.0.0.1',
      '10.255.255.255',
      '100.64.0.1',
      '100.127.255.255',
      '127.0.0.1',
      '127.255.255.254',
      '169.254.169.254',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.0.1',
      '192.168.255.255',
      '0.0.0.1',
      '0.255.255.255',
    ]) {
      assert.equal(isPrivateV4(ip4(a)), true, a);
    }
  });

  test('public addresses, the block edges and 0.0.0.0 are not private', () => {
    for (const a of [
      '8.8.8.8',
      '1.1.1.1',
      '9.255.255.255',
      '11.0.0.0',
      '100.63.255.255',
      '100.128.0.0',
      '126.255.255.255',
      '128.0.0.1',
      '169.253.255.255',
      '169.255.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '192.167.255.255',
      '192.169.0.0',
      '203.0.113.9', // Documentation addresses are not private.
      '0.0.0.0', // What blocklists answer for a blocked name.
    ]) {
      assert.equal(isPrivateV4(ip4(a)), false, a);
    }
  });
});

describe('isPrivateV6', () => {
  test('loopback, unique local, link-local and mapped private IPv4', () => {
    for (const a of [
      '::1',
      'fc00::1',
      'fd12:3456::1',
      'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      'fe80::1',
      'febf::1',
      '::ffff:0a00:0001', // ::ffff:10.0.0.1
      '::ffff:7f00:0001', // ::ffff:127.0.0.1
      '::ffff:c0a8:0101', // ::ffff:192.168.1.1
    ]) {
      assert.equal(isPrivateV6(ip6(a)), true, a);
    }
  });

  test('global addresses, :: and mapped public IPv4 are not private', () => {
    for (const a of [
      '2001:db8::1',
      '2606:4700:4700::1111',
      '::', // What blocklists answer for a blocked name.
      '::2',
      'fb00::1',
      'fe00::1',
      'fec0::1', // Site-local is deprecated, not link-local.
      '::ffff:0808:0808', // ::ffff:8.8.8.8
      '100::1',
    ]) {
      assert.equal(isPrivateV6(ip6(a)), false, a);
    }
  });
});

/** The RDATA of an HTTPS record with address hints. */
function httpsRdata(hints: {v4?: string[]; v6?: string[]}): number[] {
  const param = (key: number, bytes: number[]) => [
    key >> 8,
    key & 255,
    bytes.length >> 8,
    bytes.length & 255,
    ...bytes,
  ];
  return [
    0,
    1, // Priority.
    ...nameBytes('.'),
    ...param(1, [2, 0x68, 0x32]), // alpn=h2
    ...(hints.v4 ? param(4, hints.v4.flatMap(ip4)) : []),
    ...(hints.v6 ? param(6, hints.v6.flatMap(ip6)) : []),
  ];
}

const answer = (rr: Array<{type: number; rdata: number[]}>) =>
  makeResponse({
    qname: 'a.example.com',
    qtype: rr[0]?.type ?? T.A,
    answer: rr.map(r => ({...r, ttl: 60})),
  });

describe('rebindingAddress', () => {
  test('finds a private A or AAAA record, and says which address', () => {
    assert.deepEqual(
      rebindingAddress(answer([{type: T.A, rdata: ip4('192.168.1.1')}])),
      ip4('192.168.1.1')
    );
    assert.deepEqual(
      rebindingAddress(answer([{type: T.AAAA, rdata: ip6('fd00::1')}])),
      ip6('fd00::1')
    );
  });

  test('one private address among public ones is enough', () => {
    const msg = answer([
      {type: T.A, rdata: ip4('8.8.8.8')},
      {type: T.A, rdata: ip4('10.1.2.3')},
      {type: T.A, rdata: ip4('1.1.1.1')},
    ]);
    assert.deepEqual(rebindingAddress(msg), ip4('10.1.2.3'));
  });

  test('looks past a CNAME chain', () => {
    const msg = makeResponse({
      qname: 'a.example.com',
      qtype: T.A,
      answer: [
        {type: T.CNAME, ttl: 60, rdata: nameBytes('b.example.net')},
        {name: 'b.example.net', type: T.A, ttl: 60, rdata: ip4('127.0.0.1')},
      ],
    });
    assert.deepEqual(rebindingAddress(msg), ip4('127.0.0.1'));
  });

  test('looks in the address hints of HTTPS and SVCB records', () => {
    assert.deepEqual(
      rebindingAddress(
        answer([
          {type: T.HTTPS, rdata: httpsRdata({v4: ['8.8.8.8', '10.0.0.5']})},
        ])
      ),
      ip4('10.0.0.5')
    );
    assert.deepEqual(
      rebindingAddress(
        answer([{type: T.SVCB, rdata: httpsRdata({v6: ['fe80::1']})}])
      ),
      ip6('fe80::1')
    );
    assert.equal(
      rebindingAddress(
        answer([
          {
            type: T.HTTPS,
            rdata: httpsRdata({v4: ['8.8.8.8'], v6: ['2001:db8::1']}),
          },
        ])
      ),
      null
    );
  });

  test('is null for public answers, empty answers and other types', () => {
    assert.equal(
      rebindingAddress(answer([{type: T.A, rdata: ip4('8.8.8.8')}])),
      null
    );
    assert.equal(
      rebindingAddress(makeResponse({qname: 'a.test', qtype: T.A})),
      null
    );
    assert.equal(
      rebindingAddress(
        answer([{type: T.TXT, rdata: [3, 0x31, 0x30, 0x2e]}]) // Not an address.
      ),
      null
    );
  });

  test('only the answer section counts', () => {
    const msg = makeResponse({
      qname: 'a.example.com',
      qtype: T.A,
      answer: [{type: T.A, ttl: 60, rdata: ip4('8.8.8.8')}],
      additional: [
        {name: 'ns.example.com', type: T.A, ttl: 60, rdata: ip4('10.0.0.1')},
      ],
    });
    assert.equal(rebindingAddress(msg), null);
  });

  test('a message that cannot be read is not a hit', () => {
    assert.equal(rebindingAddress(new Uint8Array([1, 2, 3])), null);
  });

  test('a damaged hint never reads past its record', () => {
    // The hint claims more bytes than the record has: what is there is still
    // checked, and nothing beyond the record is read.
    const long = httpsRdata({v4: ['10.0.0.5']});
    long[long.length - 5] = 0xff;
    assert.deepEqual(
      rebindingAddress(answer([{type: T.HTTPS, rdata: long}])),
      ip4('10.0.0.5')
    );
    // A hint shorter than one address holds none.
    const short = httpsRdata({v4: ['10.0.0.5']}).slice(0, -1);
    short[short.length - 4] = 0; // Length high byte.
    short[short.length - 3] = 3; // Three bytes: not an address.
    assert.equal(
      rebindingAddress(answer([{type: T.HTTPS, rdata: short}])),
      null
    );
  });
});
