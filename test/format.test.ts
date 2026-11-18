/** The JSON API (Google format) and RFC 3597 text for unknown types. */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {toJson} from '../src/format.js';
import {
  T,
  ip4,
  ip6,
  makeResponse,
  mxRdata,
  nameBytes,
  nameRdata,
  soaRdata,
  txtRdata,
} from './helpers.js';

const one = (type: number, rdata: number[], extra = {}) =>
  toJson(
    makeResponse({
      qname: 'a.test',
      qtype: type,
      answer: [{type, ttl: 77, rdata}],
      ...extra,
    })
  );

describe('toJson', () => {
  test('header flags and question', () => {
    const json = toJson(
      makeResponse({
        qname: 'a.test',
        qtype: T.A,
        rcode: 3,
        ad: true,
        tc: true,
        rd: false,
      })
    );
    assert.equal(json.Status, 3);
    assert.equal(json.AD, true);
    assert.equal(json.TC, true);
    assert.equal(json.RD, false);
    assert.equal(json.RA, true);
    assert.equal(json.CD, false);
    assert.deepEqual(json.Question, [{name: 'a.test.', type: T.A}]);
    assert.equal(json.Answer, undefined, 'empty sections are left out');
    assert.equal(json.Authority, undefined);
  });

  test('A, with name and TTL', () => {
    const json = one(T.A, ip4('192.0.2.1'));
    assert.deepEqual(json.Answer, [
      {name: 'a.test.', type: 1, TTL: 77, data: '192.0.2.1'},
    ]);
  });

  test('AAAA collapses the longest run of zero groups (RFC 5952)', () => {
    const cases: Array<[string, string]> = [
      ['2001:db8::1', '2001:db8::1'],
      ['::1', '::1'],
      ['::', '::'],
      ['1::', '1::'],
      ['1:0:0:2:0:0:0:3', '1:0:0:2::3'],
      ['1:0:2:0:3:0:4:5', '1:0:2:0:3:0:4:5'],
      ['2001:db8:0:0:0:0:2:1', '2001:db8::2:1'],
    ];
    for (const [input, expected] of cases) {
      assert.equal(one(T.AAAA, ip6(input)).Answer![0].data, expected, input);
    }
  });

  test('NS, CNAME and PTR show the target name', () => {
    for (const type of [T.NS, T.CNAME, T.PTR]) {
      assert.equal(
        one(type, nameRdata('t.example.net')).Answer![0].data,
        't.example.net.'
      );
    }
  });

  test('MX', () => {
    assert.equal(
      one(T.MX, mxRdata(10, 'mail.a.test')).Answer![0].data,
      '10 mail.a.test.'
    );
  });

  test('TXT quotes each string and escapes quotes and backslashes', () => {
    assert.equal(
      one(T.TXT, txtRdata('v=spf1', 'say "hi" \\o/')).Answer![0].data,
      '"v=spf1" "say \\"hi\\" \\\\o/"'
    );
  });

  test('SOA', () => {
    assert.equal(
      one(T.SOA, soaRdata(300)).Answer![0].data,
      'ns.example. hostmaster.example. 1 7200 900 1209600 300'
    );
  });

  test('SRV and CAA', () => {
    const srv = [0, 1, 0, 2, 0x1f, 0x90, ...nameBytes('host.a.test')];
    assert.equal(one(33, srv).Answer![0].data, '1 2 8080 host.a.test.');
    const caa = [
      0,
      5,
      ...Buffer.from('issue'),
      ...Buffer.from('letsencrypt.org'),
    ];
    assert.equal(one(257, caa).Answer![0].data, '0 issue "letsencrypt.org"');
  });

  test('HTTPS shows priority, target and the service parameters (RFC 9460)', () => {
    const rdata = [
      0,
      1,
      0, // priority 1, target "."
      0,
      1,
      0,
      6,
      2,
      104,
      50,
      2,
      104,
      51, // alpn=h2,h3
      0,
      4,
      0,
      4,
      ...ip4('104.16.0.1'), // ipv4hint
      0,
      5,
      0,
      3,
      1,
      2,
      3, // ech
      0,
      6,
      0,
      16,
      ...ip6('2606:4700::1'), // ipv6hint
    ];
    assert.equal(
      one(T.HTTPS, rdata).Answer![0].data,
      '1 . alpn=h2,h3 ipv4hint=104.16.0.1 ech=AQID ipv6hint=2606:4700::1'
    );
  });

  test('an unknown type uses the RFC 3597 form', () => {
    assert.equal(one(65280, [1, 2, 255]).Answer![0].data, '\\# 3 0102ff');
  });

  test('a record that cannot be formatted falls back to RFC 3597 too', () => {
    assert.equal(one(T.A, [1, 2, 3]).Answer![0].data, '\\# 3 010203');
  });

  test('authority and additional sections; the OPT record is not listed', () => {
    const json = toJson(
      makeResponse({
        qname: 'a.test',
        qtype: T.A,
        rcode: 3,
        authority: [
          {name: 'test', type: T.SOA, ttl: 900, rdata: soaRdata(900)},
        ],
        additional: [
          {name: 'x.test', type: T.A, ttl: 5, rdata: ip4('9.9.9.9')},
        ],
      })
    );
    assert.equal(json.Authority![0].type, T.SOA);
    assert.deepEqual(
      json.Additional!.map(r => r.type),
      [T.A]
    );
  });

  test('throws on a message that runs short', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 1, rdata: ip4('1.1.1.1')}],
    });
    assert.throws(() => toJson(body.subarray(0, 38)));
  });
});
