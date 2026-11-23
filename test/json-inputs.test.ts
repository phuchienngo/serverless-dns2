/**
 * @fileoverview The JSON API (`/resolve`): a table of requests, with the HTTP
 * status, the question and Status of the answer, and what each sends to the
 * upstream. The table is the contract for each kind of input.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {handleJson} from '../src/handlers.js';
import {
  T,
  ip4,
  makeResponse,
  mockUpstream,
  parseMsg,
  resetState,
} from './helpers.js';

const CLIENT_IP = '203.0.113.5';
const ctx = {env: {}, ip: CLIENT_IP} as never;
const NOERROR = 0;
const FORMERR = 1;
const NXDOMAIN = 3;
const NOTIMP = 4;

/** The ECS option data (after code and length) that `ip` /24 gives. */
const subnet24 = (a: number, b: number, c: number) => [0, 1, 24, 0, a, b, c];

interface Expected {
  http: number;
  /** Message of an error. */
  error?: string;
  /** `Status` of the answer (the DNS rcode); the default is NOERROR. */
  status?: number;
  /** The question echoed in the answer. */
  question?: {name: string; type: number};
  /** Whether the upstream is asked (the default is yes, for an answer). */
  upstream?: boolean;
  /** Flags the upstream query carries. */
  do?: boolean;
  cd?: boolean;
  /** The ECS option data the upstream gets; null for none at all. */
  ecs?: number[];
  /** The body is a DNS message (ct=application/dns-message). */
  wire?: boolean;
  /** The Allow header of an error. */
  allow?: string;
}

type Row = [description: string, method: string, query: string, e: Expected];

const q = (params: Record<string, string>) =>
  new URLSearchParams(params).toString();
const ok = (name: string, type = T.A): Expected => ({
  http: 200,
  question: {name, type},
});
const bad = (error: string): Expected => ({http: 400, error});
const local = (e: Expected): Expected => ({...e, upstream: false});
const domain = 'example.com';
const long = (c: string, n: number) => c.repeat(n);

const rows: Row[] = [
  // Method.
  ['GET', 'GET', q({name: domain}), ok('example.com.')],
  [
    'HEAD is a bad request',
    'HEAD',
    q({name: domain}),
    {...bad('bad request'), allow: 'GET'},
  ],
  ...['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map((method): Row => [
    `${method} is not implemented`,
    method,
    q({name: domain}),
    {http: 501, error: 'not implemented', allow: 'GET'},
  ]),

  // Name.
  ['no name', 'GET', '', bad('invalid name')],
  ['an empty name', 'GET', 'name=', bad('invalid name')],
  [
    'a trailing dot is the same name',
    'GET',
    q({name: 'example.com.'}),
    ok('example.com.'),
  ],
  [
    'the case of a name is kept (RFC 4343)',
    'GET',
    q({name: 'EXAMPLE.Com'}),
    ok('EXAMPLE.Com.'),
  ],
  [
    'a label of 63 characters',
    'GET',
    q({name: `${long('a', 63)}.example.com`}),
    ok(`${long('a', 63)}.example.com.`),
  ],
  [
    'a label of 64 characters',
    'GET',
    q({name: `${long('a', 64)}.example.com`}),
    bad('invalid name'),
  ],
  [
    'a name of 253 characters',
    'GET',
    q({
      name: [
        long('a', 61),
        long('b', 61),
        long('c', 61),
        long('d', 61),
        'eeeee',
      ].join('.'),
    }),
    ok(
      `${[long('a', 61), long('b', 61), long('c', 61), long('d', 61), 'eeeee'].join('.')}.`
    ),
  ],
  [
    'a name over 253 characters',
    'GET',
    q({
      name: [long('a', 63), long('b', 63), long('c', 63), long('d', 63)].join(
        '.'
      ),
    }),
    bad('invalid name'),
  ],
  ['a space in the name', 'GET', 'name=exa mple.com', bad('invalid name')],
  [
    'a percent-encoded space',
    'GET',
    'name=ex%20ample.com',
    bad('invalid name'),
  ],
  [
    'a non-ASCII name must be punycode',
    'GET',
    'name=b%C3%BCcher.de',
    bad('invalid name'),
  ],
  [
    'an underscore label',
    'GET',
    q({name: '_dmarc.example.com'}),
    ok('_dmarc.example.com.'),
  ],
  ['an empty label', 'GET', q({name: 'a..b.com'}), bad('invalid name')],
  ['a single dot', 'GET', q({name: '.'}), bad('invalid name')],
  ['two dots', 'GET', q({name: '..'}), bad('invalid name')],
  [
    'localhost is answered here',
    'GET',
    q({name: 'localhost'}),
    local(ok('localhost.')),
  ],

  // Type.
  ['no type is A', 'GET', q({name: domain}), ok('example.com.', T.A)],
  [
    'an empty type is A',
    'GET',
    'name=example.com&type=',
    ok('example.com.', T.A),
  ],
  [
    'a type name',
    'GET',
    q({name: domain, type: 'AAAA'}),
    ok('example.com.', T.AAAA),
  ],
  [
    'a type name in lower case',
    'GET',
    q({name: domain, type: 'aaaa'}),
    ok('example.com.', T.AAAA),
  ],
  ['TXT', 'GET', q({name: domain, type: 'TXT'}), ok('example.com.', T.TXT)],
  [
    'HTTPS',
    'GET',
    q({name: domain, type: 'HTTPS'}),
    ok('example.com.', T.HTTPS),
  ],
  [
    'a type number',
    'GET',
    q({name: domain, type: '28'}),
    ok('example.com.', T.AAAA),
  ],
  [
    'type 65535 is forwarded',
    'GET',
    q({name: domain, type: '65535'}),
    ok('example.com.', 65535),
  ],
  ['type 0', 'GET', q({name: domain, type: '0'}), bad('invalid type')],
  ['type 65536', 'GET', q({name: domain, type: '65536'}), bad('invalid type')],
  [
    'a negative type',
    'GET',
    q({name: domain, type: '-1'}),
    bad('invalid type'),
  ],
  [
    'a fractional type',
    'GET',
    q({name: domain, type: '1.5'}),
    bad('invalid type'),
  ],
  [
    'a type with a space',
    'GET',
    'name=example.com&type=%201',
    bad('invalid type'),
  ],
  [
    'an unknown type name',
    'GET',
    q({name: domain, type: 'BOGUS'}),
    bad('invalid type'),
  ],
  [
    'ANY gets HINFO here',
    'GET',
    q({name: domain, type: 'ANY'}),
    local(ok('example.com.', T.ANY)),
  ],
  [
    'AXFR is NOTIMP',
    'GET',
    q({name: domain, type: 'AXFR'}),
    local({...ok('example.com.', 252), status: NOTIMP}),
  ],
  [
    'OPT is FORMERR',
    'GET',
    q({name: domain, type: 'OPT'}),
    local({...ok('example.com.', T.OPT), status: FORMERR}),
  ],
  [
    'TSIG is FORMERR',
    'GET',
    q({name: domain, type: 'TSIG'}),
    local({...ok('example.com.', 250), status: FORMERR}),
  ],

  // An IP address as the name.
  [
    'PTR of an IPv4 address is its reverse name',
    'GET',
    q({name: '8.8.8.8', type: 'PTR'}),
    ok('8.8.8.8.in-addr.arpa.', T.PTR),
  ],
  [
    'PTR of a documentation IPv6 address is NXDOMAIN, answered here',
    'GET',
    q({name: '2001:db8::1', type: 'PTR'}),
    local({
      ...ok(`1.${long('0.', 23)}8.b.d.0.1.0.0.2.ip6.arpa.`, T.PTR),
      status: NXDOMAIN,
    }),
  ],
  [
    'NAPTR of an IPv4 address is its reverse name',
    'GET',
    q({name: '8.8.8.8', type: 'NAPTR'}),
    ok('8.8.8.8.in-addr.arpa.', 35),
  ],
  [
    'PTR of a name is left alone',
    'GET',
    q({name: domain, type: 'PTR'}),
    ok('example.com.', T.PTR),
  ],
  [
    'PTR of an invalid address is left alone',
    'GET',
    q({name: '999.1.1.1', type: 'PTR'}),
    ok('999.1.1.1.', T.PTR),
  ],
  [
    'an IP address as the name of an A query is a name',
    'GET',
    q({name: '8.8.8.8'}),
    ok('8.8.8.8.'),
  ],

  // DO and CD: 1 or true, in any case.
  [
    'do=1',
    'GET',
    q({name: domain, do: '1'}),
    {...ok('example.com.'), do: true},
  ],
  [
    'do=true',
    'GET',
    q({name: domain, do: 'true'}),
    {...ok('example.com.'), do: true},
  ],
  [
    'do=TRUE',
    'GET',
    q({name: domain, do: 'TRUE'}),
    {...ok('example.com.'), do: true},
  ],
  [
    'do=0',
    'GET',
    q({name: domain, do: '0'}),
    {...ok('example.com.'), do: false},
  ],
  [
    'do=yes is not true',
    'GET',
    q({name: domain, do: 'yes'}),
    {...ok('example.com.'), do: false},
  ],
  [
    'an empty do',
    'GET',
    'name=example.com&do=',
    {...ok('example.com.'), do: false},
  ],
  [
    'cd=1',
    'GET',
    q({name: domain, cd: '1'}),
    {...ok('example.com.'), cd: true},
  ],
  [
    'do=1 and cd=1',
    'GET',
    q({name: domain, do: '1', cd: '1'}),
    {...ok('example.com.'), do: true, cd: true},
  ],

  // Content type.
  [
    'ct=application/dns-message gives the wire format',
    'GET',
    q({name: domain, ct: 'application/dns-message'}),
    {...ok('example.com.'), wire: true},
  ],
  [
    'ct=application/json',
    'GET',
    q({name: domain, ct: 'application/json'}),
    ok('example.com.'),
  ],
  [
    'another ct is JSON',
    'GET',
    q({name: domain, ct: 'text/html'}),
    ok('example.com.'),
  ],
  ['an empty ct is JSON', 'GET', 'name=example.com&ct=', ok('example.com.')],

  // Client subnet: the parameter, else the connecting address (as a /24).
  [
    'no subnet: the connecting address as /24',
    'GET',
    q({name: domain}),
    {...ok('example.com.'), ecs: subnet24(203, 0, 113)},
  ],
  [
    'a subnet',
    'GET',
    q({name: domain, edns_client_subnet: '198.51.100.0/24'}),
    {...ok('example.com.'), ecs: subnet24(198, 51, 100)},
  ],
  [
    'an address without a prefix becomes a /24',
    'GET',
    q({name: domain, edns_client_subnet: '198.51.100.7'}),
    {...ok('example.com.'), ecs: subnet24(198, 51, 100)},
  ],
  [
    'an IPv6 subnet',
    'GET',
    q({name: domain, edns_client_subnet: '2001:db8::/48'}),
    {...ok('example.com.'), ecs: [0, 2, 48, 0, 0x20, 1, 0xd, 0xb8, 0, 0]},
  ],
  [
    '0.0.0.0/0 asks not to be located',
    'GET',
    q({name: domain, edns_client_subnet: '0.0.0.0/0'}),
    {...ok('example.com.'), ecs: [0, 1, 0, 0]},
  ],
  [
    '::/0 asks not to be located',
    'GET',
    q({name: domain, edns_client_subnet: '::/0'}),
    {...ok('example.com.'), ecs: [0, 2, 0, 0]},
  ],
  [
    'a prefix of 33 for IPv4',
    'GET',
    q({name: domain, edns_client_subnet: '198.51.100.0/33'}),
    bad('invalid edns_client_subnet'),
  ],
  [
    'a subnet that is not an address',
    'GET',
    q({name: domain, edns_client_subnet: 'abc'}),
    bad('invalid edns_client_subnet'),
  ],
  [
    'a prefix that is not a number',
    'GET',
    q({name: domain, edns_client_subnet: '198.51.100.0/x'}),
    bad('invalid edns_client_subnet'),
  ],
  [
    'two prefixes',
    'GET',
    q({name: domain, edns_client_subnet: '1.2.3.4/24/1'}),
    bad('invalid edns_client_subnet'),
  ],
  [
    'an address with a byte over 255',
    'GET',
    q({name: domain, edns_client_subnet: '300.1.1.1'}),
    bad('invalid edns_client_subnet'),
  ],
  [
    'an empty subnet is no subnet',
    'GET',
    'name=example.com&edns_client_subnet=',
    {...ok('example.com.'), ecs: subnet24(203, 0, 113)},
  ],

  // Other parameters.
  [
    'unknown parameters are ignored',
    'GET',
    q({name: domain, random_padding: 'xyz', foo: 'bar'}),
    ok('example.com.'),
  ],
  [
    'a repeated name: the first',
    'GET',
    'name=a.example.com&name=b.example.com',
    ok('a.example.com.'),
  ],
  [
    'a repeated type: the first',
    'GET',
    'name=example.com&type=A&type=AAAA',
    ok('example.com.', T.A),
  ],
];

let upstream: ReturnType<typeof mockUpstream>;
beforeEach(() => {
  resetState();
  upstream = mockUpstream(query =>
    makeResponse({
      qname: query.question[0].name,
      qtype: query.question[0].type,
      answer:
        query.question[0].type === T.A
          ? [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}]
          : [],
    })
  );
});
afterEach(() => upstream.restore());

describe('/resolve: what each kind of request gets back', () => {
  for (const [description, method, query, e] of rows) {
    test(`${description} (${method} ?${query.slice(0, 40)})`, async () => {
      const res = await handleJson(
        new Request(`https://dns.test/resolve?${query}`, {method}),
        ctx
      );
      assert.equal(res.status, e.http, 'HTTP status');
      if (e.http !== 200) {
        assert.equal(await res.text(), e.error, 'message');
        assert.equal(res.headers.get('allow'), e.allow ?? null, 'Allow');
        assert.equal(upstream.calls.length, 0, 'nothing is sent upstream');
        return;
      }

      if (e.wire) {
        assert.equal(
          res.headers.get('content-type'),
          'application/dns-message'
        );
        const message = parseMsg(new Uint8Array(await res.arrayBuffer()));
        assert.equal(message.rcode, e.status ?? NOERROR, 'rcode');
        assert.deepEqual(
          [message.question[0].name, message.question[0].type],
          [e.question!.name, e.question!.type],
          'question'
        );
      } else {
        assert.equal(
          res.headers.get('content-type'),
          'application/json; charset=UTF-8'
        );
        const body = (await res.json()) as Record<string, unknown>;
        assert.equal(body.Status, e.status ?? NOERROR, 'Status');
        for (const flag of ['TC', 'RD', 'RA', 'AD', 'CD']) {
          assert.equal(typeof body[flag], 'boolean', flag);
        }
        assert.deepEqual(body.Question, [e.question], 'Question');
      }

      const asked = e.upstream ?? true;
      assert.equal(upstream.calls.length > 0, asked, 'goes to the upstream');
      if (!asked) {
        return;
      }
      const sent = upstream.calls[0].query;
      assert.equal(sent.opt?.do ?? false, e.do ?? false, 'DO');
      assert.equal(sent.cd, e.cd ?? false, 'CD');
      const ecs = sent.opt?.options.find(o => o.code === 8)?.data;
      if (e.ecs) {
        assert.deepEqual([...(ecs ?? [])], e.ecs, 'ECS sent upstream');
      }
    });
  }
});
