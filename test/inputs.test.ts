/**
 * @fileoverview The gateway's behaviour for each kind of input: a table of DNS
 * queries (well formed, malformed, odd headers, types, classes, names, EDNS
 * and ECS variants) and what each must give back, whatever the HTTP method.
 * `inputs` is the contract; the invariants below hold for every answer.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {handle} from '../src/handlers.js';
import {
  T,
  ip4,
  makeResponse,
  mockUpstream,
  parseMsg,
  resetState,
} from './helpers.js';

const ctx = {env: {}, ip: null} as never;
const ID = 0x1234;

const RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
  BADVERS: 16,
};

const u16 = (n: number) => [(n >> 8) & 255, n & 255];
const encodeName = (s: string) => [
  ...s
    .split('.')
    .filter(Boolean)
    .flatMap(label => [label.length, ...Buffer.from(label, 'latin1')]),
  0,
];

interface Raw {
  flags?: number;
  qd?: number;
  an?: number;
  ar?: number;
  /** The question name in wire format; the default is a name of its own. */
  name?: number[];
  type?: number;
  cls?: number;
  tail?: number[];
}

/** A query written byte by byte, so that it can be wrong in any one place. */
function raw(n: number, o: Raw = {}): Uint8Array {
  return new Uint8Array([
    ...u16(ID),
    ...u16(o.flags ?? 0x0100), // RD.
    ...u16(o.qd ?? 1),
    ...u16(o.an ?? 0),
    ...u16(0),
    ...u16(o.ar ?? 0),
    ...(o.name ?? encodeName(`c${n}.inputs.example.com`)),
    ...u16(o.type ?? T.A),
    ...u16(o.cls ?? 1),
    ...(o.tail ?? []),
  ]);
}

const option = (code: number, data: number[]) => [
  ...u16(code),
  ...u16(data.length),
  ...data,
];

/** An OPT record. */
function opt(
  o: {
    owner?: number[];
    version?: number;
    flags?: number;
    options?: number[];
    rdlength?: number;
  } = {}
): number[] {
  const options = o.options ?? [];
  return [
    ...(o.owner ?? [0]),
    ...u16(T.OPT),
    ...u16(1232),
    0,
    o.version ?? 0,
    ...u16(o.flags ?? 0),
    ...u16(o.rdlength ?? options.length),
    ...options,
  ];
}

const withOpt = (options: number[] = [], extra = {}) => ({
  ar: 1,
  tail: opt({options, ...extra}),
});
const ecs = (data: number[]) => withOpt(option(8, data));
const cookie = (length: number) => withOpt(option(10, Array(length).fill(1)));
const label = (c: string, n: number) => c.repeat(n);

interface Expected {
  /** HTTP status; 200 is a DNS message, whose rcode is `rcode`. */
  http: 200 | 400;
  rcode?: number;
  /** Whether the query goes to the upstream (else it is answered here). */
  upstream?: boolean;
  /** The response carries an OPT record (checked only if given). */
  opt?: boolean;
}

type Input = [
  description: string,
  make: (n: number) => Uint8Array,
  expected: Expected,
];

const answered = {http: 200, rcode: RCODE.NOERROR, upstream: true} as const;
const local = (rcode: number): Expected => ({
  http: 200,
  rcode,
  upstream: false,
});

const inputs: Input[] = [
  // Header.
  ['a plain A query', n => raw(n), answered],
  [
    'QR set: a response sent as a query',
    n => raw(n, {flags: 0x8100}),
    {http: 400},
  ],
  ['opcode IQUERY', n => raw(n, {flags: 0x0900}), local(RCODE.NOTIMP)],
  ['opcode STATUS', n => raw(n, {flags: 0x1100}), local(RCODE.NOTIMP)],
  ['opcode NOTIFY', n => raw(n, {flags: 0x2100}), local(RCODE.NOTIMP)],
  ['opcode UPDATE', n => raw(n, {flags: 0x2900}), local(RCODE.NOTIMP)],
  ['QDCOUNT 0', n => raw(n, {qd: 0}), {http: 400}],
  [
    'QDCOUNT 2 (RFC 9619)',
    n => raw(n, {qd: 2, tail: [...encodeName('b.example.com'), 0, 1, 0, 1]}),
    local(RCODE.FORMERR),
  ],
  ['Z bit set is ignored', n => raw(n, {flags: 0x0140}), answered],
  ['AA set is ignored', n => raw(n, {flags: 0x0500}), answered],
  ['TC set is ignored', n => raw(n, {flags: 0x0300}), answered],
  ['RD clear is still answered', n => raw(n, {flags: 0}), answered],
  ['AD set', n => raw(n, {flags: 0x0120}), answered],
  ['CD set', n => raw(n, {flags: 0x0110}), answered],
  ['ANCOUNT 1 with no record', n => raw(n, {an: 1}), local(RCODE.FORMERR)],
  [
    'ARCOUNT 2 with one record',
    n => raw(n, {ar: 2, tail: opt()}),
    local(RCODE.FORMERR),
  ],
  [
    'bytes after the message are ignored',
    n => raw(n, {tail: [1, 2, 3]}),
    answered,
  ],

  // Types.
  ['QTYPE 0', n => raw(n, {type: 0}), local(RCODE.FORMERR)],
  [
    'QTYPE ANY gets HINFO (RFC 8482)',
    n => raw(n, {type: T.ANY}),
    local(RCODE.NOERROR),
  ],
  [
    'QTYPE ANY with DO is forwarded, to be signed (RFC 8482 4.2)',
    n => raw(n, {type: T.ANY, ar: 1, tail: opt({flags: 0x8000})}),
    {...answered, opt: true},
  ],
  [
    'DS of home.arpa without DO is NXDOMAIN here',
    n => raw(n, {name: encodeName('home.arpa'), type: 43}),
    {http: 200, rcode: RCODE.NXDOMAIN, upstream: false},
  ],
  [
    'DS of home.arpa with DO is forwarded, to prove the absence (RFC 8375 4)',
    n =>
      raw(n, {
        name: encodeName('home.arpa'),
        type: 43,
        ar: 1,
        tail: opt({flags: 0x8000}),
      }),
    {...answered, opt: true},
  ],
  [
    'NS of home.arpa is NXDOMAIN here, even with DO',
    n =>
      raw(n, {
        name: encodeName('home.arpa'),
        type: 2,
        ar: 1,
        tail: opt({flags: 0x8000}),
      }),
    {http: 200, rcode: RCODE.NXDOMAIN, upstream: false, opt: true},
  ],
  ['QTYPE IXFR', n => raw(n, {type: 251}), local(RCODE.NOTIMP)],
  ['QTYPE AXFR', n => raw(n, {type: 252}), local(RCODE.NOTIMP)],
  ['QTYPE MAILB', n => raw(n, {type: 253}), local(RCODE.NOTIMP)],
  ['QTYPE MAILA', n => raw(n, {type: 254}), local(RCODE.NOTIMP)],
  ['QTYPE TSIG', n => raw(n, {type: 250}), local(RCODE.FORMERR)],
  ['QTYPE TKEY', n => raw(n, {type: 249}), local(RCODE.FORMERR)],
  ['QTYPE OPT', n => raw(n, {type: T.OPT}), local(RCODE.FORMERR)],
  ['QTYPE 65535 is forwarded', n => raw(n, {type: 65535}), answered],
  ['an unassigned QTYPE is forwarded', n => raw(n, {type: 1234}), answered],

  // Classes.
  ['QCLASS CH', n => raw(n, {cls: 3}), local(RCODE.REFUSED)],
  ['QCLASS HS', n => raw(n, {cls: 4}), local(RCODE.REFUSED)],
  ['QCLASS NONE', n => raw(n, {cls: 254}), local(RCODE.REFUSED)],
  ['QCLASS ANY', n => raw(n, {cls: 255}), local(RCODE.REFUSED)],
  ['QCLASS 0', n => raw(n, {cls: 0}), local(RCODE.REFUSED)],

  // Names.
  ['the root name', n => raw(n, {name: [0]}), answered],
  [
    'a name in mixed case comes back as it was written (RFC 4343)',
    n => raw(n, {name: encodeName(`C${n}.InPuTs.ExAmPlE.CoM`)}),
    answered,
  ],
  [
    'a label of 63 octets',
    n => raw(n, {name: encodeName(`${label('a', 63)}.c${n}.example.com`)}),
    answered,
  ],
  [
    'a label of 64 octets',
    n => raw(n, {name: [64, ...Array(64).fill(97), 0]}),
    {http: 400},
  ],
  [
    'a name of 253 characters',
    n =>
      raw(n, {
        name: encodeName(
          [
            label('a', 61),
            label('b', 61),
            label('c', 61),
            `d${n}`.padEnd(61, 'd'),
            'e'.repeat(5),
          ].join('.')
        ),
      }),
    answered,
  ],
  [
    'a name over 255 octets',
    n =>
      raw(n, {
        name: encodeName(
          [label('a', 63), label('b', 63), label('c', 63), label('d', 63)].join(
            '.'
          )
        ),
      }),
    {http: 400},
  ],
  [
    'a compression pointer in the question',
    n => raw(n, {name: [0xc0, 12]}),
    {http: 400},
  ],
  [
    'underscore, NUL and high bytes in a label',
    n =>
      raw(n, {
        name: [
          5,
          0x5f,
          0x00,
          0xff,
          0x41,
          0x7a,
          1,
          0x30 + (n % 10),
          3,
          99,
          111,
          109,
          0,
        ],
      }),
    answered,
  ],

  // EDNS.
  ['EDNS version 0', n => raw(n, withOpt()), {...answered, opt: true}],
  [
    'EDNS version 1 is BADVERS',
    n => raw(n, {ar: 1, tail: opt({version: 1})}),
    {...local(RCODE.BADVERS), opt: true},
  ],
  [
    'EDNS version 255 is BADVERS',
    n => raw(n, {ar: 1, tail: opt({version: 255})}),
    {...local(RCODE.BADVERS), opt: true},
  ],
  [
    'EDNS with DO',
    n => raw(n, {ar: 1, tail: opt({flags: 0x8000})}),
    {...answered, opt: true},
  ],
  [
    'EDNS with unknown flag bits',
    n => raw(n, {ar: 1, tail: opt({flags: 0x7fff})}),
    {...answered, opt: true},
  ],
  [
    'an unknown EDNS option is ignored',
    n => raw(n, withOpt(option(65001, [1, 2, 3]))),
    {...answered, opt: true},
  ],
  [
    'padding',
    n => raw(n, withOpt(option(12, Array(10).fill(0)))),
    {...answered, opt: true},
  ],
  [
    'two OPT records',
    n => raw(n, {ar: 2, tail: [...opt(), ...opt()]}),
    local(RCODE.FORMERR),
  ],
  [
    'an OPT record not owned by the root',
    n => raw(n, {ar: 1, tail: opt({owner: [1, 97, 0]})}),
    local(RCODE.FORMERR),
  ],
  [
    'an OPT RDLENGTH past the message',
    n => raw(n, {ar: 1, tail: opt({rdlength: 20})}),
    local(RCODE.FORMERR),
  ],
  [
    'an option that overruns the RDATA',
    n => raw(n, {ar: 1, tail: opt({options: [0, 10, 0, 9, 1], rdlength: 5})}),
    local(RCODE.FORMERR),
  ],

  // Cookies (RFC 7873 5.2.2: 8, or 16 to 40 bytes).
  ['a cookie of 7 bytes', n => raw(n, cookie(7)), local(RCODE.FORMERR)],
  ['a cookie of 8 bytes', n => raw(n, cookie(8)), answered],
  ['a cookie of 16 bytes', n => raw(n, cookie(16)), answered],
  ['a cookie of 40 bytes', n => raw(n, cookie(40)), answered],
  ['a cookie of 41 bytes', n => raw(n, cookie(41)), local(RCODE.FORMERR)],

  // Client subnet. A malformed one is FORMERR; a scope in a query is not checked.
  [
    'ECS IPv4 /24',
    n => raw(n, ecs([0, 1, 24, 0, 192, 0, 2])),
    {...answered, opt: true},
  ],
  [
    'ECS IPv6 /48',
    n => raw(n, ecs([0, 2, 48, 0, 0x20, 1, 0xd, 0xb8, 0, 1])),
    {...answered, opt: true},
  ],
  [
    'ECS source prefix 0',
    n => raw(n, ecs([0, 1, 0, 0])),
    {...answered, opt: true},
  ],
  [
    'ECS of an unknown family is FORMERR (RFC 7871 7.2.1)',
    n => raw(n, ecs([0, 3, 24, 0, 1, 2, 3])),
    local(RCODE.FORMERR),
  ],
  [
    'ECS prefix longer than the family is FORMERR',
    n => raw(n, ecs([0, 1, 33, 0, 1, 2, 3, 4, 5])),
    local(RCODE.FORMERR),
  ],
  [
    'ECS address shorter than its prefix is FORMERR (RFC 7871 6)',
    n => raw(n, ecs([0, 1, 24, 0, 192, 0])),
    local(RCODE.FORMERR),
  ],
  [
    'ECS address longer than its prefix is FORMERR (RFC 7871 6)',
    n => raw(n, ecs([0, 1, 24, 0, 192, 0, 2, 7])),
    local(RCODE.FORMERR),
  ],
  [
    'ECS with bits set past its prefix is FORMERR (RFC 7871 6)',
    n => raw(n, ecs([0, 1, 20, 0, 192, 0, 0xff])),
    local(RCODE.FORMERR),
  ],
  [
    'ECS with a non-zero scope in a query is accepted',
    n => raw(n, ecs([0, 1, 24, 16, 192, 0, 2])),
    answered,
  ],
];

let upstream: ReturnType<typeof mockUpstream>;
beforeEach(() => {
  resetState();
  upstream = mockUpstream(q =>
    makeResponse({
      qname: q.question[0].name,
      qtype: q.question[0].type,
      answer: [{type: T.A, ttl: 120, rdata: ip4('192.0.2.9')}],
    })
  );
});
afterEach(() => upstream.restore());

const post = (body: Uint8Array) =>
  handle(
    new Request('https://dns.test/dns-query', {
      method: 'POST',
      headers: {'content-type': 'application/dns-message'},
      body: body as never,
    }),
    ctx
  );
const get = (body: Uint8Array) =>
  handle(
    new Request(
      `https://dns.test/dns-query?dns=${Buffer.from(body).toString('base64url')}`
    ),
    ctx
  );

/** @return Where the question of a query ends (no name compression). */
function questionEnd(query: Uint8Array): number {
  let at = 12;
  while (query[at] !== 0) {
    at += query[at] + 1;
  }
  return at + 1 + 4;
}

/**
 * What every DNS answer has in common, whatever the question: the id, QR, the
 * opcode and RD of the query, the question back byte for byte (so with its
 * case, RFC 4343) if it holds one.
 */
function checkAnswer(query: Uint8Array, body: Uint8Array): void {
  const m = parseMsg(body); // Throws if it is not well formed.
  assert.equal((body[0] << 8) | body[1], ID, 'id');
  assert.equal(body[2] >> 7, 1, 'QR');
  assert.equal((body[2] >> 3) & 15, (query[2] >> 3) & 15, 'opcode');
  assert.equal(body[2] & 1, query[2] & 1, 'RD');
  if (m.question.length === 1) {
    const end = questionEnd(query);
    assert.deepEqual(body.slice(12, end), query.slice(12, end), 'the question');
  }
}

describe('what each kind of input gets back', () => {
  for (const [index, [description, make, expected]] of inputs.entries()) {
    for (const [method, send] of [
      ['POST', post],
      ['GET', get],
    ] as const) {
      test(`${description} (${method})`, async () => {
        const query = make(index);
        const res = await send(query);
        assert.equal(res.status, expected.http, 'HTTP status');
        if (expected.http === 200) {
          assert.equal(
            res.headers.get('content-type'),
            'application/dns-message'
          );
          const body = new Uint8Array(await res.arrayBuffer());
          const m = parseMsg(body);
          assert.equal(m.rcode, expected.rcode, 'rcode');
          assert.equal(
            upstream.calls.length > 0,
            expected.upstream,
            'goes to the upstream'
          );
          if (expected.opt !== undefined) {
            assert.equal(
              m.opt !== undefined && m.opt !== null,
              expected.opt,
              'OPT'
            );
          }
          checkAnswer(query, body);
        } else {
          assert.equal(upstream.calls.length, 0, 'nothing is sent upstream');
        }
      });
    }
  }
});

describe('a query cut at every byte', () => {
  const full = raw(0, {
    ar: 1,
    tail: opt({
      options: [
        ...option(8, [0, 1, 24, 0, 192, 0, 2]),
        ...option(10, Array(8).fill(1)),
        ...option(12, Array(5).fill(0)),
      ],
    }),
  });
  const questionEnd = 12 + encodeName('c0.inputs.example.com').length + 4;

  for (const [method, send] of [
    ['POST', post],
    ['GET', get],
  ] as const) {
    test(`is never a server error, and always answered the same way (${method})`, async () => {
      for (let length = 0; length <= full.length; length++) {
        const res = await send(full.slice(0, length));
        const where = `${method} cut at ${length} of ${full.length}`;
        if (length < questionEnd) {
          assert.equal(res.status, 400, where); // No question to answer.
        } else if (length < full.length) {
          assert.equal(res.status, 200, where);
          const m = parseMsg(new Uint8Array(await res.arrayBuffer()));
          assert.equal(m.rcode, RCODE.FORMERR, where); // The record is cut.
        } else {
          assert.equal(res.status, 200, where);
          const m = parseMsg(new Uint8Array(await res.arrayBuffer()));
          assert.equal(m.rcode, RCODE.NOERROR, where);
        }
      }
    });
  }
});
