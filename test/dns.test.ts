/**
 * RFC 1035 (messages), RFC 2308 (negative answers), RFC 6891 (EDNS0),
 * RFC 3225/4035 (DO), RFC 7830/8467 (padding), RFC 8914 (EDE).
 */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {EDE_BLOCKED} from '../src/constants.js';
import {
  addOptOption,
  buildQuery,
  cnameTargets,
  copyRd,
  edeOption,
  encodeName,
  lowerAscii,
  minTtl,
  padResponse,
  alpnValue,
  makeQuestion,
  optOptions,
  rcodeOf,
  svcbRdata,
  makeRecord,
  parseAdditional,
  readRecords,
  parseAnswers,
  removeOptOption,
  parseAuthority,
  parseQuestion,
  readName,
  respond,
  respondNegative,
  skipName,
  stripOpt,
} from '../src/dns.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  mxRdata,
  nameBytes,
  nameRdata,
  parseMsg,
  soaRdata,
} from './helpers.js';

const q = (name: string, type: number, o = {}) =>
  parseQuestion(makeQuery(name, type, o));

describe('parseQuestion (RFC 1035 4.1)', () => {
  test('reads name, type and the id', () => {
    const question = q('www.Example.COM', T.AAAA, {id: 0xbeef});
    assert.equal(question.id, 0xbeef);
    assert.equal(question.name, 'www.example.com');
    assert.equal(question.type, T.AAAA);
  });

  test('keeps the original case in `raw` (RFC 4343, 0x20 encoding)', () => {
    const question = q('ExAmPlE.CoM', T.A);
    const raw = Buffer.from(question.raw).toString('latin1');
    assert.ok(raw.includes('ExAmPlE'));
    assert.ok(raw.includes('CoM'));
    assert.equal(question.name, 'example.com');
  });

  test('reads the header flags', () => {
    const question = q('a.test', T.A, {
      rd: false,
      opcode: 4,
      cd: true,
      ad: true,
    });
    assert.equal(question.rd, false);
    assert.equal(question.opcode, 4);
    assert.equal(question.cd, true);
    assert.equal(question.ad, true);
    assert.equal(q('a.test', T.A).rd, true);
  });

  test('reads EDNS: presence, DO bit, version and padding', () => {
    const none = q('a.test', T.A, {edns: false});
    assert.equal(none.edns, false);
    assert.equal(none.dnssecOk, false);
    assert.equal(none.ednsVersion, 0);
    assert.equal(none.padding, false);

    const plain = q('a.test', T.A);
    assert.equal(plain.edns, true);
    assert.equal(plain.dnssecOk, false);

    assert.equal(q('a.test', T.A, {do: true}).dnssecOk, true);
    assert.equal(q('a.test', T.A, {ednsVersion: 1}).ednsVersion, 1);
    assert.equal(q('a.test', T.A, {padding: 20}).padding, true);
  });

  test('finds the OPT record after other options', () => {
    const question = q('a.test', T.A, {
      ecs: {family: 1, prefix: 24, address: [1, 2, 3]},
      padding: 8,
    });
    assert.equal(question.padding, true);
  });

  test('rejects what is not a single-question query', () => {
    const good = makeQuery('a.test', T.A);
    const response = Uint8Array.from(good);
    response[2] |= 0x80; // QR
    assert.throws(() => parseQuestion(response));

    for (const count of [0, 2]) {
      const bad = Uint8Array.from(good);
      bad[5] = count; // QDCOUNT
      assert.throws(() => parseQuestion(bad), `qdcount ${count}`);
    }
    assert.throws(() => parseQuestion(good.subarray(0, 12)), 'too short');
    assert.throws(() => parseQuestion(new Uint8Array(513)), 'too long');
  });

  test('limits a name to 255 octets on the wire (RFC 1035 2.3.4)', () => {
    const label = (c: string, n: number) => c.repeat(n);
    const name = (last: number) =>
      [label('a', 63), label('b', 63), label('c', 63), label('d', last)].join(
        '.'
      );
    assert.equal(q(name(61), T.A).type, T.A, '255 octets');
    assert.throws(() => q(name(62), T.A), '256 octets');
  });

  test('rejects compressed, over-long and truncated names', () => {
    const compressed = Uint8Array.from(makeQuery('a.test', T.A));
    compressed[12] = 0xc0;
    assert.throws(() => parseQuestion(compressed));

    const longLabel = makeQuery('a'.repeat(64) + '.test', T.A);
    assert.throws(() => parseQuestion(longLabel));

    const good = makeQuery('a.test', T.A, {edns: false});
    assert.throws(() => parseQuestion(good.subarray(0, good.length - 3)));
  });

  test('flags an invalid OPT record as malformed (RFC 6891 6.1.1)', () => {
    const base = makeQuery('a.test', T.A);
    const at = base.length - 11; // The OPT record has no options here.
    assert.equal(parseQuestion(base).malformed, false);
    assert.equal(q('a.test', T.A, {padding: 8, do: true}).malformed, false);
    assert.equal(q('a.test', T.A, {edns: false}).malformed, false);

    const two = Uint8Array.from([...base, ...base.subarray(at)]);
    two[11] = 2;
    assert.equal(parseQuestion(two).malformed, true, 'two OPT records');

    const named = Uint8Array.from([
      ...base.subarray(0, at),
      1,
      97,
      0,
      ...base.subarray(at + 1),
    ]);
    assert.equal(parseQuestion(named).malformed, true, 'owner is not the root');

    const overrun = Uint8Array.from(base);
    overrun[overrun.length - 1] = 50;
    assert.equal(parseQuestion(overrun).malformed, true, 'RDLEN past the end');

    const odd = Uint8Array.from(makeQuery('a.test', T.A, {padding: 8}));
    odd[odd.length - 13] += 1; // The padding option claims one byte more.
    assert.equal(parseQuestion(odd).malformed, true, 'option overruns RDATA');
  });

  test('reads the EDNS Cookie option, and a bad length is malformed (RFC 7873 5.2.2)', () => {
    assert.equal(q('a.test', T.A).cookie, null);
    assert.equal(q('a.test', T.A, {edns: false}).cookie, null);
    const eight = [1, 2, 3, 4, 5, 6, 7, 8];
    const parsed = q('a.test', T.A, {cookie: eight});
    assert.deepEqual(parsed.cookie, eight);
    assert.equal(parsed.malformed, false);
    for (const length of [16, 24, 40]) {
      const ok = q('a.test', T.A, {cookie: new Array(length).fill(1)});
      assert.equal(ok.malformed, false, `length ${length}`);
    }
    for (const length of [0, 1, 7, 9, 15, 41]) {
      const bad = q('a.test', T.A, {cookie: new Array(length).fill(1)});
      assert.equal(bad.malformed, true, `length ${length}`);
    }
  });

  test('ignores a damaged additional section (treated as no EDNS)', () => {
    const wire = Uint8Array.from(makeQuery('a.test', T.A, {edns: false}));
    wire[11] = 3; // ARCOUNT says 3 records, there are none
    const parsed = parseQuestion(wire);
    assert.equal(parsed.edns, false);
    assert.equal(parsed.malformed, true, 'records that do not parse');
  });
});

describe('respond (RFC 1035 4.1.1, RFC 6891)', () => {
  test('answers with the id, question and flags of the query', () => {
    const question = q('a.test', T.A, {id: 77, rd: false});
    const m = parseMsg(respond(question, 3, []));
    assert.equal(m.id, 77);
    assert.equal(m.qr, true);
    assert.equal(m.ra, true);
    assert.equal(m.aa, false);
    assert.equal(m.rd, false, 'RD is copied from the query');
    assert.equal(m.rcode, 3);
    assert.deepEqual(m.question, [{name: 'a.test.', type: T.A, cls: 1}]);
    assert.equal(parseMsg(respond(q('a.test', T.A), 0, [])).rd, true);
  });

  test('echoes CD, and never sets AD', () => {
    const m = parseMsg(respond(q('a.test', T.A, {cd: true, ad: true}), 0, []));
    assert.equal(m.cd, true);
    assert.equal(m.ad, false);
    assert.equal(parseMsg(respond(q('a.test', T.A), 0, [])).cd, false);
  });

  test('echoes the opcode', () => {
    assert.equal(
      parseMsg(respond(q('a.test', T.A, {opcode: 4}), 4, [])).opcode,
      4
    );
  });

  test('carries answer records', () => {
    const record = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip4('9.8.7.6')];
    const m = parseMsg(respond(q('a.test', T.A), 0, [record]));
    assert.equal(m.answer.length, 1);
    assert.equal(m.answer[0].name, 'a.test.');
    assert.deepEqual([...m.answer[0].rdata], ip4('9.8.7.6'));
  });

  test('has an OPT record only if the query had one (RFC 6891 7)', () => {
    assert.ok(parseMsg(respond(q('a.test', T.A), 0, [])).opt);
    assert.equal(
      parseMsg(respond(q('a.test', T.A, {edns: false}), 0, [])).opt,
      undefined
    );
  });

  test('copies the DO bit into the OPT record', () => {
    assert.equal(
      parseMsg(respond(q('a.test', T.A, {do: true}), 0, [])).opt?.do,
      true
    );
    assert.equal(parseMsg(respond(q('a.test', T.A), 0, [])).opt?.do, false);
  });

  test('puts the upper bits of an extended rcode in OPT (BADVERS)', () => {
    const m = parseMsg(respond(q('a.test', T.A, {ednsVersion: 1}), 16, []));
    assert.equal(m.rcode, 16);
    assert.equal(m.opt?.extRcode, 1);
    assert.equal(m.opt?.version, 0, 'answers with the version it supports');
  });

  test('attaches an Extended DNS Error (RFC 8914)', () => {
    const m = parseMsg(
      respond(q('a.test', T.A), 3, [], {code: EDE_BLOCKED, text: 'why'})
    );
    const [option] = m.opt!.options;
    assert.equal(option.code, 15);
    assert.deepEqual([...option.data.subarray(0, 2)], [0, EDE_BLOCKED]);
    assert.equal(Buffer.from(option.data.subarray(2)).toString(), 'why');
  });

  test('sends no EDE to a client without EDNS', () => {
    const m = parseMsg(
      respond(q('a.test', T.A, {edns: false}), 3, [], {code: 15, text: 'x'})
    );
    assert.equal(m.opt, undefined);
    assert.equal(m.additional.length, 0);
  });
});

describe('respondNegative (RFC 2308)', () => {
  test('adds a SOA to the authority section, owned by the query name', () => {
    const m = parseMsg(respondNegative(q('gone.test', T.A), 3, 300));
    assert.equal(m.rcode, 3);
    assert.equal(m.answer.length, 0);
    assert.equal(m.authority.length, 1);
    const soa = m.authority[0];
    assert.equal(soa.type, T.SOA);
    assert.equal(soa.name, 'gone.test.');
    assert.equal(soa.ttl, 300);
    // The last four bytes of SOA rdata are MINIMUM, the negative-cache TTL.
    const minimum = new DataView(
      soa.rdata.buffer,
      soa.rdata.byteOffset
    ).getUint32(soa.rdata.length - 4);
    assert.equal(minimum, 300);
  });

  test('works for NODATA (NOERROR with an empty answer)', () => {
    const m = parseMsg(respondNegative(q('a.test', T.TXT), 0, 3600));
    assert.equal(m.rcode, 0);
    assert.equal(m.answer.length, 0);
    assert.equal(m.authority[0].ttl, 3600);
  });

  test('gives clients a TTL they can use for negative caching', () => {
    const body = respondNegative(q('a.test', T.A), 3, 120);
    assert.equal(minTtl(body), 120);
  });

  test('has no OPT for a client without EDNS, and the EDE for one with', () => {
    assert.equal(
      parseMsg(respondNegative(q('a.test', T.A, {edns: false}), 3, 60)).opt,
      undefined
    );
    const m = parseMsg(
      respondNegative(q('a.test', T.A), 3, 60, {code: 15, text: 'blocklist'})
    );
    assert.equal(m.opt?.options[0].code, 15);
  });
});

describe('OPT record editing', () => {
  const upstream = () =>
    makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 30, rdata: ip4('1.1.1.1')}],
    });

  test('stripOpt removes the OPT record and fixes the counts', () => {
    const stripped = stripOpt(upstream());
    const m = parseMsg(stripped); // also checks there are no trailing bytes
    assert.equal(m.additional.length, 0);
    assert.equal(m.optCount, 0);
    assert.equal(m.answer.length, 1);
    assert.ok(stripped.length < upstream().length);
  });

  test('stripOpt keeps other additional records', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.MX,
      answer: [{type: T.MX, ttl: 30, rdata: mxRdata(10, 'mail.a.test')}],
      additional: [
        {name: 'mail.a.test', type: T.A, ttl: 30, rdata: ip4('5.6.7.8')},
      ],
    });
    assert.equal(parseMsg(body).additional.length, 2);
    const m = parseMsg(stripOpt(body));
    assert.equal(m.optCount, 0);
    assert.equal(m.additional.length, 1);
    assert.equal(m.additional[0].type, T.A);
    assert.equal(m.answer.length, 1);
  });

  test('stripOpt leaves a message without OPT (or garbage) alone', () => {
    const noOpt = makeResponse({qname: 'a.test', qtype: T.A, opt: false});
    assert.deepEqual(stripOpt(noOpt), noOpt);
    const garbage = new Uint8Array([1, 2, 3]);
    assert.deepEqual(stripOpt(garbage), garbage);
  });

  test('addOptOption appends an option and grows RDLENGTH', () => {
    const out = addOptOption(upstream(), edeOption(3, 'stale'));
    const m = parseMsg(out);
    assert.equal(m.opt!.options.length, 1);
    assert.equal(m.opt!.options[0].code, 15);
    assert.equal(m.answer.length, 1);
  });

  test('addOptOption leaves a message without OPT alone', () => {
    const noOpt = makeResponse({qname: 'a.test', qtype: T.A, opt: false});
    assert.deepEqual(addOptOption(noOpt, edeOption(3, '')), noOpt);
  });

  test('padResponse pads to a multiple of 468 bytes (RFC 8467 4.1)', () => {
    for (let n = 1; n < 40; n++) {
      const body = makeResponse({qname: `${'x'.repeat(n)}.test`, qtype: T.A});
      const padded = padResponse(body);
      assert.equal(padded.length % 468, 0, `length ${body.length}`);
      assert.ok(padded.length >= body.length);
      assert.ok(padded.length - body.length < 468 + 4);
      const m = parseMsg(padded);
      assert.equal(m.opt!.options.at(-1)!.code, 12);
      assert.ok(m.opt!.options.at(-1)!.data.every(b => b === 0));
    }
  });

  test('padResponse of a response without OPT changes nothing', () => {
    const noOpt = makeResponse({qname: 'a.test', qtype: T.A, opt: false});
    assert.deepEqual(padResponse(noOpt), noOpt);
  });

  test('copyRd sets RD without touching the input', () => {
    const rd1 = makeResponse({qname: 'a.test', qtype: T.A, rd: true});
    const rd0 = copyRd(rd1, false);
    assert.equal(parseMsg(rd0).rd, false);
    assert.equal(parseMsg(rd1).rd, true);
    assert.equal(copyRd(rd1, true), rd1, 'same object when nothing changes');
    assert.equal(parseMsg(rd0).ra, true, 'other flags are kept');
  });
});

describe('buildQuery (query sent to the upstream)', () => {
  const question = q('a.test', T.A).raw;

  test('asks recursion with one question and one OPT record', () => {
    const m = parseMsg(buildQuery(question, null));
    assert.equal(m.rd, true);
    assert.equal(m.question.length, 1);
    assert.equal(m.optCount, 1);
    assert.equal(m.opt!.udp, 4096);
    assert.equal(m.opt!.do, false);
  });

  test('sets DO, CD and AD on request', () => {
    const m = parseMsg(
      buildQuery(question, null, {dnssec: true, cd: true, ad: true})
    );
    assert.equal(m.opt!.do, true);
    assert.equal(m.cd, true);
    assert.equal(m.ad, true);
    const plain = parseMsg(buildQuery(question, null));
    assert.equal(plain.cd, false);
    assert.equal(plain.ad, false);
  });

  test('carries a client-subnet option', () => {
    const option = [0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3];
    const m = parseMsg(buildQuery(question, option));
    assert.deepEqual(
      m.opt!.options.map(o => o.code),
      [8]
    );
  });
});

describe('name and record helpers', () => {
  test('encodeName / lowerAscii', () => {
    assert.deepEqual(encodeName('a.bc'), [1, 97, 2, 98, 99, 0]);
    assert.deepEqual(encodeName('a.bc.'), encodeName('a.bc'));
    assert.deepEqual(encodeName('.'), [0]);
    assert.equal(lowerAscii('ExAmPlE-ÄÖ'), 'example-ÄÖ', 'ASCII only');
  });

  test('readName / skipName follow compression pointers', () => {
    const b = new Uint8Array([
      ...nameBytes('www.example.com'), // offset 0, 17 bytes
      3,
      102,
      116,
      112,
      0xc0,
      4, // "ftp" then pointer to "example.com"
    ]);
    const second = readName(b, 17);
    assert.equal(second.name, 'ftp.example.com.');
    assert.equal(second.next, 23);
    assert.equal(skipName(b, 17), 23);
  });

  test('readName rejects a pointer loop', () => {
    assert.throws(() => readName(new Uint8Array([0xc0, 0]), 0));
  });

  test('parseAnswers and parseAuthority list the right section', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [
        {type: T.A, ttl: 100, rdata: ip4('1.1.1.1')},
        {type: T.A, ttl: 50, rdata: ip4('2.2.2.2')},
      ],
      authority: [{type: T.SOA, ttl: 900, rdata: soaRdata(900)}],
    });
    const view = new DataView(body.buffer);
    const answers = parseAnswers(body);
    assert.deepEqual(
      answers.map(a => [a.type, a.ttl, a.length]),
      [
        [T.A, 100, 4],
        [T.A, 50, 4],
      ]
    );
    assert.equal(
      view.getUint16(answers[0].start),
      T.A,
      'start is the TYPE field'
    );
    const authority = parseAuthority(body);
    assert.deepEqual(
      authority.map(a => [a.type, a.ttl]),
      [[T.SOA, 900]]
    );
  });

  test('parseAnswers throws on a record that runs past the message', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 1, rdata: ip4('1.1.1.1')}],
    });
    assert.throws(() => parseAnswers(body.subarray(0, 38)));
  });

  test('cnameTargets lists lower-case targets without the final dot', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [
        {type: T.CNAME, ttl: 60, rdata: nameRdata('Mid.Example.NET')},
        {
          name: 'mid.example.net',
          type: T.CNAME,
          ttl: 60,
          rdata: nameRdata('end.tracker.io'),
        },
        {name: 'end.tracker.io', type: T.A, ttl: 60, rdata: ip4('1.1.1.1')},
      ],
    });
    assert.deepEqual(cnameTargets(body), ['mid.example.net', 'end.tracker.io']);
    assert.deepEqual(cnameTargets(new Uint8Array([1, 2, 3])), []);
  });
});

describe('minTtl (RFC 2181 5.2, RFC 2308 5)', () => {
  const answer = (...ttls: number[]) =>
    makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: ttls.map(ttl => ({type: T.A, ttl, rdata: ip4('1.1.1.1')})),
    });

  test('is the smallest answer TTL', () => {
    assert.equal(minTtl(answer(300, 20, 100)), 20);
  });

  test('is capped at an hour', () => {
    assert.equal(minTtl(answer(86400)), 3600);
  });

  test('uses the smaller of the SOA TTL and MINIMUM for negative answers', () => {
    const negative = (soaTtl: number, minimum: number) =>
      makeResponse({
        qname: 'a.test',
        qtype: T.A,
        rcode: 3,
        authority: [
          {name: 'test', type: T.SOA, ttl: soaTtl, rdata: soaRdata(minimum)},
        ],
      });
    assert.equal(minTtl(negative(900, 300)), 300);
    assert.equal(minTtl(negative(100, 300)), 100);
  });

  test('is 30 without answers or SOA, or for garbage', () => {
    assert.equal(minTtl(makeResponse({qname: 'a.test', qtype: T.A})), 30);
    assert.equal(minTtl(new Uint8Array([1, 2, 3])), 30);
  });
});

describe('removeOptOption', () => {
  const withOptions = () =>
    makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 30, rdata: ip4('1.1.1.1')}],
      opt: {
        options: [
          {code: 8, data: [0, 1, 24, 24, 203, 0, 113]},
          {code: 15, data: [0, 15]},
        ],
      },
    });

  test('removes only the option with that code', () => {
    const m = parseMsg(removeOptOption(withOptions(), 8));
    assert.deepEqual(
      m.opt!.options.map(o => o.code),
      [15]
    );
    assert.equal(m.answer.length, 1);
  });

  test('leaves the message alone without that option or without OPT', () => {
    const body = withOptions();
    assert.equal(removeOptOption(body, 12), body);
    const noOpt = makeResponse({qname: 'a.test', qtype: T.A, opt: false});
    assert.equal(removeOptOption(noOpt, 8), noOpt);
    const garbage = new Uint8Array([1, 2, 3]);
    assert.equal(removeOptOption(garbage, 8), garbage);
  });

  test('can empty the OPT record', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      opt: {options: [{code: 8, data: [0, 1, 24, 0, 1, 2, 3]}]},
    });
    assert.equal(parseMsg(removeOptOption(body, 8)).opt!.options.length, 0);
  });
});

describe('parseAdditional', () => {
  test('lists additional records except OPT', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.MX,
      answer: [{type: T.MX, ttl: 30, rdata: mxRdata(10, 'mail.a.test')}],
      additional: [
        {name: 'mail.a.test', type: T.A, ttl: 77, rdata: ip4('5.6.7.8')},
      ],
    });
    assert.deepEqual(
      parseAdditional(body).map(r => [r.type, r.ttl]),
      [[T.A, 77]]
    );
  });
});

describe('readRecords', () => {
  const body = makeResponse({
    qname: 'a.test',
    qtype: T.MX,
    answer: [{type: T.MX, ttl: 30, rdata: mxRdata(10, 'mail.a.test')}],
    authority: [{name: 'test', type: T.SOA, ttl: 900, rdata: soaRdata(900)}],
    additional: [
      {name: 'mail.a.test', type: T.A, ttl: 77, rdata: ip4('5.6.7.8')},
    ],
  });

  test('lists every record with its section and offsets', () => {
    const records = readRecords(body);
    assert.deepEqual(
      records.map(r => [r.section, r.type, r.ttl]),
      [
        ['answer', T.MX, 30],
        ['authority', T.SOA, 900],
        ['additional', T.A, 77],
        ['additional', 41, 0],
      ]
    );
    for (const r of records) {
      assert.equal(r.end, r.start + 10 + r.length);
      assert.ok(r.name < r.start);
    }
    assert.equal(records.at(-1)!.end, body.length);
  });

  test('throws when a record runs past the end', () => {
    assert.throws(() => readRecords(body.subarray(0, body.length - 3)));
  });
});

describe('makeRecord and makeQuestion', () => {
  test('a record is owned by the question name, class IN', () => {
    const m = parseMsg(
      respond(q('a.test', T.A), 0, [makeRecord(T.TXT, 42, [3, 97, 98, 99])])
    );
    assert.equal(m.answer[0].name, 'a.test.');
    assert.equal(m.answer[0].type, T.TXT);
    assert.equal(m.answer[0].ttl, 42);
    assert.deepEqual([...m.answer[0].rdata], [3, 97, 98, 99]);
  });

  test('a question for the JSON API wants recursion and has no EDNS', () => {
    const question = makeQuestion('WWW.Example.com.', T.AAAA);
    assert.equal(question.name, 'www.example.com');
    assert.equal(question.type, T.AAAA);
    assert.equal(question.rd, true);
    assert.equal(question.edns, false);
    assert.deepEqual(question.raw.slice(-4), [0, T.AAAA, 0, 1]);
    assert.equal(
      parseQuestion(
        Uint8Array.from([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...question.raw])
      ).name,
      'www.example.com'
    );
  });
});

describe('SVCB helpers (RFC 9460)', () => {
  test('alpnValue prefixes every id with its length', () => {
    assert.deepEqual(alpnValue(['h2', 'h3']), [2, 104, 50, 2, 104, 51]);
    assert.deepEqual(alpnValue([]), []);
  });

  test('svcbRdata writes priority, target and params in increasing key order', () => {
    const rdata = svcbRdata(1, '.', [
      [7, [9]],
      [1, alpnValue(['h2'])],
      [5, [1, 2]],
    ]);
    assert.deepEqual(rdata, [
      0,
      1, // priority
      0, // target "."
      0,
      1,
      0,
      3,
      2,
      104,
      50, // alpn
      0,
      5,
      0,
      2,
      1,
      2, // ech
      0,
      7,
      0,
      1,
      9, // dohpath
    ]);
  });

  test('a named target is written as a name', () => {
    assert.deepEqual(svcbRdata(16, 'a.b', []), [0, 16, 1, 97, 1, 98, 0]);
  });
});

describe('message helpers', () => {
  test('rcodeOf reads the low four bits only', () => {
    const body = makeResponse({qname: 'a.test', qtype: T.A, rcode: 3});
    assert.equal(rcodeOf(body), 3);
    const extended = Uint8Array.from(body);
    extended[3] |= 0xf0; // Flag bits above the rcode.
    assert.equal(rcodeOf(extended), 3);
  });

  test('records know where their data is', () => {
    const body = makeResponse({
      qname: 'a.test',
      qtype: T.A,
      answer: [{type: T.A, ttl: 5, rdata: ip4('9.8.7.6')}],
    });
    const [record] = readRecords(body);
    assert.deepEqual(
      [...body.subarray(record.data, record.end)],
      ip4('9.8.7.6')
    );
  });

  test('makeQuestion carries the DNSSEC flags it is given', () => {
    const question = makeQuestion('a.test', T.A, {dnssecOk: true, cd: true});
    assert.equal(question.dnssecOk, true);
    assert.equal(question.cd, true);
    assert.equal(question.ad, false);
    assert.equal(makeQuestion('a.test', T.A).dnssecOk, false);
  });
});

describe('optOptions', () => {
  test('lists the options of the OPT record with their data', () => {
    const wire = makeQuery('a.test', T.A, {
      ecs: {family: 1, prefix: 24, address: [1, 2, 3]},
      padding: 4,
    });
    const options = optOptions(wire);
    assert.deepEqual(
      options.map(o => o.code),
      [8, 12]
    );
    assert.deepEqual([...options[0].data], [0, 1, 24, 0, 1, 2, 3]);
    assert.equal(options[1].data.length, 4);
  });

  test('is empty without OPT and throws when the records do not parse', () => {
    assert.deepEqual(optOptions(makeQuery('a.test', T.A, {edns: false})), []);
    const wire = makeQuery('a.test', T.A);
    assert.throws(() => optOptions(wire.subarray(0, wire.length - 4)));
  });
});
