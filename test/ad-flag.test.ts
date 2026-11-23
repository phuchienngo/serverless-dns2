/**
 * The AD flag claims that the data was validated (RFC 4035 3.2.3), so an
 * answer that this gateway changes must not carry it: the ECH key added to an
 * HTTPS record is not part of what the upstream validated.
 */

import assert from 'node:assert/strict';
import {afterEach, beforeEach, describe, test} from 'node:test';
import {ECH_FRONT_DOMAIN} from '../src/config.js';
import {loadCloudflareRanges} from '../src/cloudflare-ips.js';
import {parseQuestion} from '../src/query.js';
import {resolve} from '../src/resolve.js';
import {
  T,
  ip4,
  makeQuery,
  makeResponse,
  mockUpstream,
  parseMsg,
  plainOptions,
  resetState,
} from './helpers.js';

const ECH_CONFIG = [0, 0x45, 0xfe, 0x0d, 1, 2, 3, 4];
const FLAG_AD = 0x20;

let upstream: ReturnType<typeof mockUpstream>;
beforeEach(() => {
  resetState();
  loadCloudflareRanges({v4: ['104.16.0.0/13']});
  // Every answer is validated, as far as the upstream says.
  upstream = mockUpstream(q => {
    const {name, type} = q.question[0];
    const base = {qname: name, qtype: type, opt: {do: q.opt?.do}};
    let body: Uint8Array;
    if (type === T.A) {
      body = makeResponse({
        ...base,
        answer: [
          {
            type: T.A,
            ttl: 60,
            rdata: ip4(name.startsWith('cf') ? '104.16.0.5' : '192.0.2.5'),
          },
        ],
      });
    } else if (type === T.HTTPS && name === `${ECH_FRONT_DOMAIN}.`) {
      const rdata = [0, 1, 0, 0, 5, 0, ECH_CONFIG.length, ...ECH_CONFIG];
      body = makeResponse({
        ...base,
        answer: [{type: T.HTTPS, ttl: 300, rdata}],
      });
    } else if (type === T.HTTPS) {
      body = makeResponse({
        ...base,
        answer: [
          {
            type: T.HTTPS,
            ttl: 300,
            rdata: [0, 1, 0, 0, 1, 0, 3, 2, 0x68, 0x32],
          },
        ],
      });
    } else {
      body = makeResponse(base);
    }
    body[3] |= FLAG_AD;
    return body;
  });
});
afterEach(() => upstream.restore());

async function ask(name: string, ad: boolean) {
  const q = parseQuestion(makeQuery(name, T.HTTPS, {ad}));
  return parseMsg((await resolve(q, plainOptions())).body);
}

describe('AD on an HTTPS answer', () => {
  test('is kept when the answer is not changed', async () => {
    const msg = await ask('other.example.com', true);
    assert.equal(msg.ad, true);
    assert.equal(msg.answer.length, 1);
  });

  test('is dropped when the ECH key is added to it', async () => {
    const msg = await ask('cf-site.example.com', true);
    assert.ok(
      Buffer.from(msg.answer[0].rdata).includes(Buffer.from(ECH_CONFIG)),
      'the ECH key was added'
    );
    assert.equal(msg.ad, false);
  });
});
