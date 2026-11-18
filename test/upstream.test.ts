/** What is asked of the upstream (src/upstream.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {parseQuestion} from '../src/dns.js';
import {queryFlags} from '../src/upstream.js';
import {T, makeQuery} from './helpers.js';

const flags = (o: Parameters<typeof makeQuery>[2]) =>
  queryFlags(parseQuestion(makeQuery('a.test', T.A, o)));

describe('queryFlags', () => {
  test('follow the DNSSEC flags of the client question', () => {
    assert.deepEqual(flags({}), {dnssec: false, cd: false, ad: false});
    assert.deepEqual(flags({do: true}), {dnssec: true, cd: false, ad: false});
    assert.deepEqual(flags({cd: true}), {dnssec: false, cd: true, ad: false});
    assert.deepEqual(flags({ad: true}), {dnssec: false, cd: false, ad: true});
  });

  test('AD is dropped when DO is set, as DO already brings it (RFC 6840 5.7)', () => {
    assert.deepEqual(flags({do: true, ad: true}), {
      dnssec: true,
      cd: false,
      ad: false,
    });
  });
});
