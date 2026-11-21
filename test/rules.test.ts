/** Block and allow rules (src/regexlist.ts). */

import assert from 'node:assert/strict';
import {describe, test} from 'node:test';
import {
  checkPattern,
  compilePatterns,
  domainPattern,
  splitRules,
} from '../src/regexlist.js';

describe('checkPattern', () => {
  test('accepts ordinary patterns', () => {
    for (const p of [
      '^ads?[0-9]*\\.',
      '(^|\\.)telemetry-.*\\.example\\.com$',
      '^(.+[_.-])?adse?rv(er?|ice)?s?[0-9]*[_.-]',
      '^(ads|logs)\\.roku\\.com$',
      '^(ads|logs)',
      '^\\)+\\.test$',
      '^[)+*{]+\\.test$',
      'tracking',
      '^[a-z0-9-]{20,}\\.cdn\\.test$',
    ]) {
      assert.equal(checkPattern(p), null, p);
    }
  });

  test('rejects lookaround', () => {
    for (const p of ['^(?=x)a', '(?!x)a', '(?<=x)a', '(?<!x)a']) {
      assert.equal(checkPattern(p), 'lookaround', p);
    }
  });

  test('rejects backreferences', () => {
    assert.equal(checkPattern('(a)\\1'), 'backreference');
    assert.equal(checkPattern('(?<n>a)\\k<n>'), 'backreference');
  });

  test('rejects groups with unbounded or counted repetition', () => {
    for (const p of ['(a+)+$', '(a*)*', '(a+)*b', '(a{2,})+']) {
      assert.equal(checkPattern(p), 'repeated group', p);
    }
  });

  test('rejects a pattern that does not compile', () => {
    assert.match(checkPattern('(unclosed') ?? '', /./);
    assert.notEqual(checkPattern('[z-a]'), null);
  });

  for (const p of ['^(a|aa)+$', '^(\\w+\\s?)+$', '^(.*a){20}$']) {
    test(`rejects repeated group in ${p}`, () => {
      assert.equal(checkPattern(p), 'repeated group');
    });
  }
});

describe('splitRules', () => {
  test('tells /regex/ from domains', () => {
    assert.deepEqual(splitRules(['/^ads\\./', 'Tracker.TEST', '  /x/ ', '']), {
      domains: ['tracker.test'],
      patterns: ['^ads\\.', 'x'],
    });
  });

  test('a lone slash or empty pair is not a regex', () => {
    const {domains, patterns} = splitRules(['/', '//']);
    assert.deepEqual(patterns, []);
    assert.deepEqual(domains, ['/', '//']);
  });
});

describe('domainPattern', () => {
  const matches = (domain: string, name: string) =>
    new RegExp(domainPattern(domain)).test(name);

  test('matches the domain and its subdomains only', () => {
    assert.ok(matches('example.com', 'example.com'));
    assert.ok(matches('example.com', 'www.example.com'));
    assert.ok(matches('example.com', 'a.b.example.com'));
    assert.equal(matches('example.com', 'notexample.com'), false);
    assert.equal(matches('example.com', 'example.com.evil.test'), false);
    assert.equal(matches('example.com', 'com'), false);
  });

  test('treats dots and other characters literally', () => {
    assert.equal(matches('example.com', 'exampleXcom'), false);
    assert.ok(matches('a+b.test', 'a+b.test'));
    assert.equal(matches('a+b.test', 'aab.test'), false);
  });
});

describe('compilePatterns', () => {
  test('is null without patterns', () => {
    assert.equal(compilePatterns([]), null);
  });

  test('matches any of the patterns, each keeping its own anchors', () => {
    const regex = compilePatterns(['^a$', 'b'])!;
    assert.ok(regex.test('a'));
    assert.ok(regex.test('xbx'));
    assert.equal(regex.test('xa'), false);
    assert.equal(regex.test('ax'), false);
  });

  test('keeps working over repeated use (no sticky state)', () => {
    const regex = compilePatterns(['ads'])!;
    assert.ok(regex.test('ads.test'));
    assert.ok(regex.test('ads.test'));
  });
});
