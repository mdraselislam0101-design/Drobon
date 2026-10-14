import { describe, expect, test } from 'vitest';
import {
  extractRefererOrigin,
  isAllowedOrigin,
  isValidRequestId,
  normalizeOrigin,
} from '../src/lib/security.js';

describe('isValidRequestId', () => {
  test.each([
    ['abc-123_XYZ.~', true],
    ['x'.repeat(128), true],
    ['', false],
    ['x'.repeat(129), false],
    ['has space', false],
    ['line\nbreak', false],
    ['<script>', false],
    ['semi;colon', false],
    ['quote"q', false],
  ])('isValidRequestId(%j) === %s', (value, expected) => {
    expect(isValidRequestId(value)).toBe(expected);
  });
});

describe('normalizeOrigin', () => {
  test.each([
    ['https://app.example.test', 'https://app.example.test'],
    ['https://app.example.test/', 'https://app.example.test'],
    ['HTTPS://APP.EXAMPLE.TEST', 'https://app.example.test'],
    ['http://127.0.0.1:5173', 'http://127.0.0.1:5173'],
  ])('normalizeOrigin(%j) === %j', (value, expected) => {
    expect(normalizeOrigin(value)).toBe(expected);
  });

  test.each([
    [''],
    ['   '],
    ['not a url'],
    ['https://evil.test/path'],
    ['https://evil.test/?q=1'],
    ['https://evil.test/#hash'],
    ['https://user@evil.test'],
    ['https://user:pass@evil.test'],
    ['ftp://evil.test'],
    ['null'],
    ['https://evil.test extra'],
  ])('normalizeOrigin(%j) is rejected', (value) => {
    expect(normalizeOrigin(value)).toBeUndefined();
  });
});

describe('isAllowedOrigin', () => {
  const allowlist = ['https://app.example.test', 'http://127.0.0.1:5173'];

  test.each([
    'https://app.example.test',
    'https://app.example.test/',
    'HTTPS://APP.EXAMPLE.TEST',
    'http://127.0.0.1:5173',
  ])('allows %j', (origin) => {
    expect(isAllowedOrigin(origin, allowlist)).toBe(true);
  });

  test.each([
    'https://app.example.test.evil.test',
    'https://evil-app.example.test',
    'https://app.example.test:443.evil.test',
    'http://app.example.test',
    'https://app.example.test:8443',
    'https://127.0.0.1:5173',
    'http://127.0.0.1:5174',
    'https://user@app.example.test',
    'null',
    '',
  ])('rejects %j', (origin) => {
    expect(isAllowedOrigin(origin, allowlist)).toBe(false);
  });

  test('rejects everything when the allowlist is empty', () => {
    expect(isAllowedOrigin('https://app.example.test', [])).toBe(false);
  });
});

describe('extractRefererOrigin', () => {
  test.each([
    ['https://app.example.test/account?tab=security#top', 'https://app.example.test'],
    ['http://127.0.0.1:5173/projects/prj_1', 'http://127.0.0.1:5173'],
  ])('extractRefererOrigin(%j) === %j', (value, expected) => {
    expect(extractRefererOrigin(value)).toBe(expected);
  });

  test.each([
    [''],
    ['not-a-url'],
    ['ftp://app.example.test/page'],
    ['https://user:pass@app.example.test/page'],
    ['https://app.example.test/page extra'],
  ])('extractRefererOrigin(%j) is rejected', (value) => {
    expect(extractRefererOrigin(value)).toBeUndefined();
  });
});
