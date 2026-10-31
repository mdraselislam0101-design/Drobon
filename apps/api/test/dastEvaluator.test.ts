import { describe, expect, test } from 'vitest';
import { DAST_CHECK_TYPES, evaluatePackDastCheck } from '../src/external/evaluator.js';
import { cookieHasFlag, cookieWillBeStored } from '../src/external/setCookie.js';

const obs = (headers: Record<string, string | string[] | undefined>, extra: Record<string, unknown> = {}) => ({
  url: 'https://app.example/', status: 200, headers, ...extra,
});

describe('DAST pack evaluator parity with Drobon-Dataset', () => {
  test('the check vocabulary is closed; unknown types never match', () => {
    expect(DAST_CHECK_TYPES).toHaveLength(7);
    expect(evaluatePackDastCheck({ type: 'invented' }, obs({}))).toBe(false);
    expect(evaluatePackDastCheck(null, obs({}))).toBe(false);
  });

  test('header names are case-insensitive and values are OWS-trimmed', () => {
    const check = { type: 'response-header-matches', header: 'X-Frame-Options', valuePattern: '^DENY$' };
    expect(evaluatePackDastCheck(check, obs({ 'x-frame-options': '  DENY  ' }))).toBe(true);
    expect(evaluatePackDastCheck(check, obs({}))).toBe(false);
  });

  test('all-blank repeated values count as a missing header (BLANK_VALUE_ARRAY)', () => {
    const check = { type: 'missing-response-header', header: 'content-security-policy' };
    expect(evaluatePackDastCheck(check, obs({ 'Content-Security-Policy': ['', '  '] }))).toBe(true);
    expect(evaluatePackDastCheck(check, obs({ 'Content-Security-Policy': ['', "default-src 'self'"] }))).toBe(false);
  });

  test('case-variant header keys are combined as separate values instead of overwriting', () => {
    const headers = { 'X-Frame-Options': 'DENY', 'x-frame-options': '' };
    expect(evaluatePackDastCheck({ type: 'missing-response-header', header: 'x-frame-options' }, obs(headers))).toBe(false);
    expect(evaluatePackDastCheck({ type: 'response-header-matches', header: 'x-frame-options', valuePattern: '^DENY$' }, obs(headers))).toBe(true);
    expect(evaluatePackDastCheck({ type: 'response-header-matches', header: 'server', valuePattern: 'nginx/1\\.0' },
      obs({ Server: 'nginx', server: '1.0' }))).toBe(false);
    expect(evaluatePackDastCheck({ type: 'cookie-missing-flag', flag: 'Secure' },
      obs({ 'Set-Cookie': 'a=1', 'set-cookie': 'b=2; Secure' }))).toBe(true);
  });

  test('a pattern never matches across a repeated-header value boundary', () => {
    const check = { type: 'response-header-matches', header: 'server', valuePattern: 'nginx/1\\.0' };
    // Joining with ', ' would create a cross-boundary substring; per-value
    // evaluation must not invent one.
    expect(evaluatePackDastCheck(check, obs({ server: ['nginx', '1.0'] }))).toBe(false);
    expect(evaluatePackDastCheck(check, obs({ server: ['nginx/1.0'] }))).toBe(true);
  });

  test('Set-Cookie uses the browser storage model (COOKIE_MODEL_ABSENT)', () => {
    expect(cookieWillBeStored('id=1')).toBe(true);
    expect(cookieWillBeStored('no-equals-sign')).toBe(false);
    expect(cookieWillBeStored('id=1; SameSite=None')).toBe(false);
    expect(cookieHasFlag('id=1; Secure=0', 'Secure')).toBe(true);
    expect(cookieHasFlag('id=1; HttpOnly=1', 'HttpOnly')).toBe(true);
    expect(cookieHasFlag('id=1; SameSite=Bogus', 'SameSite')).toBe(false);
    expect(cookieHasFlag('id=1; SameSite=Strict', 'SameSite')).toBe(true);

    const check = { type: 'cookie-missing-flag', flag: 'Secure' };
    // A discarded header stores NO cookie, so it cannot lack a flag.
    expect(evaluatePackDastCheck(check, obs({ 'set-cookie': 'no-equals-sign' }))).toBe(false);
    expect(evaluatePackDastCheck(check, obs({ 'set-cookie': 'id=1; Secure=0' }))).toBe(false);
    expect(evaluatePackDastCheck(check, obs({ 'set-cookie': 'id=1; HttpOnly' }))).toBe(true);
    expect(evaluatePackDastCheck(check, obs({}))).toBe(false);
  });

  test('requireScheme scopes header and body matches', () => {
    const check = { type: 'response-header-matches', header: 'server', valuePattern: 'apache', requireScheme: 'https' };
    expect(evaluatePackDastCheck(check, obs({ server: 'Apache' }))).toBe(true);
    expect(evaluatePackDastCheck(check, obs({ server: 'Apache' }, { url: 'http://app.example/' }))).toBe(false);
  });

  test('redirect host comparison is host-only and never throws on junk', () => {
    const check = { type: 'response-header-host-differs', header: 'location' };
    expect(evaluatePackDastCheck(check, obs({}, { status: 302 }))).toBe(false);
    expect(evaluatePackDastCheck(check, obs({ location: 'https://evil.example/' }, { status: 302 }))).toBe(true);
    expect(evaluatePackDastCheck(check, obs({ location: 'https://app.example:8443/' }, { status: 302 }))).toBe(false);
    expect(evaluatePackDastCheck(check, obs({ location: '::::' }, { status: 302 }))).toBe(false);
  });
});
