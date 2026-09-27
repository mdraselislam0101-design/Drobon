import { describe, expect, test } from 'vitest';
import {
  SESSION_COOKIE_NAME,
  clearSessionCookie,
  parseCookies,
  readSessionToken,
  sessionCookie,
} from '../src/auth/cookies.js';

describe('session cookie serialization', () => {
  test('sets the security attributes on issue', () => {
    const value = sessionCookie('tok_abc', { secure: false, maxAgeSeconds: 3600 });
    expect(value).toContain(`${SESSION_COOKIE_NAME}=tok_abc`);
    expect(value).toContain('Path=/');
    expect(value).toContain('HttpOnly');
    expect(value).toContain('SameSite=Strict');
    expect(value).toContain('Max-Age=3600');
    expect(value).not.toContain('Secure');
    expect(value).not.toContain('Domain'); // host-only cookie
  });

  test('adds Secure only when configured (production)', () => {
    expect(sessionCookie('tok', { secure: true, maxAgeSeconds: 60 })).toContain('Secure');
    expect(clearSessionCookie({ secure: true })).toContain('Secure');
    expect(clearSessionCookie({ secure: false })).not.toContain('Secure');
  });

  test('clearing removes the cookie immediately', () => {
    const value = clearSessionCookie({ secure: false });
    expect(value).toContain(`${SESSION_COOKIE_NAME}=;`);
    expect(value).toContain('Max-Age=0');
    expect(value).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    expect(value).toContain('HttpOnly');
    expect(value).toContain('SameSite=Strict');
  });
});

describe('cookie parsing', () => {
  test('parses multiple cookies with spacing', () => {
    expect(parseCookies('a=1; b=2;c=3')).toEqual({ a: '1', b: '2', c: '3' });
  });

  test('ignores malformed segments and duplicate names', () => {
    expect(parseCookies('=orphan; novalue; a=1; a=2')).toEqual({ a: '1' });
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('')).toEqual({});
  });

  test('reads the session token only when non-empty', () => {
    expect(readSessionToken(`other=x; ${SESSION_COOKIE_NAME}=tok`)).toBe('tok');
    expect(readSessionToken('other=x')).toBeUndefined();
    expect(readSessionToken(`${SESSION_COOKIE_NAME}=`)).toBeUndefined();
    expect(readSessionToken(undefined)).toBeUndefined();
  });
});
