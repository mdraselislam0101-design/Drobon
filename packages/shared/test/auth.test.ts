import { describe, expect, test } from 'vitest';
import {
  EMAIL_MAX_LENGTH,
  EMAIL_PATTERN,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  isAuthResponse,
  isAuthUser,
  isCurrentUserResponse,
  isLogoutResponse,
  isValidEmail,
  normalizeEmail,
  passwordPolicyIssue,
} from '../src/auth.js';

describe('email policy', () => {
  test('accepts common valid addresses and normalizes them', () => {
    for (const email of [
      'user@example.com',
      'first.last@sub.example.co.uk',
      'user+tag@example.io',
      'u_ser@ex-ample.org',
    ]) {
      expect(isValidEmail(email)).toBe(true);
    }
    expect(normalizeEmail('  User@Example.COM ')).toBe('user@example.com');
  });

  test('rejects malformed addresses', () => {
    for (const email of [
      '',
      '   ',
      'plainaddress',
      '@no-local.test',
      'no-at.test',
      'double@@at.test',
      'two@@ats.test',
      'space in@example.test',
      'trailingdot@example.',
      'user@.leadingdot.test',
      'user@example..com',
      `a${'x'.repeat(EMAIL_MAX_LENGTH)}@example.test`,
    ]) {
      expect(isValidEmail(email)).toBe(false);
    }
  });

  test('pattern never allows whitespace or credentials', () => {
    expect(EMAIL_PATTERN.test('user@exam ple.test')).toBe(false);
    expect(EMAIL_PATTERN.test('user:pass@example.test')).toBe(false);
  });
});

describe('password policy', () => {
  test('requires 8–128 characters without composition rules', () => {
    expect(PASSWORD_MIN_LENGTH).toBe(8);
    expect(PASSWORD_MAX_LENGTH).toBe(128);
    expect(passwordPolicyIssue('12345678')).toBeUndefined();
    expect(passwordPolicyIssue('aaaaaaaaaa')).toBeUndefined();
    expect(passwordPolicyIssue('1234567')).toMatch(/at least 8/);
    expect(passwordPolicyIssue('x'.repeat(129))).toMatch(/at most 128/);
    expect(passwordPolicyIssue('')).toMatch(/at least 8/);
  });

  test('never echoes the password back in the issue message', () => {
    const issue = passwordPolicyIssue('short-pw-test-1');
    expect(issue).toBeUndefined();
    const weak = passwordPolicyIssue('tiny');
    expect(weak).toBeDefined();
    expect(weak).not.toContain('tiny');
  });
});

describe('auth guards', () => {
  const user = {
    id: 'usr_test_1',
    email: 'user@example.test',
    createdAt: '2026-09-27T00:00:00.000Z',
  };

  test('isAuthUser accepts the public shape', () => {
    expect(isAuthUser(user)).toBe(true);
  });

  test('isAuthUser rejects internal security fields and bad shapes', () => {
    expect(isAuthUser({ ...user, passwordHash: 'scrypt$test' })).toBe(false);
    expect(isAuthUser({ ...user, password: 'hunter2-test' })).toBe(false);
    expect(isAuthUser({ ...user, sessionToken: 'abc' })).toBe(false);
    expect(isAuthUser(null)).toBe(false);
    expect(isAuthUser({ ...user, id: '' })).toBe(false);
    expect(isAuthUser({ ...user, email: 'not-an-email' })).toBe(false);
    expect(isAuthUser({ ...user, createdAt: 'not-a-date' })).toBe(false);
    expect(isAuthUser({ ...user, createdAt: 12345 })).toBe(false);
  });

  test('response guards validate their envelopes', () => {
    expect(isAuthResponse({ user })).toBe(true);
    expect(isAuthResponse({ user: { ...user, email: 'x' } })).toBe(false);
    expect(isCurrentUserResponse({ user })).toBe(true);
    expect(isCurrentUserResponse({})).toBe(false);
    expect(isLogoutResponse({ loggedOut: true })).toBe(true);
    expect(isLogoutResponse({ loggedOut: 'yes' })).toBe(false);
  });
});
