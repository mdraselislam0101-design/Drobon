import { describe, expect, test } from 'vitest';
import { INSPECTED_RESPONSE_HEADERS } from '../src/scans/dast/observedHeaders.js';

describe('DAST response surface (GAP-048)', () => {
  test('the allowlist still contains the original 11 headers', () => {
    for (const header of [
      'content-type', 'strict-transport-security', 'x-content-type-options', 'x-frame-options',
      'content-security-policy', 'access-control-allow-origin', 'access-control-allow-credentials',
      'server', 'x-powered-by', 'set-cookie', 'location',
    ]) expect(INSPECTED_RESPONSE_HEADERS.has(header)).toBe(true);
  });

  test('the headers that previously blocked 73 dataset rules are forwarded', () => {
    for (const header of [
      'permissions-policy', 'refresh', 'cross-origin-embedder-policy', 'cross-origin-opener-policy',
      'cross-origin-resource-policy', 'referrer-policy', 'x-permitted-cross-domain-policies',
      'access-control-allow-headers', 'access-control-allow-methods', 'cache-control',
      'content-security-policy-report-only', 'www-authenticate', 'x-xss-protection', 'expect-ct',
    ]) expect(INSPECTED_RESPONSE_HEADERS.has(header)).toBe(true);
    expect(INSPECTED_RESPONSE_HEADERS.size).toBeGreaterThan(50);
    expect(INSPECTED_RESPONSE_HEADERS.size).toBeLessThan(100); // bounded, not "forward everything"
  });

  test('no active-probing capability is introduced by the widened allowlist', () => {
    expect(INSPECTED_RESPONSE_HEADERS.has('x-payload-inject')).toBe(false);
    expect(INSPECTED_RESPONSE_HEADERS.has('authorization')).toBe(false);
  });
});
