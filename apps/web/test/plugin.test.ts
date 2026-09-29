import { describe, expect, test } from 'vitest';
import {
  getDevSecurityHeaders,
  getPreviewSecurityHeaders,
  shouldRewriteToIndex,
} from '../vite-plugin-aegis.js';

describe('preview security headers', () => {
  test('include a strict CSP with no unsafe directives', () => {
    const headers = getPreviewSecurityHeaders();
    const csp = headers['content-security-policy'] ?? '';
    for (const directive of [
      "default-src 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "script-src 'self'",
      "connect-src 'self'",
    ]) {
      expect(csp).toContain(directive);
    }
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('*');
    expect(csp).not.toContain('data:');
  });

  test('include the standard hardening set', () => {
    const headers = getPreviewSecurityHeaders();
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(headers['cross-origin-resource-policy']).toBe('same-origin');
  });

  test('opt-in allowFrameEmbedding relaxes only frame headers for sandbox preview', () => {
    const preview = getPreviewSecurityHeaders({ allowFrameEmbedding: true });
    expect(preview['x-frame-options']).toBeUndefined();
    expect(preview['content-security-policy']).toContain(
      "frame-ancestors 'self' https://*.e2b.app https://*.arena.ai",
    );
    expect(preview['x-content-type-options']).toBe('nosniff');
    const dev = getDevSecurityHeaders({ allowFrameEmbedding: true });
    expect(dev['x-frame-options']).toBeUndefined();
    expect(dev['content-security-policy']).toBeUndefined();
  });
});

describe('dev security headers', () => {
  test('match preview minus CSP (documented HMR exception)', () => {
    const preview = getPreviewSecurityHeaders();
    const dev = getDevSecurityHeaders();
    expect(dev['content-security-policy']).toBeUndefined();
    for (const [name, value] of Object.entries(preview)) {
      if (name === 'content-security-policy') {
        continue;
      }
      expect(dev[name]).toBe(value);
    }
  });
});

describe('shouldRewriteToIndex', () => {
  test.each([
    ['GET', '/status', true],
    ['GET', '/deep/nested?x=1', true],
    ['GET', '/', false],
    ['GET', '/index.html', false],
    ['GET', '/api', false],
    ['GET', '/api/v1/status', false],
    ['GET', '/api/v1/me?x=1', false],
    ['GET', '/livez', false],
    ['GET', '/readyz', false],
    ['GET', '/assets/index-abc123.js', false],
    ['GET', '/favicon.svg', false],
    ['POST', '/status', false],
    [undefined, '/status', false],
    ['GET', undefined, false],
  ])('(%j, %j) === %s', (method, url, expected) => {
    expect(shouldRewriteToIndex(method, url)).toBe(expected);
  });
});
