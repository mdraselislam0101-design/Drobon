import { describe, expect, test, vi } from 'vitest';
import {
  createDastTargetPolicy,
  DastTargetError,
  isPublicDastAddress,
  normalizeDastTarget,
} from '../src/scans/dast/target.js';

const PUBLIC_FIXTURE_IP = '93.184.216.34';

function expectTargetError(promise: Promise<unknown>, code: DastTargetError['code']): Promise<void> {
  return expect(promise).rejects.toMatchObject({ code });
}

describe('DAST target normalization and SSRF policy', () => {
  test('canonicalizes a public URL and resolves via the injected deterministic resolver', async () => {
    const target = await createDastTargetPolicy({
      resolve: async (hostname) => {
        expect(hostname).toBe('app.example.org');
        return [PUBLIC_FIXTURE_IP];
      },
    }).prepare('https://APP.example.org/health');
    expect(target).toEqual({
      url: 'https://app.example.org/health',
      hostname: 'app.example.org',
      addresses: [PUBLIC_FIXTURE_IP],
    });
  });

  test.each([
    'ftp://app.example.org/',
    'file:///etc/passwd',
    'https://user:password@app.example.org/',
    'https://app.example.org/?token=secret',
    'https://app.example.org/#fragment',
    'https://app.example.org:8443/',
    'https://app.example.org/%2e%2e/admin',
    'https://app.example.org/%252e%252e/admin',
    'https://app.example.org/api/%252e%252e%252foutside',
    'https://app.example.org/api/a%252fb',
    'https://app.example.org/api/a%25252fb',
    'https://app.example.org/api/a%2525252fb',
    'https://app.example.org/api/a%2520b', // double encoding is ambiguous even when benign
    'https://app.example.org/a%2fb',
    'https://app.example.org/a%5cb',
    ' https://app.example.org/',
    'https://app.example.org/with space',
  ])('rejects unsupported or ambiguous target syntax: %s', async (url) => {
    await expectTargetError(createDastTargetPolicy({ resolve: async () => [PUBLIC_FIXTURE_IP] }).prepare(url), 'DAST_TARGET_INVALID');
  });

  test.each([
    'http://localhost/',
    'http://service.local/',
    'http://service.internal/',
    'http://metadata/',
    'http://metadata.google.internal/',
    'http://host.example.test/',
    'http://host.example.invalid/',
    'http://host.example.onion/',
  ])('blocks local, metadata, and reserved hostnames before DNS: %s', async (url) => {
    let resolved = false;
    const policy = createDastTargetPolicy({ resolve: async () => { resolved = true; return [PUBLIC_FIXTURE_IP]; } });
    await expectTargetError(policy.prepare(url), 'DAST_TARGET_BLOCKED');
    expect(resolved).toBe(false);
  });

  test.each([
    '0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.169.254',
    '172.16.0.1', '172.31.255.254', '192.0.2.1', '192.168.1.1',
    '198.18.0.1', '198.51.100.5', '203.0.113.9', '224.0.0.1', '240.0.0.1',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::a00:1',
    'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2002::1', '3fff::1',
  ])('does not classify special-purpose address %s as public', (address) => {
    expect(isPublicDastAddress(address)).toBe(false);
  });

  test.each(['93.184.216.34', '1.1.1.1', '2606:4700:4700::1111'])('accepts globally routable fixture address %s', (address) => {
    expect(isPublicDastAddress(address)).toBe(true);
  });

  test.each(['http://169.254.169.254/latest/meta-data/', 'http://[::1]/'])('does not let an injected resolver override a private IP literal: %s', async (url) => {
    const resolve = vi.fn(async () => [PUBLIC_FIXTURE_IP]);
    await expectTargetError(createDastTargetPolicy({ resolve }).prepare(url), 'DAST_TARGET_BLOCKED');
    expect(resolve).not.toHaveBeenCalled();
  });

  test('rejects a DNS response containing any private address (including mixed public/private answers)', async () => {
    const policy = createDastTargetPolicy({ resolve: async () => [PUBLIC_FIXTURE_IP, '10.0.0.8'] });
    await expectTargetError(policy.prepare('https://app.example.org/'), 'DAST_TARGET_BLOCKED');
  });

  test('rejects empty, malformed, oversized, and excessive DNS answer sets', async () => {
    for (const addresses of [[], ['not-an-ip'], Array.from({ length: 17 }, () => PUBLIC_FIXTURE_IP)]) {
      const policy = createDastTargetPolicy({ resolve: async () => addresses });
      await expectTargetError(policy.prepare('https://app.example.org/'), 'DAST_TARGET_BLOCKED');
    }
  });

  test('resolver timeout fails closed with a bounded DNS failure', async () => {
    const policy = createDastTargetPolicy({
      resolve: async () => new Promise<never>(() => undefined),
      resolveTimeoutMs: 10,
    });
    await expectTargetError(policy.prepare('https://app.example.org/'), 'DAST_DNS_FAILED');
  });

  test('revalidates DNS to stop rebinding between target configuration and a request', async () => {
    let answers = [PUBLIC_FIXTURE_IP];
    const policy = createDastTargetPolicy({ resolve: async () => answers });
    const configured = await policy.prepare('https://app.example.org/');
    answers = ['127.0.0.1'];
    await expectTargetError(policy.resolveNormalized(configured.url), 'DAST_TARGET_BLOCKED');
  });

  test('redirects are independently normalized and restricted to the original host and secure scheme before DNS', async () => {
    const resolvedHosts: string[] = [];
    const policy = createDastTargetPolicy({ resolve: async (host) => { resolvedHosts.push(host); return [PUBLIC_FIXTURE_IP]; } });
    const current = await policy.prepare('https://app.example.org/start');
    const relative = await policy.resolveRedirect(current, '/next', current.hostname);
    expect(relative.url).toBe('https://app.example.org/next');
    const beforeDenied = resolvedHosts.length;
    await expectTargetError(policy.resolveRedirect(current, 'https://elsewhere.example.org/', current.hostname), 'DAST_TARGET_BLOCKED');
    await expectTargetError(policy.resolveRedirect(current, 'http://app.example.org/downgrade', current.hostname), 'DAST_TARGET_BLOCKED');
    await expectTargetError(policy.resolveRedirect(current, 'http://127.0.0.1/', current.hostname), 'DAST_TARGET_BLOCKED');
    await expectTargetError(policy.resolveRedirect(current, 'https://app.example.org/?credential=value', current.hostname), 'DAST_TARGET_INVALID');
    expect(resolvedHosts).toHaveLength(beforeDenied);
    expect(resolvedHosts).toEqual(['app.example.org', 'app.example.org']);
  });

  test.each([
    '/api/%2e%2e/admin',
    '/api/%2e%2e%2fadmin',
    '/api/%252e%252e%252fadmin',
    'https://app.example.org/api/%2e%2e/admin',
    '//app.example.org/api/%2e./admin',
    './%2e%2e/admin',
    '/api/a%5cb',
  ])('rejects the raw redirect reference before URL dot-segment normalization: %s', async (location) => {
    const resolve = vi.fn(async () => [PUBLIC_FIXTURE_IP]);
    const policy = createDastTargetPolicy({ resolve });
    const current = await policy.prepare('https://app.example.org/api/');
    await expectTargetError(policy.resolveRedirect(current, location, current.hostname), 'DAST_TARGET_INVALID');
    expect(resolve).toHaveBeenCalledTimes(1);
  });

  test('preserves supported ordinary relative redirects and single-encoded spaces', async () => {
    const policy = createDastTargetPolicy({ resolve: async () => [PUBLIC_FIXTURE_IP] });
    const current = await policy.prepare('https://app.example.org/api/v1/');
    expect((await policy.resolveRedirect(current, '../health%20check', current.hostname)).url).toBe('https://app.example.org/api/health%20check');
  });

  test('normalization returns only the canonical safe URL, not userinfo/query/fragment data', () => {
    expect(normalizeDastTarget('https://APP.example.org/a').url).toBe('https://app.example.org/a');
    expect(normalizeDastTarget('https://app.example.org/a%20b').url).toBe('https://app.example.org/a%20b');
  });
});
