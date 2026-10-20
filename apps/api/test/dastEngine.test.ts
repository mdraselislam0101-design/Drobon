import { describe, expect, test, vi } from 'vitest';
import { TEST_DAST_RULES } from './fixtures/testData.js';
import type { ScanRecord } from '../src/scans/store.js';
import { createDastEngine, DAST_MAX_RESPONSE_BYTES } from '../src/scans/dast/engine.js';
import { DastHttpError, type DastProbeOptions, type DastProbeResponse, type DastTransport } from '../src/scans/dast/http.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';

const TARGET = 'https://app.example.org/';
const SAFE_IP = '93.184.216.34';
const FIXED_TIME = Date.parse('2026-09-28T00:00:00.000Z');

function scanRecord(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000011',
    ownerId: 'usr_fixture',
    projectId: 'prj_00000000-0000-4000-8000-000000000011',
    scanType: 'DAST',
    status: 'RUNNING',
    dastTargetUrl: TARGET,
    createdAt: '2026-09-28T00:00:00.000Z',
    updatedAt: '2026-09-28T00:00:00.000Z',
    startedAt: '2026-09-28T00:00:00.000Z',
    ...overrides,
  };
}

function response(overrides: Partial<DastProbeResponse> = {}): DastProbeResponse {
  return {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    },
    body: '<html><body>fixture</body></html>',
    bodyTruncated: false,
    elapsedMs: 12,
    ...overrides,
  };
}

function fixtureTransport(
  exchange: (targetUrl: string, options: DastProbeOptions, index: number) => DastProbeResponse | Promise<DastProbeResponse>,
): { transport: DastTransport; calls: Array<{ targetUrl: string; options: DastProbeOptions }> } {
  const calls: Array<{ targetUrl: string; options: DastProbeOptions }> = [];
  return {
    calls,
    transport: {
      probe: async (target, options) => {
        const index = calls.length;
        calls.push({ targetUrl: target.url, options });
        return exchange(target.url, options, index);
      },
    },
  };
}

const targetPolicy = () => createDastTargetPolicy({ resolve: async () => [SAFE_IP] });
const context = () => ({ signal: new AbortController().signal });

describe('bounded passive DAST engine', () => {
  test('runs a real observed response through passive rules and creates deterministic findings', async () => {
    const fixture = fixtureTransport(async () => response({
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'access-control-allow-origin': 'https://drobon-aegis.invalid',
        'access-control-allow-credentials': 'true',
        'server': 'fixture-private-build/77',
        'set-cookie': ['private_cookie_name=private_cookie_value; Path=/'],
      },
      body: '<script src="http://app.example.org/a.js"></script>',
    }));
    const engine = createDastEngine({
      targetPolicy: targetPolicy(),
      transport: fixture.transport,
      now: () => FIXED_TIME,
      packRules: TEST_DAST_RULES as any,
    });
    const first = await engine.execute(scanRecord(), context());
    const second = await engine.execute(scanRecord(), context());
    expect(first.kind).toBe('completed');
    expect(second.kind).toBe('completed');
    if (first.kind !== 'completed' || second.kind !== 'completed') return;
    expect(first.resultSummary.requestsMade).toBe(1);
    expect(first.dast?.requestCount).toBe(1);
    expect(first.resultSummary.findingsTotal).toBeGreaterThan(0);
    expect(first.findings?.map((finding) => finding.ruleId)).toContain('DG-DAST-005');
    expect(first.findings?.map((finding) => finding.ruleId)).toContain('DG-DAST-008');
    expect(first.findings?.map((finding) => finding.id)).toEqual(second.findings?.map((finding) => finding.id));
    expect(first.findings?.map((finding) => finding.fingerprint)).toEqual(second.findings?.map((finding) => finding.fingerprint));
    const serialized = JSON.stringify(first);
    expect(serialized).not.toContain('private_cookie_name');
    expect(serialized).not.toContain('private_cookie_value');
    expect(serialized).not.toContain('fixture-private-build/77');
    expect(serialized).not.toContain('<script');
    expect(fixture.calls).toHaveLength(2);
    expect(fixture.calls[0]?.options.maxResponseBytes).toBe(DAST_MAX_RESPONSE_BYTES);
  });

  test('follows only bounded same-host redirects and records actual requests', async () => {
    const fixture = fixtureTransport(async (_url, _options, index) => index < 2
      ? response({ status: 302, headers: { location: `/page-${index + 1}` }, body: '' })
      : response());
    const outcome = await createDastEngine({
      targetPolicy: targetPolicy(),
      transport: fixture.transport,
      now: () => FIXED_TIME,
    }).execute(scanRecord(), context());
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(fixture.calls.map((call) => call.targetUrl)).toEqual([
      TARGET,
      'https://app.example.org/page-1',
      'https://app.example.org/page-2',
    ]);
    expect(fixture.calls).toHaveLength(3);
    expect(outcome.resultSummary.redirectsFollowed).toBe(2);
    expect(outcome.dast?.observations.map((item) => item.status)).toEqual([302, 302, 200]);
  });

  test('rejects cross-host/private/downgrade redirects without issuing another request', async () => {
    for (const location of ['https://elsewhere.example.org/', 'http://app.example.org/plain', 'http://127.0.0.1/']) {
      const fixture = fixtureTransport(async () => response({ status: 302, headers: { location }, body: '' }));
      const outcome = await createDastEngine({
        targetPolicy: targetPolicy(),
        transport: fixture.transport,
        now: () => FIXED_TIME,
      }).execute(scanRecord(), context());
      expect(outcome.kind).toBe('completed');
      if (outcome.kind !== 'completed') continue;
      expect(fixture.calls).toHaveLength(1);
      expect(outcome.dast?.partial).toBe(true);
      expect(outcome.dast?.redirectsFollowed).toBe(0);
    }
  });

  test('does not request a redirect loop twice and reports partial work honestly', async () => {
    const fixture = fixtureTransport(async () => response({ status: 302, headers: { location: '/' }, body: '' }));
    const outcome = await createDastEngine({
      targetPolicy: targetPolicy(),
      transport: fixture.transport,
      now: () => FIXED_TIME,
    }).execute(scanRecord(), context());
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(fixture.calls).toHaveLength(1);
    expect(outcome.dast?.partial).toBe(true);
    expect(outcome.dast?.redirectsFollowed).toBe(0);
  });

  test('enforces response bytes even when an injected transport violates its contract', async () => {
    const fixture = fixtureTransport(async () => response({ body: 'x'.repeat(40_000) }));
    const outcome = await createDastEngine({
      targetPolicy: targetPolicy(),
      transport: fixture.transport,
      maxResponseBytes: 120,
      now: () => FIXED_TIME,
    }).execute(scanRecord(), context());
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.dast?.observations[0]?.bodyBytes).toBeLessThanOrEqual(120);
    expect(outcome.dast?.observations[0]?.bodyTruncated).toBe(true);
    expect(outcome.dast?.partial).toBe(true);
    expect(JSON.stringify(outcome)).not.toContain('x'.repeat(121));
  });

  test('request timeout and end-to-end deadline are explicit timeout outcomes', async () => {
    const timedTransport = fixtureTransport(async () => { throw new DastHttpError('timeout'); });
    const timed = await createDastEngine({
      targetPolicy: targetPolicy(), transport: timedTransport.transport, now: () => FIXED_TIME,
    }).execute(scanRecord(), context());
    expect(timed).toMatchObject({ kind: 'timed-out', failureCode: 'DAST_REQUEST_TIMEOUT' });

    let clock = 0;
    const slowTransport = fixtureTransport(async () => {
      clock = 15;
      return response();
    });
    const deadline = await createDastEngine({
      targetPolicy: targetPolicy(), transport: slowTransport.transport, now: () => clock, scanDeadlineMs: 15,
    }).execute(scanRecord(), context());
    expect(deadline).toMatchObject({ kind: 'timed-out', failureCode: 'DAST_SCAN_TIMEOUT' });
  });

  test('abort is observed before a request, and request options never exceed production bounds', async () => {
    const fixture = fixtureTransport(async (_url, options) => {
      expect(options.timeoutMs).toBeLessThanOrEqual(5_000);
      expect(options.maxResponseBytes).toBeLessThanOrEqual(32_768);
      return response();
    });
    const aborted = new AbortController();
    aborted.abort();
    const canceled = await createDastEngine({ targetPolicy: targetPolicy(), transport: fixture.transport })
      .execute(scanRecord(), { signal: aborted.signal });
    expect(canceled).toMatchObject({ kind: 'timed-out', failureCode: 'DAST_SCAN_TIMEOUT' });
    expect(fixture.calls).toHaveLength(0);

    const completed = await createDastEngine({ targetPolicy: targetPolicy(), transport: fixture.transport })
      .execute(scanRecord(), context());
    expect(completed.kind).toBe('completed');
    expect(fixture.calls).toHaveLength(1);
  });

  test('fails honestly for missing targets and unusable observed responses', async () => {
    const fixture = fixtureTransport(async () => response({ status: 99 }));
    const engine = createDastEngine({ targetPolicy: targetPolicy(), transport: fixture.transport });
    const missingRecord = scanRecord();
    delete missingRecord.dastTargetUrl;
    const missing = await engine.execute(missingRecord, context());
    expect(missing).toMatchObject({ kind: 'failed', failureCode: 'DAST_TARGET_NOT_FOUND' });
    const invalid = await engine.execute(scanRecord(), context());
    expect(invalid).toMatchObject({ kind: 'failed', failureCode: 'DAST_REQUEST_FAILED' });
  });

  test('uses exactly the configured single target; never discovers links or executes content', async () => {
    const execute = vi.fn(async () => response({ body: '<a href="/admin">link</a><script>throw 1</script>' }));
    const fixture = fixtureTransport(execute);
    const outcome = await createDastEngine({ targetPolicy: targetPolicy(), transport: fixture.transport })
      .execute(scanRecord(), context());
    expect(outcome.kind).toBe('completed');
    expect(fixture.calls.map((call) => call.targetUrl)).toEqual([TARGET]);
    expect(execute).toHaveBeenCalledTimes(1);
  });
});
