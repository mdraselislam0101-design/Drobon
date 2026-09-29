import { describe, expect, test } from 'vitest';
import { isDastObservation, isDastResult, type DastResult } from '../src/dast.js';
import { isFinding, isScanDetailResponse, type Finding } from '../src/scans.js';

const TARGET = 'https://app.example.org/';

function sampleResult(overrides: Partial<DastResult> = {}): DastResult {
  return {
    targetUrl: TARGET,
    requestCount: 1,
    redirectsFollowed: 0,
    partial: false,
    observations: [{
      endpoint: TARGET,
      method: 'GET',
      status: 200,
      observedAt: '2026-09-28T00:00:00.000Z',
      responseTimeMs: 10,
      bodyBytes: 12,
      bodyTruncated: false,
      contentType: 'text/html',
      headers: ['Content-Type: text/html', 'Server: present'],
    }],
    ...overrides,
  };
}

const sampleDastFinding: Finding = {
  id: `fnd_${'a'.repeat(24)}`,
  scanId: 'scan_00000000-0000-4000-8000-000000000012',
  ruleId: 'DG-DAST-003',
  scanner: 'DAST',
  severity: 'LOW',
  title: 'X-Content-Type-Options is not nosniff',
  description: 'The response did not set X-Content-Type-Options to nosniff.',
  evidence: 'X-Content-Type-Options: missing.',
  remediation: 'Set X-Content-Type-Options: nosniff.',
  fingerprint: 'a'.repeat(64),
  projectId: 'prj_00000000-0000-4000-8000-000000000012',
  targetUrl: TARGET,
  endpoint: TARGET,
  method: 'GET',
  responseStatus: 200,
  responseTimeMs: 10,
  contentType: 'text/html',
  observedAt: '2026-09-28T00:00:00.000Z',
  observedHeaders: ['X-Content-Type-Options: missing'],
};

describe('shared passive DAST contracts', () => {
  test('accepts bounded observations and result with consistent host and redirect counts', () => {
    expect(isDastObservation(sampleResult().observations[0])).toBe(true);
    expect(isDastResult(sampleResult())).toBe(true);
    expect(isDastResult(sampleResult({
      requestCount: 2,
      redirectsFollowed: 1,
      observations: [
        ...sampleResult().observations,
        { ...sampleResult().observations[0]!, endpoint: 'https://app.example.org/next' },
      ],
    }))).toBe(true);
  });

  test.each([
    sampleResult({ requestCount: 4 }),
    sampleResult({ redirectsFollowed: 1 }),
    sampleResult({ requestCount: 2, observations: sampleResult().observations }),
    sampleResult({ partial: true }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, bodyTruncated: true }] }),
    sampleResult({ partialReason: 'reason without partial' }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, endpoint: 'https://attacker.example.net/' }] }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, endpoint: 'http://app.example.org/' }] }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, endpoint: 'https://app.example.org/?token=secret' }] }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, bodyBytes: 32_769 }] }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, method: 'POST' as 'GET' }] }),
    sampleResult({ observations: [{ ...sampleResult().observations[0]!, headers: ['x'.repeat(121)] }] }),
  ])('rejects malformed, cross-host, or over-budget result: %#', (result) => {
    expect(isDastResult(result)).toBe(false);
  });

  test('closed-shape guards reject injected fields and credential-bearing URLs', () => {
    expect(isDastObservation({ ...sampleResult().observations[0], rawBody: 'secret' })).toBe(false);
    expect(isDastResult({ ...sampleResult(), projectId: 'attacker' })).toBe(false);
    expect(isDastResult({ ...sampleResult(), targetUrl: 'https://user:pass@app.example.org/' })).toBe(false);
  });

  test('DAST findings use HTTP observations, not source paths or invented CVSS data', () => {
    expect(isFinding(sampleDastFinding)).toBe(true);
    expect(isFinding({ ...sampleDastFinding, file: 'src/index.ts' })).toBe(false);
    expect(isFinding({ ...sampleDastFinding, cvss: 9.8 })).toBe(false);
    expect(isFinding({ ...sampleDastFinding, targetUrl: 'http://127.0.0.1/' })).toBe(false);
    expect(isFinding({ ...sampleDastFinding, endpoint: 'http://app.example.org/' })).toBe(false);
  });

  test('completed DAST detail cross-checks target, summary, findings and result payload', () => {
    const result = sampleResult();
    const scan = {
      id: sampleDastFinding.scanId,
      projectId: sampleDastFinding.projectId,
      scanType: 'DAST',
      status: 'COMPLETED',
      targetUrl: TARGET,
      createdAt: '2026-09-28T00:00:00.000Z',
      updatedAt: '2026-09-28T00:00:00.000Z',
      startedAt: '2026-09-28T00:00:00.000Z',
      completedAt: '2026-09-28T00:00:01.000Z',
      resultSummary: { findingsTotal: 1, requestsMade: 1, redirectsFollowed: 0 },
      findings: [sampleDastFinding],
      dast: result,
    };
    expect(isScanDetailResponse({ scan })).toBe(true);
    expect(isScanDetailResponse({ scan: { ...scan, targetUrl: 'https://other.example.org/' } })).toBe(false);
    expect(isScanDetailResponse({ scan: { ...scan, resultSummary: { findingsTotal: 1, requestsMade: 2, redirectsFollowed: 0 } } })).toBe(false);
    expect(isScanDetailResponse({ scan: { ...scan, findings: [{ ...sampleDastFinding, projectId: 'prj_00000000-0000-4000-8000-000000000099' }] } })).toBe(false);
    expect(isScanDetailResponse({ scan: { ...scan, findings: [{ ...sampleDastFinding, endpoint: 'https://app.example.org/unobserved' }] } })).toBe(false);
  });
});
