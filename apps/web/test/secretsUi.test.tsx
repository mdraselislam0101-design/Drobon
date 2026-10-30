// @vitest-environment jsdom
/**
 * SECRETS UI (Pump 10) — the secrets findings surface over the SAME
 * findings view as SAST.
 *
 * Covers the honest-user contract:
 * - a COMPLETED SECRETS scan renders "View findings"; findings show
 *   rule id, severity, the rule-defined DETECTION confidence badge,
 *   location (file:line + CWE), REDACTED evidence and remediation —
 *   all as TEXT (React escaping);
 * - the raw secret value never reaches the DOM in ANY attribute,
 *   tooltip or text node (server-side redaction is the contract; the
 *   UI asserts it end-to-end);
 * - PARTIAL honesty: a partial scan's summary line carries the reason
 *   (a partial scan with 0 findings must never read as "no secrets");
 * - a FAILED scan (DAST, still engine-less) shows the failure code
 *   verbatim — never faked, never spun as a clean result;
 * - the scan form states the guarantees: analysis only, never
 *   executed, redacted evidence.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import {
  type ApiClient,
  ApiClientError,
} from '../src/api/client.js';
import {
  type Finding,
  type FindingDetailResponse,
  type FindingsPageResponse,
  type ProjectResponse,
  type ScanDetailResponse,
  type ScanResponse,
  type ScansResponse,
  type SourceSnapshotResponse,
  type UsageResponse,
} from '@drobon/shared';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT: ProjectResponse = {
  project: {
    id: 'prj_00000000-0000-4000-8000-000000000010',
    name: 'Secrets Project',
    description: '',
    status: 'ACTIVE',
    createdAt: '2026-09-27T10:00:00.000Z',
    updatedAt: '2026-09-27T10:00:00.000Z',
  },
};

const SNAPSHOT: SourceSnapshotResponse = {
  snapshot: {
    projectId: 'prj_00000000-0000-4000-8000-000000000010',
    fileCount: 2,
    totalBytes: 140,
    updatedAt: '2026-09-27T11:00:00.000Z',
    files: [
      { path: 'cloud.ts', bytes: 90 },
      { path: 'prod.yaml', bytes: 50 },
    ],
  },
};

const USAGE: UsageResponse = {
  plan: 'PRO',
  period: {
    period: '2026-09',
    startUtc: '2026-09-01T00:00:00.000Z',
    endUtc: '2026-10-01T00:00:00.000Z',
  },
  used: 0,
  remaining: 100,
  limit: 100,
  quotaStatus: 'OK',
};

/**
 * SYNTHETIC fixture values. The RAW values deliberately appear NOWHERE
 * in any fixture field — the contract under test is that everything
 * the server sends (and thus the DOM can contain) is already redacted.
 */
const RAW_AWS_KEY = 'AKIAP10QZ9WM7XK2BR4J'; // fake-test fixture
const RAW_API_KEY = 'P10ApiKeyZx9Qw8Er7Ty6Uio5Pl'; // fake-test fixture

function secretsScan(
  resultSummary: NonNullable<ScanResponse['scan']['resultSummary']>,
): ScanResponse['scan'] {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000010',
    projectId: 'prj_00000000-0000-4000-8000-000000000010',
    scanType: 'SECRETS',
    status: 'COMPLETED',
    createdAt: '2026-09-27T11:01:00.000Z',
    updatedAt: '2026-09-27T11:01:01.000Z',
    startedAt: '2026-09-27T11:01:00.500Z',
    completedAt: '2026-09-27T11:01:01.000Z',
    resultSummary,
  };
}

function secretsDetail(scan: ScanResponse['scan']): ScanDetailResponse {
  return {
    scan: {
      ...scan,
      findings: [
        {
          id: `fnd_${'1'.repeat(24)}`,
          scanId: scan.id,
          scanner: 'SECRETS',
          projectId: scan.projectId,
          ruleId: 'DG-SEC-002',
          severity: 'HIGH',
          confidence: 'HIGH',
          title: 'Service credential detected in source',
          description: 'A credential matching a documented service format was found.',
          cwe: 'CWE-798',
          file: 'cloud.ts',
          line: 3,
          column: 20,
          evidence: 'export const aws = "<redacted>";',
          remediation:
            'Move the key to the environment or a secret manager and rotate the exposed value.',
          fingerprint: 'a'.repeat(64),
        },
        {
          id: `fnd_${'2'.repeat(24)}`,
          scanId: scan.id,
          scanner: 'SECRETS',
          projectId: scan.projectId,
          ruleId: 'DG-SEC-005',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          title: 'API key hardcoded in source',
          description: 'A long credential-shaped literal is assigned to an api-key name.',
          file: 'prod.yaml',
          line: 1,
          column: 1,
          evidence: 'api_key: <redacted>',
          remediation: 'Move the key to a secret manager and rotate the exposed value.',
          fingerprint: 'b'.repeat(64),
        },
      ],
    },
  };
}

function signedInClient(overrides: Record<string, unknown> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async (): Promise<ProjectResponse> => PROJECT),
    getSources: vi.fn(async (): Promise<SourceSnapshotResponse> => SNAPSHOT),
    ...overrides,
  });
}

function completedSecretsClient(scan: ScanResponse['scan'], overrides: Record<string, unknown> = {}): ApiClient {
  const findings = secretsDetail(scan).scan.findings;
  const getFindings = vi.fn(async (_projectId: string, _scanId: string, filters: { severity?: Finding['severity']; scanner?: 'SAST' | 'SECRETS' | 'SCA' | 'DAST'; page?: number; pageSize?: number } = {}): Promise<FindingsPageResponse> => {
    const filtered = findings.filter((finding) =>
      (filters.severity === undefined || finding.severity === filters.severity) &&
      (filters.scanner === undefined || finding.scanner === filters.scanner));
    const pageSize = filters.pageSize ?? 20;
    const page = filters.page ?? 1;
    return {
      findings: filtered.slice((page - 1) * pageSize, page * pageSize),
      page, pageSize, total: filtered.length, totalPages: Math.ceil(filtered.length / pageSize),
      ...(filters.severity === undefined ? {} : { severity: filters.severity }),
      ...(filters.scanner === undefined ? {} : { scanner: filters.scanner }),
    };
  });
  const getFinding = vi.fn(async (_projectId: string, _scanId: string, findingId: string): Promise<FindingDetailResponse> => {
    const finding = findings.find((item) => item.id === findingId);
    if (finding === undefined) throw new Error('missing fixture finding');
    return { project: PROJECT.project, scan, finding };
  });
  return signedInClient({
    getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
    getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
    getFindings,
    getFinding,
    ...overrides,
  });
}

const screen = {
  find: async (testid: string): Promise<HTMLElement> => {
    const { waitFor } = await import('@testing-library/react');
    return waitFor(() => {
      const el = document.querySelector(`[data-testid="${testid}"]`);
      if (el === null) {
        throw new Error(`missing ${testid}`);
      }
      return el as HTMLElement;
    });
  },
  findAll: async (testid: string): Promise<HTMLElement[]> => {
    await screen.find(testid);
    return Array.from(document.querySelectorAll(`[data-testid="${testid}"]`)) as HTMLElement[];
  },
};

describe('SECRETS UI: findings over the shared findings surface', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('SECRETS findings render: rule, severity, confidence badge, redacted evidence, remediation', async () => {
    const scan = secretsScan({
      findingsTotal: 2,
      findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
    });
    const client = completedSecretsClient(scan);
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);

    expect(await screen.find('scan-result')).toBeTruthy();
    const listText = (document.querySelector('[data-testid="scans-list"]') as HTMLElement).textContent;
    expect(listText).toContain('SECRETS');
    expect(listText).toContain('Findings: 2');
    expect(listText).not.toContain('partial');

    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    const items = await screen.findAll('finding-item');
    expect(items).toHaveLength(2);

    const first = items[0] as HTMLElement;
    expect(first.querySelector('[data-testid="finding-severity"]')?.textContent).toBe('HIGH');
    expect(first.querySelector('[data-testid="finding-rule"]')?.textContent).toBe('DG-SEC-002');
    expect(first.querySelector('[data-testid="finding-confidence"]')?.textContent).toContain('HIGH detection confidence');
    expect(first.querySelector('[data-testid="finding-location"]')?.textContent).toContain('cloud.ts:3');
    expect(first.querySelector('[data-testid="finding-location"]')?.textContent).toContain('CWE-798');
    (first.querySelector('[data-testid="finding-detail-button"]') as HTMLElement).click();
    const detail = await screen.find('finding-detail');
    expect(detail.querySelector('[data-testid="finding-evidence"]')?.textContent).toBe('export const aws = "<redacted>";');
    expect(detail.querySelector('[data-testid="finding-remediation"]')?.textContent).toContain('secret manager');
    const second = items[1] as HTMLElement;
    expect(second.querySelector('[data-testid="finding-confidence"]')?.textContent).toContain('MEDIUM detection confidence');
  });

  test('raw secret values never appear anywhere in the DOM — text, attributes or markup', async () => {
    const scan = secretsScan({
      findingsTotal: 2,
      findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
    });
    const client = completedSecretsClient(scan);
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    await screen.findAll('finding-item');

    // Whole-document sweep: text nodes AND raw HTML (attributes,
    // tooltips, inline handlers cannot hide a value either).
    const html = document.documentElement.outerHTML;
    expect(html).not.toContain(RAW_AWS_KEY);
    expect(html).not.toContain(RAW_API_KEY);
    // No URL/query embedding either.
    expect(window.location.href).not.toContain('AKIA');
  });

  test('severity filtering is server-side and requests another bounded page', async () => {
    const scan = secretsScan({
      findingsTotal: 2,
      findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
    });
    const client = completedSecretsClient(scan);
    const getFindings = client.getFindings;
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    await screen.findAll('finding-item');

    const filter = document.querySelector('[data-testid="findings-filter"]') as HTMLSelectElement;
    filter.value = 'MEDIUM';
    filter.dispatchEvent(new Event('change', { bubbles: true }));

    const { waitFor } = await import('@testing-library/react');
    await waitFor(() => {
      const items = document.querySelectorAll('[data-testid="finding-item"]');
      if (items.length !== 0) throw new Error(`expected 0 MEDIUM findings, got ${items.length}`);
    });
    const calls = (getFindings as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[1]?.[2]).toEqual({ page: 1, pageSize: 20, severity: 'MEDIUM' });
    expect(document.querySelector('[data-testid="findings-empty"]')).toBeTruthy();
  });

  test('PARTIAL honesty: the summary line carries the reason — 0 findings is never "no secrets"', async () => {
    const partialScan = secretsScan({
      findingsTotal: 0,
      findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
      truncated: true,
      partial: true,
      partialReason: 'the findings cap was reached; later matches are not listed.',
    });
    const client = signedInClient({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [partialScan] })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
    });
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    const result = await screen.find('scan-result');
    expect(result.textContent).toContain('Findings: 0');
    expect(result.textContent).toContain('partial scan');
    expect(result.textContent).toContain('findings cap');
  });

  test('a failed DAST scan shows its target-policy failure honestly', async () => {
    const failed: ScanResponse['scan'] = {
      id: 'scan_00000000-0000-4000-8000-000000000011',
      projectId: 'prj_00000000-0000-4000-8000-000000000010',
      scanType: 'DAST' as const,
      status: 'FAILED' as const,
      createdAt: '2026-09-27T11:02:00.000Z',
      updatedAt: '2026-09-27T11:02:01.000Z',
      startedAt: '2026-09-27T11:02:00.500Z',
      completedAt: '2026-09-27T11:02:01.000Z',
      failureCode: 'DAST_TARGET_BLOCKED',
      failureMessage: 'The configured target was blocked before any request was made.',
    };
    const client = signedInClient({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [failed] })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
    });
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    const failure = await screen.find('scan-failure');
    expect(failure.textContent).toContain('DAST_TARGET_BLOCKED');
    expect(document.querySelector('[data-testid="scan-result"]')).toBeNull();
    expect(document.querySelector('[data-testid="view-findings"]')).toBeNull();
  });

  test('the scan form states the secrets guarantees: analysis only, never executed, redacted', async () => {
    const client = signedInClient({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [] })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
    });
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    const formText = (document.querySelector('[data-testid="scan-form"]') as HTMLElement)
      .textContent;
    expect(formText).toContain('never executed');
    expect(formText).toContain('never verified');
    expect(formText).toContain('redacted');
    expect(formText).toContain('bounded GET requests');
    expect(formText).toContain('Neither mode uses a browser');
    expect(formText).toContain('Active Safe may perform a bounded same-host crawl');
    expect(formText).toContain('query-bearing URLs are not supported');
    expect(formText).toContain('AST examines only already-observed response scripts');
  });

  test('a findings-page failure renders verbatim with retry (no silent findings)', async () => {
    const scan = secretsScan({
      findingsTotal: 2,
      findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
    });
    const findings = secretsDetail(scan).scan.findings;
    const getFindings = vi.fn<ApiClient['getFindings']>()
      .mockRejectedValueOnce(new ApiClientError({ kind: 'http', message: 'Store unavailable.', status: 500, requestId: 'test-500' }))
      .mockResolvedValueOnce({ findings, page: 1, pageSize: 20, total: findings.length, totalPages: 1 });
    const client = completedSecretsClient(scan, { getFindings });
    await renderAt('/projects/prj_00000000-0000-4000-8000-000000000010', client);
    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    expect((await screen.find('findings-error')).textContent).toBe('Store unavailable.');
    (await screen.find('findings-retry')).click();
    await screen.findAll('finding-item');
    expect(getFindings).toHaveBeenCalledTimes(2);
  });
});
