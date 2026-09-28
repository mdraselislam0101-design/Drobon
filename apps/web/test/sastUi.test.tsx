// @vitest-environment jsdom
/**
 * SAST UI (Pump 8) — the source snapshot + real findings surface.
 *
 * Covers the honest-user contract:
 * - the source-snapshot section: empty state (no snapshot → 404-shaped),
 *   metadata after upload, the upload path (file names → paths, content
 *   read as text, replacement semantics), server-rejected uploads shown
 *   verbatim, archived projects cannot upload;
 * - the scan form stays honest: SAST analyzes (never executes) the
 *   snapshot; SECRETS (Pump 10) is real too; DAST still fails with
 *   SCAN_ENGINE_NOT_IMPLEMENTED;
 * - findings: lazy "View findings", server-ordered rendering as TEXT
 *   (React escaping — a rule-1 command-injection payload in evidence is
 *   displayed, never executed), redacted secrets stay redacted, the
 *   severity filter is client-side over the SAME bounded response;
 * - failure honesty: a detail load error renders verbatim with retry.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';
import {
  type ApiClient,
  ApiClientError,
} from '../src/api/client.js';
import {
  type ProjectResponse,
  type ScanDetailResponse,
  type ScanResponse,
  type ScansResponse,
  type SourceSnapshotResponse,
  type UsageResponse,
} from '@drobon/shared';
import userEvent from '@testing-library/user-event';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT: ProjectResponse = {
  project: {
    id: 'prj_test-sast-0001',
    name: 'Sast Project',
    description: '',
    status: 'ACTIVE',
    createdAt: '2026-09-27T10:00:00.000Z',
    updatedAt: '2026-09-27T10:00:00.000Z',
  },
};

const SNAPSHOT: SourceSnapshotResponse = {
  snapshot: {
    projectId: 'prj_test-sast-0001',
    fileCount: 2,
    totalBytes: 120,
    updatedAt: '2026-09-27T11:00:00.000Z',
    files: [
      { path: 'index.ts', bytes: 80 },
      { path: 'lib.ts', bytes: 40 },
    ],
  },
};

const USAGE: UsageResponse = {
  plan: 'FREE',
  period: {
    period: '2026-09',
    startUtc: '2026-09-01T00:00:00.000Z',
    endUtc: '2026-10-01T00:00:00.000Z',
  },
  used: 0,
  remaining: 3,
  limit: 3,
  quotaStatus: 'OK',
};

/** A COMPLETED SAST scan whose findings span severities and carry an XSS/
 * command-injection-shaped evidence string (displayed, never executed). */
function completedScan(): { scan: ScanResponse['scan']; detail: ScanDetailResponse } {
  const scan = {
    id: 'scan_completed_0001',
    projectId: 'prj_test-sast-0001',
    scanType: 'SAST' as const,
    status: 'COMPLETED' as const,
    createdAt: '2026-09-27T11:01:00.000Z',
    updatedAt: '2026-09-27T11:01:01.000Z',
    startedAt: '2026-09-27T11:01:00.500Z',
    completedAt: '2026-09-27T11:01:01.000Z',
    resultSummary: {
      findingsTotal: 3,
      findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0 },
      filesScanned: 2,
      filesSkipped: 0,
    },
  };
  const detail: ScanDetailResponse = {
    scan: {
      ...scan,
      findings: [
        {
          id: 'fnd_aaaa',
          scanId: scan.id,
          ruleId: 'DG-SAST-001',
          severity: 'HIGH',
          title: 'Shell command built from untrusted input',
          description: 'exec with interpolated input allows command injection.',
          cwe: 'CWE-78',
          file: 'cmd.ts',
          line: 2,
          column: 3,
          evidence: "exec(`rm -rf ${dir}`)",
          remediation: 'Avoid exec with interpolated input; use a safe API.',
          fingerprint: 'fp1',
        },
        {
          id: 'fnd_bbbb',
          scanId: scan.id,
          ruleId: 'DG-SAST-005',
          severity: 'HIGH',
          title: 'Hardcoded credential',
          description: 'Credential literal in source.',
          file: 'config.ts',
          line: 4,
          column: 1,
          evidence: "const apiKey = '<redacted>';",
          remediation: 'Move secrets to a secret manager.',
          fingerprint: 'fp2',
        },
        {
          id: 'fnd_cccc',
          scanId: scan.id,
          ruleId: 'DG-SAST-003',
          severity: 'MEDIUM',
          title: 'DangerouslySetInnerHTML with dynamic value',
          description: 'Raw HTML sink.',
          file: 'html.ts',
          line: 6,
          column: 11,
          evidence: 'dangerouslySetInnerHTML={{ __html: html }}',
          remediation: 'Render text or sanitize.',
          fingerprint: 'fp3',
        },
      ],
    },
  };
  return { scan, detail };
}

/** Every SAST-UI journey starts signed in (the default fixture is not). */
function signedInClient(overrides: Record<string, unknown> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async (): Promise<ProjectResponse> => PROJECT),
    getSources: vi.fn(async (): Promise<SourceSnapshotResponse> => SNAPSHOT),
    ...overrides,
  });
}

async function renderSastPage(overrides: Record<string, unknown> = {}): Promise<ApiClient> {
  const client = signedInClient(overrides);
  await renderAt('/projects/prj_test-sast-0001', client);
  return client;
}

describe('SAST UI: source snapshot section', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('no snapshot yet renders the honest empty state (a 404 is not an error)', async () => {
    const client = signedInClient({
      getSources: vi.fn(async (): Promise<SourceSnapshotResponse> => {
        throw new ApiClientError({
          kind: 'http',
          message: 'Not found.',
          status: 404,
          requestId: 'test-404',
        });
      }),
    });
    await renderAt('/projects/prj_test-sast-0001', client);
    expect(await screen.find('snapshot-empty')).toBeTruthy();
    expect(document.querySelector('[data-testid="source-upload-error"]')).toBeNull();
  });

  test('snapshot metadata renders: file count, bytes and the replacement rule', async () => {
    await renderSastPage();
    const meta = await screen.find('snapshot-meta');
    expect(meta.textContent).toContain('2 files');
    expect(meta.textContent).toContain('120 bytes');
    expect(meta.textContent).toContain('The latest upload replaces');
  });

  test('uploading files sends file names as paths and text content, then refreshes metadata', async () => {
    const uploadSources = vi.fn(async (): Promise<SourceSnapshotResponse> => SNAPSHOT);
    await renderSastPage({ uploadSources });

    const input = document.querySelector(
      '[data-testid="source-file-input"]',
    ) as HTMLInputElement | null;
    expect(input).not.toBeNull();

    const fileA = new File(['const x = 1;\n'], 'index.ts', { type: 'text/plain' });
    const fileB = new File(['export const y = 2;\n'], 'lib.ts', { type: 'text/plain' });
    const user = userEvent.setup();
    await user.upload(input!, [fileA, fileB]);

    // The change handler reads the files asynchronously (FileReader) —
    // wait for the upload call, don't assume event dispatch == done.
    const { waitFor } = await import('@testing-library/react');
    await waitFor(() => expect(uploadSources).toHaveBeenCalledTimes(1));
    const [projectId, files] = (uploadSources as unknown as { mock: { calls: unknown[][] } })
      .mock.calls[0] as [
      string,
      Array<{ path: string; content: string }>,
    ];
    expect(projectId).toBe('prj_test-sast-0001');
    expect(files).toEqual([
      { path: 'index.ts', content: 'const x = 1;\n' },
      { path: 'lib.ts', content: 'export const y = 2;\n' },
    ]);
    expect(await screen.find('snapshot-meta')).toBeTruthy();
  });

  test('a server-rejected upload shows the server message verbatim and keeps the old snapshot', async () => {
    const uploadSources = vi.fn(async (): Promise<SourceSnapshotResponse> => {
      throw new ApiClientError({
        kind: 'http',
        message: 'Source file .env is not allowed.',
        status: 422,
        requestId: 'test-422',
      });
    });
    await renderSastPage({ uploadSources });

    const input = document.querySelector(
      '[data-testid="source-file-input"]',
    ) as HTMLInputElement | null;
    const bad = new File(['SECRET=1\n'], '.env', { type: 'text/plain' });
    const user = userEvent.setup();
    await user.upload(input!, [bad]);

    const error = await screen.find('source-upload-error');
    expect(error.textContent).toBe('Source file .env is not allowed.');
    // The previous snapshot metadata is still visible (fail closed, no wipe).
    expect(await screen.find('snapshot-meta')).toBeTruthy();
  });

  test('archived projects cannot replace the snapshot (form hidden, note shown)', async () => {
    const client = signedInClient({
      getProject: vi.fn(async (): Promise<ProjectResponse> => ({
        project: { ...PROJECT.project, status: 'ARCHIVED' },
      })),
    });
    await renderAt('/projects/prj_test-sast-0001', client);
    expect(await screen.find('archived-source-note')).toBeTruthy();
    expect(document.querySelector('[data-testid="source-file-input"]')).toBeNull();
  });
});

describe('SAST UI: real findings on completed scans', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function clientWithCompletedScans(): ApiClient {
    const { scan, detail } = completedScan();
    return signedInClient({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
      getScan: vi.fn(async (): Promise<ScanDetailResponse> => detail),
    });
  }

  test('findings are lazy: nothing loads until "View findings", then renders in server order as text', async () => {
    const client = clientWithCompletedScans();
    await renderAt('/projects/prj_test-sast-0001', client);

    // The list shows the completed scan and its summary…
    expect(await screen.find('scan-result')).toBeTruthy();
    // …but no findings yet, and no detail request fired.
    expect(document.querySelector('[data-testid="findings-list"]')).toBeNull();
    expect((client.getScan as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(0);

    const button = document.querySelector('[data-testid="view-findings"]') as HTMLElement;
    button.click();

    const items = await screen.findAll('finding-item');
    expect(items.length).toBe(3);
    // Server order is severity order: the first finding is the HIGH rule-1.
    const first = items[0] as HTMLElement;
    expect(first.querySelector('[data-testid="finding-severity"]')?.textContent).toBe('HIGH');
    expect(first.querySelector('[data-testid="finding-rule"]')?.textContent).toBe('DG-SAST-001');
    expect(first.querySelector('[data-testid="finding-location"]')?.textContent).toContain(
      'cmd.ts:2',
    );
    expect(first.querySelector('[data-testid="finding-location"]')?.textContent).toContain(
      'CWE-78',
    );
    // Evidence is present as literal text (React escaping — never HTML).
    expect(first.querySelector('[data-testid="finding-evidence"]')?.textContent).toBe(
      'exec(`rm -rf ${dir}`)',
    );
    expect(first.querySelector('[data-testid="finding-remediation"]')?.textContent).toContain(
      'safe API',
    );
    // Redacted secrets stay redacted.
    const second = items[1] as HTMLElement;
    expect(second.querySelector('[data-testid="finding-evidence"]')?.textContent).toContain(
      '<redacted>',
    );
    expect(document.body.innerHTML).not.toContain('sk_live_abcdef123456');
  });

  test('the severity filter is client-side over the same response (no extra request)', async () => {
    const client = clientWithCompletedScans();
    await renderAt('/projects/prj_test-sast-0001', client);

    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    expect(await screen.findAll('finding-item')).toHaveLength(3);

    const select = document.querySelector(
      '[data-testid="findings-filter"]',
    ) as HTMLSelectElement;
    select.value = 'HIGH';
    select.dispatchEvent(new Event('change', { bubbles: true }));

    const visible = await screen.findAll('finding-item');
    expect(visible.length).toBe(2);
    expect(
      (visible as HTMLElement[]).every(
        (item) => item.querySelector('[data-testid="finding-severity"]')?.textContent === 'HIGH',
      ),
    ).toBe(true);
    // Same single detail request — filtering never re-fetches.
    expect((client.getScan as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(1);

    // Filtering to a severity with no findings is honest about it.
    select.value = 'CRITICAL';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    expect(await screen.find('findings-empty')).toBeTruthy();
  });

  test('a detail-load failure renders verbatim with a retry that can recover', async () => {
    const { detail } = completedScan();
    const getScan = vi
      .fn<() => Promise<ScanDetailResponse>>()
      .mockRejectedValueOnce(
        new ApiClientError({
          kind: 'http',
          message: 'The scan is not available.',
          status: 403,
          requestId: 'test-403',
        }),
      )
      .mockResolvedValueOnce(detail);
    const client = signedInClient({
      getScans: vi.fn(async (): Promise<ScansResponse> => ({
        scans: [completedScan().scan],
      })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => USAGE),
      getScan,
    });
    await renderAt('/projects/prj_test-sast-0001', client);

    (document.querySelector('[data-testid="view-findings"]') as HTMLElement).click();
    const error = await screen.find('findings-error');
    expect(error.textContent).toBe('The scan is not available.');

    // Retry recovers into the findings list.
    const retryButton = (await screen.find('findings-retry')) as HTMLElement;
    retryButton.click();
    expect(await screen.findAll('finding-item')).toHaveLength(3);
  });

  test('the scan form stays honest about which engines exist', async () => {
    const client = clientWithCompletedScans();
    await renderAt('/projects/prj_test-sast-0001', client);
    expect(await screen.find('scan-form')).toBeTruthy();
    const formText = (document.querySelector('[data-testid="scan-form"]') as HTMLElement)
      .textContent;
    expect(formText).toContain('never executed');
    expect(formText).toContain('SCAN_ENGINE_NOT_IMPLEMENTED');
  });
});

/** Tiny finders kept local so the suite reads like the user's journey. */
const screen = {
  find: async (testid: string): Promise<HTMLElement> => {
    const { waitFor } = await import('@testing-library/react');
    const found = await waitFor(() => {
      const el = document.querySelector(`[data-testid="${testid}"]`);
      if (el === null) {
        throw new Error(`missing ${testid}`);
      }
      return el as HTMLElement;
    });
    return found;
  },
  findAll: async (testid: string): Promise<HTMLElement[]> => {
    await screen.find(testid);
    return Array.from(document.querySelectorAll(`[data-testid="${testid}"]`)) as HTMLElement[];
  },
};
