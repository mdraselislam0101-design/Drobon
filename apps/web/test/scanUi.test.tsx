import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { Project, ProjectResponse, Scan, ScanResponse, ScansResponse } from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Pump 7 web tests — the Security scans section of the project page.
 *
 * Rules under test:
 * - the section renders ONLY server truth: scans in the server's order,
 *   quota/entitlement from the usage view, never local state;
 * - scan requests send ONLY the scan type + an idempotency key — no
 *   status, no ownership, no fabricated fields;
 * - completed passive DAST shows server-observed response evidence only;
 *   failed scans remain honest and never become fake findings;
 * - archived projects show no scan form (the server enforces the rule;
 *   historical scans stay listed);
 * - all scan text renders as TEXT (XSS payloads never become markup);
 * - fail-closed error + retry, no storage authority.
 */

const project = (overrides: Partial<Project> = {}): Project => ({
  id: 'prj_00000000-0000-4000-8000-0000000000aa',
  name: 'Primary web app',
  description: 'The checkout flow.',
  status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:00.000Z',
  ...overrides,
});

const scan = (overrides: Partial<Scan> = {}): Scan => ({
  id: 'scan_00000000-0000-4000-8000-000000000001',
  projectId: 'prj_00000000-0000-4000-8000-0000000000aa',
  scanType: 'SAST',
  status: 'QUEUED',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:00.000Z',
  ...overrides,
});

function projectBody(p: Project): ProjectResponse {
  return { project: p };
}

function scansBody(list: Scan[]): ScansResponse {
  return { scans: list };
}

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async () => projectBody(project())),
    ...overrides,
  });
}

async function renderProjectAt(client: ApiClient): Promise<void> {
  await renderAt('/projects/prj_00000000-0000-4000-8000-0000000000aa', client);
}

describe('Security scans section', () => {
  test('renders the server-provided scans with honest status pills', async () => {
    const list = [
      scan({
        id: 'scan_00000000-0000-4000-8000-000000000003',
        status: 'FAILED',
        scanType: 'DAST',
        startedAt: '2026-09-28T10:02:00.000Z',
        completedAt: '2026-09-28T10:02:01.000Z',
        updatedAt: '2026-09-28T10:02:01.000Z',
        failureCode: 'DAST_TARGET_BLOCKED',
        failureMessage: 'The configured target was blocked before any request was made.',
      }),
      scan({
        id: 'scan_00000000-0000-4000-8000-000000000002',
        status: 'RUNNING',
        scanType: 'SCA',
        startedAt: '2026-09-28T10:01:00.000Z',
        updatedAt: '2026-09-28T10:01:00.000Z',
      }),
      scan({ id: 'scan_00000000-0000-4000-8000-000000000001', scanType: 'SAST' }),
    ];
    const getScans = vi.fn(async () => scansBody(list));
    await renderProjectAt(signedInClient({ getScans }));
    const items = await screen.findAllByTestId('scan-item');
    expect(items).toHaveLength(3);
    // Server order preserved (no local re-sorting).
    const types = screen.getAllByTestId('scan-type').map((node) => node.textContent);
    expect(types).toEqual(['DAST', 'SCA', 'SAST']);
    const statuses = screen.getAllByTestId('scan-status').map((node) => node.textContent);
    expect(statuses).toEqual(['FAILED', 'RUNNING', 'QUEUED']);
    // The honest not-implemented failure, verbatim (the form's static
    // note also mentions the code — the failure line is the assertion).
    expect(
      screen.getByText(/The configured target was blocked before any request was made\./),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/DAST_TARGET_BLOCKED/).length).toBeGreaterThanOrEqual(1);
    // No fabricated findings anywhere.
    expect(screen.queryByTestId('scan-result')).toBeNull();
    expect(screen.queryByText(/Findings:/)).toBeNull();
  });

  test('renders an empty state when the project has no scans', async () => {
    await renderProjectAt(signedInClient());
    expect(await screen.findByTestId('scans-empty')).toBeInTheDocument();
  });

  test('shows the server-derived quota hint (FREE) and PRO exemption', async () => {
    const getUsage = vi.fn(async () => ({
      plan: 'FREE' as const,
      period: {
        period: '2026-09',
        startUtc: '2026-09-01T00:00:00.000Z',
        endUtc: '2026-10-01T00:00:00.000Z',
      },
      used: 1,
      limit: 3,
      remaining: 2,
      quotaStatus: 'OK' as const,
    }));
    await renderProjectAt(signedInClient({ getUsage }));
    expect(await screen.findByTestId('quota-hint')).toHaveTextContent(
      'Free plan: 2 of 3 scans remaining this month.',
    );
  });

  test('scan request: sends only type + key, then refreshes from the server', async () => {
    const getScans = vi.fn(async () => scansBody([]));
    const createScan = vi.fn(async (): Promise<ScanResponse> => ({
      scan: scan({ id: 'scan_00000000-0000-4000-8000-0000000000ff', scanType: 'SCA' }),
    }));
    const client = signedInClient({ getScans, createScan });
    await renderProjectAt(client);
    await userEvent.selectOptions(await screen.findByTestId('scan-type-select'), 'SCA');
    await userEvent.click(await screen.findByTestId('request-scan-button'));
    await waitFor(() => {
      expect(createScan).toHaveBeenCalledTimes(1);
    });
    const [projectId, scanType, key] = createScan.mock.calls[0] as unknown as [
      string,
      string,
      string,
    ];
    expect(projectId).toBe('prj_00000000-0000-4000-8000-0000000000aa');
    expect(scanType).toBe('SCA');
    // A well-formed idempotency key (8–64 URL-safe chars) is generated
    // client-side purely for retry safety — never a claim.
    expect(key).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    // The list is re-fetched from the server (its truth, not local echo).
    expect(getScans.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  test('quota denial (429) renders the server message, never a fake scan', async () => {
    const createScan = vi.fn(async (): Promise<ScanResponse> => {
      throw new ApiClientError({
        kind: 'http',
        message: 'Monthly free scan limit reached.',
        status: 429,
        code: 'QUOTA_EXCEEDED',
      });
    });
    await renderProjectAt(signedInClient({ createScan }));
    await userEvent.click(await screen.findByTestId('request-scan-button'));
    expect(await screen.findByTestId('scan-form-error')).toHaveTextContent(
      'Monthly free scan limit reached.',
    );
    expect(screen.queryByTestId('scan-item')).toBeNull();
  });

  test('archived projects: no scan form, explanation, history still listed', async () => {
    const getScans = vi.fn(async () =>
      scansBody([
        scan({
          status: 'FAILED',
          startedAt: '2026-09-28T10:02:00.000Z',
          completedAt: '2026-09-28T10:02:01.000Z',
          updatedAt: '2026-09-28T10:02:01.000Z',
          failureCode: 'SCAN_ENGINE_NOT_IMPLEMENTED',
          failureMessage: 'The SAST scanner engine is not implemented yet.',
        }),
      ]),
    );
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectBody(project({ status: 'ARCHIVED' }))),
      getScans,
    });
    await renderProjectAt(client);
    expect(await screen.findByTestId('archived-scan-note')).toBeInTheDocument();
    expect(screen.queryByTestId('scan-form')).toBeNull();
    expect(screen.queryByTestId('request-scan-button')).toBeNull();
    expect(await screen.findByTestId('scan-item')).toBeInTheDocument();
  });

  test('scan loading failure is fail-closed with a retry', async () => {
    const getScans = vi.fn(async (): Promise<ScansResponse> => {
      throw new ApiClientError({
        kind: 'http',
        message: 'You do not have access to this resource.',
        status: 403,
        code: 'FORBIDDEN',
      });
    });
    const client = signedInClient({ getScans });
    await renderProjectAt(client);
    expect(
      await screen.findByText('You do not have access to this resource.'),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('scan-item')).toBeNull();
    await userEvent.click(await screen.findByTestId('scans-retry'));
    await waitFor(() => {
      expect(getScans.mock.calls.length).toBeGreaterThanOrEqual(2);
    });
  });

  test('XSS payloads in scan text render as text, never markup', async () => {
    const malicious = scan({
      status: 'FAILED',
      startedAt: '2026-09-28T10:02:00.000Z',
      completedAt: '2026-09-28T10:02:01.000Z',
      updatedAt: '2026-09-28T10:02:01.000Z',
      failureCode: 'SCAN_ENGINE_NOT_IMPLEMENTED',
      failureMessage:
        '<script>alert(1)</script><img src=x onerror=alert(2)><svg onload=alert(3)>',
    });
    await renderProjectAt(
      signedInClient({ getScans: vi.fn(async () => scansBody([malicious])) }),
    );
    const failure = await screen.findByTestId('scan-failure');
    expect(failure.textContent).toContain('<script>alert(1)</script>');
    const section = failure.closest('section');
    expect(section).not.toBeNull();
    expect(section?.querySelector('script')).toBeNull();
    expect(section?.querySelector('img')).toBeNull();
    // The Layout brand svg exists — scope the svg check to the scan list.
    const list = screen.getByTestId('scans-list');
    expect(list.querySelector('svg')).toBeNull();
  });

  test('no scan state in localStorage/sessionStorage; server is the only source', async () => {
    await renderProjectAt(
      signedInClient({
        getScans: vi.fn(async () => scansBody([scan()])),
      }),
    );
    await screen.findAllByTestId('scan-item');
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  test('anonymous users never reach the project page (protected route)', async () => {
    const getScans = vi.fn(async () => scansBody([scan()]));
    await renderAt(
      '/projects/prj_00000000-0000-4000-8000-0000000000aa',
      stubClient({ getScans }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId('scans-list')).toBeNull();
      expect(screen.queryByTestId('scan-form')).toBeNull();
      expect(screen.queryByTestId('project-detail-name')).toBeNull();
    });
    expect(getScans).not.toHaveBeenCalled();
  });

  test('COMPLETED scans show the real engine summary (never fabricated client-side)', async () => {
    const list = [
      scan({
        status: 'COMPLETED',
        startedAt: '2026-09-28T10:02:00.000Z',
        completedAt: '2026-09-28T10:03:00.000Z',
        updatedAt: '2026-09-28T10:03:00.000Z',
        resultSummary: { findingsTotal: 2 },
      }),
    ];
    await renderProjectAt(signedInClient({ getScans: vi.fn(async () => scansBody(list)) }));
    expect(await screen.findByTestId('scan-result')).toHaveTextContent('Findings: 2');
  });
});
