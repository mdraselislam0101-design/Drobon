import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { FindingDetailResponse, FindingsPageResponse, Project, ProjectResponse, Scan, ScanDetailResponse, ScansResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT_ID = 'prj_00000000-0000-4000-8000-0000000000aa';
const SCAN_ID = 'scan_00000000-0000-4000-8000-000000000001';
const TARGET = 'https://fixture.example.org/';

function project(overrides: Partial<Project> = {}): Project {
  return {
    id: PROJECT_ID,
    name: 'Fixture application',
    description: '',
    status: 'ACTIVE',
    createdAt: '2026-09-28T10:00:00.000Z',
    updatedAt: '2026-09-28T10:00:00.000Z',
    ...overrides,
  };
}

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: TEST_USER })), ...overrides });
}

describe('passive DAST project UI', () => {
  test('owner configures/removes the target and DAST stays disabled until the server confirms it', async () => {
    const saved = project({ dastTargetUrl: TARGET, updatedAt: '2026-09-28T10:01:00.000Z' });
    const cleared = project({ updatedAt: '2026-09-28T10:02:00.000Z' });
    const setDastTarget = vi.fn(async (): Promise<ProjectResponse> => ({ project: saved }));
    const clearDastTarget = vi.fn(async (): Promise<ProjectResponse> => ({ project: cleared }));
    const client = signedInClient({
      getProject: vi.fn(async () => ({ project: project() })),
      setDastTarget,
      clearDastTarget,
    });
    await renderAt(`/projects/${PROJECT_ID}`, client);

    const typeSelect = await screen.findByTestId('scan-type-select');
    expect(typeSelect.querySelector('option[value="DAST"]')).toBeDisabled();
    expect(screen.getByTestId('dast-authorization-status')).toHaveTextContent('Target authorization status: UNVERIFIED');
    expect(screen.getByTestId('dast-authorization-status')).toHaveTextContent('does not independently verify permission to assess');
    await userEvent.type(screen.getByLabelText('Project target URL'), TARGET);
    await userEvent.click(screen.getByRole('button', { name: 'Save target' }));
    await waitFor(() => expect(setDastTarget).toHaveBeenCalledWith(PROJECT_ID, TARGET));
    expect(await screen.findByTestId('dast-configured-target')).toHaveTextContent(TARGET);
    expect(typeSelect.querySelector('option[value="DAST"]')).not.toBeDisabled();

    await userEvent.click(screen.getByRole('button', { name: 'Remove target' }));
    await waitFor(() => expect(clearDastTarget).toHaveBeenCalledWith(PROJECT_ID));
    expect(screen.queryByTestId('dast-configured-target')).toBeNull();
    expect(typeSelect.querySelector('option[value="DAST"]')).toBeDisabled();
  });

  test('renders only bounded observed HTTP evidence from a completed DAST detail', async () => {
    const completed: Scan = {
      id: SCAN_ID,
      projectId: PROJECT_ID,
      scanType: 'DAST',
      status: 'COMPLETED',
      targetUrl: TARGET,
      createdAt: '2026-09-28T10:00:00.000Z',
      updatedAt: '2026-09-28T10:00:02.000Z',
      startedAt: '2026-09-28T10:00:00.100Z',
      completedAt: '2026-09-28T10:00:02.000Z',
      resultSummary: { findingsTotal: 1, requestsMade: 1, redirectsFollowed: 0, partial: false },
    };
    const scans: ScansResponse = { scans: [completed] };
    const detail: ScanDetailResponse = {
      scan: {
        ...completed,
        findings: [{
          id: 'fnd_0123456789abcdef01234567',
          scanId: SCAN_ID,
          ruleId: 'DG-DAST-001',
          scanner: 'DAST',
          projectId: PROJECT_ID,
          targetUrl: TARGET,
          endpoint: TARGET,
          method: 'GET',
          responseStatus: 200,
          responseTimeMs: 42,
          contentType: 'text/html',
          observedAt: '2026-09-28T10:00:01.000Z',
          observedHeaders: ['x-frame-options: missing'],
          severity: 'LOW',
          title: 'Frame embedding policy was not observed',
          description: 'The observed response did not include an X-Frame-Options header.',
          evidence: 'HTTP 200 response had no X-Frame-Options header.',
          remediation: 'Set an appropriate frame-ancestors policy.',
          fingerprint: 'a'.repeat(64),
        }],
        dast: {
          targetUrl: TARGET,
          requestCount: 1,
          redirectsFollowed: 0,
          partial: false,
          observations: [{
            endpoint: TARGET,
            method: 'GET',
            status: 200,
            observedAt: '2026-09-28T10:00:01.000Z',
            responseTimeMs: 42,
            bodyBytes: 128,
            bodyTruncated: false,
            contentType: 'text/html',
            headers: ['x-frame-options: missing'],
          }],
        },
      },
    };
    const finding = detail.scan.findings?.[0];
    if (finding === undefined) throw new Error('missing DAST fixture finding');
    const getProject = vi.fn(async () => ({ project: project({ dastTargetUrl: TARGET }) }));
    const getScans = vi.fn(async () => scans);
    const getFindings = vi.fn(async (): Promise<FindingsPageResponse> => ({
      findings: [finding], page: 1, pageSize: 20, total: 1, totalPages: 1,
    }));
    const getFinding = vi.fn(async (): Promise<FindingDetailResponse> => ({ project: project({ dastTargetUrl: TARGET }), scan: detail.scan, finding }));
    const getScan = vi.fn(async () => detail);
    const client = signedInClient({ getProject, getScans, getScan, getFindings, getFinding });
    await renderAt(`/projects/${PROJECT_ID}`, client);

    expect(await screen.findByTestId('scan-result')).toHaveTextContent('Requests: 1');
    await userEvent.click(await screen.findByTestId('view-findings'));
    expect(await screen.findByTestId('dast-observations')).toBeInTheDocument();
    expect(screen.getByTestId('dast-observation')).toHaveTextContent('GET · HTTP 200');
    await userEvent.click(screen.getByTestId('finding-detail-button'));
    expect(await screen.findByTestId('finding-evidence')).toHaveTextContent('HTTP 200 response had no X-Frame-Options header.');
    expect(screen.getByText(/No browser, JavaScript, authentication, or crawling was used/)).toBeInTheDocument();
    expect(getFindings).toHaveBeenCalledWith(PROJECT_ID, SCAN_ID, { page: 1, pageSize: 20 });
    expect(getScan).toHaveBeenCalledWith(PROJECT_ID, SCAN_ID);
    expect(getFinding).toHaveBeenCalledWith(PROJECT_ID, SCAN_ID, finding.id);
  });

  test('archived projects display configured target read-only and hide the DAST target form', async () => {
    const client = signedInClient({
      getProject: vi.fn(async () => ({
        project: project({ status: 'ARCHIVED', dastTargetUrl: TARGET }),
      })),
    });
    await renderAt(`/projects/${PROJECT_ID}`, client);

    expect(await screen.findByTestId('archived-dast-target-note')).toHaveTextContent(
      'Archived projects cannot change the DAST target.',
    );
    expect(screen.getByTestId('dast-configured-target')).toHaveTextContent(TARGET);
    expect(screen.queryByTestId('dast-target-form')).toBeNull();
  });
});
