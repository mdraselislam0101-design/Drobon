import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { Assessment, AssessmentDetailResponse, CurrentUserResponse, Project, UsageResponse } from '@drobon/shared';
import { type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT_ID = 'prj_00000000-0000-4000-8000-0000000000aa';
const ASSESSMENT_ID = 'asm_00000000-0000-4000-8000-0000000000a1';
const TARGET = 'https://fixture.example.org/';

const project: Project = {
  id: PROJECT_ID, name: 'Professional target', description: '', status: 'ACTIVE',
  createdAt: '2026-09-29T10:00:00.000Z', updatedAt: '2026-09-29T10:00:00.000Z', dastTargetUrl: TARGET,
};
const assessment: Assessment = {
  id: ASSESSMENT_ID, projectId: PROJECT_ID, title: 'Quarterly authorization review',
  objectives: ['Review server authorization'],
  scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: ['admin.fixture.example.org'], notes: 'Exact-host scope only.' },
  status: 'ACTIVE', createdAt: '2026-09-29T10:00:00.000Z', updatedAt: '2026-09-29T10:10:00.000Z', startedAt: '2026-09-29T10:10:00.000Z',
  authorizationDeclarations: [], history: [
    { id: 'ase_00000000-0000-4000-8000-0000000000a1', type: 'CREATED', at: '2026-09-29T10:00:00.000Z' },
    { id: 'ase_00000000-0000-4000-8000-0000000000a2', type: 'STATUS_CHANGED', at: '2026-09-29T10:10:00.000Z', status: 'ACTIVE' },
  ],
};
const detail: AssessmentDetailResponse = {
  assessment,
  progress: { totalScans: 1, completedScans: 1, failedScans: 0, activeScans: 0, findingsTotal: 2,
    recentScans: [{ id: 'scan_00000000-0000-4000-8000-000000000001', scanType: 'DAST', status: 'COMPLETED', createdAt: '2026-09-29T10:20:00.000Z', completedAt: '2026-09-29T10:21:00.000Z', targetUrl: TARGET, findingsTotal: 2, reportAvailable: true }] },
};
const usage: UsageResponse = { plan: 'FREE', quotaStatus: 'OK', used: 0, limit: 3, remaining: 3, period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' } };

function professionalClient(userType: 'SECURITY_PROFESSIONAL' | 'PENTESTER', overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: { ...TEST_USER, userType } })),
    getProject: vi.fn(async () => ({ project })),
    getScans: vi.fn(async () => ({ scans: [] })),
    getUsage: vi.fn(async () => usage),
    getAssessments: vi.fn(async () => ({ assessments: [assessment] })),
    getAssessment: vi.fn(async () => detail),
    ...overrides,
  });
}

describe('structured assessment project UI', () => {
  test.each(['SECURITY_PROFESSIONAL', 'PENTESTER'] as const)('%s sees bounded scope/history and can link a scan plus record—not verify—a declaration', async (userType) => {
    const user = userEvent.setup();
    const createScan = vi.fn(async () => ({ scan: { id: 'scan_00000000-0000-4000-8000-000000000002', projectId: PROJECT_ID, scanType: 'SAST' as const, status: 'QUEUED' as const, assessmentId: ASSESSMENT_ID, createdAt: '2026-09-29T10:30:00.000Z', updatedAt: '2026-09-29T10:30:00.000Z' } }));
    const recordAssessmentAuthorization = vi.fn(async () => ({ assessment }));
    const client = professionalClient(userType, { createScan, recordAssessmentAuthorization });
    await renderAt(`/projects/${PROJECT_ID}`, client);

    expect(await screen.findByTestId('assessments-section')).toBeTruthy();
    expect(screen.getByText(/Third-party permission is not independently verified/)).toBeTruthy();
    expect(screen.getByTestId('assessment-authorization-status').textContent).toBe('UNVERIFIED');
    expect(screen.getByTestId('assessment-detail').textContent).toContain('report saved');
    expect(screen.getByTestId('assessment-history').textContent).toContain('STATUS_CHANGED');

    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByTestId('assessment-authorization-action'));
    await waitFor(() => expect(recordAssessmentAuthorization).toHaveBeenCalledWith(PROJECT_ID, ASSESSMENT_ID, 'DECLARE'));

    await user.selectOptions(screen.getByTestId('scan-assessment-select'), ASSESSMENT_ID);
    await user.click(screen.getByTestId('request-scan-button'));
    await waitFor(() => expect(createScan).toHaveBeenCalled());
    expect(createScan.mock.calls[0]).toEqual([PROJECT_ID, 'SAST', expect.any(String), undefined, ASSESSMENT_ID, undefined]);
  });

  test('classification-only surface stays hidden for Developer and Student presentation', async () => {
    const client = stubClient({
      getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: { ...TEST_USER, userType: 'STUDENT' } })),
      getProject: vi.fn(async () => ({ project })),
      getScans: vi.fn(async () => ({ scans: [] })),
      getUsage: vi.fn(async () => usage),
    });
    await renderAt(`/projects/${PROJECT_ID}`, client);
    await waitFor(() => expect(screen.getByTestId('scan-form')).toBeTruthy());
    expect(screen.queryByTestId('assessments-section')).toBeNull();
    expect(screen.queryByTestId('scan-assessment-select')).toBeNull();
  });
});
