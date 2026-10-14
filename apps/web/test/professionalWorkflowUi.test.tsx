import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type {
  AssessmentSummaryResponse,
  CurrentUserResponse,
  Project,
  ScanComparisonResponse,
  ScansResponse,
  UsageResponse,
} from '@drobon/shared';
import { type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Phase 22 Pump 3 web suite: the regression-compare and assessment-summary
 * surfaces render ONLY the server-computed, honest aggregates — never
 * client-side verdicts.
 */

const PROJECT_ID = 'prj_00000000-0000-4000-8000-0000000000aa';
const SCAN_A = 'scan_00000000-0000-4000-8000-000000000001';
const SCAN_B = 'scan_00000000-0000-4000-8000-000000000002';
const ASSESSMENT_ID = 'asm_00000000-0000-4000-8000-0000000000a1';

const project: Project = {
  id: PROJECT_ID, name: 'Professional regression lab', description: '', status: 'ACTIVE',
  createdAt: '2026-09-30T10:00:00.000Z', updatedAt: '2026-09-30T10:00:00.000Z',
};

const scan = (id: string): ScansResponse['scans'][number] => ({
  id, projectId: PROJECT_ID, scanType: 'SAST', status: 'COMPLETED',
  createdAt: '2026-09-30T10:05:00.000Z', updatedAt: '2026-09-30T10:06:00.000Z', completedAt: '2026-09-30T10:06:00.000Z',
  resultSummary: { findingsTotal: 2 },
});

const comparison: ScanComparisonResponse = {
  projectId: PROJECT_ID,
  scanType: 'SAST',
  baselineScanId: SCAN_B,
  currentScanId: SCAN_A,
  generatedAt: '2026-09-30T10:10:00.000Z',
  counts: { new: 1, unchanged: 1, resolved: 1, reopened: 0, changed: 0 },
  entries: [
    { fingerprint: 'c'.repeat(64), findingId: `fnd_${'c'.repeat(24)}`, ruleId: 'DG-SAST-002', location: 'src/app.js', state: 'NEW', currentSeverity: 'HIGH' },
    { fingerprint: 'd'.repeat(64), findingId: `fnd_${'d'.repeat(24)}`, ruleId: 'DG-SAST-001', location: 'src/app.js', state: 'UNCHANGED', baselineSeverity: 'HIGH', currentSeverity: 'HIGH' },
    { fingerprint: 'e'.repeat(64), findingId: `fnd_${'e'.repeat(24)}`, ruleId: 'DG-SAST-004', location: 'src/app.js', state: 'RESOLVED', baselineSeverity: 'MEDIUM' },
  ],
};

const usage: UsageResponse = { plan: 'FREE', quotaStatus: 'OK', used: 0, limit: 3, remaining: 3, period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' } };

const assessmentDetail = {
  assessment: {
    id: ASSESSMENT_ID, projectId: PROJECT_ID, title: 'Quarterly review',
    objectives: ['Objective one'], scope: { inScopeHosts: ['app.example.test'], outOfScopeHosts: [] },
    status: 'ACTIVE' as const, createdAt: '2026-09-30T09:00:00.000Z', updatedAt: '2026-09-30T09:05:00.000Z',
    startedAt: '2026-09-30T09:05:00.000Z', authorizationDeclarations: [], history: [],
  },
  progress: { totalScans: 2, completedScans: 2, failedScans: 0, activeScans: 0, findingsTotal: 3, recentScans: [] },
};

const summary: AssessmentSummaryResponse = {
  assessment: { id: ASSESSMENT_ID, title: 'Quarterly review', status: 'ACTIVE', createdAt: '2026-09-30T09:00:00.000Z', startedAt: '2026-09-30T09:05:00.000Z' },
  objectivesTotal: 1,
  scope: { inScopeHosts: ['app.example.test'], outOfScopeHosts: [] },
  totals: {
    scansLinked: 2, scansCompleted: 2, scansFailed: 0, scansActive: 0,
    findingsTotal: 3, findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0 },
    partialScans: 0,
  },
  scans: [
    { scanId: SCAN_A, scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-30T10:05:00.000Z', completedAt: '2026-09-30T10:06:00.000Z', findingsTotal: 2, findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 }, reportAvailable: true },
    { scanId: SCAN_B, scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-30T09:10:00.000Z', completedAt: '2026-09-30T09:11:00.000Z', findingsTotal: 1, findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 }, reportAvailable: false },
  ],
  generatedAt: '2026-09-30T10:12:00.000Z',
};

function professionalClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: { ...TEST_USER, userType: 'SECURITY_PROFESSIONAL' } })),
    getProject: vi.fn(async () => ({ project })),
    getScans: vi.fn(async () => ({ scans: [scan(SCAN_A), scan(SCAN_B)] })),
    getUsage: vi.fn(async () => usage),
    getAssessments: vi.fn(async () => ({ assessments: [assessmentDetail.assessment] })),
    getAssessment: vi.fn(async () => assessmentDetail),
    compareScans: vi.fn(async (): Promise<ScanComparisonResponse> => comparison),
    getAssessmentSummary: vi.fn(async (): Promise<AssessmentSummaryResponse> => summary),
    ...overrides,
  });
}

describe('professional regression and summary UI (Phase 22 Pump 3)', () => {
  test('regression compare renders the server-computed honest states', async () => {
    const user = userEvent.setup();
    const client = professionalClient();
    await renderAt(`/projects/${PROJECT_ID}`, client);

    const openButton = await screen.findByTestId(`scan-compare-open-${SCAN_A}`);
    await user.click(openButton);
    await user.selectOptions(screen.getByTestId(`scan-compare-select-${SCAN_A}`), SCAN_B);
    await user.click(screen.getByTestId(`scan-compare-run-${SCAN_A}`));

    await waitFor(() => expect(screen.getByTestId(`scan-compare-result-${SCAN_A}`)).toBeTruthy());
    expect(client.compareScans).toHaveBeenCalledWith(PROJECT_ID, SCAN_A, SCAN_B);
    expect(screen.getByTestId(`scan-compare-new-${SCAN_A}`).textContent).toContain('NEW 1');
    expect(screen.getByTestId(`scan-compare-resolved-${SCAN_A}`).textContent).toContain('RESOLVED 1');
    expect(screen.getByTestId(`scan-compare-result-${SCAN_A}`).textContent).toContain('never proof of repair');
    expect(screen.getByTestId(`scan-compare-result-${SCAN_A}`).textContent).toContain('DG-SAST-002');
  });

  test('assessment engagement summary renders honest bounded totals', async () => {
    const user = userEvent.setup();
    const client = professionalClient();
    await renderAt(`/projects/${PROJECT_ID}`, client);

    await user.click(await screen.findByTestId('assessment-summary-load'));
    await waitFor(() => expect(screen.getByTestId('assessment-summary-content')).toBeTruthy());
    expect(client.getAssessmentSummary).toHaveBeenCalledWith(PROJECT_ID, ASSESSMENT_ID);
    expect(screen.getByTestId('assessment-summary-scans').textContent).toContain('2 completed');
    expect(screen.getByTestId('assessment-summary-findings').textContent).toBe('3');
    expect(screen.getByTestId('assessment-summary-content').textContent).toContain('no security score');
    expect(screen.getByTestId(`assessment-summary-scan-${SCAN_A}`).textContent).toContain('report saved');
  });
});
