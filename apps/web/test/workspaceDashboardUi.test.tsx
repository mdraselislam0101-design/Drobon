import { screen, within } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import type { SubscriptionResponse, UsageResponse, WorkspaceSecurityOverviewResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

function signedIn(userType: 'DEVELOPER' | 'STUDENT' | 'SECURITY_PROFESSIONAL' | 'PENTESTER' | null, overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType } })),
    ...overrides,
  });
}

const STUDENT_OVERVIEW: WorkspaceSecurityOverviewResponse = { overview: {
  generatedAt: '2026-09-01T00:00:00.000Z',
  projects: { total: 1, active: 1, archived: 0, dastTargetsConfigured: 0, recent: [{
    id: 'prj_00000000-0000-4000-8000-000000000001', name: 'Learning project', status: 'ACTIVE', updatedAt: '2026-09-01T00:00:00.000Z', dastTargetConfigured: false,
  }] },
  scans: { total: 1, byStatus: { QUEUED: 0, RUNNING: 0, COMPLETED: 1, FAILED: 0, TIMED_OUT: 0 }, recent: [{
    scanId: 'scan_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000001',
    scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-01T00:00:00.000Z', completedAt: '2026-09-01T00:01:00.000Z',
    findingsTotal: 1, partial: false, reportAvailable: true, dastObservationsCount: null, scaAssessmentState: null, scaDatasetStatus: null,
  }] },
  findings: {
    currentObserved: 1, unresolved: 1,
    unresolvedBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
    byLifecycleState: { OPEN: 0, ACKNOWLEDGED: 0, IN_PROGRESS: 1, RESOLVED: 0, REOPENED: 0 },
    byVerificationState: { OBSERVED: 1, NOT_OBSERVED_IN_LATEST_SCAN: 0 },
    recent: [{
      findingId: 'fnd_000000000000000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000001',
      scanId: 'scan_00000000-0000-4000-8000-000000000001', scanner: 'SAST', ruleId: 'TS-EVAL-001', severity: 'HIGH',
      lifecycleState: 'IN_PROGRESS', verificationState: 'OBSERVED', observedAt: '2026-09-01T00:01:00.000Z', workflowUpdatedAt: '2026-09-01T00:02:00.000Z',
    }],
  },
  reports: { availableCount: 1, recent: [{
    reportId: 'rpt_0123456789abcdef01234567', projectId: 'prj_00000000-0000-4000-8000-000000000001',
    scanId: 'scan_00000000-0000-4000-8000-000000000001', generatedAt: '2026-09-01T00:03:00.000Z',
  }] },
} };

const PROFESSIONAL_OVERVIEW: WorkspaceSecurityOverviewResponse = { overview: {
  generatedAt: '2026-09-02T00:00:00.000Z',
  projects: { total: 1, active: 1, archived: 0, dastTargetsConfigured: 0, recent: [{
    id: 'prj_00000000-0000-4000-8000-000000000001', name: 'Professional assessment', status: 'ACTIVE', updatedAt: '2026-09-02T00:00:00.000Z', dastTargetConfigured: false,
  }] },
  scans: { total: 3, byStatus: { QUEUED: 0, RUNNING: 0, COMPLETED: 3, FAILED: 0, TIMED_OUT: 0 }, recent: [
    { scanId: 'scan_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000001', scanType: 'DAST', status: 'COMPLETED', createdAt: '2026-09-02T00:00:00.000Z', completedAt: '2026-09-02T00:01:00.000Z', findingsTotal: 0, partial: false, reportAvailable: false, dastObservationsCount: 2, scaAssessmentState: null, scaDatasetStatus: null },
    { scanId: 'scan_00000000-0000-4000-8000-000000000002', projectId: 'prj_00000000-0000-4000-8000-000000000001', scanType: 'SCA', status: 'COMPLETED', createdAt: '2026-09-02T00:00:00.000Z', completedAt: '2026-09-02T00:01:00.000Z', findingsTotal: 0, partial: false, reportAvailable: true, dastObservationsCount: null, scaAssessmentState: 'NOT_ASSESSED', scaDatasetStatus: 'NO_DATA_LOADED' },
    { scanId: 'scan_00000000-0000-4000-8000-000000000003', projectId: 'prj_00000000-0000-4000-8000-000000000001', scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-02T00:00:00.000Z', completedAt: '2026-09-02T00:01:00.000Z', findingsTotal: 1, partial: false, reportAvailable: true, dastObservationsCount: null, scaAssessmentState: null, scaDatasetStatus: null },
  ] },
  findings: STUDENT_OVERVIEW.overview.findings,
  reports: STUDENT_OVERVIEW.overview.reports,
} };

const PENTESTER_OVERVIEW: WorkspaceSecurityOverviewResponse = { overview: {
  ...PROFESSIONAL_OVERVIEW.overview,
  projects: {
    total: 1, active: 1, archived: 0, dastTargetsConfigured: 1,
    recent: [{ ...PROFESSIONAL_OVERVIEW.overview.projects.recent[0]!, dastTargetConfigured: true }],
  },
} };

describe('Developer workspace dashboard UX', () => {
  test('shows server-derived account activity and FREE usage without an overall security verdict', async () => {
    const client = signedIn('DEVELOPER');
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Developer dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.getByRole('link', { name: 'My projects' })).toHaveAttribute('href', '/projects');
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Payment review' })).toBeNull();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: FREE/);
    expect(planCard).toHaveTextContent(/0 used of 3 · 3 remaining/);
    expect(screen.getByText(/No projects yet/)).toBeInTheDocument();
    expect(screen.getByText(/not a claim that every security area is clear or assessed/)).toBeInTheDocument();
    expect(screen.queryByText(/All clear/i)).toBeNull();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
    expect(client.getUsage).toHaveBeenCalledTimes(1);
    expect(client.getSubscription).toHaveBeenCalledTimes(1);
  });

  test('Developer PRO summary displays only the server entitlement and exempt usage verdict', async () => {
    const client = signedIn('DEVELOPER', {
      getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
        entitlements: ['plan:view', 'feature:pro'],
      })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => ({
        plan: 'PRO',
        period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
        used: 5, limit: null, remaining: null, quotaStatus: 'EXEMPT',
      })),
    });
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: PRO/);
    expect(planCard).toHaveTextContent(/5 used · quota exempt/);
    expect(planCard).toHaveTextContent(/PRO entitlement: granted by server/);
  });

  test('Student lands on the Student dashboard with real progress sections and shared-project workflow shortcuts', async () => {
    const client = signedIn('STUDENT', {
      getSecurityOverview: vi.fn(async () => STUDENT_OVERVIEW),
    });
    await renderAt('/student/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    expect(screen.getByText(/persisted progress—not a grade, complete-coverage claim, or security score/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Student dashboard' })).toHaveAttribute('href', '/student/dashboard');
    const workflow = screen.getByRole('navigation', { name: 'Student security workflow' });
    expect(within(workflow).getByRole('link', { name: 'My projects' })).toHaveAttribute('href', '/projects');
    expect(screen.getByRole('heading', { name: 'My progress & security history' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Understand & fix findings' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'My reports' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Scans' }).parentElement).toHaveTextContent('1 completed · 1 recorded');
    expect(within(workflow).getByRole('link', { name: 'Security scan' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#security-scans');
    expect(within(workflow).getByRole('link', { name: 'AI Security Assistant' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#assistant-title');
    expect(within(workflow).getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/account');
    expect(screen.queryByRole('link', { name: 'Developer dashboard' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Payment review' })).toBeNull();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Student PRO dashboard displays the server entitlement and exempt scan usage', async () => {
    const client = signedIn('STUDENT', {
      getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
        entitlements: ['plan:view', 'feature:pro'],
      })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => ({
        plan: 'PRO',
        period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
        used: 5, limit: null, remaining: null, quotaStatus: 'EXEMPT',
      })),
    });
    await renderAt('/student/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: PRO/);
    expect(planCard).toHaveTextContent(/5 used · quota exempt/);
    expect(planCard).toHaveTextContent(/PRO entitlement: granted by server/);
  });

  test('Security Professional dashboard shows bounded assessments, DAST, lifecycle summaries, reports, and shared workflow links', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType: 'SECURITY_PROFESSIONAL' as const } })),
      getSecurityOverview: vi.fn(async () => PROFESSIONAL_OVERVIEW),
    });
    await renderAt('/security-professional/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Security Professional dashboard' })).toHaveAttribute('href', '/security-professional/dashboard');
    expect(screen.getByRole('heading', { name: 'Assessment history & engine status' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Finding & remediation status' })).toBeInTheDocument();
    expect(screen.getByText(/Lifecycle: IN PROGRESS: 1 · Verification: OBSERVED: 1/)).toBeInTheDocument();
    expect(screen.getByText(/Passive DAST: 2 bounded response observations/)).toBeInTheDocument();
    expect(screen.getByText(/SCA vulnerability intelligence: NOT_ASSESSED · dataset: NO_DATA_LOADED/)).toBeInTheDocument();
    expect(screen.getByText(/Recent lists are bounded/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Reports' })).toBeInTheDocument();
    const workflow = screen.getByRole('navigation', { name: 'Security Professional workflow' });
    for (const label of ['Assessments & projects', 'Source snapshot', 'SAST', 'SCA / SBOM', 'Secrets', 'Passive DAST', 'Findings & evidence', 'Remediation & verification', 'AI Security Assistant', 'Project reports', 'Settings']) {
      expect(within(workflow).getByRole('link', { name: label })).toBeInTheDocument();
    }
    expect(within(workflow).getByRole('link', { name: 'SCA / SBOM' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#security-scans');
    expect(within(workflow).getByRole('link', { name: 'Passive DAST' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#dast-target');
    expect(within(workflow).getByRole('link', { name: 'Project reports' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#security-scans');
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Payment review' })).toBeNull();
  });

  test('Security Professional PRO dashboard reflects only server entitlement and exempt usage', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType: 'SECURITY_PROFESSIONAL' as const } })),
      getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-02T00:00:00.000Z', updatedAt: '2026-09-02T00:00:00.000Z' },
        entitlements: ['plan:view', 'feature:pro'],
      })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => ({
        plan: 'PRO', period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
        used: 6, limit: null, remaining: null, quotaStatus: 'EXEMPT',
      })),
    });
    await renderAt('/security-professional/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: PRO/);
    expect(planCard).toHaveTextContent(/6 used · quota exempt/);
    expect(planCard).toHaveTextContent(/PRO entitlement: granted by server/);
  });

  test('Pentester dashboard exposes only server-configured project targets and shared passive-assessment workflows', async () => {
    const client = signedIn('PENTESTER', {
      getSecurityOverview: vi.fn(async () => PENTESTER_OVERVIEW),
    });
    await renderAt('/pentester/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Pentester assessment dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Pentester dashboard' })).toHaveAttribute('href', '/pentester/dashboard');
    expect(screen.getByRole('heading', { name: 'Authorized targets' }).parentElement).toHaveTextContent('1 project target configured on the server');
    expect(screen.getByText(/does not itself verify third-party authorization/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Projects & authorized targets' })).toBeInTheDocument();
    expect(screen.getByText(/Server target configuration: configured/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Assessment history & recent activity' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Findings & retest status' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Assessment reports' })).toBeInTheDocument();
    expect(screen.getByText(/Passive DAST: 2 bounded response observations/)).toBeInTheDocument();
    const workflow = screen.getByRole('navigation', { name: 'Pentester assessment workflow' });
    for (const label of ['Assessments & projects', 'Authorized targets', 'Start or review DAST', 'Observations', 'Findings & evidence', 'Remediation', 'Retest & verification', 'Reports', 'AI Security Assistant', 'Settings']) {
      expect(within(workflow).getByRole('link', { name: label })).toBeInTheDocument();
    }
    expect(within(workflow).getByRole('link', { name: 'Authorized targets' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#dast-target');
    expect(within(workflow).getByRole('link', { name: 'Findings & evidence' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#security-scans');
    expect(within(workflow).getByRole('link', { name: 'AI Security Assistant' })).toHaveAttribute('href', '/projects/prj_00000000-0000-4000-8000-000000000001#assistant-title');
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Payment review' })).toBeNull();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Professional classification does not suppress role-based admin navigation', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const, userType: 'SECURITY_PROFESSIONAL' as const } })),
      getSecurityOverview: vi.fn(async () => PROFESSIONAL_OVERVIEW),
    });
    await renderAt('/security-professional/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Platform operations' })).toHaveAttribute('href', '/admin/operations');
    expect(screen.getByRole('link', { name: 'Payment review' })).toHaveAttribute('href', '/admin/payments');
  });

  test('non-Professional classification cannot enter the professional dashboard directly', async () => {
    const client = signedIn('STUDENT');
    await renderAt('/security-professional/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Security Professional dashboard' })).toBeNull();
    expect(client.getSecurityOverview).not.toHaveBeenCalled();
  });

  test('Student classification does not replace role-based privileged navigation', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const, userType: 'STUDENT' as const } })),
    });
    await renderAt('/student/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Platform operations' })).toHaveAttribute('href', '/admin/operations');
    expect(screen.getByRole('link', { name: 'Payment review' })).toHaveAttribute('href', '/admin/payments');
  });

  test('non-Student classification cannot enter the Student dashboard by direct navigation', async () => {
    const client = signedIn('DEVELOPER');
    await renderAt('/student/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Student security dashboard' })).toBeNull();
    expect(client.getSecurityOverview).not.toHaveBeenCalled();
  });

  test('non-Developer classification cannot enter the Developer dashboard by direct navigation', async () => {
    const client = signedIn('STUDENT');
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Security overview' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Developer dashboard' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(client.getSecurityOverview).not.toHaveBeenCalled();
  });
});
