// @vitest-environment jsdom
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type {
  Finding,
  FindingDetailResponse,
  FindingHistoryResponse,
  FindingLifecycleState,
  FindingWorkflow,
  FindingWorkflowResponse,
  FindingsPageResponse,
  Project,
  ProjectResponse,
  Scan,
  ScansResponse,
  FindingSeverity,
  ScanType,
  SecurityReportResponse,
} from '@drobon/shared';
import type { ApiClient, ReportDownload } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const project: Project = {
  id: 'prj_00000000-0000-4000-8000-0000000000ab',
  name: 'Pump 12 UI fixture',
  description: '',
  status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:01:00.000Z',
};
const scan: Scan = {
  id: 'scan_00000000-0000-4000-8000-0000000000ab',
  projectId: project.id,
  scanType: 'SAST',
  status: 'COMPLETED',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:01:00.000Z',
  startedAt: '2026-09-28T10:00:01.000Z',
  completedAt: '2026-09-28T10:01:00.000Z',
  resultSummary: {
    findingsTotal: 1,
    findingsBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
  },
};
const finding: Finding = {
  id: `fnd_${'a'.repeat(24)}`,
  scanId: scan.id,
  scanner: 'SAST',
  ruleId: 'DG-SAST-004',
  severity: 'HIGH',
  title: 'Unsafe evaluation',
  description: 'Untrusted input reaches an evaluation sink.',
  evidence: 'eval("<img src=x onerror=alert(1)>");',
  remediation: 'Remove dynamic evaluation.',
  file: 'src/app.ts',
  line: 4,
  column: 1,
  fingerprint: 'b'.repeat(64),
};
const projectResponse: ProjectResponse = { project };
const detail: FindingDetailResponse = { project, scan, finding };
const workflow: FindingWorkflow = {
  id: 'fwf_00000000-0000-4000-8000-0000000000ab',
  projectId: project.id,
  findingId: finding.id,
  fingerprint: finding.fingerprint,
  scanner: 'SAST',
  ruleId: finding.ruleId,
  state: 'OPEN',
  firstObservedScanId: scan.id,
  firstObservedAt: scan.completedAt!,
  lastObservedScanId: scan.id,
  lastObservedAt: scan.completedAt!,
  lastVerificationScanId: scan.id,
  lastVerificationAt: scan.completedAt!,
  verificationState: 'OBSERVED',
  notes: [],
  historyTotal: 1,
  updatedAt: scan.completedAt!,
};
const report: SecurityReportResponse = {
  report: {
    reportId: 'rpt_0123456789abcdef01234567',
    reportVersion: '1.0',
    schemaVersion: 1,
    generatedAt: '2026-09-28T10:02:00.000Z',
    project: { id: project.id, name: project.name, status: project.status },
    scan: { ...scan, status: 'COMPLETED', completedAt: '2026-09-28T10:01:00.000Z' },
    scannerCoverage: [
      { scanner: 'SAST', status: 'RAN' },
      { scanner: 'SCA', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
      { scanner: 'SECRETS', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
      { scanner: 'DAST', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
    ],
    findingSummary: {
      total: 1,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byScanner: { SAST: 1, SCA: 0, SECRETS: 0, DAST: 0 },
    },
    findings: [finding],
    findingWorkflows: [workflow],
    dependencyIntelligence: { status: 'NOT_ASSESSED', reason: 'Dependency analysis was not run in this scan.' },
    inventory: { status: 'NOT_INCLUDED', reason: 'Dependency inventory was not part of this scan.' },
    contentDigest: 'c'.repeat(64),
    integrityDigest: 'd'.repeat(64),
  },
};

async function renderProject(client: ApiClient): Promise<void> {
  await renderAt(`/projects/${project.id}`, client);
}

describe('completed scan findings and report UI', () => {
  test('summarizes completed scans, filters server-side, and displays finding details as text', async () => {
    const getFindings = vi.fn(async (_projectId: string, _scanId: string, filters?: { severity?: FindingSeverity; scanner?: ScanType; page?: number; pageSize?: number }): Promise<FindingsPageResponse> => ({
      findings: [finding], page: filters?.page ?? 1, pageSize: 20, total: 1, totalPages: 1,
      ...(filters?.severity === undefined ? {} : { severity: filters.severity }), scanner: 'SAST',
    }));
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getFindings,
      getFinding: vi.fn(async (): Promise<FindingDetailResponse> => detail),
    });
    await renderProject(client);
    expect(await screen.findByTestId('project-findings-total')).toHaveTextContent('1 persisted finding');
    await userEvent.click(await screen.findByTestId('view-findings'));
    expect(await screen.findByTestId('findings-list')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByTestId('findings-filter'), 'HIGH');
    await waitFor(() => expect(getFindings).toHaveBeenCalledWith(project.id, scan.id, { page: 1, pageSize: 20, severity: 'HIGH' }));
    await userEvent.click(screen.getByTestId('finding-detail-button'));
    const findingDetail = await screen.findByTestId('finding-detail');
    expect(within(findingDetail).getByTestId('finding-fingerprint')).toHaveTextContent('b'.repeat(64));
    expect(within(findingDetail).getByTestId('finding-evidence')).toHaveTextContent('<img src=x onerror=alert(1)>');
    expect(findingDetail.querySelector('img')).toBeNull();
    expect(findingDetail.querySelector('[onerror]')).toBeNull();
    const task = within(findingDetail).getByTestId('finding-task-draft');
    expect(task).toHaveTextContent('does not create a Jira issue');
    const draft = within(task).getByLabelText('Task draft (selectable, no evidence)') as HTMLTextAreaElement;
    expect(draft.value).toContain('Severity: HIGH');
    expect(draft.value).not.toContain(finding.evidence);
    await userEvent.type(within(task).getByLabelText('Suggested assignee (optional, text only)'), 'Reviewer A');
    expect(draft.value).toContain('Suggested assignee (manual): Reviewer A');
    await userEvent.click(within(task).getByRole('button', { name: 'Copy task draft' }));
    expect(within(task).getByRole('status')).toHaveTextContent(/Draft copied|Clipboard unavailable/);
  });

  test('shows category attribution and a project source-to-sink trace', async () => {
    const traced: Finding = {
      ...finding, scanner: 'SAST', astFlow: { mode: 'PROJECT', category: 'code', attribution: 'CATEGORY_REPORTER',
        source: { file: 'src/input.ts', line: 3, column: 8 }, via: [{ file: 'src/handler.ts', line: 7, column: 4 }] },
    };
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getFindings: vi.fn(async (): Promise<FindingsPageResponse> => ({ findings: [traced], page: 1, pageSize: 20, total: 1, totalPages: 1 })),
      getFinding: vi.fn(async (): Promise<FindingDetailResponse> => ({ project, scan, finding: traced })),
    });
    await renderProject(client);
    await userEvent.click(await screen.findByTestId('view-findings'));
    await userEvent.click(await screen.findByTestId('finding-detail-button'));
    const trace = await screen.findByTestId('finding-ast-flow');
    expect(trace).toHaveTextContent('rule selected by category');
    expect(trace).toHaveTextContent('src/input.ts:3:8');
    expect(trace).toHaveTextContent('src/handler.ts:7:4');
    expect(trace).toHaveTextContent('src/app.ts:4:1');
  });

  test('shows DAST script-flow attribution without presenting it as an established exploit', async () => {
    const targetUrl = 'https://app.example.org/';
    const dastScan: Scan = { ...scan, scanType: 'DAST', targetUrl };
    const candidate: Finding = {
      id: finding.id, scanId: scan.id, ruleId: 'DG-DAST-900', severity: 'HIGH', scanner: 'DAST',
      title: 'Possible HTML flow', description: 'Review candidate.', evidence: 'AST flow metadata only.', remediation: 'Review.',
      fingerprint: finding.fingerprint, projectId: project.id, targetUrl, endpoint: targetUrl, method: 'GET',
      responseStatus: 200, responseTimeMs: 4, observedAt: scan.completedAt!, observedHeaders: [],
      astContext: { kind: 'DAST_RESPONSE_FLOW', category: 'html', attribution: 'CATEGORY_REPORTER', script: 2, line: 3, column: 4 },
    };
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })), getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async () => ({ scans: [dastScan] })),
      getScan: vi.fn(async () => ({ scan: { ...dastScan, findings: [candidate], dast: { targetUrl, requestCount: 1, redirectsFollowed: 0, partial: false, observations: [{ endpoint: targetUrl, method: 'GET' as const, status: 200, observedAt: scan.completedAt!, responseTimeMs: 4, bodyBytes: 0, bodyTruncated: false, headers: [] }] } } })),
      getFindings: vi.fn(async () => ({ findings: [candidate], page: 1, pageSize: 20, total: 1, totalPages: 1 })),
      getFinding: vi.fn(async () => ({ project, scan: dastScan, finding: candidate })),
    });
    await renderProject(client);
    await userEvent.click(await screen.findByTestId('view-findings'));
    await userEvent.click(await screen.findByTestId('finding-detail-button'));
    const context = await screen.findByTestId('finding-ast-context');
    expect(context).toHaveTextContent('script 2, line 3, column 4');
    expect(context).toHaveTextContent('exact rule check and exploitability not established');
  });

  test('shows workflow verification, rule guidance, bounded history, and saved remediation notes', async () => {
    let currentWorkflow = { ...workflow };
    const getFinding = vi.fn(async (): Promise<FindingDetailResponse> => ({
      ...detail,
      workflow: currentWorkflow,
      guidance: {
        ruleId: finding.ruleId,
        status: 'RULE_SPECIFIC',
        whyItMatters: 'Fixture-only explanation.',
        actions: ['Use a safe alternative.'],
        verification: 'Run this same scanner again; absence is not proof of a fix.',
      },
    }));
    const setFindingLifecycle = vi.fn(async (_projectId: string, _scanId: string, _findingId: string, state: FindingLifecycleState): Promise<FindingWorkflowResponse> => {
      currentWorkflow = { ...currentWorkflow, state, historyTotal: currentWorkflow.historyTotal + 1 };
      return { workflow: currentWorkflow };
    });
    const addFindingNote = vi.fn(async (_projectId: string, _scanId: string, _findingId: string, note: string): Promise<FindingWorkflowResponse> => {
      currentWorkflow = {
        ...currentWorkflow,
        notes: [{ id: 'fnt_00000000-0000-4000-8000-0000000000ab', text: note, actorId: TEST_USER.id, createdAt: scan.completedAt!, redacted: false }],
        historyTotal: currentWorkflow.historyTotal + 1,
      };
      return { workflow: currentWorkflow };
    });
    const getFindingHistory = vi.fn(async (): Promise<FindingHistoryResponse> => ({
      events: [{
        id: 'fev_00000000-0000-4000-8000-0000000000ab', findingId: finding.id,
        previousState: null, newState: 'OPEN', actorId: 'system:scanner', actorType: 'SYSTEM',
        action: 'FINDING_OBSERVED', at: scan.completedAt!,
      }],
      page: 1, pageSize: 20, total: 1, totalPages: 1,
    }));
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      getFindings: vi.fn(async (): Promise<FindingsPageResponse> => ({ findings: [finding], page: 1, pageSize: 20, total: 1, totalPages: 1 })),
      getFinding,
      setFindingLifecycle,
      addFindingNote,
      getFindingHistory,
    });
    await renderProject(client);
    await userEvent.click(await screen.findByTestId('view-findings'));
    await userEvent.click(await screen.findByTestId('finding-detail-button'));
    const panel = await screen.findByTestId('finding-workflow');
    expect(within(panel).getByTestId('finding-lifecycle-state')).toHaveTextContent('OPEN');
    expect(within(panel).getByTestId('finding-verification-state')).toHaveTextContent('Observed in the recorded verification scan');
    expect(screen.getByTestId('finding-guidance')).toHaveTextContent('RULE SPECIFIC');

    await userEvent.selectOptions(within(panel).getByLabelText('Change lifecycle state'), 'ACKNOWLEDGED');
    await userEvent.click(within(panel).getByRole('button', { name: 'Update status' }));
    expect(await within(await screen.findByTestId('finding-workflow')).findByTestId('finding-lifecycle-state')).toHaveTextContent('ACKNOWLEDGED');
    expect(setFindingLifecycle).toHaveBeenCalledWith(project.id, scan.id, finding.id, 'ACKNOWLEDGED');

    // Phase 22: FALSE_POSITIVE triage is offered from ACKNOWLEDGED and is terminal in the UI.
    await userEvent.selectOptions(within(panel).getByLabelText('Change lifecycle state'), 'FALSE_POSITIVE');
    await userEvent.click(within(panel).getByRole('button', { name: 'Update status' }));
    expect(await within(await screen.findByTestId('finding-workflow')).findByTestId('finding-lifecycle-state')).toHaveTextContent('FALSE_POSITIVE');
    expect(setFindingLifecycle).toHaveBeenCalledWith(project.id, scan.id, finding.id, 'FALSE_POSITIVE');

    await userEvent.type(screen.getByLabelText('Remediation note (plain text; secrets are redacted)'), 'Reviewed safely.');
    await userEvent.click(screen.getByRole('button', { name: 'Add note' }));
    expect(await screen.findByTestId('finding-notes')).toHaveTextContent('Reviewed safely.');
    expect(addFindingNote).toHaveBeenCalledWith(project.id, scan.id, finding.id, 'Reviewed safely.');
    await userEvent.click(screen.getByTestId('load-finding-history'));
    expect(await screen.findByTestId('finding-history')).toHaveTextContent('FINDING OBSERVED');
    expect(getFindingHistory).toHaveBeenCalledWith(project.id, scan.id, finding.id, 1, 20);
  });

  test('generates/retrieves honest saved reports and offers PDF and existing exports', async () => {
    const createReport = vi.fn(async (): Promise<SecurityReportResponse> => report);
    const getReport = vi.fn(async (): Promise<SecurityReportResponse> => report);
    const downloadReport = vi.fn(async (): Promise<ReportDownload> => ({ blob: new Blob(['{}']), filename: `drobon-${report.report.reportId}.sarif`, contentType: 'application/sarif+json' }));
    const downloadSbom = vi.fn(async (): Promise<ReportDownload> => ({ blob: new Blob(['{"bomFormat":"CycloneDX"}']), filename: `drobon-${report.report.reportId}.cdx.json`, contentType: 'application/json' }));
    const downloadProjectReport = vi.fn(async (): Promise<ReportDownload> => ({ blob: new Blob(['%PDF-1.3']), filename: `drobon-project-${project.id}.pdf`, contentType: 'application/pdf' }));
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      createReport,
      getReport,
      downloadReport,
      downloadProjectReport,
      downloadSbom,
    });
    await renderProject(client);
    await userEvent.click(await screen.findByTestId('generate-report'));
    expect(await screen.findByTestId('report-not-assessed')).toHaveTextContent('NOT ASSESSED');
    expect(screen.getByTestId('report-id')).toHaveTextContent(report.report.reportId);
    expect(screen.getByTestId('report-content-digest')).toHaveTextContent('c'.repeat(64));
    expect(screen.getByTestId('report-inventory-summary')).toHaveTextContent('NOT INCLUDED');
    expect(screen.getByTestId('report-scanner-coverage')).toHaveTextContent('SAST: RAN');
    expect(screen.getByTestId('report-scanner-coverage')).toHaveTextContent('SCA: NOT_RUN');
    expect(screen.getByTestId('report-workflow-snapshot')).toHaveTextContent('OPEN');
    expect(screen.getByTestId('report-workflow-snapshot')).toHaveTextContent('not technical verification');
    expect(createReport).toHaveBeenCalledWith(project.id, scan.id);
    expect(screen.getByTestId('download-report-json')).toBeInTheDocument();
    expect(screen.getByTestId('download-report-markdown')).toBeInTheDocument();
    expect(screen.getByTestId('download-report-sarif')).toBeInTheDocument();
    expect(screen.getByTestId('download-report-sbom')).toBeInTheDocument();
    expect(screen.getByTestId('download-report-pdf')).toBeInTheDocument();
    expect(screen.getByTestId('download-project-pdf')).toBeInTheDocument();
    URL.createObjectURL = (): string => 'blob:fixture';
    URL.revokeObjectURL = (): void => undefined;
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    await userEvent.click(screen.getByTestId('download-report-pdf'));
    await waitFor(() => expect(downloadReport).toHaveBeenCalledWith(project.id, scan.id, 'pdf'));
    await userEvent.click(screen.getByTestId('download-project-pdf'));
    await waitFor(() => expect(downloadProjectReport).toHaveBeenCalledWith(project.id));
    await userEvent.click(screen.getByTestId('download-report-sarif'));
    await waitFor(() => expect(downloadReport).toHaveBeenCalledWith(project.id, scan.id, 'sarif'));
    expect(screen.getByTestId('report-guidance')).not.toBeChecked();
    expect(screen.getByTestId('project-report-guidance')).not.toBeChecked();
    await userEvent.click(screen.getByTestId('report-guidance'));
    await userEvent.click(screen.getByTestId('download-report-json'));
    await waitFor(() => expect(downloadReport).toHaveBeenCalledWith(project.id, scan.id, 'json', undefined, true));
    await userEvent.click(screen.getByTestId('project-report-guidance'));
    await userEvent.click(screen.getByTestId('download-project-pdf'));
    await waitFor(() => expect(downloadProjectReport).toHaveBeenCalledWith(project.id, undefined, true));
    await userEvent.click(screen.getByTestId('download-report-sbom'));
    await waitFor(() => expect(downloadSbom).toHaveBeenCalledWith(project.id, scan.id));
    await userEvent.click(screen.getByTestId('refresh-report'));
    expect(getReport).toHaveBeenCalledWith(project.id, scan.id);
    await userEvent.click(screen.getByTestId('refresh-report-snapshot'));
    expect(createReport).toHaveBeenCalledTimes(2);
    anchorClick.mockRestore();
  });
});
