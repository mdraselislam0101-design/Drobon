// @vitest-environment jsdom
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type {
  Finding,
  FindingDetailResponse,
  FindingsPageResponse,
  Project,
  ProjectResponse,
  Scan,
  ScansResponse,
  FindingSeverity,
  ScanType,
  SecurityReportResponse,
} from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
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
  });

  test('generates/retrieves honest saved reports and offers only JSON/Markdown exports', async () => {
    const createReport = vi.fn(async (): Promise<SecurityReportResponse> => report);
    const getReport = vi.fn(async (): Promise<SecurityReportResponse> => report);
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => projectResponse),
      getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
      createReport,
      getReport,
    });
    await renderProject(client);
    await userEvent.click(await screen.findByTestId('generate-report'));
    expect(await screen.findByTestId('report-not-assessed')).toHaveTextContent('NOT ASSESSED');
    expect(screen.getByTestId('report-id')).toHaveTextContent(report.report.reportId);
    expect(screen.getByTestId('report-content-digest')).toHaveTextContent('c'.repeat(64));
    expect(screen.getByTestId('report-inventory-summary')).toHaveTextContent('NOT INCLUDED');
    expect(screen.getByTestId('report-scanner-coverage')).toHaveTextContent('SAST: RAN');
    expect(screen.getByTestId('report-scanner-coverage')).toHaveTextContent('SCA: NOT_RUN');
    expect(createReport).toHaveBeenCalledWith(project.id, scan.id);
    expect(screen.getByTestId('download-report-json')).toBeInTheDocument();
    expect(screen.getByTestId('download-report-markdown')).toBeInTheDocument();
    expect(screen.queryByText(/PDF/i)).toBeNull();
    await userEvent.click(screen.getByTestId('refresh-report'));
    expect(getReport).toHaveBeenCalledWith(project.id, scan.id);
  });
});
