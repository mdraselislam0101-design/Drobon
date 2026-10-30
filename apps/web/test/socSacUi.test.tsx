// @vitest-environment jsdom
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AstSupplementSummary, Project, SacAssessment, Scan, ScanType, SecurityReportResponse, SocPostureResponse } from '@drobon/shared';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const project: Project = {
  id: 'prj_00000000-0000-4000-8000-0000000000aa', name: 'Security project', description: '', status: 'ACTIVE',
  createdAt: '2026-10-28T10:00:00.000Z', updatedAt: '2026-10-28T10:00:00.000Z',
};
const scan: Scan = {
  id: 'scan_00000000-0000-4000-8000-0000000000aa', projectId: project.id, scanType: 'SAST', status: 'COMPLETED',
  createdAt: '2026-10-28T10:00:00.000Z', updatedAt: '2026-10-28T10:01:00.000Z', startedAt: '2026-10-28T10:00:01.000Z',
  completedAt: '2026-10-28T10:01:00.000Z', resultSummary: { findingsTotal: 0 },
};

const posture: SocPostureResponse = {
  posture: {
    schemaVersion: '1.0', projectId: project.id, generatedAt: '2026-10-28T12:00:00.000Z',
    scansReviewed: 1, scansOmitted: 0,
    scannerCoverage: [
      { scanner: 'SAST', lastCompletedAt: '2026-10-28T10:01:00.000Z' },
      { scanner: 'SCA', lastCompletedAt: null },
      { scanner: 'SECRETS', lastCompletedAt: null },
      { scanner: 'DAST', lastCompletedAt: null },
    ],
    sources: { dataset: 'NOT_CONFIGURED', advisory: 'NOT_CONFIGURED' },
    alerts: [{
      id: `soca_${'a'.repeat(24)}`, ruleId: 'MISSING_RECENT_SCANS', severity: 'MEDIUM',
      title: 'Recent scan coverage not recorded', detail: 'No recent DAST scan among the records reviewed.',
      observedAt: '2026-10-28T12:00:00.000Z',
    }, {
      id: `soca_${'b'.repeat(24)}`, ruleId: 'HIGH_SEVERITY_ADVISORY', severity: 'HIGH',
      title: 'High-severity dependency advisory matched', detail: 'Latest completed SCA scan matched a synthetic advisory.',
      observedAt: '2026-10-28T12:00:00.000Z',
    }],
    limitations: ['This is not live intrusion monitoring.'], truncated: false,
  },
};

const sac: SacAssessment = {
  schemaVersion: '1.0', assessmentLevel: 'AUTOMATED_BOUNDED_ASSESSMENT', verdict: 'NO_FINDINGS_RECORDED',
  verdictStatement: 'No findings were recorded in this scan. This does not establish that the target is secure.',
  scope: { projectId: project.id, scanId: scan.id, scanType: 'SAST', completedAt: '2026-10-28T10:01:00.000Z' },
  scannerCoverage: [
    { scanner: 'SAST', status: 'RAN', reason: 'The scanner completed; rule-level completeness is not established.' },
    { scanner: 'SCA', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
    { scanner: 'SECRETS', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
    { scanner: 'DAST', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
  ],
  metrics: {
    filesScanned: null, filesSkipped: null, requestsMade: null, redirectsFollowed: null,
    declarationRulesEvaluated: null, declarationRulesNotEvaluated: null,
    astFilesAnalyzed: null, astFlowsFound: null, partial: null, truncated: null, partialReason: null,
  },
  findings: { total: 0, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
  ruleProvenance: 'NOT_RECORDED_AT_SCAN',
  limitations: ['This is not proof that the target is safe.'],
  residualRisk: { status: 'UNKNOWN', statement: 'Residual risk is unknown.' },
  compliance: { status: 'NOT_ASSESSED', statement: 'This is not a compliance certification.' },
  nextSteps: ['Review and re-scan after changes.'],
};

const report: SecurityReportResponse = {
  report: {
    reportId: 'rpt_0123456789abcdef01234567', reportVersion: '1.0', schemaVersion: 1,
    generatedAt: '2026-10-28T12:00:00.000Z', project: { id: project.id, name: project.name, status: project.status },
    scan: { ...scan, status: 'COMPLETED', completedAt: '2026-10-28T10:01:00.000Z' },
    scannerCoverage: [
      { scanner: 'SAST', status: 'RAN' },
      { scanner: 'SCA', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
      { scanner: 'SECRETS', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
      { scanner: 'DAST', status: 'NOT_RUN', reason: 'Not run in this single-scan assessment.' },
    ],
    findingSummary: { total: 0, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byScanner: { SAST: 0, SCA: 0, SECRETS: 0, DAST: 0 } },
    findings: [], sac,
    dependencyIntelligence: { status: 'NOT_ASSESSED', reason: 'Dependency analysis was not run in this scan.' },
    inventory: { status: 'NOT_INCLUDED', reason: 'Dependency inventory was not part of this scan.' },
    contentDigest: 'a'.repeat(64), integrityDigest: 'b'.repeat(64),
  },
};

describe('operations and assessment coverage UI', () => {
  test('loads owner-scoped saved-scan alerts only on request and shows limitations', async () => {
    const getSocPosture = vi.fn(async () => posture);
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => ({ project })),
      getScans: vi.fn(async () => ({ scans: [] })),
      getSocPosture,
    });
    await renderAt(`/projects/${project.id}`, client);
    expect(await screen.findByTestId('soc-overview')).toBeInTheDocument();
    expect(getSocPosture).not.toHaveBeenCalled();
    await userEvent.click(screen.getByTestId('soc-load'));
    const content = await screen.findByTestId('soc-content');
    expect(content).toHaveTextContent('Recent scan coverage not recorded');
    expect(content).toHaveTextContent('High-severity dependency advisory matched');
    expect(content).toHaveTextContent('DAST: no completed scan');
    expect(getSocPosture).toHaveBeenCalledWith(project.id);
    await userEvent.click(within(content).getByText('Overview limitations'));
    expect(content).toHaveTextContent('not live intrusion monitoring');
  });

  test('shows actual AST parser coverage in the scan and saved report', async () => {
    const astScan: Scan = {
      ...scan,
      resultSummary: {
        findingsTotal: 0, filesScanned: 2, partial: true, partialReason: 'Some AST inputs were incomplete.',
        astParser: { parsedFiles: 1, incompleteFiles: 1, filesWithoutRules: 1, findings: 0 },
        astCoverage: {
          rules: { source: 'NONE', count: 0, sha256: 'c'.repeat(64) },
          parsers: { typescript: '5.9.3', python: '1.1.19', php: '3.7.0', java: '1.1.5' },
          families: [{ family: 'javascript', reporters: {} }],
          files: [{ path: 'src/app.js', family: 'javascript', status: 'OK' }, { path: 'src/broken.js', family: 'javascript', status: 'SYNTAX_ERROR' }],
          unstructuredFiles: 0,
          projectFlow: { status: 'INCOMPLETE', examinedFiles: 1, unresolvedImports: 1, findings: 0 },
        },
      },
    };
    const astReport: SecurityReportResponse = {
      report: { ...report.report, scan: { ...astScan, status: 'COMPLETED', completedAt: '2026-10-28T10:01:00.000Z' } },
    };
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => ({ project })),
      getScans: vi.fn(async () => ({ scans: [astScan] })),
      createReport: vi.fn(async () => astReport),
    });
    await renderAt(`/projects/${project.id}`, client);
    const scanCoverage = await screen.findByTestId('scan-ast-coverage');
    expect(scanCoverage).toHaveTextContent('1 parsed');
    expect(scanCoverage).toHaveTextContent('1 incomplete');
    expect(scanCoverage).toHaveTextContent('1 without applicable AST rules');
    expect(scanCoverage).toHaveTextContent('Python, PHP, Java');
    await userEvent.click(within(scanCoverage).getByText('Rule, parser and file coverage'));
    expect(scanCoverage).toHaveTextContent('src/broken.js');
    expect(scanCoverage).toHaveTextContent('SYNTAX_ERROR');
    expect(scanCoverage).toHaveTextContent('missing: command, sql, html, code');
    expect(scanCoverage).toHaveTextContent('1 unresolved relative named imports');
    await userEvent.click(await screen.findByTestId('generate-report'));
    const reportCoverage = await screen.findByTestId('report-ast-coverage');
    expect(reportCoverage).toHaveTextContent('JavaScript, TypeScript, JSX, TSX');
    expect(reportCoverage).toHaveTextContent('not a safety guarantee');
  });

  test.each([
    ['DAST', { mode: 'DAST_RESPONSE_SCRIPTS', status: 'PARTIAL', parsed: 1, incomplete: 0, skipped: 1, signals: 0, parserVersion: '5.9.3', reporterRuleId: 'DG-DAST-900' }, 'external scripts are not fetched'],
    ['SECRETS', { mode: 'SECRETS_LITERAL_CONTEXT', status: 'PARTIAL', parsed: 1, incomplete: 0, skipped: 1, signals: 0, parserVersion: '5.9.3' }, 'does not verify credentials'],
    ['SCA', { mode: 'SCA_JSON_MANIFEST', status: 'PARTIAL', parsed: 1, incomplete: 0, skipped: 1, signals: 3, parserVersion: '5.9.3' }, 'not installed-package or vulnerability proof'],
  ] as Array<[ScanType, AstSupplementSummary, string]>)('%s supplement is shown in scan and report', async (scanType, astSupplement, limitation) => {
    const supplemented: Scan = { ...scan, scanType, ...(scanType === 'DAST' ? { targetUrl: 'https://app.example.org/' } : {}), resultSummary: { findingsTotal: 0, astSupplement } };
    const suppliedReport: SecurityReportResponse = { report: { ...report.report, scan: { ...supplemented, status: 'COMPLETED', completedAt: scan.completedAt! } } };
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => ({ project })),
      getScans: vi.fn(async () => ({ scans: [supplemented] })),
      createReport: vi.fn(async () => suppliedReport),
    });
    await renderAt(`/projects/${project.id}`, client);
    const scanCoverage = await screen.findByTestId('scan-ast-supplement');
    expect(scanCoverage).toHaveTextContent('PARTIAL');
    expect(scanCoverage).toHaveTextContent(limitation);
    await userEvent.click(await screen.findByTestId('generate-report'));
    const reportCoverage = await screen.findByTestId('report-ast-supplement');
    expect(reportCoverage).toHaveTextContent(limitation);
  });

  test('a legacy non-SAST scan does not imply AST coverage', async () => {
    const legacy: Scan = { ...scan, scanType: 'SECRETS' };
    const client = stubClient({ getMe: vi.fn(async () => ({ user: TEST_USER })), getProject: vi.fn(async () => ({ project })), getScans: vi.fn(async () => ({ scans: [legacy] })) });
    await renderAt(`/projects/${project.id}`, client);
    expect(await screen.findByText('This saved scan has no scanner-specific AST supplement record; coverage is unknown.')).toBeInTheDocument();
  });

  test('a generated report displays unknown risk, not-assessed compliance and unrun scanners', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      getProject: vi.fn(async () => ({ project })),
      getScans: vi.fn(async () => ({ scans: [scan] })),
      createReport: vi.fn(async () => report),
    });
    await renderAt(`/projects/${project.id}`, client);
    await userEvent.click(await screen.findByTestId('generate-report'));
    const coverage = await screen.findByTestId('report-sac-coverage');
    expect(coverage).toHaveTextContent('NO_FINDINGS_RECORDED');
    expect(coverage).toHaveTextContent('does not establish that the target is secure');
    expect(coverage).toHaveTextContent('UNKNOWN');
    expect(coverage).toHaveTextContent('NOT_ASSESSED');
    expect(coverage).toHaveTextContent('DAST: NOT_RUN');
  });
});
