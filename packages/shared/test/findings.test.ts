import { describe, expect, test } from 'vitest';
import {
  isFindingDetailResponse,
  isFindingHistoryResponse,
  isFindingWorkflow,
  isFindingWorkflowResponse,
  isFindingsPageResponse,
} from '../src/findings.js';
import type { Finding, FindingWorkflow, Project, Scan } from '../src/index.js';

const project: Project = {
  id: 'prj_00000000-0000-4000-8000-000000000021',
  name: 'Findings contract fixture',
  description: '',
  status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:00.000Z',
};

const scan: Scan = {
  id: 'scan_00000000-0000-4000-8000-000000000021',
  projectId: project.id,
  scanType: 'SAST',
  status: 'COMPLETED',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:01.000Z',
  startedAt: '2026-09-28T10:00:00.100Z',
  completedAt: '2026-09-28T10:00:01.000Z',
  resultSummary: { findingsTotal: 1 },
};

const finding: Finding = {
  id: `fnd_${'a'.repeat(24)}`,
  scanId: scan.id,
  scanner: 'SAST',
  ruleId: 'DG-SAST-001',
  severity: 'HIGH',
  title: 'Unsafe source construct',
  description: 'Synthetic contract fixture.',
  evidence: 'line 1: <redacted>',
  remediation: 'Use a safe alternative.',
  file: 'src/app.ts',
  line: 1,
  column: 1,
  fingerprint: 'b'.repeat(64),
};

const workflow: FindingWorkflow = {
  id: 'fwf_00000000-0000-4000-8000-000000000021',
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

describe('bounded findings page and detail contracts', () => {
  test('accepts consistent filtered pages and rejects cross-filter data', () => {
    const page = {
      findings: [finding], page: 1, pageSize: 1, total: 1, totalPages: 1,
      severity: 'HIGH', scanner: 'SAST',
    };
    expect(isFindingsPageResponse(page)).toBe(true);
    expect(isFindingsPageResponse({ ...page, findings: [{ ...finding, severity: 'LOW' }] })).toBe(false);
    expect(isFindingsPageResponse({ ...page, findings: [{ ...finding, scanner: 'SECRETS' }] })).toBe(false);
    expect(isFindingsPageResponse({ ...page, pageSize: 0 })).toBe(false);
    expect(isFindingsPageResponse({ ...page, total: 201 })).toBe(false);
    expect(isFindingsPageResponse({ ...page, unexpected: true })).toBe(false);
  });

  test('detail must bind the finding, project, scan and scanner together', () => {
    const detail = { project, scan, finding };
    expect(isFindingDetailResponse(detail)).toBe(true);
    expect(isFindingDetailResponse({ ...detail, project: { ...project, id: 'prj_00000000-0000-4000-8000-000000000022' } })).toBe(false);
    expect(isFindingDetailResponse({ ...detail, finding: { ...finding, scanId: 'scan_00000000-0000-4000-8000-000000000022' } })).toBe(false);
    expect(isFindingDetailResponse({ ...detail, finding: { ...finding, projectId: 'prj_00000000-0000-4000-8000-000000000022' } })).toBe(false);
    expect(isFindingDetailResponse({ ...detail, scan: { ...scan, scanType: 'SECRETS' } })).toBe(false);
  });

  test('workflow, mutation, history and current finding-detail contracts stay bounded and cross-bound', () => {
    expect(isFindingWorkflow(workflow)).toBe(true);
    expect(isFindingWorkflow({ ...workflow, state: 'FIXED' })).toBe(false);
    expect(isFindingWorkflowResponse({ workflow })).toBe(true);
    expect(isFindingWorkflowResponse({ workflow, projectId: project.id })).toBe(false);
    const currentDetail = {
      project, scan, finding, workflow,
      guidance: {
        ruleId: finding.ruleId, status: 'RULE_SPECIFIC', whyItMatters: 'Rule-bound explanation.',
        actions: ['Review the scanner rule.'], verification: 'Run the same authorized scanner again.',
      },
    };
    expect(isFindingDetailResponse(currentDetail)).toBe(true);
    expect(isFindingDetailResponse({ ...currentDetail, workflow: { ...workflow, fingerprint: 'c'.repeat(64) } })).toBe(false);
    expect(isFindingDetailResponse({ ...currentDetail, guidance: { ...currentDetail.guidance, ruleId: 'DG-SAST-002' } })).toBe(false);
    const history = {
      events: [{
        id: 'fev_00000000-0000-4000-8000-000000000021', findingId: finding.id,
        previousState: null, newState: 'OPEN', actorId: 'system:scanner', actorType: 'SYSTEM',
        action: 'FINDING_OBSERVED', at: scan.completedAt,
      }],
      page: 1, pageSize: 20, total: 1, totalPages: 1,
    };
    expect(isFindingHistoryResponse(history)).toBe(true);
    expect(isFindingHistoryResponse({ ...history, total: 201 })).toBe(false);
    expect(isFindingWorkflow({ ...workflow, notes: [{
      id: 'fnt_00000000-0000-4000-8000-000000000021', text: '<img src=x>', actorId: 'usr_owner',
      createdAt: scan.completedAt, redacted: false,
    }] })).toBe(false);
  });
});
