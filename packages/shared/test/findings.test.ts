import { describe, expect, test } from 'vitest';
import { isFindingDetailResponse, isFindingsPageResponse } from '../src/findings.js';
import type { Finding, Project, Scan } from '../src/index.js';

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
});
