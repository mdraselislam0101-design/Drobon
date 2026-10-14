import { describe, expect, test } from 'vitest';
import { isAssessment, isAssessmentDetailResponse, isAssessmentHostname, isAssessmentScope, isAssessmentSummaryResponse } from '../src/assessments.js';

const assessment = {
  id: 'asm_00000000-0000-4000-8000-000000000001',
  projectId: 'prj_00000000-0000-4000-8000-000000000001',
  title: 'Authorization review',
  objectives: ['Review ownership boundaries'],
  scope: { inScopeHosts: ['app.example.test'], outOfScopeHosts: ['admin.example.test'] },
  status: 'ACTIVE',
  createdAt: '2026-09-29T10:00:00.000Z',
  updatedAt: '2026-09-29T10:05:00.000Z',
  startedAt: '2026-09-29T10:05:00.000Z',
  authorizationDeclarations: [{ targetUrl: 'https://app.example.test/', state: 'USER_DECLARED', declaredAt: '2026-09-29T10:06:00.000Z' }],
  history: [
    { id: 'ase_00000000-0000-4000-8000-000000000001', type: 'CREATED', at: '2026-09-29T10:00:00.000Z' },
    { id: 'ase_00000000-0000-4000-8000-000000000002', type: 'STATUS_CHANGED', at: '2026-09-29T10:05:00.000Z', status: 'ACTIVE' },
    { id: 'ase_00000000-0000-4000-8000-000000000003', type: 'AUTHORIZATION_DECLARED', at: '2026-09-29T10:06:00.000Z', targetUrl: 'https://app.example.test/' },
  ],
};

describe('structured assessment contracts', () => {
  test('accepts bounded owner/project workflow contracts with honest user-declaration state', () => {
    expect(isAssessment(assessment)).toBe(true);
    expect(isAssessment({ ...assessment, ownerId: 'usr_should-never-be-public' })).toBe(false);
    expect(isAssessment({ ...assessment, status: 'VERIFIED' })).toBe(false);
    expect(isAssessment({ ...assessment, completedAt: '2026-09-29T10:07:00.000Z' })).toBe(false);
  });

  test('scope is exact-host DNS metadata, rejecting wildcards, address literals, duplicates, and overlap', () => {
    expect(isAssessmentHostname('app.example.test')).toBe(true);
    for (const host of ['*.example.test', '127.0.0.1', 'localhost', 'app.example.test.', 'a..example.test', 'UPPER.example.test']) {
      expect(isAssessmentHostname(host)).toBe(false);
    }
    expect(isAssessmentScope({ inScopeHosts: ['app.example.test'], outOfScopeHosts: [] })).toBe(true);
    expect(isAssessmentScope({ inScopeHosts: ['app.example.test', 'app.example.test'], outOfScopeHosts: [] })).toBe(false);
    expect(isAssessmentScope({ inScopeHosts: ['app.example.test'], outOfScopeHosts: ['app.example.test'] })).toBe(false);
  });

  test('assessment detail progress has a strict bounded scan-summary shape', () => {
    const value = {
      assessment,
      progress: {
        totalScans: 1, completedScans: 1, failedScans: 0, activeScans: 0, findingsTotal: 2,
        recentScans: [{ id: 'scan_00000000-0000-4000-8000-000000000001', scanType: 'DAST', status: 'COMPLETED', createdAt: '2026-09-29T10:20:00.000Z', completedAt: '2026-09-29T10:21:00.000Z', targetUrl: 'https://app.example.test/', findingsTotal: 2, reportAvailable: true }],
      },
    };
    expect(isAssessmentDetailResponse(value)).toBe(true);
    expect(isAssessmentDetailResponse({ ...value, progress: { ...value.progress, activeScans: 1 } })).toBe(false);
  });
});

describe('assessment summary guard (Phase 22 Pump 3)', () => {
  const summary = {
    assessment: { id: 'asm_00000000-0000-4000-8000-000000000001', title: 'Quarterly review', status: 'ACTIVE', createdAt: '2026-09-30T09:00:00.000Z', startedAt: '2026-09-30T09:05:00.000Z' },
    objectivesTotal: 2,
    scope: { inScopeHosts: ['app.example.test'], outOfScopeHosts: [] },
    totals: { scansLinked: 2, scansCompleted: 2, scansFailed: 0, scansActive: 0, findingsTotal: 3, findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 0 }, partialScans: 0 },
    scans: [
      { scanId: 'scan_00000000-0000-4000-8000-000000000001', scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-30T09:10:00.000Z', completedAt: '2026-09-30T09:11:00.000Z', findingsTotal: 2, findingsBySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 }, reportAvailable: true },
      { scanId: 'scan_00000000-0000-4000-8000-000000000002', scanType: 'SAST', status: 'QUEUED', createdAt: '2026-09-30T09:12:00.000Z', reportAvailable: false },
    ],
    generatedAt: '2026-09-30T09:20:00.000Z',
  };
  test('accepts the honest bounded aggregate', () => {
    expect(isAssessmentSummaryResponse(summary)).toBe(true);
  });
  test('rejects broken shapes', () => {
    expect(isAssessmentSummaryResponse({ ...summary, totals: { ...summary.totals, findingsTotal: -1 } })).toBe(false);
    expect(isAssessmentSummaryResponse({ ...summary, totals: { ...summary.totals, findingsBySeverity: { CRITICAL: 0, HIGH: 2 } } })).toBe(false);
    expect(isAssessmentSummaryResponse({ ...summary, scans: [...summary.scans, { ...summary.scans[1], scanId: 'bogus' }] })).toBe(false);
    expect(isAssessmentSummaryResponse({ ...summary, extra: 1 })).toBe(false);
  });
});
