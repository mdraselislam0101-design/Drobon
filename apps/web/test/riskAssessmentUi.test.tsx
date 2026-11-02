// @vitest-environment jsdom
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { Project, RiskAssessmentResponse } from '@drobon/shared';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const project: Project = {
  id: 'prj_00000000-0000-4000-8000-0000000000bb', name: 'Risk project', description: '', status: 'ACTIVE',
  createdAt: '2026-11-01T10:00:00.000Z', updatedAt: '2026-11-01T10:00:00.000Z',
};

const assessment: RiskAssessmentResponse = {
  assessment: {
    schemaVersion: '1.0', assessmentLevel: 'DERIVED_CORRELATION', scoringModel: 'SEVERITY_SUM_V1',
    projectId: project.id, generatedAt: '2026-11-02T09:00:00.000Z',
    status: 'ASSESSED', band: 'HIGH', score: 13,
    sources: [
      { scanner: 'SAST', scanId: 'scan_00000000-0000-4000-8000-000000000001', completedAt: '2026-11-01T10:00:00.000Z', findings: 1 },
      { scanner: 'SCA', scanId: null, completedAt: null, findings: 0 },
      { scanner: 'SECRETS', scanId: null, completedAt: null, findings: 0 },
      { scanner: 'DAST', scanId: 'scan_00000000-0000-4000-8000-000000000004', completedAt: '2026-11-01T11:00:00.000Z', findings: 1 },
    ],
    findingsAnalysed: 2, correlatedFindings: 2, unclusteredFindings: 0,
    clusters: [{
      id: `risk_${'a'.repeat(24)}`, kind: 'CODE_AND_RUNTIME_CWE', band: 'HIGH', score: 13,
      scanners: ['DAST', 'SAST'], title: 'CWE-89 is present in code and observed at runtime',
      summary: '1 SAST and 1 DAST finding(s) carry CWE-89. This is a correlation of class, not proof of an attack chain.',
      asset: 'CWE-89',
      evidence: [
        { findingId: `fnd_${'b'.repeat(24)}`, scanner: 'SAST', severity: 'HIGH', ruleId: 'DG-SAST-002', asset: 'src/db.js' },
        { findingId: `fnd_${'c'.repeat(24)}`, scanner: 'DAST', severity: 'HIGH', ruleId: 'DG-DAST-990002', asset: 'https://fixture.example.org/login' },
      ],
    }],
    disclosures: ['Correlation groups findings that were already recorded.', 'Scores are triage aids, not CVSS.'],
    truncated: false,
  },
};

async function renderPage(response: RiskAssessmentResponse) {
  const getRiskAssessment = vi.fn(async () => response);
  const client = stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async () => ({ project })),
    getScans: vi.fn(async () => ({ scans: [] })),
    getRiskAssessment,
  });
  await renderAt(`/projects/${project.id}`, client);
  return getRiskAssessment;
}

describe('correlated risk UI', () => {
  test('loads only on request and names the evidence behind every cluster', async () => {
    const getRiskAssessment = await renderPage(assessment);
    expect(await screen.findByTestId('risk-assessment')).toBeInTheDocument();
    expect(getRiskAssessment).not.toHaveBeenCalled();
    await userEvent.click(screen.getByTestId('risk-load'));
    const content = await screen.findByTestId('risk-content');
    expect(content).toHaveTextContent('HIGH band');
    expect(content).toHaveTextContent('score 13');
    expect(content).toHaveTextContent('2 finding(s) analysed, 2 correlated, 0 unclustered');
    expect(content).toHaveTextContent('DAST: 1 finding(s)');
    expect(content).toHaveTextContent('SCA: no completed scan');
    expect(content).toHaveTextContent('CWE-89 is present in code and observed at runtime');
    expect(content).toHaveTextContent(`fnd_${'b'.repeat(24)}`);
    expect(content).toHaveTextContent(`fnd_${'c'.repeat(24)}`);
    expect(getRiskAssessment).toHaveBeenCalledWith(project.id);
    await userEvent.click(within(content).getByText('What this assessment cannot claim'));
    expect(content).toHaveTextContent('not CVSS');
  });

  test('shows an honest empty state instead of implying the project is safe', async () => {
    await renderPage({
      assessment: {
        ...assessment.assessment,
        status: 'NO_FINDINGS', band: 'UNKNOWN', score: 0,
        sources: assessment.assessment.sources.map((source) => ({ ...source, scanId: null, completedAt: null, findings: 0 })),
        findingsAnalysed: 0, correlatedFindings: 0, unclusteredFindings: 0, clusters: [],
      },
    });
    await userEvent.click(screen.getByTestId('risk-load'));
    const content = await screen.findByTestId('risk-content');
    expect(content).toHaveTextContent('UNKNOWN band');
    expect(content).toHaveTextContent('No evidence overlap was found');
    expect(content).toHaveTextContent('not evidence that the project is safe');
    expect(screen.queryByTestId('risk-clusters')).toBeNull();
  });
});
