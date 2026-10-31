import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AgentAssessment, Assessment, CurrentUserResponse, EngagementResponse, Project } from '@drobon/shared';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT = 'prj_00000000-0000-4000-8000-0000000000aa';
const ASSESSMENT = 'asm_00000000-0000-4000-8000-0000000000a1';
const SCAN = 'scan_00000000-0000-4000-8000-000000000001';
const ENGAGEMENT = 'eng_00000000-0000-4000-8000-000000000001';
const target = 'https://fixture.example.org/';
const project: Project = { id: PROJECT, name: 'Agent fixture', description: '', status: 'ACTIVE',
  dastTargetUrl: target, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' };
const assessment: Assessment = { id: ASSESSMENT, projectId: PROJECT, title: 'Local assessment', objectives: ['Review fixture'],
  scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] }, status: 'ACTIVE',
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', startedAt: '2026-01-01T00:00:00.000Z',
  authorizationDeclarations: [], history: [{ id: 'ase_00000000-0000-4000-8000-000000000001', type: 'CREATED', at: '2026-01-01T00:00:00.000Z' }] };
const progress = { totalScans: 0, completedScans: 0, failedScans: 0, activeScans: 0, findingsTotal: 0, recentScans: [] };
const plan: AgentAssessment = {
  assessmentId: ASSESSMENT, generatedAt: '2026-10-31T00:00:00.000Z', mode: 'DETERMINISTIC', model: 'NONE', state: 'PARTIAL',
  inventory: { sourceFiles: 2, targetConfigured: true, manifestFiles: 1, routeCandidates: 1, routeAnalysis: 'PARTIAL' },
  tasks: [
    { scanner: 'SAST', state: 'READY', reason: 'Eligible after rechecks.' },
    { scanner: 'SECRETS', state: 'BLOCKED', reason: 'Engagement excludes this scanner.' },
    { scanner: 'SCA', state: 'PARTIAL', reason: 'Some rules were not evaluated.', scanId: SCAN, findingsTotal: 1, datasetDigest: 'a'.repeat(64) },
    { scanner: 'DAST', state: 'BLOCKED', reason: 'Target is not authorized.' },
  ],
  reviews: [{ scanId: SCAN, findingId: `fnd_${'a'.repeat(24)}`, ruleId: 'DPK-SCA-9901', scanner: 'SCA', severity: 'HIGH',
    verdict: 'INCONCLUSIVE', basis: 'The scan was partial.', priority: 80 }], reviewsOmitted: 0,
  paths: [{ status: 'THEORETICAL', confidence: 'LOW', entryPoint: 'NOT_ESTABLISHED', findingIds: [`fnd_${'a'.repeat(24)}`, `fnd_${'b'.repeat(24)}`],
    explanation: 'Only a same-file observation.', prerequisites: 'Verify reachability.', impact: 'Unknown.', remediation: 'Review manually.' }],
  limitations: ['No AI model.', 'Not exploit validation.'],
};
function clientWith(selected: Assessment = assessment) {
  return stubClient({
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: { ...TEST_USER, userType: 'SECURITY_PROFESSIONAL' } })),
    getProject: vi.fn(async () => ({ project })),
    getAssessments: vi.fn(async () => ({ assessments: [selected] })),
    getAssessment: vi.fn(async () => ({ assessment: selected, progress })),
    getAgentAssessment: vi.fn(async () => ({ agent: plan })),
    executeAgent: vi.fn(async () => ({ agent: { ...plan, state: 'ACTIVE' as const, tasks: plan.tasks.map((task) => task.scanner === 'SAST' ? { ...task, state: 'QUEUED' as const, scanId: SCAN } : task) },
      actions: [{ scanner: 'SAST' as const, result: 'CREATED' as const, reason: 'Queued through existing quota.' }] })),
  });
}

describe('assessment-scoped deterministic agent UI', () => {
  test('loads a bounded plan, presents uncertainty, requires confirmation and refreshes existing scans', async () => {
    const user = userEvent.setup();
    const client = clientWith();
    await renderAt(`/projects/${PROJECT}`, client);
    expect(await screen.findByTestId('assessment-agent')).toHaveTextContent('no AI model or independent exploit validation');
    expect(client.getAgentAssessment).not.toHaveBeenCalled();
    await user.click(screen.getByTestId('agent-load'));
    expect(await screen.findByTestId('agent-content')).toHaveTextContent('Model: NONE');
    expect(screen.getByTestId('agent-tasks')).toHaveTextContent('SECRETS: BLOCKED');
    expect(screen.getByTestId('agent-reviews')).toHaveTextContent('INCONCLUSIVE');
    expect(screen.getByTestId('agent-paths')).toHaveTextContent('THEORETICAL');
    expect(screen.getByTestId('agent-execute')).toBeDisabled();
    const scanCallsBefore = vi.mocked(client.getScans).mock.calls.length;
    await user.click(screen.getByTestId('agent-confirm'));
    await user.click(screen.getByTestId('agent-execute'));
    await waitFor(() => expect(client.executeAgent).toHaveBeenCalledWith(PROJECT, ASSESSMENT));
    expect(await screen.findByTestId('agent-actions')).toHaveTextContent('CREATED');
    await waitFor(() => expect(vi.mocked(client.getScans).mock.calls.length).toBeGreaterThan(scanCallsBefore));
  });

  test('requires a separate confirmation before cancelling one active agent job', async () => {
    const user = userEvent.setup();
    const client = clientWith();
    const active: AgentAssessment = { ...plan, state: 'ACTIVE', tasks: plan.tasks.map((task) =>
      task.scanner === 'SAST' ? { ...task, state: 'RUNNING', scanId: SCAN } : task) };
    const pending: AgentAssessment = { ...active, tasks: active.tasks.map((task) =>
      task.scanner === 'SAST' ? { ...task, state: 'CANCELLING', reason: 'Cancellation is recorded; worker still settling.' } : task) };
    client.getAgentAssessment = vi.fn().mockResolvedValueOnce({ agent: active }).mockResolvedValue({ agent: pending });
    client.cancelAgentScan = vi.fn(async () => ({ scanId: SCAN, state: 'CANCELLING' as const }));
    await renderAt(`/projects/${PROJECT}`, client);
    await user.click(await screen.findByTestId('agent-load'));
    await user.click(await screen.findByTestId('agent-cancel-SAST'));
    expect(client.cancelAgentScan).not.toHaveBeenCalled();
    expect(screen.getByTestId('agent-tasks')).toHaveTextContent('in-flight request cannot be recalled');
    await user.click(screen.getByTestId('agent-cancel-confirm-SAST'));
    await waitFor(() => expect(client.cancelAgentScan).toHaveBeenCalledWith(PROJECT, ASSESSMENT, SCAN));
    await waitFor(() => expect(screen.getByTestId('agent-tasks')).toHaveTextContent('SAST: CANCELLING'));
  });

  test('exports only the bounded public JSON summary, not raw source or fabricated evidence', async () => {
    const user = userEvent.setup();
    const client = clientWith();
    const createUrl = vi.fn((_blob: Blob | MediaSource) => 'blob:agent-fixture');
    URL.createObjectURL = createUrl;
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    await renderAt(`/projects/${PROJECT}`, client);
    await user.click(await screen.findByTestId('agent-load'));
    await user.click(await screen.findByTestId('agent-export'));
    expect(createUrl).toHaveBeenCalledTimes(1);
    const blob = createUrl.mock.calls[0]?.[0] as Blob;
    const text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = () => reject(reader.error); reader.readAsText(blob);
    });
    const parsed: unknown = JSON.parse(text);
    expect(parsed).toEqual({ reportType: 'drobon-agent-assessment-summary', agent: plan });
    expect(text).not.toContain('source content');
    expect(click).toHaveBeenCalledTimes(1);
    click.mockRestore();
  });

  test('records only explicit engagement choices and supports deliberate withdrawal', async () => {
    const user = userEvent.setup();
    const engagement: EngagementResponse['engagement'] = { id: ENGAGEMENT, clientName: 'Fixture client', targetUrl: target,
      inScopeHosts: ['fixture.example.org'], scopePaths: ['/api'], allowedScanTypes: ['SAST', 'DAST'],
      validFrom: '2026-10-31T00:00:00.000Z', validUntil: '2026-11-01T00:00:00.000Z', statement: 'I authorize this local fixture test.',
      declaredBy: 'usr_fixture', declaredAt: '2026-10-31T00:00:00.000Z', state: 'DECLARED', status: 'ACTIVE' };
    const selected = { ...assessment, engagements: [engagement] };
    const client = clientWith(selected);
    client.createEngagement = vi.fn(async () => ({ engagement }));
    client.withdrawEngagement = vi.fn(async (): Promise<EngagementResponse> => ({ engagement: { ...engagement, state: 'WITHDRAWN', status: 'WITHDRAWN', withdrawnAt: '2026-10-31T01:00:00.000Z' } }));
    await renderAt(`/projects/${PROJECT}`, client);
    await user.click(await screen.findByTestId('engagement-open'));
    const form = screen.getByTestId('engagement-form');
    await user.type(within(form).getByLabelText('Client or owner name'), 'Fixture client');
    await user.type(within(form).getByLabelText('Authorized path prefixes (one per line)'), '/api');
    await user.click(within(form).getByLabelText('SAST'));
    await user.click(within(form).getByLabelText('DAST'));
    fireEvent.change(within(form).getByLabelText('Valid from (local time)'), { target: { value: '2026-10-31T00:00' } });
    fireEvent.change(within(form).getByLabelText('Valid until (local time)'), { target: { value: '2026-11-01T00:00' } });
    await user.type(within(form).getByLabelText('Authorization statement'), 'I authorize this local fixture test.');
    expect(screen.getByTestId('engagement-submit')).toBeDisabled();
    await user.click(within(form).getByLabelText(/I attest/));
    await user.click(screen.getByTestId('engagement-submit'));
    await waitFor(() => expect(client.createEngagement).toHaveBeenCalledWith(PROJECT, ASSESSMENT, expect.objectContaining({
      clientName: 'Fixture client', targetUrl: target, inScopeHosts: ['fixture.example.org'], scopePaths: ['/api'], allowedScanTypes: ['SAST', 'DAST'], confirm: true,
    })));
    await user.click(await screen.findByTestId('engagement-withdraw'));
    expect(client.withdrawEngagement).not.toHaveBeenCalled();
    expect(screen.getByTestId('engagement-controls')).toHaveTextContent('in-flight request cannot be recalled');
    await user.click(screen.getByTestId('engagement-withdraw-confirm'));
    await waitFor(() => expect(client.withdrawEngagement).toHaveBeenCalledWith(PROJECT, ASSESSMENT, ENGAGEMENT));
  });
});
