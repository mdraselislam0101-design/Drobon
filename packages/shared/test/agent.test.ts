import { describe, expect, test } from 'vitest';
import { isAgentAssessmentResponse, isAgentCancellationResponse, isAgentExecutionResponse } from '../src/agent.js';

const agent = {
  assessmentId: 'asm_00000000-0000-4000-8000-000000000001', generatedAt: '2026-10-31T00:00:00.000Z',
  mode: 'DETERMINISTIC', model: 'NONE', state: 'NOT_STARTED',
  inventory: { sourceFiles: 1, targetConfigured: true, manifestFiles: 0, routeCandidates: 0, routeAnalysis: 'COMPLETE' },
  tasks: ['SAST', 'SECRETS', 'SCA', 'DAST'].map((scanner) => ({ scanner, state: 'READY', reason: 'Authorized checks are re-evaluated.' })),
  reviews: [], reviewsOmitted: 0, paths: [], limitations: ['No model is running.'],
};

describe('agent public contract guards', () => {
  test('accepts only bounded deterministic plan and execution shapes', () => {
    expect(isAgentAssessmentResponse({ agent })).toBe(true);
    expect(isAgentExecutionResponse({ agent, actions: [{ scanner: 'SAST', result: 'INCONCLUSIVE', reason: 'Queue result unknown.' }] })).toBe(true);
    expect(isAgentAssessmentResponse({ agent: { ...agent, model: 'GPT' } })).toBe(false);
    expect(isAgentAssessmentResponse({ agent: { ...agent, source: 'raw source' } })).toBe(false);
    expect(isAgentAssessmentResponse({ agent: { ...agent, inventory: { ...agent.inventory, sourceFiles: 201 } } })).toBe(false);
    expect(isAgentAssessmentResponse({ agent: { ...agent, tasks: [agent.tasks[0], agent.tasks[0], agent.tasks[2], agent.tasks[3]] } })).toBe(false);
    expect(isAgentAssessmentResponse({ agent: { ...agent, reviews: Array(101).fill({}) } })).toBe(false);
    expect(isAgentExecutionResponse({ agent, actions: [{ scanner: 'SAST', result: 'CONFIRMED', reason: 'Invalid.' }] })).toBe(false);
  });
  test('accepts only explicit bounded cancellation responses', () => {
    const scanId = 'scan_00000000-0000-4000-8000-000000000001';
    expect(isAgentCancellationResponse({ scanId, state: 'CANCELLING' })).toBe(true);
    expect(isAgentCancellationResponse({ scanId, state: 'CANCELLED' })).toBe(true);
    expect(isAgentCancellationResponse({ scanId, state: 'COMPLETED' })).toBe(false);
    expect(isAgentCancellationResponse({ scanId, state: 'CANCELLED', agent: 'raw' })).toBe(false);
    expect(isAgentCancellationResponse({ scanId: 'bad', state: 'CANCELLED' })).toBe(false);
  });
  test('does not accept a theoretical path claimed as validated', () => {
    const path = { status: 'THEORETICAL', confidence: 'LOW', entryPoint: 'NOT_ESTABLISHED',
      findingIds: [`fnd_${'a'.repeat(24)}`, `fnd_${'b'.repeat(24)}`], explanation: 'Same file only.', prerequisites: 'Verify reachability.',
      impact: 'Unknown.', remediation: 'Review manually.' };
    expect(isAgentAssessmentResponse({ agent: { ...agent, paths: [path] } })).toBe(true);
    expect(isAgentAssessmentResponse({ agent: { ...agent, paths: [{ ...path, status: 'VALIDATED' }] } })).toBe(false);
    expect(isAgentAssessmentResponse({ agent: { ...agent, paths: [{ ...path, findingIds: ['bad'] }] } })).toBe(false);
  });
});
