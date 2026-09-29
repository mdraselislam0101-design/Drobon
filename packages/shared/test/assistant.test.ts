import { describe, expect, test } from 'vitest';
import {
  ASSISTANT_CONTEXT_MAX_LENGTH,
  isAssistantQuestionRequest,
  isAssistantResponse,
  isAssistantStatusResponse,
} from '../src/assistant.js';

const PROJECT = 'prj_00000000-0000-4000-8000-000000000001';
const SCAN = 'scan_00000000-0000-4000-8000-000000000001';
const FINDING = `fnd_${'a'.repeat(24)}`;

const response = {
  state: 'SUPPORTED',
  mode: 'DETERMINISTIC',
  providerState: 'NONE',
  answer: 'The completed SAST scan stored one finding.',
  facts: ['One finding was persisted.'],
  interpretations: ['This is scanner evidence, not proof of exploitability.'],
  recommendations: [],
  limitations: ['Only the selected scan is covered.'],
  evidence: [{ sourceType: 'SCAN', sourceId: SCAN, projectId: PROJECT, scanId: SCAN }],
  context: { itemCount: 1, characterCount: 42, redactedItems: 0, truncated: false },
};

describe('AI Security Assistant shared contracts', () => {
  test('strictly validates bounded user requests and server-owned selectors', () => {
    expect(isAssistantQuestionRequest({ question: 'Explain this finding', scanId: SCAN, findingId: FINDING })).toBe(true);
    expect(isAssistantQuestionRequest({ question: 'x'.repeat(1201) })).toBe(false);
    expect(isAssistantQuestionRequest({ question: 'Explain', findingId: FINDING })).toBe(false);
    expect(isAssistantQuestionRequest({ question: 'Explain', provider: 'arbitrary' })).toBe(false);
    expect(isAssistantQuestionRequest({ question: 'Compare', scanId: SCAN, compareScanId: 'foreign' })).toBe(false);
    expect(isAssistantQuestionRequest({ question: ' \n ' })).toBe(false);
  });

  test('validates deterministic response structure, explicit state and bounded provenance', () => {
    expect(isAssistantResponse(response)).toBe(true);
    expect(isAssistantResponse({ ...response, confidence: 0.99 })).toBe(false);
    expect(isAssistantResponse({ ...response, evidence: Array.from({ length: 31 }, () => response.evidence[0]) })).toBe(false);
    expect(isAssistantResponse({ ...response, context: { ...response.context, characterCount: ASSISTANT_CONTEXT_MAX_LENGTH + 1 } })).toBe(false);
    expect(isAssistantResponse({ ...response, mode: 'FAKE_LLM' })).toBe(false);
  });

  test('provider status is closed-shaped and declares history/tools disabled', () => {
    const fixed = { deterministicQuestionsAvailable: true, conversationPersistence: 'NOT_IMPLEMENTED', toolsEnabled: false };
    expect(isAssistantStatusResponse({ providerState: 'NONE', providerId: null, ...fixed })).toBe(true);
    expect(isAssistantStatusResponse({ providerState: 'UNAVAILABLE', providerId: null, ...fixed })).toBe(true);
    expect(isAssistantStatusResponse({ providerState: 'AVAILABLE', providerId: 'provider-x', ...fixed })).toBe(true);
    expect(isAssistantStatusResponse({ providerState: 'AVAILABLE', providerId: null, ...fixed })).toBe(false);
    expect(isAssistantStatusResponse({ providerState: 'MADE_UP', providerId: null, ...fixed })).toBe(false);
    expect(isAssistantStatusResponse({ providerState: 'NONE', providerId: null, ...fixed, toolsEnabled: true })).toBe(false);
  });
});
