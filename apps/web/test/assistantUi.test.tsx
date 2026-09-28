import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AssistantResponse, Project, ProjectResponse, Scan, ScansResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const PROJECT_ID = 'prj_00000000-0000-4000-8000-0000000000aa';
const SCAN_ID = 'scan_00000000-0000-4000-8000-000000000001';
const project: Project = {
  id: PROJECT_ID, name: 'Assistant UI fixture', description: '', status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z', updatedAt: '2026-09-28T10:00:00.000Z',
};
const scan: Scan = {
  id: SCAN_ID, projectId: PROJECT_ID, scanType: 'SAST', status: 'COMPLETED',
  createdAt: '2026-09-28T10:00:00.000Z', updatedAt: '2026-09-28T10:00:00.000Z',
  completedAt: '2026-09-28T10:01:00.000Z', resultSummary: { findingsTotal: 0 },
};
const answer: AssistantResponse = {
  state: 'SUPPORTED', mode: 'DETERMINISTIC', providerState: 'NONE',
  answer: 'The selected scan stored no finding details; this is not a security guarantee.',
  facts: ['The completed SAST scan persisted zero findings.'],
  interpretations: ['A scan result only describes what this scanner inspected.'],
  recommendations: ['Review scan scope and limitations.'],
  limitations: ['No finding record was returned.'],
  evidence: [{ sourceType: 'SCAN', sourceId: SCAN_ID, projectId: PROJECT_ID, scanId: SCAN_ID }],
  context: { itemCount: 2, characterCount: 140, redactedItems: 0, truncated: false },
};

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getProject: vi.fn(async (): Promise<ProjectResponse> => ({ project })),
    getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [scan] })),
    askAssistant: vi.fn(async (): Promise<AssistantResponse> => answer),
    ...overrides,
  });
}

describe('Pump 14 assistant project UI', () => {
  test('selects authorized scan context, submits a bounded question, and labels deterministic output honestly', async () => {
    const askAssistant = vi.fn(async (): Promise<AssistantResponse> => answer);
    const client = signedInClient({ askAssistant });
    await renderAt(`/projects/${PROJECT_ID}`, client);
    expect(await screen.findByTestId('assistant-section')).toBeInTheDocument();
    expect(await screen.findByTestId('assistant-provider-state')).toHaveTextContent('NONE');
    expect(screen.getByText(/No AI-generated answer, chat history, tool execution/)).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByTestId('assistant-scan-select'), SCAN_ID);
    await userEvent.clear(screen.getByLabelText('Security question'));
    await userEvent.type(screen.getByLabelText('Security question'), 'What did the latest scan report?');
    await userEvent.click(screen.getByTestId('assistant-submit'));

    await waitFor(() => expect(askAssistant).toHaveBeenCalledTimes(1));
    expect(askAssistant).toHaveBeenCalledWith(PROJECT_ID, {
      question: 'What did the latest scan report?', scanId: SCAN_ID,
    });
    expect(await screen.findByTestId('assistant-answer-state')).toHaveTextContent('SUPPORTED');
    expect(screen.getByText('DETERMINISTIC')).toBeInTheDocument();
    expect(screen.getByTestId('assistant-answer-text')).toHaveTextContent('not a security guarantee');
    expect(screen.getByText('Facts from saved records')).toBeInTheDocument();
    expect(screen.getByText('Recommendations')).toBeInTheDocument();
    expect(screen.getByText(/Suggestions are not proof of remediation/)).toBeInTheDocument();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  test('renders server-provided answer strings as inert text', async () => {
    const xssAnswer: AssistantResponse = {
      ...answer,
      answer: '<img src=x onerror=alert(1)> scanner text',
      facts: ['<script>alert(2)</script>'],
    };
    const client = signedInClient({ askAssistant: vi.fn(async () => xssAnswer) });
    await renderAt(`/projects/${PROJECT_ID}`, client);
    await screen.findByTestId('assistant-section');
    await userEvent.click(screen.getByTestId('assistant-submit'));
    const response = await screen.findByTestId('assistant-answer');
    expect(response).toHaveTextContent('<img src=x onerror=alert(1)> scanner text');
    expect(response.querySelector('img, script')).toBeNull();
  });
});
