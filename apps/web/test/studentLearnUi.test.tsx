import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type {
  CurrentUserResponse,
  StudentLessonCatalogResponse,
  StudentProgressResponse,
  StudentQuizResultResponse,
} from '@drobon/shared';
import { ApiClientError } from '../src/api/client.js';
import { TEST_USER, renderAt, stubClient } from './appFixtures.js';

/**
 * Phase 22 Pump 2 web suite: the Student learning path renders the
 * internally authored catalog, never exposes quiz answers, records read
 * state and quiz submissions through the server-authoritative client, and
 * surfaces honest practice-verification verdicts (including failure text).
 */

const lessonCatalog: StudentLessonCatalogResponse = {
  lessons: [
    {
      id: 'lsn_code_injection_eval',
      title: 'Code injection through dynamic evaluation',
      summary: 'Why eval on untrusted input is never safe.',
      concept: 'eval() treats its argument as code. Anything concatenated into it executes.',
      objectives: ['Recognize the pattern', 'Replace it with data'],
      practice: {
        instruction: 'Copy the starter file into your own project and run a SAST scan.',
        targetRuleId: 'DG-SAST-002',
        starterFiles: [{ path: 'src/calculator.js', content: 'function compute(expr){ return eval(expr); }\n' }],
        fixInstruction: 'Replace eval with an explicit lookup of allowed operations.',
      },
      quiz: [
        { prompt: 'Why is eval risky on user input?', options: ['It is slow', 'Concatenated input becomes executable code', 'It logs the input'] },
      ],
    },
    {
      id: 'lsn_command_injection_exec',
      title: 'Command injection through shell calls',
      summary: 'exec spawns a shell; execFile does not.',
      concept: 'Strings passed to exec can contain shell metacharacters.',
      objectives: ['Prefer execFile'],
      practice: {
        instruction: 'Copy the starter file into your own project and run a SAST scan.',
        targetRuleId: 'DG-SAST-001',
        starterFiles: [{ path: 'src/archive.js', content: "exec('tar czf backup.tgz ' + dir);\n" }],
        fixInstruction: 'Use execFile with an argv array.',
      },
      quiz: [{ prompt: 'Which call avoids a shell?', options: ['exec(cmd)', 'execFile(file, args)', 'system(cmd)'] }],
    },
  ],
};

const emptyProgress: StudentProgressResponse = { lessons: [] };

const studentClient = (overrides: Parameters<typeof stubClient>[0] = {}): ReturnType<typeof stubClient> =>
  stubClient({
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: { ...TEST_USER, userType: 'STUDENT' } })),
    getStudentLessons: vi.fn(async (): Promise<StudentLessonCatalogResponse> => lessonCatalog),
    getStudentProgress: vi.fn(async (): Promise<StudentProgressResponse> => emptyProgress),
    ...overrides,
  });

describe('student learning path UI', () => {
  test('catalog renders with progress badges and answers never reach the DOM', async () => {
    const client = studentClient();
    await renderAt('/student/learn', client);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Learning path' })).toBeTruthy());
    expect(screen.getByText(/Code injection through dynamic evaluation/)).toBeTruthy();
    expect(screen.getByText(/Command injection through shell calls/)).toBeTruthy();
    expect(screen.getByText(/Practice rule: DG-SAST-002/)).toBeTruthy();
    expect(document.body.textContent).not.toContain('answerIndex');
    expect(document.body.textContent).not.toContain('Concatenated input becomes executable code');
  });

  test('read acknowledgement, quiz submission, and practice verification flow through the client', async () => {
    const user = userEvent.setup();
    const progressAfterRead: StudentProgressResponse = {
      lessons: [{ lessonId: 'lsn_code_injection_eval', readAcknowledgedAt: '2026-09-30T10:00:00.000Z' }],
    };
    const quizResult: StudentQuizResultResponse = {
      correctCount: 1,
      total: 1,
      passed: true,
      feedback: [{ index: 0, chosen: 1, correctIndex: 1, explanation: 'exec spawns a shell; argv arrays do not.' }],
    };
    const getStudentProgress = vi.fn()
      .mockResolvedValueOnce(emptyProgress)
      .mockResolvedValueOnce(progressAfterRead)
      .mockResolvedValue(progressAfterRead);
    const client = studentClient({
      getStudentProgress,
      acknowledgeLessonRead: vi.fn(async (): Promise<StudentProgressResponse> => progressAfterRead),
      submitLessonQuiz: vi.fn(async (): Promise<StudentQuizResultResponse> => quizResult),
      verifyLessonPractice: vi.fn(async (): Promise<StudentProgressResponse> => progressAfterRead),
    });
    await renderAt('/student/learn', client);
    await waitFor(() => expect(screen.getByText(/Code injection through dynamic evaluation/)).toBeTruthy());

    await user.click(screen.getAllByRole('button', { name: 'Open lesson' })[0]!);
    await user.click(screen.getByRole('button', { name: /Mark lesson as read/ }));
    await waitFor(() => expect(client.acknowledgeLessonRead).toHaveBeenCalledWith('lsn_code_injection_eval'));

    const quizFieldset = screen.getByRole('group');
    await user.click(within(quizFieldset).getByRole('radio', { name: /Concatenated input becomes executable code/ }));
    await user.click(screen.getByRole('button', { name: 'Submit answers' }));
    await waitFor(() => expect(client.submitLessonQuiz).toHaveBeenCalledWith('lsn_code_injection_eval', [1]));
    expect(await screen.findByText(/Score: 1\/1/)).toBeTruthy();

    await user.click(screen.getByRole('button', { name: /Verify identification/ }));
    await waitFor(() => expect(client.verifyLessonPractice).toHaveBeenCalledWith('lsn_code_injection_eval', 'IDENTIFY'));
    await waitFor(() => expect(screen.getByText(/Identification evidence recorded/)).toBeTruthy());

    await user.click(screen.getByRole('button', { name: /Verify fix/ }));
    await waitFor(() => expect(client.verifyLessonPractice).toHaveBeenCalledWith('lsn_code_injection_eval', 'FIX'));
    expect(await screen.findByText(/Fix verified — the rule is no longer observed/)).toBeTruthy();
  });

  test('practice verification surfaces the honest server refusal when no evidence exists', async () => {
    const user = userEvent.setup();
    const client = studentClient({
      verifyLessonPractice: vi.fn(async (): Promise<StudentProgressResponse> => {
        throw new ApiClientError({ kind: 'http', message: 'No identification evidence yet — scan your own project first.', status: 409, requestId: 'test' });
      }),
    });
    await renderAt('/student/learn', client);
    await waitFor(() => expect(screen.getByText(/Code injection through dynamic evaluation/)).toBeTruthy());
    await user.click(screen.getAllByRole('button', { name: 'Open lesson' })[0]!);
    await user.click(screen.getByRole('button', { name: /Verify identification/ }));
    await waitFor(() => expect(screen.getByText(/No identification evidence yet/)).toBeTruthy());
  });
});
