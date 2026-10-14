import { describe, expect, test } from 'vitest';
import {
  isStudentLessonCatalogResponse,
  isStudentLessonPublic,
  isStudentLessonProgress,
  isStudentPracticeRecord,
  isStudentProgressResponse,
  isStudentQuizRecord,
  type StudentLessonPublic,
} from '../src/student.js';

const lesson: StudentLessonPublic = {
  id: 'lsn_demo_lesson',
  title: 'Demo lesson',
  summary: 'A synthetic lesson for guard tests.',
  concept: 'Concept text with no dataset content.',
  objectives: ['Understand the shape.'],
  practice: {
    instruction: 'Import the starter file into your own project and scan.',
    targetRuleId: 'DG-SAST-002',
    starterFiles: [{ path: 'src/demo.js', content: 'const x = 1;\n' }],
    fixInstruction: 'Apply the data-structure fix.',
  },
  quiz: [{ prompt: 'Pick the safe pattern.', options: ['eval(input)', 'lookup table'] }],
};

describe('student shared guards', () => {
  test('a public lesson never carries quiz answers', () => {
    expect(isStudentLessonPublic(lesson)).toBe(true);
    const withAnswer = { ...lesson, quiz: [{ prompt: 'q', options: ['a', 'b'], answerIndex: 0 }] };
    expect(isStudentLessonPublic(withAnswer)).toBe(false);
    const withExtra = { ...lesson, explanation: 'leak' };
    expect(isStudentLessonPublic(withExtra)).toBe(false);
  });

  test('catalog and progress response guards are strict', () => {
    expect(isStudentLessonCatalogResponse({ lessons: [lesson] })).toBe(true);
    expect(isStudentLessonCatalogResponse({ lessons: [] })).toBe(false);
    expect(isStudentLessonCatalogResponse({ lessons: [lesson], next: 'x' })).toBe(false);

    expect(isStudentLessonProgress({ lessonId: 'lsn_demo_lesson', readAcknowledgedAt: '2026-09-30T10:00:00.000Z' })).toBe(true);
    expect(isStudentLessonProgress({ lessonId: 'lsn_demo_lesson' })).toBe(false);
    expect(isStudentLessonProgress({ lessonId: 'bogus', readAcknowledgedAt: '2026-09-30T10:00:00.000Z' })).toBe(false);

    expect(isStudentQuizRecord({ bestCorrect: 2, total: 3, passed: false, attempts: 1, lastAttemptAt: '2026-09-30T10:00:00.000Z' })).toBe(true);
    expect(isStudentQuizRecord({ bestCorrect: 4, total: 3, passed: true, attempts: 1, lastAttemptAt: '2026-09-30T10:00:00.000Z' })).toBe(false);

    expect(isStudentPracticeRecord({ identifiedScanId: 'scan_00000000-0000-4000-8000-000000000001', identifiedAt: '2026-09-30T10:00:00.000Z' })).toBe(true);
    expect(isStudentPracticeRecord({ identifiedScanId: 'scan_00000000-0000-4000-8000-000000000001', verifiedScanId: 'scan_00000000-0000-4000-8000-000000000002' })).toBe(false);

    expect(isStudentProgressResponse({ lessons: [{ lessonId: 'lsn_demo_lesson', readAcknowledgedAt: '2026-09-30T10:00:00.000Z' }] })).toBe(true);
    expect(isStudentProgressResponse({ lessons: [{ lessonId: 'lsn_demo_lesson', readAcknowledgedAt: '2026-09-30T10:00:00.000Z' }, { lessonId: 'lsn_demo_lesson', quiz: { bestCorrect: 1, total: 1, passed: true, attempts: 1, lastAttemptAt: '2026-09-30T10:00:00.000Z' } }] })).toBe(false);
  });
});
