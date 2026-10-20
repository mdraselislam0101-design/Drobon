import type { StudentLessonPublic, StudentPracticeFile, StudentQuizQuestionPublic } from '@drobon/shared';

/**
 * Student lesson framework — engine only, no embedded lessons.
 * All lesson data lives in Drobon-Dataset learning/lessons (lsn_*).
 * Paid-tool parity: content is data, code is engine.
 */

interface StudentQuizQuestionInternal extends StudentQuizQuestionPublic {
  answerIndex: number;
  explanation: string;
}

export interface StudentLessonInternal {
  id: string;
  title: string;
  summary: string;
  concept: string;
  objectives: string[];
  practice: {
    instruction: string;
    targetRuleId: string;
    starterFiles: StudentPracticeFile[];
    fixInstruction: string;
    fixedFiles: StudentPracticeFile[];
  };
  quiz: StudentQuizQuestionInternal[];
}

/**
 * No embedded lessons — all lessons are loaded from dataset.
 * Engine falls back to 0 lessons when dataset not configured (honest).
 */
const LESSONS: StudentLessonInternal[] = [];

export const STUDENT_LESSON_CATALOG: readonly StudentLessonInternal[] = LESSONS;

export function findStudentLesson(lessonId: string): StudentLessonInternal | undefined {
  return LESSONS.find((lesson) => lesson.id === lessonId);
}

export function studentLessonPublic(lesson: StudentLessonInternal): StudentLessonPublic {
  return {
    id: lesson.id,
    title: lesson.title,
    summary: lesson.summary,
    concept: lesson.concept,
    objectives: lesson.objectives,
    practice: {
      instruction: lesson.practice.instruction,
      targetRuleId: lesson.practice.targetRuleId,
      starterFiles: lesson.practice.starterFiles,
      fixInstruction: lesson.practice.fixInstruction,
    },
    quiz: lesson.quiz.map((question) => ({ prompt: question.prompt, options: question.options })),
  };
}

export function studentLessonCatalogPublic(): StudentLessonPublic[] {
  return LESSONS.map(studentLessonPublic);
}
