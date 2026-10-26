/**
 * Lesson provider — merges embedded 4-lesson catalog with dataset 6-lesson catalog.
 * Honest: if dataset unavailable, returns embedded only. Deduplicates by id.
 */

import { STUDENT_LESSON_CATALOG, type StudentLessonInternal } from '../student/lessons.js';
import type { DatasetService } from './service.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
function convertDatasetLesson(raw: any): StudentLessonInternal | undefined {
  if (raw?.schemaVersion !== 'drobon.learning.lesson/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^lsn_[a-z0-9_]{3,40}$/.test(raw.id)) return undefined;
  if (!Array.isArray(raw.quiz) || raw.quiz.length === 0) return undefined;
  // Minimal conversion, keep quiz answerIndex
  return {
    id: raw.id,
    title: raw.title ?? raw.id,
    summary: raw.summary ?? '',
    concept: raw.concept ?? '',
    objectives: Array.isArray(raw.objectives) ? raw.objectives : [],
    practice: {
      instruction: raw.practice?.instruction ?? '',
      targetRuleId: raw.practice?.targetRuleId ?? '',
      starterFiles: Array.isArray(raw.practice?.starterFiles) ? raw.practice.starterFiles : [],
      fixInstruction: raw.practice?.fixInstruction ?? '',
      fixedFiles: Array.isArray(raw.practice?.fixedFiles) ? raw.practice.fixedFiles : [],
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    quiz: raw.quiz.map((q: any) => ({
      prompt: q.prompt ?? '',
      options: Array.isArray(q.options) ? q.options : [],
      answerIndex: typeof q.answerIndex === 'number' ? q.answerIndex : 0,
      explanation: q.explanation ?? '',
    })),
  };
}

export async function getMergedLessons(dataset: DatasetService): Promise<readonly StudentLessonInternal[]> {
  const base = [...STUDENT_LESSON_CATALOG];
  try {
    const raw = await dataset.lessons();
    for (const r of raw) {
      const conv = convertDatasetLesson(r);
      if (conv && !base.some(b => b.id === conv.id)) base.push(conv);
    }
  } catch { /* fail closed: optional path */ }
  return base;
}

export function findLessonInMerged(lessons: readonly StudentLessonInternal[], id: string) {
  return lessons.find(l => l.id === id);
}
