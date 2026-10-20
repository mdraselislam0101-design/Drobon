function isBoundedText(value: unknown, max: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 40) return false;
  return Number.isFinite(Date.parse(value));
}

/**
 * Student learning domain (Phase 22 Pump 2). Internally authored,
 * bounded educational content plus server-authoritative progress.
 * The catalog lives in the API (`apps/api/src/student/lessons.ts`);
 * this module defines the public (answer-free) shapes, progress records
 * and runtime guards shared by API and web.
 */

export const STUDENT_LESSON_ID_PATTERN = /^lsn_[a-z0-9_]{3,40}$/;
export const STUDENT_LESSONS_MAX = 12;
export const STUDENT_LESSON_OBJECTIVES_MAX = 5;
export const STUDENT_LESSON_TEXT_MAX = 2_000;
export const STUDENT_QUIZ_QUESTIONS_MAX = 6;
export const STUDENT_QUIZ_OPTIONS_MAX = 5;
export const STUDENT_QUIZ_ATTEMPTS_MAX = 200;
export const STUDENT_PRACTICE_FILES_MAX = 3;
export const STUDENT_PRACTICE_FILE_MAX_CHARS = 800;
export const STUDENT_PROGRESS_LESSONS_MAX = STUDENT_LESSONS_MAX;

/** One bounded synthetic source file a learner imports into their OWN project. */
export interface StudentPracticeFile {
  path: string;
  content: string;
}

/** Public quiz question: prompt and options only — the answer stays server-side. */
export interface StudentQuizQuestionPublic {
  prompt: string;
  options: string[];
}

/** The bounded practice exercise of a lesson. Static analysis only: the
 * learner runs the EXISTING scanners over the synthetic snapshot in their
 * own project; no code is ever executed by DROBON. */
export interface StudentLessonPracticePublic {
  instruction: string;
  targetRuleId: string;
  starterFiles: StudentPracticeFile[];
  fixInstruction: string;
}

/** Public lesson shape — quiz answers and explanations are stripped. */
export interface StudentLessonPublic {
  id: string;
  title: string;
  summary: string;
  concept: string;
  objectives: string[];
  practice: StudentLessonPracticePublic;
  quiz: StudentQuizQuestionPublic[];
}

export interface StudentLessonCatalogResponse {
  lessons: StudentLessonPublic[];
}

/** Per-question feedback, revealed only after a server-scored attempt. */
export interface StudentQuizFeedback {
  index: number;
  chosen: number | null;
  correctIndex: number;
  explanation: string;
}

export interface StudentQuizRecord {
  bestCorrect: number;
  total: number;
  passed: boolean;
  attempts: number;
  lastAttemptAt: string;
}

/** Practice stages are recorded by the server only after it verifies real
 * completed-scan evidence in the learner's OWN projects. */
export interface StudentPracticeRecord {
  identifiedScanId?: string;
  identifiedAt?: string;
  verifiedScanId?: string;
  verifiedAt?: string;
}

export interface StudentLessonProgress {
  lessonId: string;
  readAcknowledgedAt?: string;
  quiz?: StudentQuizRecord;
  practice?: StudentPracticeRecord;
}

export interface StudentProgressResponse {
  lessons: StudentLessonProgress[];
}

export interface StudentQuizResultResponse {
  correctCount: number;
  total: number;
  passed: boolean;
  record?: StudentQuizRecord;
  feedback: StudentQuizFeedback[];
}

export function isStudentPracticeFile(value: unknown): value is StudentPracticeFile {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !keys.includes('path') || !keys.includes('content')) return false;
  return typeof record['path'] === 'string' && record['path'].length >= 1 && record['path'].length <= 120 &&
    typeof record['content'] === 'string' && record['content'].length >= 1 &&
    record['content'].length <= STUDENT_PRACTICE_FILE_MAX_CHARS;
}

export function isStudentQuizQuestionPublic(value: unknown): value is StudentQuizQuestionPublic {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !keys.includes('prompt') || !keys.includes('options')) return false;
  const options = record['options'];
  if (!isBoundedText(record['prompt'], 400) || !Array.isArray(options) ||
    options.length < 2 || options.length > STUDENT_QUIZ_OPTIONS_MAX) return false;
  return options.every((option) => isBoundedText(option, 200));
}

export function isStudentLessonPublic(value: unknown): value is StudentLessonPublic {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 7) return false;
  const { id, title, summary, concept, objectives, practice, quiz } = record as Record<string, unknown>;
  if (typeof id !== 'string' || !STUDENT_LESSON_ID_PATTERN.test(id) ||
    !isBoundedText(title, 120) || !isBoundedText(summary, 300) ||
    !isBoundedText(concept, STUDENT_LESSON_TEXT_MAX) || !Array.isArray(objectives) ||
    objectives.length < 1 || objectives.length > STUDENT_LESSON_OBJECTIVES_MAX ||
    !objectives.every((objective) => isBoundedText(objective, 200)) ||
    typeof practice !== 'object' || practice === null || !Array.isArray(quiz) ||
    quiz.length < 1 || quiz.length > STUDENT_QUIZ_QUESTIONS_MAX) return false;
  const practiceRecord = practice as Record<string, unknown>;
  if (Object.keys(practiceRecord).length !== 4) return false;
  const starterFiles = practiceRecord['starterFiles'];
  return isBoundedText(practiceRecord['instruction'], 600) &&
    typeof practiceRecord['targetRuleId'] === 'string' &&
    /^(?:DG|DPK)-[A-Z]+-[0-9]{3,}$/.test(practiceRecord['targetRuleId'] as string) &&
    Array.isArray(starterFiles) && starterFiles.length >= 1 &&
    starterFiles.length <= STUDENT_PRACTICE_FILES_MAX &&
    starterFiles.every((file) => isStudentPracticeFile(file)) &&
    isBoundedText(practiceRecord['fixInstruction'], 600) &&
    quiz.every((question) => isStudentQuizQuestionPublic(question));
}

export function isStudentLessonCatalogResponse(value: unknown): value is StudentLessonCatalogResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record['lessons']) ||
    record['lessons'].length < 1 || record['lessons'].length > STUDENT_LESSONS_MAX) return false;
  return record['lessons'].every((lesson) => isStudentLessonPublic(lesson));
}

export function isStudentQuizRecord(value: unknown): value is StudentQuizRecord {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 5) return false;
  const { bestCorrect, total, passed, attempts, lastAttemptAt } = record as Record<string, unknown>;
  return typeof bestCorrect === 'number' && Number.isInteger(bestCorrect) && bestCorrect >= 0 &&
    typeof total === 'number' && Number.isInteger(total) && total >= 1 &&
    bestCorrect <= total && typeof passed === 'boolean' &&
    typeof attempts === 'number' && Number.isInteger(attempts) && attempts >= 1 &&
    attempts <= STUDENT_QUIZ_ATTEMPTS_MAX && isTimestamp(lastAttemptAt);
}

export function isStudentPracticeRecord(value: unknown): value is StudentPracticeRecord {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 2 && keys.length !== 4) return false;
  const identified = keys.includes('identifiedAt') && keys.includes('identifiedScanId');
  const verified = keys.includes('verifiedAt') && keys.includes('verifiedScanId');
  if (!identified || (keys.length === 4 && !verified)) return false;
  if (typeof record['identifiedScanId'] !== 'string' || !/^scan_[0-9a-f-]{36}$/.test(record['identifiedScanId'] as string) ||
    !isTimestamp(record['identifiedAt'])) return false;
  if (keys.length === 4 && (typeof record['verifiedScanId'] !== 'string' ||
    !/^scan_[0-9a-f-]{36}$/.test(record['verifiedScanId'] as string) || !isTimestamp(record['verifiedAt']))) return false;
  return true;
}

export function isStudentLessonProgress(value: unknown): value is StudentLessonProgress {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length < 2 || Object.keys(record).length > 4) return false;
  if (typeof record['lessonId'] !== 'string' || !STUDENT_LESSON_ID_PATTERN.test(record['lessonId'])) return false;
  if (record['readAcknowledgedAt'] !== undefined && !isTimestamp(record['readAcknowledgedAt'])) return false;
  if (record['quiz'] !== undefined && !isStudentQuizRecord(record['quiz'])) return false;
  if (record['practice'] !== undefined && !isStudentPracticeRecord(record['practice'])) return false;
  return record['quiz'] !== undefined || record['practice'] !== undefined || record['readAcknowledgedAt'] !== undefined;
}

export function isStudentQuizResultResponse(value: unknown): value is StudentQuizResultResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 5 || !Array.isArray(record['feedback'])) return false;
  const { correctCount, total, passed } = record as Record<string, unknown>;
  if (typeof correctCount !== 'number' || !Number.isInteger(correctCount) || correctCount < 0 ||
    typeof total !== 'number' || !Number.isInteger(total) || total < 1 || correctCount > total ||
    typeof passed !== 'boolean' || (record['record'] !== undefined && !isStudentQuizRecord(record['record']))) return false;
  return record['feedback'].every((entry) => {
    if (typeof entry !== 'object' || entry === null) return false;
    const feedback = entry as Record<string, unknown>;
    if (Object.keys(feedback).length !== 4) return false;
    const { index, chosen, correctIndex, explanation } = feedback as Record<string, unknown>;
    return typeof index === 'number' && Number.isInteger(index) && index >= 0 &&
      (chosen === null || (typeof chosen === 'number' && Number.isInteger(chosen))) &&
      typeof correctIndex === 'number' && Number.isInteger(correctIndex) &&
      isBoundedText(explanation, 400);
  });
}

export function isStudentProgressResponse(value: unknown): value is StudentProgressResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record['lessons']) ||
    record['lessons'].length > STUDENT_PROGRESS_LESSONS_MAX) return false;
  const lessonIds = new Set<string>();
  return record['lessons'].every((entry) => {
    if (!isStudentLessonProgress(entry)) return false;
    const id = (entry as StudentLessonProgress).lessonId;
    if (lessonIds.has(id)) return false;
    lessonIds.add(id);
    return true;
  });
}
