import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  STUDENT_LESSON_ID_PATTERN,
  STUDENT_LESSONS_MAX,
  STUDENT_QUIZ_ATTEMPTS_MAX,
  isStudentLessonProgress,
  type StudentLessonProgress,
} from '@drobon/shared';
import { findStudentLesson } from './lessons.js';

/**
 * Server-authoritative Student progress store (Phase 22 Pump 2). One record
 * per account. Progress entries are written ONLY through the methods below:
 * lesson reads are self-acknowledgements; quiz records are computed by the
 * server from submitted answers; practice stages are written only after the
 * routes layer verifies real completed-scan evidence in the learner's OWN
 * projects. The client can never submit "completed = true" or a score.
 */

const STUDENT_DOCUMENT_MAX_BYTES = 8 * 1024 * 1024;
const STUDENT_RECORDS_MAX = 50_000;

interface StudentRecord { userId: string; lessons: StudentLessonProgress[]; updatedAt: string }
interface StoreDocument { version: 1; users: StudentRecord[] }

export interface StudentQuizUpdate {
  bestCorrect: number;
  total: number;
  passed: boolean;
  attempts: number;
  lastAttemptAt: string;
}

export interface StudentStore {
  getProgress(userId: string): Promise<StudentLessonProgress[]>;
  acknowledgeRead(userId: string, lessonId: string, at: string): Promise<StudentLessonProgress[]>;
  recordQuiz(userId: string, lessonId: string, correct: number, total: number, at: string): Promise<{ outcome: 'recorded'; progress: StudentLessonProgress[] } | { outcome: 'attempt-limit' }>;
  recordIdentify(userId: string, lessonId: string, scanId: string, at: string): Promise<StudentLessonProgress[]>;
  recordVerify(userId: string, lessonId: string, scanId: string, at: string): Promise<StudentLessonProgress[]>;
}

function parseLessonEntry(value: unknown, userId: string): StudentLessonProgress | undefined {
  if (!isStudentLessonProgress(value)) return undefined;
  const entry = value as StudentLessonProgress;
  // Catalog alignment: a persisted entry must reference a shipped lesson.
  if (findStudentLesson(entry.lessonId) === undefined) return undefined;
  void userId;
  return entry;
}

function parseRecord(value: unknown, path: string, index: number): StudentRecord {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`Student store at ${path} has an invalid record at index ${index} — refusing to start.`);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'lessons,updatedAt,userId' || typeof record['userId'] !== 'string' ||
    record['userId'].length === 0 || record['userId'].length > 80 ||
    typeof record['updatedAt'] !== 'string' || !Array.isArray(record['lessons']) ||
    record['lessons'].length > STUDENT_LESSONS_MAX) {
    throw new Error(`Student store at ${path} has an invalid record at index ${index} — refusing to start.`);
  }
  const seen = new Set<string>();
  const lessons: StudentLessonProgress[] = [];
  for (const entry of record['lessons'] as unknown[]) {
    const parsed = parseLessonEntry(entry, record['userId'] as string);
    if (parsed === undefined || seen.has(parsed.lessonId)) {
      throw new Error(`Student store at ${path} has an invalid lesson entry at index ${index} — refusing to start.`);
    }
    seen.add(parsed.lessonId);
    lessons.push(parsed);
  }
  return { userId: record['userId'] as string, lessons, updatedAt: record['updatedAt'] as string };
}

function readDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return { version: 1, users: [] };
  }
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error(`Student store at ${path} is not an object — refusing to start.`);
  }
  const document = parsed as Record<string, unknown>;
  if (document['version'] !== 1 || !Array.isArray(document['users'])) {
    throw new Error(`Student store at ${path} has an unsupported document shape — refusing to start.`);
  }
  const users = (document['users'] as unknown[]).map((value, index) => parseRecord(value, path, index));
  if (users.length > STUDENT_RECORDS_MAX) {
    throw new Error(`Student store at ${path} exceeds the record limit — refusing to start.`);
  }
  const userIds = new Set<string>();
  for (const record of users) {
    if (userIds.has(record.userId)) {
      throw new Error(`Student store at ${path} has a duplicate user record — refusing to start.`);
    }
    userIds.add(record.userId);
  }
  return { version: 1, users };
}

function createStore(initial: StudentRecord[], persistWith: (users: StudentRecord[]) => void): StudentStore {
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T | Promise<T>): Promise<Awaited<T>> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run as Promise<Awaited<T>>;
  };
  const byUser = new Map(initial.map((record) => [record.userId, record]));
  const upsert = (userId: string, now: string, lessonId: string, build: (existing: StudentLessonProgress | undefined) => StudentLessonProgress): StudentLessonProgress[] => {
    if (findStudentLesson(lessonId) === undefined) throw new Error(`Unknown student lesson id: ${lessonId}`);
    const record = byUser.get(userId) ?? { userId, lessons: [], updatedAt: now };
    const existing = record.lessons.find((entry) => entry.lessonId === lessonId);
    const nextEntry = build(existing);
    const lessons = existing === undefined
      ? [...record.lessons, nextEntry]
      : record.lessons.map((entry) => (entry.lessonId === nextEntry.lessonId ? nextEntry : entry));
    const next: StudentRecord = { userId, lessons, updatedAt: now };
    persistWith([...byUser.values()].filter((candidate) => candidate.userId !== userId).concat(next));
    byUser.set(userId, next);
    return next.lessons;
  };

  return {
    getProgress: (userId) => Promise.resolve(byUser.get(userId)?.lessons ?? []),

    acknowledgeRead: (userId, lessonId, at) => runExclusive(() => upsert(userId, at, lessonId, (existing) => ({
      lessonId,
      readAcknowledgedAt: existing?.readAcknowledgedAt ?? at,
      ...(existing?.quiz === undefined ? {} : { quiz: existing.quiz }),
      ...(existing?.practice === undefined ? {} : { practice: existing.practice }),
    }))),

    recordQuiz: (userId, lessonId, correct, total, at) => runExclusive(() => {
      const record = byUser.get(userId);
      const existing = record?.lessons.find((entry) => entry.lessonId === lessonId);
      const attempts = (existing?.quiz?.attempts ?? 0) + 1;
      if (attempts > STUDENT_QUIZ_ATTEMPTS_MAX) return { outcome: 'attempt-limit' as const };
      const bestCorrect = Math.max(existing?.quiz?.bestCorrect ?? 0, correct);
      const next: StudentLessonProgress = {
        lessonId,
        ...(existing?.readAcknowledgedAt === undefined ? {} : { readAcknowledgedAt: existing.readAcknowledgedAt }),
        quiz: { bestCorrect, total, passed: bestCorrect === total, attempts, lastAttemptAt: at },
        ...(existing?.practice === undefined ? {} : { practice: existing.practice }),
      };
      return {
        outcome: 'recorded' as const,
        progress: upsert(userId, at, lessonId, () => next),
      };
    }),

    recordIdentify: (userId, lessonId, scanId, at) => runExclusive(() => upsert(userId, at, lessonId, (existing) => ({
      lessonId,
      ...(existing?.readAcknowledgedAt === undefined ? {} : { readAcknowledgedAt: existing.readAcknowledgedAt }),
      ...(existing?.quiz === undefined ? {} : { quiz: existing.quiz }),
      practice: {
        identifiedScanId: existing?.practice?.identifiedScanId ?? scanId,
        identifiedAt: existing?.practice?.identifiedAt ?? at,
        ...(existing?.practice?.verifiedScanId === undefined ? {} : { verifiedScanId: existing.practice.verifiedScanId }),
        ...(existing?.practice?.verifiedAt === undefined ? {} : { verifiedAt: existing.practice.verifiedAt }),
      },
    }))),

    recordVerify: (userId, lessonId, scanId, at) => runExclusive(() => upsert(userId, at, lessonId, (existing) => ({
      lessonId,
      ...(existing?.readAcknowledgedAt === undefined ? {} : { readAcknowledgedAt: existing.readAcknowledgedAt }),
      ...(existing?.quiz === undefined ? {} : { quiz: existing.quiz }),
      practice: {
        identifiedScanId: existing?.practice?.identifiedScanId ?? scanId,
        identifiedAt: existing?.practice?.identifiedAt ?? at,
        verifiedScanId: scanId,
        verifiedAt: at,
      },
    }))),
  };
}

export function createJsonFileStudentStore(path: string): StudentStore {
  const document = readDocument(path);
  const persistWith = (users: StudentRecord[]): void => {
    const payload: StoreDocument = { version: 1, users };
    const serialized = `${JSON.stringify(payload, null, 2)}\n`;
    if (Buffer.byteLength(serialized, 'utf8') > STUDENT_DOCUMENT_MAX_BYTES) throw new RangeError('Student store capacity has been reached.');
    mkdirSync(dirname(path), { recursive: true });
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, serialized, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createStore(document.users, persistWith);
}

export function createMemoryStudentStore(): StudentStore {
  return createStore([], () => undefined);
}

export { STUDENT_LESSON_ID_PATTERN };
