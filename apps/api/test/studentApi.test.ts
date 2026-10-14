import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import type { ScanDetail, StudentLessonCatalogResponse, StudentLessonProgress, StudentProgressResponse } from '@drobon/shared';
import {
  cleanupTempStoreDir,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';
import { createJsonFileStudentStore, createMemoryStudentStore } from '../src/student/store.js';

const FIXTURE_LOGIN_PHRASE = 'pump twenty two student fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }

function cookieHeader(cookies: Cookies): string {
  return `${cookies.session}; drobon_device=${cookies.device}`;
}

async function register(server: TestServer, email: string): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_LOGIN_PHRASE, userType: 'STUDENT' }),
  });
  expect(response.status).toBe(201);
}

async function login(server: TestServer, email: string): Promise<Cookies> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_LOGIN_PHRASE }),
  });
  expect(response.status).toBe(200);
  const session = sessionCookieFrom(response);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(probe.status).toBe(200);
  const deviceCookie = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(deviceCookie).toBeDefined();
  return { session, device: deviceCookie!.split(';')[0]!.slice('drobon_device='.length) };
}

async function responseData<T>(response: Response): Promise<T> {
  const envelope = await readJson(response) as { data: T };
  return envelope.data;
}

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  expect(response.status).toBe(201);
  return (await responseData<{ project: { id: string } }>(response)).project.id;
}

async function uploadFiles(server: TestServer, cookies: Cookies, projectId: string, files: Array<{ path: string; content: string }>): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files }),
  });
  expect(response.status).toBe(200);
}

async function runSastScan(server: TestServer, cookies: Cookies, projectId: string, key: string): Promise<ScanDetail> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType: 'SAST' }),
  });
  expect(created.status).toBe(201);
  const scanId = (await responseData<{ scan: { id: string } }>(created)).scan.id;
  await server.scanProcessor.drain();
  const detail = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  expect(detail.status).toBe(200);
  const body = await responseData<{ scan: ScanDetail }>(detail);
  expect(body.scan.status).toBe('COMPLETED');
  return body.scan;
}

describe('student learning API (Phase 22 Pump 2)', () => {
  test('catalog, progress, quiz integrity, practice verification, isolation, and UserType-switch neutrality', async () => {
    const dataDir = makeTempStoreDir('student-e2e');
    try {
      const server = await startTestServer({ authStoreDir: dataDir, usageStoreDir: dataDir, projectStoreDir: dataDir, scanStoreDir: dataDir, sourceStoreDir: dataDir, studentStoreDir: dataDir });
      SERVERS.push(server);

      // Unauthenticated requests fail closed on every route.
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons`)).status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/student/progress`)).status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/read`, { method: 'POST' })).status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/quiz`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/practice/IDENTIFY`, { method: 'POST' })).status).toBe(401);

      await register(server, 'student22@example.test');
      const student = await login(server, 'student22@example.test');

      // Catalog: internally authored lessons, answers never leave the server.
      const catalog = await responseData<StudentLessonCatalogResponse>(await fetch(`${server.baseUrl}/api/v1/student/lessons`, { headers: { cookie: cookieHeader(student) } }));
      expect(catalog.lessons.length).toBe(4);
      const serialized = JSON.stringify(catalog);
      expect(serialized).not.toContain('answerIndex');
      expect(serialized).not.toContain('explanation');
      const evalLesson = catalog.lessons.find((lesson) => lesson.id === 'lsn_code_injection_eval');
      expect(evalLesson).toBeDefined();
      expect(evalLesson!.practice.targetRuleId).toBe('DG-SAST-002');
      expect(evalLesson!.quiz.length).toBe(3);
      expect(evalLesson!.practice.starterFiles.length).toBeGreaterThan(0);

      // Unknown lessons and unsupported input fail closed.
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_does_not_exist/read`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/not-a-lesson-id/quiz`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/practice/SOMETHING`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/student/progress?user=other`, { headers: { cookie: cookieHeader(student) } })).status).toBe(400);

      // Read acknowledgement is idempotent.
      const firstRead = await responseData<{ lessons: StudentLessonProgress[] }>(await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/read`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}',
      }));
      expect(firstRead.lessons[0]?.readAcknowledgedAt).toBeDefined();
      const secondRead = await responseData<{ lessons: StudentLessonProgress[] }>(await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/read`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}',
      }));
      expect(secondRead.lessons[0]?.readAcknowledgedAt).toBe(firstRead.lessons[0]?.readAcknowledgedAt);

      // Quiz integrity: wrong shapes, forged fields and malformed bodies fail closed.
      const quizPath = `${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/quiz`;
      expect((await fetch(quizPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [0, 1] }) })).status).toBe(422);
      expect((await fetch(quizPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: ['0', '1', '2'] }) })).status).toBe(422);
      expect((await fetch(quizPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [0, 1, 9] }) })).status).toBe(422);
      expect((await fetch(quizPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [0, 1, 2], score: 3 }) })).status).toBe(422);
      expect((await fetch(quizPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{broken' })).status).toBe(400);

      // A wrong attempt scores 0 and gets per-question feedback.
      const wrong = await responseData<{ correctCount: number; total: number; passed: boolean; feedback: Array<{ chosen: number | null; correctIndex: number; explanation: string }> }>(await fetch(quizPath, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [2, 1, 1] }),
      }));
      expect(wrong.correctCount).toBe(0);
      expect(wrong.passed).toBe(false);
      expect(wrong.feedback).toHaveLength(3);
      expect(wrong.feedback[0]!.correctIndex).toBe(1);
      expect(wrong.feedback[0]!.explanation.length).toBeGreaterThan(10);

      // The correct attempt passes; attempts accumulate, bestCorrect never decreases.
      const right = await responseData<{ correctCount: number; passed: boolean; record: { attempts: number; bestCorrect: number; passed: boolean } }>(await fetch(quizPath, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [1, 2, 0] }),
      }));
      expect(right.correctCount).toBe(3);
      expect(right.passed).toBe(true);
      expect(right.record.attempts).toBe(2);
      const again = await responseData<{ record: { attempts: number; bestCorrect: number; passed: boolean } }>(await fetch(quizPath, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ answers: [2, 1, 1] }),
      }));
      expect(again.record.attempts).toBe(3);
      expect(again.record.bestCorrect).toBe(3);
      expect(again.record.passed).toBe(true);

      // Practice IDENTIFY is honest before any evidence exists.
      const identifyPath = `${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/practice/IDENTIFY`;
      const earlyIdentify = await fetch(identifyPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' });
      expect(earlyIdentify.status).toBe(409);
      expect(((await readJson(earlyIdentify) as { error: { message: string } }).error.message)).toContain('your own projects');

      // The student imports the LESSON'S OWN starter file into their OWN project and scans.
      const projectId = await createProject(server, student, 'Student practice lab');
      await uploadFiles(server, student, projectId, evalLesson!.practice.starterFiles);
      const vulnerableScan = await runSastScan(server, student, projectId, 'student22-sast-1');
      expect(vulnerableScan.findings?.some((finding) => finding.ruleId === 'DG-SAST-002')).toBe(true);

      const identified = await responseData<{ lessons: StudentLessonProgress[] }>(await fetch(identifyPath, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}',
      }));
      expect(identified.lessons[0]?.practice?.identifiedScanId).toBe(vulnerableScan.id);
      const identifiedAt = identified.lessons[0]?.practice?.identifiedAt;

      // FIX is honestly refused while the finding is still observed.
      const fixPath = `${server.baseUrl}/api/v1/student/lessons/lsn_code_injection_eval/practice/FIX`;
      const earlyFix = await fetch(fixPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' });
      expect(earlyFix.status).toBe(409);
      expect(((await readJson(earlyFix) as { error: { message: string } }).error.message)).toContain('no longer be observed');

      // The student applies the lesson's fix (per fixInstruction) and re-scans:
      // the workflow records NOT_OBSERVED.
      await uploadFiles(server, student, projectId, [
        { path: 'src/calculator.js', content: [
          '// Fixed: no dynamic evaluation, the operation is plain data.',
          'const operations = { add: 1, sub: 2, mul: 3 };',
          '',
          'function compute(kind, a, b) {',
          '  const offset = operations[kind];',
          '  if (offset === undefined) throw new Error("unknown operation");',
          '  return a + b - offset;',
          '}',
          '',
          'module.exports = { compute };',
          '',
        ].join('\n') },
      ]);
      await runSastScan(server, student, projectId, 'student22-sast-2');
      const verified = await responseData<{ lessons: StudentLessonProgress[] }>(await fetch(fixPath, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}',
      }));
      expect(verified.lessons[0]?.practice?.verifiedScanId).toBeDefined();
      expect(verified.lessons[0]?.practice?.identifiedAt).toBe(identifiedAt);

      // Cross-account isolation: another account has no evidence and no progress of its own.
      await register(server, 'other22@example.test');
      const other = await login(server, 'other22@example.test');
      const otherIdentify = await fetch(identifyPath, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(other) }, body: '{}' });
      expect(otherIdentify.status).toBe(409);
      const otherProgress = await responseData<StudentProgressResponse>(await fetch(`${server.baseUrl}/api/v1/student/progress`, { headers: { cookie: cookieHeader(other) } }));
      expect(otherProgress.lessons).toHaveLength(0);

      // UserType switching is presentation-only: progress belongs to the account.
      const switchResponse = await fetch(`${server.baseUrl}/api/v1/me/user-type`, {
        method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ userType: 'DEVELOPER' }),
      });
      expect(switchResponse.status).toBe(200);
      const afterSwitch = await responseData<StudentProgressResponse>(await fetch(`${server.baseUrl}/api/v1/student/progress`, { headers: { cookie: cookieHeader(student) } }));
      expect(afterSwitch.lessons.find((entry) => entry.lessonId === 'lsn_code_injection_eval')?.practice?.verifiedAt).toBeDefined();
      expect((await fetch(`${server.baseUrl}/api/v1/me/user-type`, {
        method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: JSON.stringify({ userType: 'STUDENT' }),
      })).status).toBe(200);
    } finally {
      cleanupTempStoreDir(dataDir);
    }
  });

  test('progress persists across a restart and a corrupt store refuses to start', async () => {
    const dir = makeTempStoreDir('student-restart');
    try {
      const store = createJsonFileStudentStore(join(dir, 'student-progress.json'));
      await store.acknowledgeRead('usr_student_a', 'lsn_code_injection_eval', '2026-09-30T10:00:00.000Z');
      await store.recordQuiz('usr_student_a', 'lsn_code_injection_eval', 3, 3, '2026-09-30T10:01:00.000Z');

      const reloaded = createJsonFileStudentStore(join(dir, 'student-progress.json'));
      const progress = await reloaded.getProgress('usr_student_a');
      expect(progress).toHaveLength(1);
      expect(progress[0]?.quiz).toMatchObject({ bestCorrect: 3, total: 3, passed: true, attempts: 1 });

      // Unknown lesson ids cannot be persisted through the store.
      const memory = createMemoryStudentStore();
      await expect(memory.acknowledgeRead('usr_student_a', 'lsn_unknown_lesson', '2026-09-30T10:02:00.000Z')).rejects.toThrow();

      // A corrupt document is a fail-fast startup error, never silent data loss.
      writeFileSync(join(dir, 'corrupt.json'), '{"version":1,"users":[{"userId":"u","lessons":[{"lessonId":"bogus"}]}]}\n');
      expect(() => createJsonFileStudentStore(join(dir, 'corrupt.json'))).toThrow(/refusing to start/);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

  test('quiz attempt limit is enforced without partial writes', async () => {
    const store = createMemoryStudentStore();
    let last: 'recorded' | 'attempt-limit' = 'recorded';
    for (let attempt = 0; attempt < 205; attempt += 1) {
      const outcome = await store.recordQuiz('usr_student_a', 'lsn_command_injection_exec', 0, 3, '2026-09-30T10:00:00.000Z');
      last = outcome.outcome;
      if (outcome.outcome === 'attempt-limit') break;
    }
    expect(last).toBe('attempt-limit');
    const progress = await store.getProgress('usr_student_a');
    expect(progress[0]?.quiz?.attempts).toBe(200);
  });
});
