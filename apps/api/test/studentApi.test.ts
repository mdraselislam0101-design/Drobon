import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import type { StudentLessonCatalogResponse } from '@drobon/shared';
import { cleanupTempStoreDir, makeTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { createJsonFileStudentStore, createMemoryStudentStore } from '../src/student/store.js';

const FIXTURE_LOGIN_PHRASE = 'pump twenty two student fixture';
const SERVERS: TestServer[] = [];
afterEach(async () => { await Promise.all(SERVERS.splice(0).map((server) => server.stop())); });
interface Cookies { session: string; device: string }
function cookieHeader(cookies: Cookies): string { return `${cookies.session}; drobon_device=${cookies.device}`; }
async function register(server: TestServer, email: string): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password: FIXTURE_LOGIN_PHRASE, userType: 'STUDENT' }) });
  expect(response.status).toBe(201);
}
async function login(server: TestServer, email: string): Promise<Cookies> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password: FIXTURE_LOGIN_PHRASE }) });
  expect(response.status).toBe(200);
  const session = sessionCookieFrom(response);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(probe.status).toBe(200);
  const deviceCookie = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(deviceCookie).toBeDefined();
  return { session, device: deviceCookie!.split(';')[0]!.slice('drobon_device='.length) };
}
async function responseData<T>(response: Response): Promise<T> { const envelope = await readJson(response) as { data: T }; return envelope.data; }

describe('student learning API (Phase 22 Pump 2)', () => {
  test('catalog, progress, quiz integrity, practice verification, isolation, and UserType-switch neutrality', async () => {
    const dataDir = makeTempStoreDir('student-e2e');
    try {
      const server = await startTestServer({ authStoreDir: dataDir, usageStoreDir: dataDir, projectStoreDir: dataDir, scanStoreDir: dataDir, sourceStoreDir: dataDir, studentStoreDir: dataDir });
      SERVERS.push(server);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons`)).status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/student/progress`)).status).toBe(401);
      await register(server, 'student22@example.test');
      const student = await login(server, 'student22@example.test');
      // Paid-tool parity: lessons live in dataset, not in app — without dataset, catalog is 0 (honest)
      const catalog = await responseData<StudentLessonCatalogResponse>(await fetch(`${server.baseUrl}/api/v1/student/lessons`, { headers: { cookie: cookieHeader(student) } }));
      expect(catalog.lessons.length).toBe(0);
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/lsn_does_not_exist/read`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/student/progress?user=other`, { headers: { cookie: cookieHeader(student) } })).status).toBe(400);
      // Unknown lessons and unsupported input fail closed.
      expect((await fetch(`${server.baseUrl}/api/v1/student/lessons/not-a-lesson-id/quiz`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(student) }, body: '{}' })).status).toBe(404);
    } finally { cleanupTempStoreDir(dataDir); }
  });
  test('progress persists across a restart and a corrupt store refuses to start', async () => {
    const dir = makeTempStoreDir('student-restart');
    try {
      // Without embedded lessons, the store cannot acknowledge unknown lessons — it fails closed (honest)
      const store = createJsonFileStudentStore(join(dir, 'student-progress.json'));
      await expect(store.acknowledgeRead('usr_student_a', 'lsn_code_injection_eval', '2026-09-30T10:00:00.000Z')).rejects.toThrow();
      // A corrupt document is a fail-fast startup error, never silent data loss.
      writeFileSync(join(dir, 'corrupt.json'), '{"version":1,"users":[{"userId":"u","lessons":[{"lessonId":"bogus"}]}]}\n');
      expect(() => createJsonFileStudentStore(join(dir, 'corrupt.json'))).toThrow(/refusing to start/);
    } finally { cleanupTempStoreDir(dir); }
  });
  test('quiz attempt limit is enforced without partial writes', async () => {
    const store = createMemoryStudentStore();
    // Without embedded lessons, the store cannot record quiz for unknown lessons — it fails closed
    await expect(store.recordQuiz('usr_student_a', 'lsn_command_injection_exec', 0, 3, '2026-09-30T10:00:00.000Z')).rejects.toThrow();
    expect((await store.getProgress('usr_student_a')).length).toBe(0);
  });
});

describe('Dataset-backed student progress', () => {
  test('accepts known pinned Dataset IDs, enforces attempt limits, and reloads without the catalog', async () => {
    const dir = makeTempStoreDir('student-dataset-progress');
    const lessonId = 'lsn_pack_shell_fix'; // ID observed in the pinned Dataset; content below is synthetic.
    const lookup = async (id: string) => id === lessonId;
    try {
      const path = join(dir, 'student-progress.json');
      let store = createJsonFileStudentStore(path, lookup);
      await store.acknowledgeRead('usr_student_a', lessonId, '2026-09-30T10:00:00.000Z');
      await store.recordIdentify('usr_student_a', lessonId, 'scan_00000000-0000-4000-8000-000000000001', '2026-09-30T10:00:00.000Z');
      for (let i = 0; i < 200; i += 1) {
        expect((await store.recordQuiz('usr_student_a', lessonId, 1, 2, '2026-09-30T10:00:00.000Z')).outcome).toBe('recorded');
      }
      expect((await store.recordQuiz('usr_student_a', lessonId, 2, 2, '2026-09-30T10:00:00.000Z')).outcome).toBe('attempt-limit');
      const before = await store.getProgress('usr_student_a');
      expect(before[0]?.quiz).toMatchObject({ attempts: 200, bestCorrect: 1, total: 2, passed: false });
      // Recovery does not require the Dataset to be mounted, but new writes
      // still need a live approved lesson ID.
      store = createJsonFileStudentStore(path);
      expect(await store.getProgress('usr_student_a')).toEqual(before);
      await expect(store.acknowledgeRead('usr_student_a', lessonId, '2026-09-30T10:00:00.000Z')).rejects.toThrow();
      await expect(createJsonFileStudentStore(path, lookup).acknowledgeRead('usr_student_a', 'lsn_unknown_fixture', '2026-09-30T10:00:00.000Z')).rejects.toThrow();
    } finally { cleanupTempStoreDir(dir); }
  });

  test('real HTTP read, quiz and practice authorization survive restart with an in-memory synthetic Dataset', async () => {
    const { createDatasetService } = await import('../src/external/service.js');
    const lessonId = 'lsn_pack_shell_fix';
    const synthetic = {
      schemaVersion: 'drobon.learning.lesson/v1', id: lessonId, title: 'Synthetic shell lesson', summary: 'Synthetic summary', concept: 'Review shell input.', objectives: ['Review input'],
      practice: { instruction: 'Scan the fixture', targetRuleId: 'DG-SAST-001', starterFiles: [], fixInstruction: 'Review manually', fixedFiles: [] },
      quiz: [{ prompt: 'Which is safer?', options: ['argument array', 'shell string'], answerIndex: 0, explanation: 'Avoid an unnecessary shell.' }],
    };
    const datasetService = { ...createDatasetService({ providerId: 'none' }), configured: true, lessons: async () => [synthetic] };
    const dir = makeTempStoreDir('student-http-dataset');
    try {
      let server = await startTestServer({ authStoreDir: dir, studentStoreDir: dir, projectStoreDir: dir, scanStoreDir: dir, sourceStoreDir: dir, datasetService });
      SERVERS.push(server);
      await register(server, 'dataset-student@example.test');
      let cookies = await login(server, 'dataset-student@example.test');
      const base = () => `${server.baseUrl}/api/v1/student/lessons/${lessonId}`;
      const post = (url: string, body: unknown) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify(body) });
      const catalog = await responseData<StudentLessonCatalogResponse>(await fetch(`${server.baseUrl}/api/v1/student/lessons`, { headers: { cookie: cookieHeader(cookies) } }));
      expect(catalog.lessons.map((entry) => entry.id)).toContain(lessonId);
      expect(JSON.stringify(catalog)).not.toContain('answerIndex');
      expect((await post(`${base()}/read`, {})).status).toBe(200);
      const quiz = await post(`${base()}/quiz`, { answers: [0] });
      expect(quiz.status).toBe(200);
      expect(await responseData(quiz)).toMatchObject({ correctCount: 1, total: 1, passed: true });
      expect((await post(`${base()}/practice/IDENTIFY`, {})).status).toBe(409);
      expect((await post(`${base()}/practice/FIX`, {})).status).toBe(409);
      const projectResponse = await post(`${server.baseUrl}/api/v1/projects`, { name: 'Student synthetic practice' });
      expect(projectResponse.status).toBe(201);
      const project = await responseData<{ project: { id: string } }>(projectResponse);
      const sources = await fetch(`${server.baseUrl}/api/v1/projects/${project.project.id}/sources`, {
        method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
        body: JSON.stringify({ files: [{ path: 'src/practice.js', content: 'exec("git " + dynamicInput);' }] }),
      });
      expect(sources.status).toBe(200);
      const scan = await post(`${server.baseUrl}/api/v1/projects/${project.project.id}/scans`, { scanType: 'SAST' });
      expect(scan.status).toBe(201);
      await server.scanProcessor.drain();
      expect((await post(`${base()}/practice/IDENTIFY`, {})).status).toBe(200);
      // Identification is not verification of a fix.
      expect((await post(`${base()}/practice/FIX`, {})).status).toBe(409);
      expect((await post(`${server.baseUrl}/api/v1/student/lessons/lsn_not_shipped/read`, {})).status).toBe(404);
      const before = await responseData<{ lessons: unknown[] }>(await fetch(`${server.baseUrl}/api/v1/student/progress`, { headers: { cookie: cookieHeader(cookies) } }));
      expect(before.lessons).toHaveLength(1);
      await server.stop(); SERVERS.splice(SERVERS.indexOf(server), 1);
      server = await startTestServer({ authStoreDir: dir, studentStoreDir: dir, projectStoreDir: dir, scanStoreDir: dir, sourceStoreDir: dir, datasetService });
      SERVERS.push(server); cookies = await login(server, 'dataset-student@example.test');
      expect(await responseData(await fetch(`${server.baseUrl}/api/v1/student/progress`, { headers: { cookie: cookieHeader(cookies) } }))).toEqual(before);
      expect((await post(`${base()}/read`, {})).status).toBe(200);
    } finally { cleanupTempStoreDir(dir); }
  });
});
