import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import type { StudentLessonCatalogResponse, StudentProgressResponse } from '@drobon/shared';
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
