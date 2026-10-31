import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { createDatasetService } from '../src/external/service.js';
import { getCweMap, getRemediationMap } from '../src/external/knowledge.js';
import { getMergedLessons } from '../src/external/lessonProvider.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

// Only disposable synthetic local files are created; the Dataset repository is never accessed.
const directories: string[] = [];
const servers: TestServer[] = [];
const PRIVATE_MARKER = 'q7z-private-fixture-name'; // test-only synthetic fixture
const LOGIN_PHRASE = 'dataset completeness fixture phrase';

function fixtureRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'main-app-readonly-fixture-'));
  directories.push(root);
  const write = (path: string, content: string): void => {
    const full = join(root, path);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  };
  write('knowledge/remediation/good.json', JSON.stringify({ ruleId: 'fixture', actions: ['Review'] }));
  write(`knowledge/remediation/${PRIVATE_MARKER}.json`, '{broken json');
  symlinkSync(join(root, 'knowledge', 'remediation'), join(root, 'knowledge', 'remediation', 'loop'));
  write('knowledge/cwe/good.json', JSON.stringify({ id: 'CWE-999', name: 'Synthetic' }));
  write('learning/lessons/good.json', JSON.stringify({ id: 'lsn_fixture', title: 'Fixture' }));
  write('assessments/templates/bad.json', '{malformed');
  // engagement directory is deliberately absent, so its hidden cardinality is unknown.
  write('vuln-intel/npm/good.json', JSON.stringify({ id: 'ADV-TEST-1', ecosystem: 'npm', package: 'fixture', provenance: { source: 'fixture' } }));
  write('vuln-intel/npm/no-id.json', JSON.stringify({ ecosystem: 'npm' }));
  write('vuln-intel/npm/broken.json', '{broken');
  mkdirSync(join(root, 'vuln-intel', 'pypi'), { recursive: true });
  return root;
}

/** Snapshot local fixture bytes and symlink metadata without following links. */
function snapshot(root: string): Record<string, string> {
  const result: Record<string, string> = {};
  const walk = (path: string): void => {
    for (const name of readdirSync(path)) {
      const item = join(path, name);
      const info = lstatSync(item);
      const key = relative(root, item);
      if (info.isSymbolicLink()) result[key] = 'symlink';
      else if (info.isDirectory()) { result[key] = 'directory'; walk(item); }
      else if (info.isFile()) result[key] = createHash('sha256').update(readFileSync(item)).digest('hex');
    }
  };
  walk(root);
  return result;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop()));
  for (const root of directories.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Dataset category completeness', () => {
  test('reports unreadable, invalid and unenumerated entries without changing successfully loaded records', async () => {
    const root = fixtureRoot();
    const before = snapshot(root);
    const lines: string[] = [];
    const logger = { info: (message: string) => lines.push(message), warn: (message: string) => lines.push(message), error: (message: string) => lines.push(message) };
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger });
    const [status, remediation, lessons] = await Promise.all([service.status(), service.remediation(), service.lessons()]);

    expect(status.remediation).toMatchObject({ status: 'AVAILABLE', count: 1, incomplete: true,
      loadIssues: { filesSeen: 2, unreadableFiles: 1, invalidRecords: 0, enumerationFailures: 1 } });
    expect(remediation).toEqual([{ ruleId: 'fixture', actions: ['Review'] }]);
    expect(status.lessons).toMatchObject({ status: 'AVAILABLE', count: 1 });
    expect(status.lessons.incomplete).toBeUndefined();
    expect(lessons).toEqual([{ id: 'lsn_fixture', title: 'Fixture' }]);
    expect(status.cwe).toMatchObject({ status: 'AVAILABLE', count: 1 });
    expect(status.cwe.incomplete).toBeUndefined();
    expect(status.assessmentTemplates).toMatchObject({ status: 'UNAVAILABLE', count: 0, incomplete: true,
      loadIssues: { filesSeen: 1, unreadableFiles: 1, invalidRecords: 0, enumerationFailures: 0 } });
    expect(status.engagementTemplates).toMatchObject({ status: 'UNAVAILABLE', count: 0, incomplete: true,
      loadIssues: { filesSeen: 0, unreadableFiles: 0, invalidRecords: 0, enumerationFailures: 1 } });
    expect(status.vulnIntel).toMatchObject({ status: 'AVAILABLE', count: 3, incomplete: true,
      loadIssues: { filesSeen: 3, unreadableFiles: 1, invalidRecords: 1, enumerationFailures: 0 } });
    expect(status.vulnIntelCounts).toEqual({ files: 3, identityItems: 1, advisoryIds: 1 });
    expect(JSON.stringify(status)).not.toContain(PRIVATE_MARKER);
    expect(lines.join('\n')).not.toContain(PRIVATE_MARKER);
    expect(snapshot(root)).toEqual(before);
  });

  test('unexpected null knowledge entries are reported without hiding subsequent valid entries', async () => {
    const root = fixtureRoot();
    writeFileSync(join(root, 'knowledge/remediation/0-null.json'), 'null');
    writeFileSync(join(root, 'knowledge/cwe/0-null.json'), 'null');
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem' });
    const status = await service.status();
    expect(status.remediation).toMatchObject({ incomplete: true, loadIssues: { invalidRecords: 1 } });
    expect(status.cwe).toMatchObject({ incomplete: true, loadIssues: { invalidRecords: 1 } });
    expect((await getRemediationMap(service)).has('fixture')).toBe(true);
    expect((await getCweMap(service)).has('CWE-999')).toBe(true);
  });

  test('invalid lessons do not hide later usable lessons or crash the authenticated list', async () => {
    const root = fixtureRoot();
    writeFileSync(join(root, 'learning/lessons/0-null.json'), 'null');
    writeFileSync(join(root, 'learning/lessons/1-invalid.json'), JSON.stringify({ schemaVersion: 'drobon.learning.lesson/v1', id: 'lsn_bad_fixture', title: 'Bad fixture', quiz: [null] }));
    writeFileSync(join(root, 'learning/lessons/2-valid.json'), JSON.stringify({ schemaVersion: 'drobon.learning.lesson/v1', id: 'lsn_valid_fixture', title: 'Valid fixture', quiz: [{ prompt: 'Question', options: ['A'], answerIndex: 0 }] }));
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem' });
    const merged = await getMergedLessons(service);
    expect(merged.some((lesson) => lesson.id === 'lsn_valid_fixture')).toBe(true);
    expect(merged.some((lesson) => lesson.id === 'lsn_bad_fixture')).toBe(false);
    const server = await startTestServer({ datasetService: service });
    servers.push(server);
    const auth = { email: 'lesson-fixture@example.test', password: LOGIN_PHRASE };
    expect((await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...auth, userType: 'DEVELOPER' }) })).status).toBe(201);
    const login = await fetch(`${server.baseUrl}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(auth) });
    const response = await fetch(`${server.baseUrl}/api/v1/dataset/lessons`, { headers: { cookie: sessionCookieFrom(login) } });
    expect(response.status).toBe(200);
    const payload = await response.json() as { data: { count: number; lessons: Array<{ id: string }> } };
    expect(payload.data.count).toBe(4); // existing count remains the raw JSON record count
    expect(payload.data.lessons.some((lesson) => lesson.id === 'lsn_valid_fixture')).toBe(true);
  });

  test('keeps unconfigured state unchanged and does not claim failed categories are complete', async () => {
    const status = await createDatasetService({ providerId: 'none' }).status();
    for (const category of [status.vulnIntel, status.remediation, status.cwe, status.lessons, status.assessmentTemplates, status.engagementTemplates]) {
      expect(category.status).toBe('NOT_CONFIGURED');
      expect(category.incomplete).toBeUndefined();
      expect(category.loadIssues).toBeUndefined();
    }
  });

  test('authenticated status exposes aggregate completeness without local paths or fixture names', async () => {
    const root = fixtureRoot();
    const before = snapshot(root);
    const datasetService = createDatasetService({ datasetPath: root, providerId: 'filesystem' });
    const server = await startTestServer({ datasetService });
    servers.push(server);
    expect((await fetch(`${server.baseUrl}/api/v1/dataset/status`)).status).toBe(401);
    const auth = { email: 'completeness-fixture@example.test', password: LOGIN_PHRASE };
    const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...auth, userType: 'DEVELOPER' }) });
    expect(registered.status).toBe(201);
    const loggedIn = await fetch(`${server.baseUrl}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(auth) });
    expect(loggedIn.status).toBe(200);
    const response = await fetch(`${server.baseUrl}/api/v1/dataset/status`, { headers: { cookie: sessionCookieFrom(loggedIn) } });
    expect(response.status).toBe(200);
    const body = await response.text();
    const parsed = JSON.parse(body) as { data: { dataset: { datasetPath?: string; remediation: { incomplete?: boolean; loadIssues?: { filesSeen: number; unreadableFiles: number; enumerationFailures: number } } } } };
    expect(parsed.data.dataset.datasetPath).toBeUndefined();
    expect(parsed.data.dataset.remediation).toMatchObject({ incomplete: true, loadIssues: { filesSeen: 2, unreadableFiles: 1, enumerationFailures: 1 } });
    expect(body).not.toContain(root);
    expect(body).not.toContain(PRIVATE_MARKER);
    expect(snapshot(root)).toEqual(before);
  });
});
