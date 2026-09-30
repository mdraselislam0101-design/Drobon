import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import type { ScanComparisonResponse, ScanDetail, AssessmentSummaryResponse } from '@drobon/shared';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import {
  cleanupTempStoreDir,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

/**
 * Phase 22 Pump 3 — Professional/Pentester workflow expansion:
 * 1. fingerprint-based scan regression comparison (NEW/UNCHANGED/RESOLVED/
 *    REOPENED/CHANGED) within one owned project, with uniform-404 probing
 *    defense, type/completed guards, and honest absence semantics;
 * 2. the bounded assessment engagement summary over OWN linked scans.
 */

const LOGIN_PHRASE = 'pump twenty three professional fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }

function cookieHeader(cookies: Cookies): string {
  return `${cookies.session}; drobon_device=${cookies.device}`;
}

async function registerAndLogin(server: TestServer, email: string, userType: 'SECURITY_PROFESSIONAL' | 'PENTESTER'): Promise<Cookies> {
  const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: LOGIN_PHRASE, userType }),
  });
  expect([201, 409]).toContain(registered.status); // 409 = already seeded (PRO)
  const login = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: LOGIN_PHRASE }),
  });
  expect(login.status).toBe(200);
  const session = sessionCookieFrom(login);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(probe.status).toBe(200);
  const deviceCookie = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(deviceCookie).toBeDefined();
  return { session, device: deviceCookie!.split(';')[0]!.slice('drobon_device='.length) };
}

async function getJson<T>(response: Response): Promise<T> {
  const envelope = await readJson(response) as { data: T };
  return envelope.data;
}

/** Seed a PRO-classified account (server-authoritative entitlement; FREE quota exempt) — the established tests-only pattern. */
async function seedProUser(dataDir: string, email: string, userType: 'SECURITY_PROFESSIONAL' | 'PENTESTER', userId: string): Promise<void> {
  const repository = createJsonFileUserRepository(join(dataDir, 'users.json'));
  const createdAt = '2026-09-01T00:00:00.000Z';
  const user: UserRecord = {
    id: userId, email,
    passwordHash: await hashPassword(LOGIN_PHRASE, 1024), createdAt, role: 'MEMBER', userType,
    subscription: { plan: 'PRO', status: 'ACTIVE', createdAt, updatedAt: createdAt },
  };
  expect(await repository.create(user)).toBe(true);
}

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  expect(response.status).toBe(201);
  return (await getJson<{ project: { id: string } }>(response)).project.id;
}

async function upload(server: TestServer, cookies: Cookies, projectId: string, content: string): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files: [{ path: 'src/app.js', content }] }),
  });
  expect(response.status).toBe(200);
}

const VULNERABLE_FILE = [
  '// SYNTHETIC comparison fixture (never executed).',
  'function compute(kind, value) {',
  "  return eval('offset + ' + value);",
  '}',
  '',
  'function renderUnsafe(markup) {',
  "  document.body.innerHTML = '<div>' + markup + '</div>';",
  '}',
  '',
].join('\n');

const PARTIALLY_FIXED_FILE = [
  '// SYNTHETIC comparison fixture (never executed).',
  'function compute(kind, value) {',
  "  return eval('offset + ' + value);",
  '}',
  '',
  'function renderSafe(text) {',
  '  document.body.textContent = text;',
  '}',
  '',
].join('\n');

async function runSastScan(server: TestServer, cookies: Cookies, projectId: string, key: string, assessmentId?: string): Promise<ScanDetail> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType: 'SAST', ...(assessmentId === undefined ? {} : { assessmentId }) }),
  });
  expect(created.status).toBe(201);
  const scanId = (await getJson<{ scan: { id: string } }>(created)).scan.id;
  await server.scanProcessor.drain();
  const detail = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  expect(detail.status).toBe(200);
  const scan = (await getJson<{ scan: ScanDetail }>(detail)).scan;
  expect(scan.status).toBe('COMPLETED');
  return scan;
}

async function runScaScan(server: TestServer, cookies: Cookies, projectId: string, key: string): Promise<ScanDetail> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType: 'SCA' }),
  });
  expect(created.status).toBe(201);
  const scanId = (await getJson<{ scan: { id: string } }>(created)).scan.id;
  await server.scanProcessor.drain();
  const detail = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  const scan = (await getJson<{ scan: ScanDetail }>(detail)).scan;
  expect(scan.status).toBe('COMPLETED');
  return scan;
}

const compareUrl = (server: TestServer, projectId: string, currentId: string, baselineId: string): string =>
  `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(currentId)}/compare/${encodeURIComponent(baselineId)}`;

describe('scan regression comparison (Phase 22 Pump 3)', () => {
  test('NEW / UNCHANGED / RESOLVED / REOPENED semantics, guards, and probing defense', async () => {
    const dataDir = makeTempStoreDir('pump3-compare');
    try {
      await seedProUser(dataDir, 'pro23@example.test', 'SECURITY_PROFESSIONAL', 'usr_00000000-0000-4000-8000-0000000000a1');
      const server = await startTestServer({
        authStoreDir: dataDir, usageStoreDir: dataDir, projectStoreDir: dataDir,
        scanStoreDir: dataDir, sourceStoreDir: dataDir, studentStoreDir: dataDir, assessmentStoreDir: dataDir,
      });
      SERVERS.push(server);
      const pro = await registerAndLogin(server, 'pro23@example.test', 'SECURITY_PROFESSIONAL');

      // Fail-closed basics.
      expect((await fetch(compareUrl(server, 'prj_00000000-0000-4000-8000-000000000001', 'scan_00000000-0000-4000-8000-000000000001', 'scan_00000000-0000-4000-8000-000000000002'))).status).toBe(401);
      const projectId = await createProject(server, pro, 'Regression lab');
      await upload(server, pro, projectId, VULNERABLE_FILE);
      const scan1 = await runSastScan(server, pro, projectId, 'pro23-sast-1');
      expect(scan1.findings?.length).toBe(2);

      // Same scan on both sides is refused.
      const sameResponse = await fetch(compareUrl(server, projectId, scan1.id, scan1.id), { headers: { cookie: cookieHeader(pro) } });
      expect(sameResponse.status).toBe(422);

      // Query params are rejected (no query surface at all).
      expect((await fetch(`${compareUrl(server, projectId, scan1.id, scan1.id)}?strict=1`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);

      // Malformed and foreign scan ids answer the SAME uniform 404.
      expect((await fetch(compareUrl(server, projectId, 'not-a-scan-id', scan1.id), { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);
      expect((await fetch(compareUrl(server, projectId, 'scan_00000000-0000-4000-8000-0000000000ff', scan1.id), { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);

      // A queued/incomplete scan cannot be compared.
      const queued = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'idempotency-key': 'pro23-sast-queued', cookie: cookieHeader(pro) },
        body: JSON.stringify({ scanType: 'SAST' }),
      });
      expect(queued.status).toBe(201);
      const queuedId = (await getJson<{ scan: { id: string } }>(queued)).scan.id;
      const incompleteResponse = await fetch(compareUrl(server, projectId, queuedId, scan1.id), { headers: { cookie: cookieHeader(pro) } });
      expect(incompleteResponse.status).toBe(409);

      // Cross scan TYPE is refused.
      const scaScan = await runScaScan(server, pro, projectId, 'pro23-sca-1');
      const typeMismatch = await fetch(compareUrl(server, projectId, scaScan.id, scan1.id), { headers: { cookie: cookieHeader(pro) } });
      expect(typeMismatch.status).toBe(409);
      expect(((await readJson(typeMismatch) as { error: { message: string } }).error.message)).toContain('same type');

      // Cross-account probing: another account cannot compare ITS scan with
      // this project's scans — and cannot resolve this project at all.
      const other = await registerAndLogin(server, 'other23@example.test', 'PENTESTER');
      expect((await fetch(compareUrl(server, projectId, scan1.id, scan1.id), { headers: { cookie: cookieHeader(other) } })).status).toBe(403);

      // Fix one of two issues, re-scan: UNCHANGED + RESOLVED.
      await upload(server, pro, projectId, PARTIALLY_FIXED_FILE);
      const scan2 = await runSastScan(server, pro, projectId, 'pro23-sast-2');
      expect(scan2.findings?.length).toBe(1);
      const forward = await getJson<ScanComparisonResponse>(await fetch(compareUrl(server, projectId, scan2.id, scan1.id), { headers: { cookie: cookieHeader(pro) } }));
      expect(forward.counts).toEqual({ new: 0, unchanged: 1, resolved: 1, reopened: 0, changed: 0 });
      expect(forward.entries).toHaveLength(2);
      const resolvedEntry = forward.entries.find((entry) => entry.state === 'RESOLVED');
      expect(resolvedEntry?.baselineSeverity).toBeDefined();
      expect(resolvedEntry?.currentSeverity).toBeUndefined();
      const unchangedEntry = forward.entries.find((entry) => entry.state === 'UNCHANGED');
      expect(unchangedEntry?.ruleId).toBe('DG-SAST-002');
      expect(forward.entries.every((entry) => /^[0-9a-f]{64}$/.test(entry.fingerprint))).toBe(true);

      // The reversed direction honestly reports NEW, not negative RESOLVED.
      const reverse = await getJson<ScanComparisonResponse>(await fetch(compareUrl(server, projectId, scan1.id, scan2.id), { headers: { cookie: cookieHeader(pro) } }));
      expect(reverse.counts).toEqual({ new: 1, unchanged: 1, resolved: 0, reopened: 0, changed: 0 });

      // REOPENED: mark the remaining finding FALSE_POSITIVE, re-observe it,
      // then the diff of the two observing scans shows REOPENED.
      const fingerprint = scan2.findings?.[0]?.fingerprint ?? '';
      const findingId = scan2.findings?.[0]?.id ?? '';
      const marked = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scan2.id)}/findings/${encodeURIComponent(findingId)}/lifecycle`, {
        method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) },
        body: JSON.stringify({ state: 'FALSE_POSITIVE' }),
      });
      expect(marked.status).toBe(200);
      await upload(server, pro, projectId, VULNERABLE_FILE);
      const scan3 = await runSastScan(server, pro, projectId, 'pro23-sast-3');
      expect(scan3.findings?.some((finding) => finding.fingerprint === fingerprint)).toBe(true);
      const reopened = await getJson<ScanComparisonResponse>(await fetch(compareUrl(server, projectId, scan3.id, scan1.id), { headers: { cookie: cookieHeader(pro) } }));
      expect(reopened.counts.reopened).toBe(1);
      expect(reopened.entries.find((entry) => entry.fingerprint === fingerprint)?.state).toBe('REOPENED');
    } finally {
      cleanupTempStoreDir(dataDir);
    }
  });
});

describe('assessment engagement summary (Phase 22 Pump 3)', () => {
  test('bounded aggregate over OWN linked scans with honest totals and refusal surfaces', async () => {
    const dataDir = makeTempStoreDir('pump3-summary');
    try {
      await seedProUser(dataDir, 'sum23@example.test', 'SECURITY_PROFESSIONAL', 'usr_00000000-0000-4000-8000-0000000000b1');
      const server = await startTestServer({
        authStoreDir: dataDir, usageStoreDir: dataDir, projectStoreDir: dataDir,
        scanStoreDir: dataDir, sourceStoreDir: dataDir, studentStoreDir: dataDir, assessmentStoreDir: dataDir,
      });
      SERVERS.push(server);
      const pro = await registerAndLogin(server, 'sum23@example.test', 'SECURITY_PROFESSIONAL');

      const summaryPath = (projectId: string, assessmentId: string): string =>
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/assessments/${encodeURIComponent(assessmentId)}/summary`;
      expect((await fetch(summaryPath('prj_00000000-0000-4000-8000-000000000001', 'asm_00000000-0000-4000-8000-000000000001'))).status).toBe(401);
      expect((await fetch(`${summaryPath('prj_00000000-0000-4000-8000-000000000001', 'bogus-assessment')}?x=1`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);

      const projectId = await createProject(server, pro, 'Engagement lab');
      // Malformed assessment id and unknown assessment answer the same 404.
      expect((await fetch(summaryPath(projectId, 'bogus-assessment'), { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);
      expect((await fetch(summaryPath(projectId, 'asm_00000000-0000-4000-8000-0000000000ff'), { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);

      // Create an assessment, start it, link two completed SAST scans.
      const created = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/assessments`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) },
        body: JSON.stringify({
          title: 'Quarterly SAST review',
          objectives: ['Verify no dynamic evaluation', 'Confirm injection hygiene'],
          scope: { inScopeHosts: ['lab.example.org'], outOfScopeHosts: ['admin.lab.example.org'] },
        }),
      });
      expect(created.status).toBe(201);
      const assessmentId = (await getJson<{ assessment: { id: string } }>(created)).assessment.id;
      const started = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/assessments/${encodeURIComponent(assessmentId)}/status`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) },
        body: JSON.stringify({ status: 'ACTIVE' }),
      });
      expect(started.status).toBe(200);

      await upload(server, pro, projectId, VULNERABLE_FILE);
      const scan1 = await runSastScan(server, pro, projectId, 'sum23-sast-1', assessmentId);
      expect(scan1.assessmentId).toBe(assessmentId);
      await upload(server, pro, projectId, PARTIALLY_FIXED_FILE);
      const scan2 = await runSastScan(server, pro, projectId, 'sum23-sast-2', assessmentId);

      const summary = await getJson<AssessmentSummaryResponse>(await fetch(summaryPath(projectId, assessmentId), { headers: { cookie: cookieHeader(pro) } }));
      expect(summary.assessment.id).toBe(assessmentId);
      expect(summary.assessment.status).toBe('ACTIVE');
      expect(summary.objectivesTotal).toBe(2);
      expect(summary.scope.inScopeHosts).toEqual(['lab.example.org']);
      expect(summary.totals.scansLinked).toBe(2);
      expect(summary.totals.scansCompleted).toBe(2);
      expect(summary.totals.findingsTotal).toBe(3); // 2 + 1, real engine output
      expect(summary.totals.findingsBySeverity).toBeDefined();
      const totalFromSeverity = Object.values(summary.totals.findingsBySeverity ?? {}).reduce((sum, count) => sum + count, 0);
      expect(totalFromSeverity).toBe(3);
      expect(summary.totals.partialScans).toBe(0);
      expect(summary.scans).toHaveLength(2);
      expect(summary.scans.every((line) => line.scanId === scan1.id || line.scanId === scan2.id)).toBe(true);

      // Another account's assessment is invisible through this path.
      const other = await registerAndLogin(server, 'other-sum23@example.test', 'PENTESTER');
      expect((await fetch(summaryPath(projectId, assessmentId), { headers: { cookie: cookieHeader(other) } })).status).toBe(403);
    } finally {
      cleanupTempStoreDir(dataDir);
    }
  });
});
