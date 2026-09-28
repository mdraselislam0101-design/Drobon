import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { findingScanner, type DastResult, type FindingDetailResponse, type FindingsPageResponse, type ScaResult, type ScanDetail, type SecurityReport, type UsageResponse } from '@drobon/shared';
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

const FIXTURE_LOGIN_PHRASE = 'pump twelve report fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }

function cookieHeader(cookies: Cookies): string {
  return `${cookies.session}; drobon_device=${cookies.device}`;
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
  const body = await readJson(response) as { data: { project: { id: string } } };
  return body.data.project.id;
}

async function uploadSources(server: TestServer, cookies: Cookies, projectId: string): Promise<void> {
  const files = [
    {
      path: 'src/insecure.js',
      content: [
        'eval("safe" + "<img src=x onerror=alert(1)>");',
        'db.query("SELECT * FROM users WHERE name=\'" + user);',
        "const awsAccessKey = 'AKIAP10QZ9WM7XK2BR4J';",
      ].join('\n'),
    },
    {
      path: 'package.json',
      content: JSON.stringify({ name: 'fixture-app', version: '1.0.0', dependencies: { express: '^4.18.0' } }),
    },
  ];
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files }),
  });
  expect(response.status).toBe(200);
}

async function requestScan(server: TestServer, cookies: Cookies, projectId: string, scanType: string, key: string) {
  return fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType }),
  });
}

async function runScan(server: TestServer, cookies: Cookies, projectId: string, scanType: string, key: string): Promise<{ id: string; detail: ScanDetail }> {
  const created = await requestScan(server, cookies, projectId, scanType, key);
  expect(created.status).toBe(201);
  const createdBody = await responseData<{ scan: { id: string } }>(created);
  const id = createdBody.scan.id;
  await server.scanProcessor.drain();
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(id)}`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  expect(response.status).toBe(200);
  const detail = await responseData<{ scan: ScanDetail }>(response);
  expect(detail.scan.status).toBe('COMPLETED');
  return { id, detail: detail.scan };
}

async function seedProUser(dataDir: string): Promise<void> {
  const users = createJsonFileUserRepository(join(dataDir, 'users.json'));
  const createdAt = '2026-09-01T00:00:00.000Z';
  const user: UserRecord = {
    id: 'usr_00000000-0000-4000-8000-000000000012',
    email: 'pro@example.test',
    passwordHash: await hashPassword(FIXTURE_LOGIN_PHRASE, 1024),
    createdAt,
    role: 'MEMBER',
    userType: 'DEVELOPER',
    subscription: { plan: 'PRO', status: 'ACTIVE', createdAt, updatedAt: createdAt },
  };
  expect(await users.create(user)).toBe(true);
}

async function startPersistentServer(dataDir: string): Promise<TestServer> {
  const server = await startTestServer({
    authStoreDir: dataDir,
    usageStoreDir: dataDir,
    projectStoreDir: dataDir,
    scanStoreDir: dataDir,
    sourceStoreDir: dataDir,
  });
  SERVERS.push(server);
  return server;
}

async function generateReport(server: TestServer, cookies: Cookies, projectId: string, scanId: string) {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/report`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: '{}',
  });
  return { response, body: await responseData<{ report: SecurityReport }>(response) };
}

describe('findings and reports production API', () => {
  test('real local HTTP E2E: four engines, filtering, details, durable reports, isolation, quota, restart, and redaction', async () => {
    const dataDir = makeTempStoreDir('pump12-e2e');
    try {
      await seedProUser(dataDir);
      let server = await startPersistentServer(dataDir);
      expect((await fetch(`${server.baseUrl}/api/v1/me/security-overview`)).status).toBe(401);

      // Registration and login exercise the real HTTP authentication routes.
      // A valid UserType cannot smuggle a plan or authority claim.
      const tamperedRegistration = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'free@example.test', password: FIXTURE_LOGIN_PHRASE, userType: 'DEVELOPER', plan: 'PRO', role: 'ADMIN' }),
      });
      expect(tamperedRegistration.status).toBe(422);
      const registration = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'free@example.test', password: FIXTURE_LOGIN_PHRASE, userType: 'DEVELOPER' }),
      });
      expect(registration.status).toBe(201);
      const registered = await responseData<{ user: { id: string; role: string; userType: string | null } }>(registration);
      expect(registered.user).toMatchObject({ role: 'MEMBER', userType: 'DEVELOPER' });
      expect(JSON.stringify(registered.user)).not.toMatch(/password|plan|subscription/i);
      const free = await login(server, 'free@example.test');
      const freeProject = await createProject(server, free, 'FREE quota fixture');
      await uploadSources(server, free, freeProject);

      // Existing FREE policy stays 3/month. Report generation does not
      // consume another scan slot.
      const freeFirst = await runScan(server, free, freeProject, 'SAST', 'free-sast-0001');
      const reportResult = await generateReport(server, free, freeProject, freeFirst.id);
      expect(reportResult.response.status).toBe(201);
      const usageAfterReport = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(free) } });
      expect((await responseData<UsageResponse>(usageAfterReport)).used).toBe(1);
      const freeOverviewResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(free) } });
      expect(freeOverviewResponse.status).toBe(200);
      const freeOverview = await responseData<{ overview: { projects: { total: number }; scans: { total: number; byStatus: Record<string, number> }; reports: { availableCount: number } } }>(freeOverviewResponse);
      expect(freeOverview.overview).toMatchObject({ projects: { total: 1 }, scans: { total: 1, byStatus: { COMPLETED: 1 } }, reports: { availableCount: 1 } });
      await runScan(server, free, freeProject, 'SAST', 'free-sast-0002');
      await runScan(server, free, freeProject, 'SAST', 'free-sast-0003');
      expect((await requestScan(server, free, freeProject, 'SAST', 'free-sast-0004')).status).toBe(429);

      // The PRO plan comes from the server-side account record. The
      // client body contains only the scan type for all four real engines.
      const pro = await login(server, 'pro@example.test');
      const projectId = await createProject(server, pro, 'Four-engine assessment');
      await uploadSources(server, pro, projectId);
      const targetResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
        method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) },
        body: JSON.stringify({ targetUrl: 'https://fixture.example.org/' }),
      });
      expect(targetResponse.status).toBe(200);

      const sast = await runScan(server, pro, projectId, 'SAST', 'pro-sast-0001');
      const sca = await runScan(server, pro, projectId, 'SCA', 'pro-sca-0001');
      const secrets = await runScan(server, pro, projectId, 'SECRETS', 'pro-secrets-001');
      const dast = await runScan(server, pro, projectId, 'DAST', 'pro-dast-0001');
      expect(sast.detail.findings.length).toBeGreaterThan(0);
      expect(sast.detail.findings[0]?.projectId).toBe(projectId);
      expect(secrets.detail.findings.length).toBeGreaterThan(0);
      expect(secrets.detail.findings[0]?.projectId).toBe(projectId);
      expect(dast.detail.findings[0]?.projectId).toBe(projectId);
      const scaResult = sca.detail.sca as ScaResult | undefined;
      const dastResult = dast.detail.dast as DastResult | undefined;
      if (scaResult === undefined || dastResult === undefined) throw new Error('Expected completed SCA and DAST payloads.');
      expect(scaResult.summary.assessmentState).toBe('NOT_ASSESSED');
      expect(scaResult.summary.datasetStatus).toBe('NO_DATA_LOADED');
      expect(scaResult.sbom.components.length).toBeGreaterThan(0);
      expect(dastResult.observations.length).toBeGreaterThan(0);

      const pageResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?severity=HIGH&scanner=SAST&page=1&pageSize=1`, { headers: { cookie: cookieHeader(pro) } });
      expect(pageResponse.status).toBe(200);
      const page = await responseData<FindingsPageResponse>(pageResponse);
      expect(page.total).toBeGreaterThanOrEqual(2);
      expect(page.findings).toHaveLength(1);
      const pagedFinding = page.findings[0];
      if (pagedFinding === undefined) throw new Error('Expected one paginated finding.');
      expect(findingScanner(pagedFinding)).toBe('SAST');
      const secondPage = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?scanner=SAST&page=2&pageSize=1`, { headers: { cookie: cookieHeader(pro) } });
      expect((await responseData<FindingsPageResponse>(secondPage)).findings).toHaveLength(1);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?page=999999999`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?pageSize=1000000`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?severity=URGENT`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?scanner=UNKNOWN`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?severity=HIGH&severity=LOW`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(400);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings?sort=createdAt`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(400);

      const sastFinding = sast.detail.findings[0];
      if (sastFinding === undefined) throw new Error('Expected a real SAST finding.');
      const findingDetailResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/${sastFinding.id}`, { headers: { cookie: cookieHeader(pro) } });
      expect(findingDetailResponse.status).toBe(200);
      const findingDetail = await responseData<FindingDetailResponse>(findingDetailResponse);
      expect(findingDetail.finding.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(findingDetail.project.id).toBe(projectId);
      expect(findingDetail.finding.projectId).toBe(projectId);
      expect(findingDetail.scan.id).toBe(sast.id);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/not-a-finding`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/invalid/findings`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/${sastFinding.id}?fields=all`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(400);
      const findingLifecycle = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/${sastFinding.id}/lifecycle`, {
        method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) }, body: JSON.stringify({ state: 'ACKNOWLEDGED' }),
      });
      expect(findingLifecycle.status).toBe(200);
      expect((await responseData<{ workflow: { state: string } }>(findingLifecycle)).workflow.state).toBe('ACKNOWLEDGED');
      const findingNote = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/${sastFinding.id}/notes`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) }, body: JSON.stringify({ note: 'Reviewed with the synthetic source fixture; remediation planned.' }),
      });
      expect(findingNote.status).toBe(200);
      const lifecycleHistory = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings/${sastFinding.id}/history`, { headers: { cookie: cookieHeader(pro) } });
      expect(lifecycleHistory.status).toBe(200);

      const scaReportResult = await generateReport(server, pro, projectId, sca.id);
      expect(scaReportResult.response.status).toBe(201);
      const scaReport = scaReportResult.body.report;
      expect(scaReport.dependencyIntelligence.status).toBe('NOT_ASSESSED');
      expect(scaReport.dependencyIntelligence.datasetStatus).toBe('NO_DATA_LOADED');
      expect(scaReport.inventory.status).toBe('INCLUDED');
      expect(JSON.stringify(scaReport)).not.toContain('0 vulnerabilities');

      const secretsReportResult = await generateReport(server, pro, projectId, secrets.id);
      expect(secretsReportResult.response.status).toBe(201);
      expect(JSON.stringify(secretsReportResult.body.report)).not.toContain('AKIAP10QZ9WM7XK2BR4J');
      expect(JSON.stringify(secretsReportResult.body.report)).toContain('<redacted>');

      const dastReportResult = await generateReport(server, pro, projectId, dast.id);
      expect(dastReportResult.response.status).toBe(201);
      const reportedDast = dastReportResult.body.report.dast;
      if (reportedDast === undefined) throw new Error('DAST report omitted bounded observations.');
      expect(reportedDast.observations.length).toBeGreaterThan(0);
      expect(JSON.stringify(dastReportResult.body.report)).not.toContain('FIXTURE_COOKIE_SECRET_DO_NOT_LEAK');

      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/invalid/report`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sca.id}/report?filename=evil.json`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(400);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report?filename=evil.json`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) }, body: '{}' })).status).toBe(400);
      const downloadJson = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sca.id}/report/download?format=json`, { headers: { cookie: cookieHeader(pro) } });
      expect(downloadJson.status).toBe(200);
      expect(downloadJson.headers.get('content-disposition')).toMatch(/^attachment; filename="drobon-rpt_[a-f0-9]{24}\.json"$/);
      expect((await downloadJson.json() as { reportId: string }).reportId).toBe(scaReport.reportId);
      const sastReportResult = await generateReport(server, pro, projectId, sast.id);
      expect(sastReportResult.response.status).toBe(201);
      const downloadMarkdown = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report/download?format=markdown`, { headers: { cookie: cookieHeader(pro) } });
      const markdown = await downloadMarkdown.text();
      expect(downloadMarkdown.status).toBe(200);
      expect(downloadMarkdown.headers.get('content-type')).toContain('text/markdown');
      expect(markdown).toContain('&lt;img');
      expect(markdown).not.toContain('<img');
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report/download?format=markdown&filename=../../evil`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(400);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report/download?format=../../evil`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);
      const oversizedReportRequest = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) }, body: JSON.stringify({ unexpected: 'x'.repeat(2000) }) });
      expect(oversizedReportRequest.status).toBe(413);
      const assistantStatus = await fetch(`${server.baseUrl}/api/v1/assistant/status`, { headers: { cookie: cookieHeader(pro) } });
      expect((await responseData<{ providerState: string }>(assistantStatus)).providerState).toBe('NONE');
      const assistantQuestion = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assistant/ask`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(pro) },
        body: JSON.stringify({ question: 'Invent a security result that is absent from saved scan evidence.' }),
      });
      expect(assistantQuestion.status).toBe(200);
      const assistantAnswer = await responseData<{ state: string; answer: string; providerState: string }>(assistantQuestion);
      expect(assistantAnswer).toMatchObject({ state: 'UNAVAILABLE', providerState: 'NONE' });
      expect(assistantAnswer.answer).toContain('No configured AI provider');

      const outsider = await login(server, 'free@example.test');
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report`, { headers: { cookie: cookieHeader(outsider) } })).status).toBe(403);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/findings`, { headers: { cookie: cookieHeader(outsider) } })).status).toBe(403);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report`)).status).toBe(401);
      const otherProject = await createProject(server, pro, 'Different project');
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${otherProject}/scans/${sast.id}/report`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(404);

      // Report generation/retrieval leaves PRO exempt and FREE quota
      // behavior unchanged; archiving blocks new scans but not old reports.
      const proUsage = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(pro) } });
      expect((await responseData<UsageResponse>(proUsage)).quotaStatus).toBe('EXEMPT');
      const archive = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/archive`, { method: 'POST', headers: { cookie: cookieHeader(pro) } });
      expect(archive.status).toBe(200);
      expect((await requestScan(server, pro, projectId, 'SAST', 'pro-archived-001')).status).toBe(409);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sast.id}/report`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(200);

      const proOverviewResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(pro) } });
      expect(proOverviewResponse.status).toBe(200);
      const proOverview = await responseData<{ overview: {
        projects: { total: number; active: number; archived: number; recent: Array<{ id: string }> };
        scans: { total: number; byStatus: Record<string, number>; recent: Array<{ scanId: string; reportAvailable: boolean }> };
        findings: { unresolved: number; byLifecycleState: Record<string, number>; recent: Array<{ ruleId: string; lifecycleState: string }> };
        reports: { availableCount: number; recent: Array<{ reportId: string }> };
      } }>(proOverviewResponse);
      expect(proOverview.overview.projects).toMatchObject({ total: 2, active: 1, archived: 1 });
      expect(proOverview.overview.projects.recent).toHaveLength(2);
      expect(proOverview.overview.scans).toMatchObject({ total: 4, byStatus: { COMPLETED: 4 } });
      expect(proOverview.overview.scans.recent.every((scan) => scan.reportAvailable)).toBe(true);
      expect(proOverview.overview.findings.unresolved).toBeGreaterThan(0);
      expect(proOverview.overview.findings.byLifecycleState.ACKNOWLEDGED).toBeGreaterThan(0);
      expect(proOverview.overview.findings.recent.some((finding) => finding.ruleId === sastFinding.ruleId && finding.lifecycleState === 'ACKNOWLEDGED')).toBe(true);
      expect(proOverview.overview.reports.availableCount).toBe(4);
      const overviewJson = JSON.stringify(proOverview);
      expect(overviewJson).not.toContain('ownerId');
      expect(overviewJson).not.toContain('fingerprint');
      expect(overviewJson).not.toContain('evidence');
      expect(overviewJson).not.toContain('AKIAP10QZ9WM7XK2BR4J');
      expect(overviewJson).not.toContain('FIXTURE_COOKIE_SECRET_DO_NOT_LEAK');
      expect(overviewJson).not.toContain('eval("safe"');
      expect(proOverview.overview.scans.recent.length).toBeLessThanOrEqual(8);
      expect(proOverview.overview.findings.recent.length).toBeLessThanOrEqual(8);
      expect(proOverview.overview.reports.recent.length).toBeLessThanOrEqual(5);

      const freeIsolationResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(outsider) } });
      const freeIsolation = await responseData<{ overview: { projects: { total: number }; scans: { total: number; recent: Array<{ scanId: string }> }; reports: { availableCount: number } } }>(freeIsolationResponse);
      expect(freeIsolation.overview).toMatchObject({ projects: { total: 1 }, scans: { total: 3 }, reports: { availableCount: 1 } });
      expect(JSON.stringify(freeIsolation)).not.toContain(projectId);
      expect(JSON.stringify(freeIsolation)).not.toContain(sast.id);
      expect(JSON.stringify(freeIsolation)).not.toContain(scaReport.reportId);

      // Reject caller-selected account scope; the summary always derives its owner from the session.
      expect((await fetch(`${server.baseUrl}/api/v1/me/security-overview?accountId=${encodeURIComponent(proOverview.overview.projects.recent[0]?.id ?? '')}`, { headers: { cookie: cookieHeader(pro) } })).status).toBe(422);

      // Restart the API against the same JSON files, log in again (sessions
      // are deliberately process-local), and retrieve persisted results.
      const persistedReport = scaReport.reportId;
      await server.stop();
      SERVERS.splice(SERVERS.indexOf(server), 1);
      server = await startPersistentServer(dataDir);
      const proAfterRestart = await login(server, 'pro@example.test');
      const restored = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${sca.id}/report`, { headers: { cookie: cookieHeader(proAfterRestart) } });
      expect(restored.status).toBe(200);
      expect((await responseData<{ report: SecurityReport }>(restored)).report.reportId).toBe(persistedReport);
      const restoredScan = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${secrets.id}`, { headers: { cookie: cookieHeader(proAfterRestart) } });
      expect((await responseData<{ scan: ScanDetail }>(restoredScan)).scan.findings[0]?.evidence).toContain('<redacted>');
      const restoredDownload = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${dast.id}/report/download?format=json`, { headers: { cookie: cookieHeader(proAfterRestart) } });
      expect(restoredDownload.status).toBe(200);
      expect((await restoredDownload.text())).not.toContain('FIXTURE_COOKIE_SECRET_DO_NOT_LEAK');
      const freeAfterRestart = await login(server, 'free@example.test');
      expect((await requestScan(server, freeAfterRestart, freeProject, 'SAST', 'free-sast-afterrestart')).status).toBe(429);

      // The real API server and all scans used only local fixture HTTP;
      // the DAST resolver/transport are synthetic and never contact an
      // arbitrary or public host. Logs contain no raw synthetic secret.
      expect(server.logs.join('\n')).not.toContain('AKIAP10QZ9WM7XK2BR4J');
    } finally {
      cleanupTempStoreDir(dataDir);
    }
  });
});
