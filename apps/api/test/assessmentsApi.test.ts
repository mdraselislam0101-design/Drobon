import { afterEach, describe, expect, test } from 'vitest';
import { join } from 'node:path';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { cleanupTempStoreDir, makeTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const PASSWORD = 'test-pump twenty two assessment fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }
const cookieHeader = (cookies: Cookies): string => `${cookies.session}; drobon_device=${cookies.device}`;

async function responseData<T>(response: Response): Promise<T> {
  return (await readJson(response) as { data: T }).data;
}

async function register(server: TestServer, email: string, userType: 'SECURITY_PROFESSIONAL' | 'PENTESTER' | 'DEVELOPER' = 'SECURITY_PROFESSIONAL'): Promise<Cookies> {
  const created = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD, userType }),
  });
  expect(created.status).toBe(201);
  const session = sessionCookieFrom(created);
  const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(me.status).toBe(200);
  const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(device).toBeDefined();
  return { session, device: device!.split(';')[0]!.slice('drobon_device='.length) };
}

async function login(server: TestServer, email: string): Promise<Cookies> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password: PASSWORD }),
  });
  expect(response.status).toBe(200);
  const session = sessionCookieFrom(response);
  const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(device).toBeDefined();
  return { session, device: device!.split(';')[0]!.slice('drobon_device='.length) };
}

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ name }),
  });
  expect(response.status).toBe(201);
  return (await responseData<{ project: { id: string } }>(response)).project.id;
}

const scope = (inScopeHosts: string[] = [], outOfScopeHosts: string[] = []) => ({ inScopeHosts, outOfScopeHosts, notes: 'Only explicitly listed hosts; no inherited subdomains.' });
const assessmentInput = (scopeInput = scope()) => ({ title: 'Payment-flow assessment', objectives: ['Review server-side authorization boundaries', 'Document findings and remediation evidence'], scope: scopeInput });

async function createAssessment(server: TestServer, cookies: Cookies, projectId: string, input = assessmentInput()): Promise<{ id: string; raw: Record<string, unknown> }> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify(input),
  });
  expect(response.status).toBe(201);
  const data = await responseData<{ assessment: { id: string } }>(response);
  return { id: data.assessment.id, raw: data.assessment as unknown as Record<string, unknown> };
}

async function setTarget(server: TestServer, cookies: Cookies, projectId: string): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ targetUrl: 'https://fixture.example.org/' }),
  });
  expect(response.status).toBe(200);
}

async function seedProUser(dataDir: string): Promise<void> {
  const repository = createJsonFileUserRepository(join(dataDir, 'users.json'));
  const createdAt = '2026-09-01T00:00:00.000Z';
  const user: UserRecord = {
    id: 'usr_00000000-0000-4000-8000-000000000022', email: 'pro.professional@example.test',
    passwordHash: await hashPassword(PASSWORD, 1024), createdAt, role: 'MEMBER', userType: 'SECURITY_PROFESSIONAL',
    subscription: { plan: 'PRO', status: 'ACTIVE', createdAt, updatedAt: createdAt },
  };
  expect(await repository.create(user)).toBe(true);
}

describe('structured Security Professional assessment API', () => {
  test('controlled local E2E: ownership, bounded scope, passive DAST link, user declaration, report/history, and restart persistence', async () => {
    const dataDir = makeTempStoreDir('pump22-assessment-e2e');
    let server: TestServer | undefined;
    try {
      await seedProUser(dataDir);
      server = await startTestServer({ authStoreDir: dataDir, projectStoreDir: dataDir, scanStoreDir: dataDir, assessmentStoreDir: dataDir });
      SERVERS.push(server);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-000000000001/assessments`)).status).toBe(401);

      const professional = await login(server, 'pro.professional@example.test');
      const other = await register(server, 'other.professional@example.test', 'PENTESTER');
      const projectId = await createProject(server, professional, 'Assessment project');
      const sameOwnerOtherProjectId = await createProject(server, professional, 'Second professional project');
      const otherProjectId = await createProject(server, other, 'Other owner project');
      const pentesterAssessment = await createAssessment(server, other, otherProjectId);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${otherProjectId}/assessments/${pentesterAssessment.id}`, { headers: { cookie: cookieHeader(other) } })).status).toBe(200);
      await setTarget(server, professional, projectId);

      const route = `${server.baseUrl}/api/v1/projects/${projectId}/assessments`;
      const unauthorizedCreate = await fetch(route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(assessmentInput()) });
      expect(unauthorizedCreate.status).toBe(401);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${otherProjectId}/assessments`, { headers: { cookie: cookieHeader(professional) } })).status).toBe(403);

      const malformedScope = await fetch(route, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify(assessmentInput(scope(['*.fixture.example.org']))) });
      expect(malformedScope.status).toBe(422);
      const overlappingScope = await fetch(route, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify(assessmentInput(scope(['fixture.example.org'], ['fixture.example.org']))) });
      expect(overlappingScope.status).toBe(422);
      const forgedCreate = await fetch(route, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ ...assessmentInput(), ownerId: 'usr_attacker', projectId: otherProjectId, userType: 'PENTESTER', status: 'ACTIVE' }) });
      expect(forgedCreate.status).toBe(422);

      const created = await createAssessment(server, professional, projectId, assessmentInput(scope(['fixture.example.org'], ['admin.fixture.example.org'])));
      const assessmentId = created.id;
      const anonymousDetail = await fetch(`${route}/${assessmentId}`);
      expect(anonymousDetail.status).toBe(401);
      expect((await fetch(`${route}/${assessmentId}/status`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(401);
      expect((await fetch(`${route}/${assessmentId}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(assessmentInput()) })).status).toBe(401);
      expect((await fetch(`${route}/${assessmentId}/authorization-declarations`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'DECLARE', confirm: true }) })).status).toBe(401);
      expect(created.raw).not.toHaveProperty('ownerId');
      expect(created.raw).toMatchObject({ projectId, status: 'PLANNED', title: 'Payment-flow assessment' });
      expect((await server.assessments.listByProject('usr_attacker', projectId))).toHaveLength(0);
      expect((await fetch(`${route}/malformed`, { headers: { cookie: cookieHeader(professional) } })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${sameOwnerOtherProjectId}/assessments/${assessmentId}`, { headers: { cookie: cookieHeader(professional) } })).status).toBe(404);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}`, { headers: { cookie: cookieHeader(other) } })).status).toBe(403);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(other) }, body: JSON.stringify(assessmentInput()) })).status).toBe(403);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}/status`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(other) }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(403);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}/authorization-declarations`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(other) }, body: JSON.stringify({ action: 'DECLARE', confirm: true }) })).status).toBe(403);

      const plannedScan = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId }),
      });
      expect(plannedScan.status).toBe(409);
      const clientAuthorityScan = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId, targetUrl: 'https://other.example.org/', userType: 'PENTESTER' }),
      });
      expect(clientAuthorityScan.status).toBe(422);
      const malformedLinkedScan = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId: 'asm_tampered' }),
      });
      expect(malformedLinkedScan.status).toBe(404);
      const statusUrl = `${route}/${assessmentId}/status`;
      const started = await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'ACTIVE' }) });
      expect(started.status).toBe(200);
      const active = await responseData<{ assessment: { history: unknown[] } }>(started);
      const historyAfterStart = active.assessment.history.length;
      expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(200);
      const duplicateStart = await responseData<{ assessment: { history: unknown[] } }>(await fetch(`${route}/${assessmentId}`, { headers: { cookie: cookieHeader(professional) } }));
      expect(duplicateStart.assessment.history).toHaveLength(historyAfterStart);
      const activeScopeUpdate = await fetch(`${route}/${assessmentId}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify(assessmentInput(scope(['new.fixture.example.org']))) });
      expect(activeScopeUpdate.status).toBe(409);

      const outOfScope = await createAssessment(server, professional, projectId, assessmentInput(scope(['outside.example.org'])));
      const outOfScopeStatus = `${route}/${outOfScope.id}/status`;
      expect((await fetch(outOfScopeStatus, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(200);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId: outOfScope.id }) })).status).toBe(409);
      expect((await fetch(`${route}/${outOfScope.id}/authorization-declarations`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ action: 'DECLARE', confirm: true }) })).status).toBe(409);
      expect((await fetch(outOfScopeStatus, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'CANCELLED' }) })).status).toBe(200);

      // Assessment linkage does not require a declaration and cannot bypass
      // existing project URL/DNS/SSRF/passive-GET controls. This test uses the
      // API's synthetic DNS and DAST transport fixtures only.
      const dastCreated = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'assessment-dast-0001', cookie: cookieHeader(professional) },
        body: JSON.stringify({ scanType: 'DAST', assessmentId }),
      });
      expect(dastCreated.status).toBe(201);
      const scan = (await responseData<{ scan: { id: string; assessmentId?: string } }>(dastCreated)).scan;
      expect(scan.assessmentId).toBe(assessmentId);
      expect((await server.scans.listByProject(projectId)).find((item) => item.id === scan.id)?.assessmentId).toBe(assessmentId);
      const replay = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'assessment-dast-0001', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId }) });
      expect(replay.status).toBe(200);
      expect((await responseData<{ scan: { id: string } }>(replay)).scan.id).toBe(scan.id);
      const wrongAssociationReplay = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'assessment-dast-0001', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST' }) });
      expect(wrongAssociationReplay.status).toBe(409);
      await server.scanProcessor.drain();
      const reportResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${scan.id}/report`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: '{}',
      });
      expect(reportResponse.status).toBe(201);
      const report = (await responseData<{ report: { scan: { assessmentId?: string } } }>(reportResponse)).report;
      expect(report.scan.assessmentId).toBe(assessmentId);

      // The declaration is a timestamped USER_DECLARED statement, not
      // evidence verified by Drobon. Duplicate actions are idempotent and
      // withdrawal restores UNVERIFIED rather than deleting history.
      const declarationUrl = `${route}/${assessmentId}/authorization-declarations`;
      const declare = () => fetch(declarationUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ action: 'DECLARE', confirm: true }) });
      expect((await declare()).status).toBe(200);
      const declared = await responseData<{ assessment: { authorizationDeclarations: Array<{ state: string; targetUrl: string; declaredAt: string }>; history: unknown[] } }>(await fetch(`${route}/${assessmentId}`, { headers: { cookie: cookieHeader(professional) } }));
      expect(declared.assessment.authorizationDeclarations.at(-1)).toMatchObject({ state: 'USER_DECLARED', targetUrl: 'https://fixture.example.org/' });
      expect(Number.isNaN(Date.parse(declared.assessment.authorizationDeclarations.at(-1)!.declaredAt))).toBe(false);
      const declarationHistoryLength = declared.assessment.history.length;
      expect((await declare()).status).toBe(200);
      const repeated = await responseData<{ assessment: { history: unknown[] } }>(await fetch(`${route}/${assessmentId}`, { headers: { cookie: cookieHeader(professional) } }));
      expect(repeated.assessment.history).toHaveLength(declarationHistoryLength);
      const withdrawn = await fetch(declarationUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ action: 'WITHDRAW', confirm: true }) });
      expect(withdrawn.status).toBe(200);
      expect((await responseData<{ assessment: { authorizationDeclarations: Array<{ state: string }> } }>(withdrawn)).assessment.authorizationDeclarations.at(-1)?.state).toBe('WITHDRAWN');
      expect((await fetch(declarationUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ action: 'WITHDRAW', confirm: true }) })).status).toBe(200);
      expect((await fetch(declarationUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ action: 'DECLARE', confirm: false }) })).status).toBe(422);

      const detailUrl = `${route}/${assessmentId}`;
      const detail = await responseData<{ progress: { totalScans: number; completedScans: number; findingsTotal: number; recentScans: Array<{ reportAvailable: boolean }> } }>(await fetch(detailUrl, { headers: { cookie: cookieHeader(professional) } }));
      expect(detail.progress).toMatchObject({ totalScans: 1, completedScans: 1 });
      expect(detail.progress.recentScans[0]?.reportAvailable).toBe(true);
      expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'COMPLETED' }) })).status).toBe(200);
      const completed = await responseData<{ assessment: { status: string; completedAt?: string } }>(await fetch(detailUrl, { headers: { cookie: cookieHeader(professional) } }));
      expect(completed.assessment).toMatchObject({ status: 'COMPLETED' });
      expect(completed.assessment.completedAt).toBeDefined();
      const completedHistoryLength = (await responseData<{ assessment: { history: unknown[] } }>(await fetch(detailUrl, { headers: { cookie: cookieHeader(professional) } }))).assessment.history.length;
      expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'COMPLETED' }) })).status).toBe(200);
      expect((await responseData<{ assessment: { history: unknown[] } }>(await fetch(detailUrl, { headers: { cookie: cookieHeader(professional) } }))).assessment.history).toHaveLength(completedHistoryLength);
      expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(409);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(professional) }, body: JSON.stringify({ scanType: 'DAST', assessmentId }) })).status).toBe(409);

      // Restart the actual JSON-backed stores. The prior session is process
      // local and is deliberately re-established; assessment, scan and report
      // records remain and preserve the association/history.
      const beforeRestart = server;
      await beforeRestart.stop();
      SERVERS.splice(SERVERS.indexOf(beforeRestart), 1);
      server = undefined;
      server = await startTestServer({ authStoreDir: dataDir, projectStoreDir: dataDir, scanStoreDir: dataDir, assessmentStoreDir: dataDir });
      SERVERS.push(server);
      const afterRestart = await login(server, 'pro.professional@example.test');
      const otherAfterRestart = await login(server, 'other.professional@example.test');
      const persisted = await responseData<{ assessment: { status: string; authorizationDeclarations: Array<{ state: string }>; history: unknown[] }; progress: { totalScans: number; recentScans: Array<{ reportAvailable: boolean }> } }>(await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}`, { headers: { cookie: cookieHeader(afterRestart) } }));
      expect(persisted.assessment.status).toBe('COMPLETED');
      expect(persisted.assessment.authorizationDeclarations.map((item) => item.state)).toEqual(['USER_DECLARED', 'WITHDRAWN']);
      expect(persisted.progress.totalScans).toBe(1);
      expect(persisted.progress.recentScans[0]?.reportAvailable).toBe(true);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${scan.id}/report`, { headers: { cookie: cookieHeader(afterRestart) } })).status).toBe(200);

      const archive = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/archive`, { method: 'POST', headers: { cookie: cookieHeader(afterRestart) } });
      expect(archive.status).toBe(200);
      expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}/status`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(afterRestart) }, body: JSON.stringify({ status: 'CANCELLED' }) })).status).toBe(409);
      const attackerClaim = await fetch(`${server.baseUrl}/api/v1/projects/${otherProjectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(otherAfterRestart) }, body: JSON.stringify({ scanType: 'SAST', assessmentId }),
      });
      expect(attackerClaim.status).toBe(404);
    } finally {
      if (server !== undefined) {
        const index = SERVERS.indexOf(server);
        if (index >= 0) SERVERS.splice(index, 1);
        await server.stop().catch(() => undefined);
      }
      cleanupTempStoreDir(dataDir);
    }
  });

  test('FREE linked scans preserve server quota; exhausted quota is unchanged and assessment cannot close with active scans', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    const cookies = await register(server, 'free.assessment@example.test');
    const projectId = await createProject(server, cookies, 'FREE assessment quota');
    const upload = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'const safeValue = 1;' }] }),
    });
    expect(upload.status).toBe(200);
    const created = await createAssessment(server, cookies, projectId);
    const statusUrl = `${server.baseUrl}/api/v1/projects/${projectId}/assessments/${created.id}/status`;
    expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(200);
    for (let index = 0; index < 3; index += 1) {
      const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': `free-assess-${index}000`, cookie: cookieHeader(cookies) }, body: JSON.stringify({ scanType: 'SAST', assessmentId: created.id }),
      });
      expect(response.status).toBe(201);
      if (index === 0) {
        const prematureClose = await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ status: 'COMPLETED' }) });
        expect(prematureClose.status).toBe(409);
        const prematureCancel = await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ status: 'CANCELLED' }) });
        expect(prematureCancel.status).toBe(409);
      }
      await server.scanProcessor.drain();
    }
    const overQuota = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'free-assess-over', cookie: cookieHeader(cookies) }, body: JSON.stringify({ scanType: 'SAST', assessmentId: created.id }),
    });
    expect(overQuota.status).toBe(429);
    const usage = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(cookies) } });
    expect((await responseData<{ used: number }>(usage)).used).toBe(3);
    const detail = await responseData<{ progress: { totalScans: number; completedScans: number; activeScans: number } }>(await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${created.id}`, { headers: { cookie: cookieHeader(cookies) } }));
    expect(detail.progress).toMatchObject({ totalScans: 3, completedScans: 3, activeScans: 0 });
    expect((await fetch(statusUrl, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) }, body: JSON.stringify({ status: 'COMPLETED' }) })).status).toBe(200);
  });
});
