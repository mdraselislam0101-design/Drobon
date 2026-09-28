import { afterEach, describe, expect, test } from 'vitest';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const FIXTURE_PASSWORD = 'pump thirteen lifecycle fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }

function cookieHeader(cookies: Cookies): string {
  return `${cookies.session}; drobon_device=${cookies.device}`;
}

async function createAccount(server: TestServer, email: string): Promise<Cookies> {
  const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_PASSWORD }),
  });
  expect(registered.status).toBe(201);
  const login = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_PASSWORD }),
  });
  expect(login.status).toBe(200);
  const session = sessionCookieFrom(login);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(probe.status).toBe(200);
  const deviceCookie = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  expect(deviceCookie).toBeDefined();
  return { session, device: deviceCookie!.split(';')[0]!.slice('drobon_device='.length) };
}

async function data<T>(response: Response): Promise<T> {
  return (await readJson(response) as { data: T }).data;
}

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  expect(response.status).toBe(201);
  return (await data<{ project: { id: string } }>(response)).project.id;
}

async function uploadFindingSource(server: TestServer, cookies: Cookies, projectId: string): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'exec("git " + dynamicText);\n' }] }),
  });
  expect(response.status).toBe(200);
}

async function runSast(server: TestServer, cookies: Cookies, projectId: string, key: string): Promise<{ scanId: string; finding: Record<string, unknown> }> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType: 'SAST' }),
  });
  expect(created.status).toBe(201);
  const scanId = (await data<{ scan: { id: string } }>(created)).scan.id;
  const serverForDrain = server;
  await serverForDrain.scanProcessor.drain();
  const scan = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${scanId}`, { headers: { cookie: cookieHeader(cookies) } });
  expect(scan.status).toBe(200);
  const detail = (await data<{ scan: { status: string; findings: Array<Record<string, unknown>> } }>(scan)).scan;
  expect(detail.status).toBe('COMPLETED');
  const finding = detail.findings[0];
  if (finding === undefined) throw new Error('Fixture source did not produce a SAST finding.');
  return { scanId, finding };
}

describe('authorized finding remediation lifecycle API', () => {
  test('enforces ownership and archived state, redacts notes, records transitions, and reopens on reobservation without quota changes', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    const owner = await createAccount(server, 'lifecycle-owner@example.test');
    const other = await createAccount(server, 'lifecycle-other@example.test');
    const projectId = await createProject(server, owner, 'Lifecycle fixture');
    const foreignProjectId = await createProject(server, other, 'Foreign fixture');
    await uploadFindingSource(server, owner, projectId);
    const first = await runSast(server, owner, projectId, 'pump13-sast-0001');
    const findingId = String(first.finding['id']);
    const originalEvidence = first.finding['evidence'];
    const detailPath = `/api/v1/projects/${projectId}/scans/${first.scanId}/findings/${findingId}`;
    const lifecyclePath = `${detailPath}/lifecycle`;
    const notesPath = `${detailPath}/notes`;
    const historyPath = `${detailPath}/history`;
    const sendState = (state: string, cookies = owner) => fetch(`${server.baseUrl}${lifecyclePath}`, {
      method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ state }),
    });

    const detailResponse = await fetch(`${server.baseUrl}${detailPath}`, { headers: { cookie: cookieHeader(owner) } });
    expect(detailResponse.status).toBe(200);
    const detail = await data<{ finding: Record<string, unknown>; workflow: { state: string }; guidance: { status: string } }>(detailResponse);
    expect(detail.workflow.state).toBe('OPEN');
    expect(detail.guidance.status).toBe('RULE_SPECIFIC');

    expect((await fetch(`${server.baseUrl}${lifecyclePath}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ state: 'ACKNOWLEDGED' }) })).status).toBe(401);
    expect((await sendState('ACKNOWLEDGED', other)).status).toBe(403);
    const foreignFindingPath = `/api/v1/projects/${foreignProjectId}/scans/${first.scanId}/findings/${findingId}/lifecycle`;
    expect((await fetch(`${server.baseUrl}${foreignFindingPath}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) }, body: JSON.stringify({ state: 'ACKNOWLEDGED' }) })).status).toBe(403);
    expect((await sendState('ACKNOWLEDGED')).status).toBe(200);
    expect((await sendState('OPEN')).status).toBe(409); // Backward transition is not allowed.
    expect((await fetch(`${server.baseUrl}${lifecyclePath}`, { method: 'PATCH', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) }, body: JSON.stringify({ state: 'RESOLVED', role: 'ADMIN' }) })).status).toBe(422);

    const badHtmlNote = await fetch(`${server.baseUrl}${notesPath}`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ note: '<script>alert(1)</script>' }),
    });
    expect(badHtmlNote.status).toBe(422);
    const syntheticCredentialFixture = 'SYNTHETIC_SECRET_DO_NOT_LEAK_7e2e09f5a1';
    const noteResponse = await fetch(`${server.baseUrl}${notesPath}`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ note: `Reviewed credential value: ${syntheticCredentialFixture}` }),
    });
    expect(noteResponse.status).toBe(200);
    const noteBody = await readJson(noteResponse);
    expect(JSON.stringify(noteBody)).not.toContain(syntheticCredentialFixture);
    expect(JSON.stringify(noteBody)).toContain('credential-shaped content omitted');
    const markdownNote = await fetch(`${server.baseUrl}${notesPath}`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ note: 'Follow-up:\n# injected-section' }),
    });
    expect(markdownNote.status).toBe(200);

    const usageBefore = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(owner) } });
    const beforeUsed = (await data<{ used: number }>(usageBefore)).used;
    expect(beforeUsed).toBe(1);
    expect((await sendState('IN_PROGRESS')).status).toBe(200);
    expect((await sendState('RESOLVED')).status).toBe(200);
    const usageAfterWorkflow = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(owner) } });
    expect((await data<{ used: number }>(usageAfterWorkflow)).used).toBe(beforeUsed);

    const history = await fetch(`${server.baseUrl}${historyPath}?page=1&pageSize=20`, { headers: { cookie: cookieHeader(owner) } });
    expect(history.status).toBe(200);
    const historyBody = await data<{ events: Array<{ action: string }>; total: number }>(history);
    expect(historyBody.total).toBeGreaterThanOrEqual(5);
    expect(historyBody.events[0]?.action).toBe('STATE_CHANGED');
    expect((await fetch(`${server.baseUrl}${historyPath}`, { headers: { cookie: cookieHeader(other) } })).status).toBe(403);

    const reportResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${first.scanId}/report`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) }, body: '{}',
    });
    expect(reportResponse.status).toBe(201);
    const report = (await data<{ report: { findingWorkflows?: Array<{ state: string; verificationState: string }>; findings: Array<Record<string, unknown>> } }>(reportResponse)).report;
    expect(report.findingWorkflows?.[0]?.state).toBe('RESOLVED');
    expect(report.findingWorkflows?.[0]?.verificationState).toBe('OBSERVED');
    expect(JSON.stringify(report)).not.toContain(syntheticCredentialFixture);
    const markdown = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${first.scanId}/report/download?format=markdown`, { headers: { cookie: cookieHeader(owner) } });
    const markdownText = await markdown.text();
    expect(markdownText).toContain('user-marked addressed; not proof of technical remediation');
    expect(markdownText).not.toContain('# injected-section');

    const archived = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/archive`, { method: 'POST', headers: { cookie: cookieHeader(owner) } });
    expect(archived.status).toBe(200);
    const archivedMutation = await sendState('IN_PROGRESS');
    expect(archivedMutation.status).toBe(409);
    expect((await readJson(archivedMutation) as { error: { code: string } }).error.code).toBe('PROJECT_ARCHIVED');
    expect((await fetch(`${server.baseUrl}${historyPath}`, { headers: { cookie: cookieHeader(owner) } })).status).toBe(200);
    expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/unarchive`, { method: 'POST', headers: { cookie: cookieHeader(owner) } })).status).toBe(200);

    const second = await runSast(server, owner, projectId, 'pump13-sast-0002');
    expect(second.finding['id']).toBe(findingId);
    expect(second.finding['evidence']).toBe(originalEvidence);
    const reopenedResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${second.scanId}/findings/${findingId}`, { headers: { cookie: cookieHeader(owner) } });
    expect(reopenedResponse.status).toBe(200);
    const reopened = await data<{ finding: Record<string, unknown>; workflow: { state: string; verificationState: string; lastVerificationScanId: string } }>(reopenedResponse);
    expect(reopened.finding['evidence']).toBe(originalEvidence);
    expect(reopened.workflow.state).toBe('REOPENED');
    expect(reopened.workflow.verificationState).toBe('OBSERVED');
    expect(reopened.workflow.lastVerificationScanId).toBe(second.scanId);
    const usageAfterRescan = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(owner) } });
    expect((await data<{ used: number }>(usageAfterRescan)).used).toBe(beforeUsed + 1);
    expect(server.logs.join('')).not.toContain(syntheticCredentialFixture);
  });
});
