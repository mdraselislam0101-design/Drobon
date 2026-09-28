import { afterEach, describe, expect, test } from 'vitest';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const FIXTURE_PASSWORD = 'pump fourteen assistant fixture';
const SERVERS: TestServer[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

interface Cookies { session: string; device: string }
function cookieHeader(cookies: Cookies): string { return `${cookies.session}; drobon_device=${cookies.device}`; }
async function data<T>(response: Response): Promise<T> { return (await readJson(response) as { data: T }).data; }

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

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  expect(created.status).toBe(201);
  return (await data<{ project: { id: string } }>(created)).project.id;
}

async function runLocalSast(server: TestServer, cookies: Cookies, projectId: string, key: string): Promise<{ scanId: string; finding: Record<string, unknown> }> {
  const upload = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files: [{ path: 'src/fixture.js', content: 'exec("git " + dynamicText);\n' }] }),
  });
  expect(upload.status).toBe(200);
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': key, cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType: 'SAST' }),
  });
  expect(created.status).toBe(201);
  const scanId = (await data<{ scan: { id: string } }>(created)).scan.id;
  await server.scanProcessor.drain();
  const detail = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${scanId}`, { headers: { cookie: cookieHeader(cookies) } });
  expect(detail.status).toBe(200);
  const scan = (await data<{ scan: { status: string; findings: Array<Record<string, unknown>> } }>(detail)).scan;
  expect(scan.status).toBe('COMPLETED');
  const finding = scan.findings[0];
  if (finding === undefined) throw new Error('The synthetic local fixture did not produce a SAST finding.');
  return { scanId, finding };
}

async function ask(server: TestServer, cookies: Cookies, projectId: string, body: unknown): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assistant/ask`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify(body),
  });
}

describe('Pump 14 assistant API authorization and honest behavior', () => {
  test('requires auth, reports no provider, bounds requests, and explicitly declines unsupported generation', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    const owner = await createAccount(server, 'assistant-status@example.test');
    const projectId = await createProject(server, owner, 'Assistant status fixture');

    expect((await fetch(`${server.baseUrl}/api/v1/assistant/status`)).status).toBe(401);
    const statusResponse = await fetch(`${server.baseUrl}/api/v1/assistant/status`, { headers: { cookie: cookieHeader(owner) } });
    expect(statusResponse.status).toBe(200);
    expect(await data(statusResponse)).toEqual({
      providerState: 'NONE', providerId: null, deterministicQuestionsAvailable: true,
      conversationPersistence: 'NOT_IMPLEMENTED', toolsEnabled: false,
    });

    const unsupported = await ask(server, owner, projectId, { question: 'Write a novel security plan for an architecture not represented in scan data.' });
    expect(unsupported.status).toBe(200);
    const unavailable = await data<{ state: string; mode: string; providerState: string; answer: string }>(unsupported);
    expect(unavailable).toMatchObject({ state: 'UNAVAILABLE', mode: 'DETERMINISTIC', providerState: 'NONE' });
    expect(unavailable.answer).toContain('No configured AI provider');

    expect((await ask(server, owner, projectId, { question: 'valid', provider: 'client-selected-provider' })).status).toBe(422);
    expect((await ask(server, owner, projectId, { question: 'x'.repeat(1_201) })).status).toBe(422);
    expect((await ask(server, owner, projectId, { question: '   ' })).status).toBe(422);
    expect((await ask(server, owner, projectId, { question: 'Explain', findingId: `fnd_${'a'.repeat(24)}` })).status).toBe(422);
    expect((await ask(server, owner, projectId, { question: 'Compare scans', compareScanId: 'scan_00000000-0000-4000-8000-000000000001' })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assistant/ask?provider=external`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ question: 'valid' }),
    })).status).toBe(400);
    expect((await ask(server, owner, projectId, { question: 'x'.repeat(9_000) })).status).toBe(413);
  });

  test('uses only the authenticated project, keeps lifecycle read-only, and does not consume scan quota', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    const owner = await createAccount(server, 'assistant-owner@example.test');
    const other = await createAccount(server, 'assistant-other@example.test');
    const projectId = await createProject(server, owner, 'Owned assistant fixture');
    const foreignProjectId = await createProject(server, other, 'Foreign assistant fixture');
    const own = await runLocalSast(server, owner, projectId, 'pump14-assistant-owner');
    const foreign = await runLocalSast(server, other, foreignProjectId, 'pump14-assistant-other');
    const findingId = String(own.finding['id']);
    const foreignFindingId = String(foreign.finding['id']);
    const detailPath = `/api/v1/projects/${projectId}/scans/${own.scanId}/findings/${findingId}`;

    expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assistant/ask`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: 'Top findings?' }),
    })).status).toBe(401);
    expect((await ask(server, other, projectId, { question: 'Top findings?' })).status).toBe(403);
    expect((await ask(server, owner, foreignProjectId, { question: 'Top findings?' })).status).toBe(403);

    const usageBefore = await data<{ used: number; limit: number }>(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(owner) } }));
    const remediation = await ask(server, owner, projectId, {
      question: 'How do I fix this finding?', scanId: own.scanId, findingId,
    });
    expect(remediation.status).toBe(200);
    const result = await data<{ state: string; mode: string; providerState: string; answer: string; facts: string[]; recommendations: string[]; evidence: Array<{ projectId: string; scanId?: string }> }>(remediation);
    expect(result.mode).toBe('DETERMINISTIC');
    expect(result.providerState).toBe('NONE');
    expect(result.state).toBe('SUPPORTED');
    expect(result.answer).toContain('guidance');
    expect(result.recommendations.length).toBeGreaterThan(0);
    expect(result.evidence.every((reference) => reference.projectId === projectId)).toBe(true);
    expect(result.evidence.some((reference) => reference.scanId === foreign.scanId)).toBe(false);

    const workflowBefore = await data<{ workflow: { state: string; verificationState: string } }>(await fetch(`${server.baseUrl}${detailPath}`, { headers: { cookie: cookieHeader(owner) } }));
    expect(workflowBefore.workflow.state).toBe('OPEN');
    const lifecycle = await ask(server, owner, projectId, { question: 'What is the lifecycle and verification status?', scanId: own.scanId, findingId });
    expect(lifecycle.status).toBe(200);
    const lifecycleResult = await data<{ state: string; answer: string }>(lifecycle);
    expect(lifecycleResult.state).toBe('SUPPORTED');
    expect(lifecycleResult.answer).toContain('not proof of a technical fix');
    const workflowAfter = await data<{ workflow: { state: string; verificationState: string } }>(await fetch(`${server.baseUrl}${detailPath}`, { headers: { cookie: cookieHeader(owner) } }));
    expect(workflowAfter.workflow).toEqual(workflowBefore.workflow);
    const usageAfter = await data<{ used: number; limit: number }>(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(owner) } }));
    expect(usageAfter).toEqual(usageBefore);

    const wrongFindingId = `fnd_${'b'.repeat(24)}`;
    const wrongFinding = await ask(server, owner, projectId, {
      question: 'How do I fix this finding?', scanId: own.scanId, findingId: wrongFindingId,
    });
    expect(wrongFinding.status).toBe(200);
    const noMissingFinding = await data<{ state: string; evidence: Array<{ sourceId: string }> }>(wrongFinding);
    expect(noMissingFinding.state).toBe('UNAVAILABLE');
    expect(JSON.stringify(noMissingFinding)).not.toContain(wrongFindingId);

    const wrongScan = await ask(server, owner, projectId, {
      question: 'How do I fix this finding?', scanId: foreign.scanId, findingId: foreignFindingId,
    });
    expect(wrongScan.status).toBe(200);
    const noForeignData = await data<{ state: string; answer: string; evidence: Array<{ scanId?: string; sourceId: string }> }>(wrongScan);
    expect(noForeignData.state).toBe('UNAVAILABLE');
    expect(JSON.stringify(noForeignData)).not.toContain(foreign.scanId);
    expect(JSON.stringify(noForeignData)).not.toContain(foreignFindingId);

    const foreignComparison = await ask(server, owner, projectId, {
      question: 'Compare these two scans and what changed?', scanId: own.scanId, compareScanId: foreign.scanId,
    });
    expect(foreignComparison.status).toBe(200);
    const comparisonData = await data<{ state: string; evidence: Array<{ scanId?: string }> }>(foreignComparison);
    expect(comparisonData.state).toBe('UNAVAILABLE');
    expect(comparisonData.evidence.every((reference) => reference.scanId !== foreign.scanId)).toBe(true);

    const foreignReport = await ask(server, owner, projectId, { question: 'Summarize the persisted report.', scanId: foreign.scanId });
    expect(foreignReport.status).toBe(200);
    const reportData = await data<{ state: string; answer: string }>(foreignReport);
    expect(reportData.state).toBe('UNAVAILABLE');
    expect(JSON.stringify(reportData)).not.toContain(foreign.scanId);

    const topFindings = await ask(server, owner, projectId, { question: 'What are the top findings?', scanId: own.scanId });
    expect(topFindings.status).toBe(200);
    const topResult = await data<{ facts: string[]; state: string }>(topFindings);
    expect(topResult.state).toBe('SUPPORTED');
    expect(topResult.facts.length).toBeGreaterThan(0);
  });

  test('states dependency intelligence as NOT ASSESSED without loading a vulnerability dataset', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    const owner = await createAccount(server, 'assistant-sca@example.test');
    const projectId = await createProject(server, owner, 'Assistant SCA fixture');
    const response = await ask(server, owner, projectId, { question: 'What dependency vulnerability intelligence was not assessed?' });
    expect(response.status).toBe(200);
    const result = await data<{ state: string; answer: string; limitations: string[] }>(response);
    expect(result.state).toBe('NOT_ASSESSED');
    expect(result.answer).toContain('No completed SCA result');
    expect(result.limitations.join(' ')).toContain('cannot be determined');

    const upload = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ files: [{ path: 'package.json', content: JSON.stringify({ name: 'synthetic-app', version: '1.0.0', dependencies: { express: '^4.18.0' } }) }] }),
    });
    expect(upload.status).toBe(200);
    const scanCreate = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'pump14-assistant-sca', cookie: cookieHeader(owner) },
      body: JSON.stringify({ scanType: 'SCA' }),
    });
    expect(scanCreate.status).toBe(201);
    const scaScanId = (await data<{ scan: { id: string } }>(scanCreate)).scan.id;
    await server.scanProcessor.drain();
    const scaDetail = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${scaScanId}`, { headers: { cookie: cookieHeader(owner) } });
    expect(scaDetail.status).toBe(200);
    expect((await data<{ scan: { sca: { summary: { assessmentState: string; datasetStatus: string } } } }>(scaDetail)).scan.sca.summary).toMatchObject({ assessmentState: 'NOT_ASSESSED', datasetStatus: 'NO_DATA_LOADED' });
    const inventoryAnswer = await ask(server, owner, projectId, { question: 'What dependency vulnerability intelligence was assessed?', scanId: scaScanId });
    expect(inventoryAnswer.status).toBe(200);
    const inventoryResult = await data<{ state: string; answer: string; facts: string[] }>(inventoryAnswer);
    expect(inventoryResult.state).toBe('NOT_ASSESSED');
    expect(inventoryResult.answer).toContain('Vulnerability intelligence remains NOT ASSESSED');
    expect(inventoryResult.facts.join(' ')).toContain('NO_DATA_LOADED');
    expect(JSON.stringify(inventoryResult)).not.toMatch(/CVE-\d{4}-\d+/);
    const latestInventoryAnswer = await ask(server, owner, projectId, { question: 'Show the package inventory and dataset assessment.' });
    expect(latestInventoryAnswer.status).toBe(200);
    const latestInventoryResult = await data<{ state: string; answer: string }>(latestInventoryAnswer);
    expect(latestInventoryResult.state).toBe('NOT_ASSESSED');
    expect(latestInventoryResult.answer).toContain('NOT ASSESSED');
  });
});
