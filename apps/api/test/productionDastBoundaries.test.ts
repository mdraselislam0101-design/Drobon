import { afterEach, describe, expect, test } from 'vitest';
import { engagementAllowsScan } from '@drobon/shared';
import { createMemoryAssessmentStore } from '../src/assessments/store.js';
import { createAssessmentDastAuthorizer } from '../src/scans/dast/authorization.js';
import { createActiveDastEngine } from '../src/scans/dast/activeEngine.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy, normalizeDastTarget } from '../src/scans/dast/target.js';
import type { DastTransport } from '../src/scans/dast/http.js';
import type { ScanRecord } from '../src/scans/store.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

// All DNS answers and responses below are injected; no target network request occurs.
const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const TARGET = 'https://fixture.example.org/api/start';
const NOW = '2026-10-31T10:00:00.000Z';
const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

async function scopedFixture() {
  const store = createMemoryAssessmentStore();
  const assessment = await store.create({ ownerId: OWNER, projectId: PROJECT, title: 'Synthetic scope',
    objectives: ['Exercise scope handling'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] }, now: NOW });
  if ('outcome' in assessment) throw new Error('synthetic assessment creation failed');
  await store.transition({ ownerId: OWNER, projectId: PROJECT, assessmentId: assessment.id, status: 'ACTIVE', now: NOW });
  const declared = await store.recordEngagement({ ownerId: OWNER, projectId: PROJECT, assessmentId: assessment.id,
    action: 'DECLARE', now: NOW, engagement: {
      clientName: 'Fixture', targetUrl: TARGET, inScopeHosts: ['fixture.example.org'], scopePaths: ['/api'],
      allowedScanTypes: ['DAST'], validFrom: '2026-10-01T00:00:00.000Z', validUntil: '2026-12-01T00:00:00.000Z',
      statement: 'Synthetic authorization for a mock transport only.',
    } });
  const engagement = declared.assessment?.engagements?.[0];
  if (engagement === undefined) throw new Error('synthetic engagement creation failed');
  const scan: ScanRecord = { id: 'scan_00000000-0000-4000-8000-000000000003', ownerId: OWNER, projectId: PROJECT,
    scanType: 'DAST', status: 'RUNNING', assessmentId: assessment.id, dastTargetUrl: TARGET,
    createdAt: NOW, updatedAt: NOW, startedAt: NOW };
  return { engagement, scan, authorize: createAssessmentDastAuthorizer(store, () => Date.parse(NOW), { requireEngagement: true }) };
}

// Some servers remove matrix parameters before resolving dot segments, e.g.
// /api/..;v=1/outside can become /outside. These are NOT real network scans.
const AMBIGUOUS = ['/api/..;v=1/outside', '/api/..%3Bv=1/outside', '/api/.;v=1/item'];

describe('production DAST boundary: matrix-parameter dot segments', () => {
  test.each(AMBIGUOUS)('rejects ambiguous configured targets before normalization: %s', (path) => {
    expect(() => normalizeDastTarget(`https://fixture.example.org${path}`)).toThrow();
  });

  test.each(AMBIGUOUS)('scope gate and strict authorizer reject ambiguous path: %s', async (path) => {
    const { engagement, scan, authorize } = await scopedFixture();
    expect(engagementAllowsScan([engagement], { scanType: 'DAST', hostname: 'fixture.example.org', path, nowIso: NOW }).allowed).toBe(false);
    expect(await authorize(scan, `https://fixture.example.org${path}`)).toBe(false);
    expect(await authorize(scan, 'https://fixture.example.org/api/item;v=1')).toBe(true);
  });

  test.each(AMBIGUOUS)('passive redirect does not resolve or contact ambiguous path: %s', async (location) => {
    const { scan, authorize } = await scopedFixture();
    const calls: string[] = [];
    const resolved: string[] = [];
    const targetPolicy = createDastTargetPolicy({ resolve: async (host) => { resolved.push(host); return ['93.184.216.34']; } });
    const transport: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return target.url === TARGET
        ? { status: 302, headers: { location }, body: '', bodyTruncated: false, elapsedMs: 1 }
        : { status: 200, headers: {}, body: '', bodyTruncated: false, elapsedMs: 1 };
    } };
    const result = await createDastEngine({ targetPolicy, transport, authorize }).execute(scan, { signal: new AbortController().signal });
    expect(result.kind).toBe('completed');
    expect(calls).toEqual([TARGET]);
    expect(resolved.every((host) => host === 'fixture.example.org')).toBe(true);
    if (result.kind === 'completed') expect(result.dast?.partial).toBe(true);
  });

  test.each(AMBIGUOUS)('active crawl never probes an ambiguous path: %s', async (path) => {
    const { scan, authorize } = await scopedFixture();
    const calls: string[] = [];
    const targetPolicy = createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
    const transport: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return { status: 200, headers: {}, body: target.url === TARGET ? `<a href="${path}">synthetic</a>` : '', bodyTruncated: false, elapsedMs: 1 };
    } };
    await createActiveDastEngine({ targetPolicy, transport, authorize, throttleMs: 0 }).execute(
      { ...scan, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal: new AbortController().signal });
    expect(calls[0]).toBe(TARGET);
    expect(calls).not.toContain(`https://fixture.example.org${path}`);
  });
});

describe('strict target configuration is offline until authorization', () => {
  test('owner can configure syntax without DNS; DNS safety is enforced after engagement and before quota', async () => {
    const resolved: string[] = [];
    let answer = '127.0.0.1';
    const server = await startTestServer({ dastRequireEngagement: true,
      dastTargetPolicy: createDastTargetPolicy({ resolve: async (host) => { resolved.push(host); return [answer]; } }) });
    servers.push(server);
    const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'boundary-fixture@example.test', password: 'boundary fixture password', userType: 'SECURITY_PROFESSIONAL' }) });
    expect(registered.status).toBe(201);
    const session = sessionCookieFrom(registered);
    const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
    const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
    expect(device).toBeDefined();
    const cookie = `${session}; ${device!.split(';')[0]}`;
    const headers = { 'content-type': 'application/json', cookie };
    const createdProject = await fetch(`${server.baseUrl}/api/v1/projects`, { method: 'POST', headers, body: JSON.stringify({ name: 'Synthetic boundary' }) });
    const projectId = ((await readJson(createdProject)) as { data: { project: { id: string } } }).data.project.id;
    const targetRoute = `${server.baseUrl}/api/v1/projects/${projectId}/dast-target`;
    const put = (targetUrl: string) => fetch(targetRoute, { method: 'PUT', headers, body: JSON.stringify({ targetUrl }) });
    for (const unsafe of ['http://127.0.0.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fc00::1]/']) {
      expect((await put(unsafe)).status).toBe(422);
    }
    expect((await put(TARGET)).status).toBe(200); // DNS is deliberately unavailable/unsafe until scan preflight.
    expect(resolved).toEqual([]);
    const scans = `${server.baseUrl}/api/v1/projects/${projectId}/scans`;
    const request = (value: Record<string, unknown>) => fetch(scans, { method: 'POST', headers, body: JSON.stringify(value) });
    expect((await request({ scanType: 'DAST' })).status).toBe(409);
    expect(resolved).toEqual([]);
    const createdAssessment = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments`, {
      method: 'POST', headers, body: JSON.stringify({ title: 'Synthetic review', objectives: ['Review fixture'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] } }) });
    const assessmentId = ((await readJson(createdAssessment)) as { data: { assessment: { id: string } } }).data.assessment.id;
    const assessmentRoute = `${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}`;
    expect((await fetch(`${assessmentRoute}/status`, { method: 'POST', headers, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(200);
    expect((await fetch(`${assessmentRoute}/engagements`, { method: 'POST', headers, body: JSON.stringify({
      clientName: 'Fixture', targetUrl: TARGET, inScopeHosts: ['fixture.example.org'], scopePaths: ['/api'], allowedScanTypes: ['DAST'],
      validFrom: new Date(Date.now() - 60_000).toISOString(), validUntil: new Date(Date.now() + 86_400_000).toISOString(),
      statement: 'Authorized synthetic fixture with a fake resolver and transport.', confirm: true,
    }) })).status).toBe(200);
    expect((await request({ scanType: 'DAST', assessmentId })).status).toBe(409); // private DNS answer
    expect(resolved).toEqual(['fixture.example.org']);
    const usage = (await readJson(await fetch(`${server.baseUrl}/api/v1/usage`, { headers }))) as { data: { used: number } };
    expect(usage.data.used).toBe(0);
    answer = '93.184.216.34';
    expect((await request({ scanType: 'DAST', assessmentId })).status).toBe(201);
  });
});
