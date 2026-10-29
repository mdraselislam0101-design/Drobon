import { afterEach, describe, expect, test } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  engagementAllowsScan,
  engagementStatus,
  isAssessment,
  isAssessmentEngagement,
  isEngagementResponse,
  isEngagementsResponse,
  type Assessment,
  type AssessmentEngagement,
  type ScanType,
} from '@drobon/shared';
import { createJsonFileAssessmentStore, createMemoryAssessmentStore } from '../src/assessments/store.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 17 — third-party ENGAGEMENT / AUTHORIZATION RECORD.
 * Additive on the existing assessment store: no new durable store, no
 * database, no independent "verification" claim. Proves append-only
 * declare/withdraw, exact host + scan-type + validity gating and honest
 * UNVERIFIED behaviour when no engagement exists.
 */

const PASSWORD = 'pump seventeen engagement fixture'; // fake test fixture
const NOW = '2026-10-26T10:00:00.000Z';
const SERVERS: TestServer[] = [];
const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

interface Cookies { session: string; device: string }
const cookieHeader = (cookies: Cookies): string => `${cookies.session}; drobon_device=${cookies.device}`;

function engagement(overrides: Partial<AssessmentEngagement> = {}): AssessmentEngagement {
  return {
    id: 'eng_00000000-0000-4000-8000-000000000001',
    clientName: 'Acme Corp',
    targetUrl: 'https://fixture.example.org/',
    inScopeHosts: ['fixture.example.org'],
    scopePaths: ['/api/'],
    allowedScanTypes: ['SAST'],
    validFrom: '2026-10-01T00:00:00.000Z',
    validUntil: '2026-12-01T00:00:00.000Z',
    statement: 'Written owner-attested authorization for this engagement window.',
    declaredBy: 'usr_00000000-0000-4000-8000-000000000001',
    declaredAt: '2026-10-01T00:00:00.000Z',
    state: 'DECLARED',
    ...overrides,
  };
}

describe('engagement contract (pure, deterministic)', () => {
  test('valid records pass; malformed / over-long / traversal records fail', () => {
    expect(isAssessmentEngagement(engagement())).toBe(true);
    expect(isAssessmentEngagement(engagement({ validUntil: '2026-09-01T00:00:00.000Z' }))).toBe(false);
    expect(isAssessmentEngagement(engagement({ scopePaths: ['/../../etc'] }))).toBe(false);
    expect(isAssessmentEngagement(engagement({ allowedScanTypes: [] }))).toBe(false);
    expect(isAssessmentEngagement(engagement({ inScopeHosts: ['*.example.org'] }))).toBe(false);
    expect(isAssessmentEngagement(engagement({ state: 'WITHDRAWN' }))).toBe(false); // needs withdrawnAt
    expect(isAssessmentEngagement(engagement({ state: 'WITHDRAWN', withdrawnAt: NOW }))).toBe(true);
  });

  test('status is time-derived and never guesses', () => {
    expect(engagementStatus(engagement(), NOW)).toBe('ACTIVE');
    expect(engagementStatus(engagement(), '2026-01-01T00:00:00.000Z')).toBe('NOT_YET_VALID');
    expect(engagementStatus(engagement(), '2027-01-01T00:00:00.000Z')).toBe('EXPIRED');
    expect(engagementStatus(engagement({ state: 'WITHDRAWN', withdrawnAt: NOW }), NOW)).toBe('WITHDRAWN');
  });

  test('gate keeps legacy UNVERIFIED path with no engagement, then enforces scope', () => {
    expect(engagementAllowsScan(undefined, { scanType: 'SAST', nowIso: NOW })).toEqual({ allowed: true });
    expect(engagementAllowsScan([], { scanType: 'DAST', nowIso: NOW })).toEqual({ allowed: true });
    const records = [engagement()];
    expect(engagementAllowsScan(records, { scanType: 'SAST', nowIso: NOW }).allowed).toBe(true);
    expect(engagementAllowsScan(records, { scanType: 'DAST', nowIso: NOW }).allowed).toBe(false);
    expect(engagementAllowsScan(records, { scanType: 'SAST', nowIso: '2027-01-01T00:00:00.000Z' }).allowed).toBe(false);
    expect(engagementAllowsScan(records, {
      scanType: 'SAST', hostname: 'fixture.example.org', path: '/admin', nowIso: NOW,
    }).allowed).toBe(false);
    expect(engagementAllowsScan(records, {
      scanType: 'SAST', hostname: 'other.example.org', path: '/api/x', nowIso: NOW,
    }).allowed).toBe(false);
    expect(engagementAllowsScan(records, {
      scanType: 'SAST', hostname: 'fixture.example.org', path: '/api/x', nowIso: NOW,
    })).toMatchObject({ allowed: true, engagementId: engagement().id });
    expect(engagementAllowsScan([engagement({ scopePaths: ['/api'] })], {
      scanType: 'SAST', hostname: 'fixture.example.org', path: '/api2', nowIso: NOW,
    }).allowed).toBe(false);
    expect(engagementAllowsScan(records, { scanType: 'SAST', nowIso: 'not-a-time' }).allowed).toBe(false);
    expect(engagementAllowsScan([engagement({ scopePaths: ['/api'] })], {
      scanType: 'SAST', hostname: 'fixture.example.org', path: '/api/%2e%2e%2fadmin', nowIso: NOW,
    }).allowed).toBe(false);
  });

  test('assessment guard accepts legacy records and validates engagements', () => {
    const base: Assessment = {
      id: 'asm_00000000-0000-4000-8000-000000000001',
      projectId: 'prj_00000000-0000-4000-8000-000000000001',
      title: 'Fixture', objectives: ['Review'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] },
      status: 'ACTIVE', createdAt: NOW, updatedAt: NOW, startedAt: NOW,
      authorizationDeclarations: [],
      history: [{ id: 'ase_00000000-0000-4000-8000-000000000001', type: 'CREATED', at: NOW }],
    };
    expect(isAssessment(base)).toBe(true);
    expect(isAssessment({ ...base, engagements: [engagement()] })).toBe(true);
    expect(isAssessment({ ...base, engagements: [{ ...engagement(), id: 'bad' }] })).toBe(false);
    expect(isEngagementsResponse({ engagements: [{ ...engagement(), status: 'ACTIVE' }] })).toBe(true);
    expect(isEngagementResponse({ engagement: { ...engagement(), status: 'ACTIVE' } })).toBe(true);
  });
});

describe('assessment store: append-only engagement history', () => {
  test('declare → withdraw → persist across restart, with no edits/deletes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-engagement-store-'));
    dirs.push(dir);
    const path = join(dir, 'assessments.json');
    const store = createJsonFileAssessmentStore(path);
    const created = await store.create({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', title: 'Fixture engagement',
      objectives: ['Review third-party target'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] }, now: NOW,
    });
    if ('outcome' in created) throw new Error('assessment creation failed');
    const declared = await store.recordEngagement({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', assessmentId: created.id, now: NOW, action: 'DECLARE',
      engagement: {
        clientName: 'Acme Corp', targetUrl: 'https://fixture.example.org/',
        inScopeHosts: ['fixture.example.org'], scopePaths: [], allowedScanTypes: ['SAST', 'DAST'],
        validFrom: '2026-10-01T00:00:00.000Z', validUntil: '2026-12-01T00:00:00.000Z',
        statement: 'Written owner-attested authorization for this engagement window.',
      },
    });
    expect(declared.outcome).toBe('updated');
    expect(declared.assessment?.engagements).toHaveLength(1);
    const id = declared.assessment?.engagements?.[0]?.id;
    expect(id).toBeDefined();
    if (id === undefined) return;

    const reloaded = createJsonFileAssessmentStore(path);
    const before = await reloaded.findByProjectAndId('usr_00000000-0000-4000-8000-000000000001', 'prj_00000000-0000-4000-8000-000000000002', created.id);
    expect(before?.engagements).toHaveLength(1);
    expect(before?.engagements?.[0]?.state).toBe('DECLARED');

    const withdrawn = await reloaded.recordEngagement({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', assessmentId: created.id,
      now: '2026-10-27T10:00:00.000Z', action: 'WITHDRAW', engagementId: id,
    });
    expect(withdrawn.outcome).toBe('updated');
    expect(withdrawn.assessment?.engagements?.[0]?.state).toBe('WITHDRAWN');
    expect(withdrawn.assessment?.engagements).toHaveLength(1); // append-only: no deletion
    expect(withdrawn.assessment?.history.some((event) => event.type === 'AUTHORIZATION_WITHDRAWN')).toBe(true);
    const after = await createJsonFileAssessmentStore(path).findByProjectAndId('usr_00000000-0000-4000-8000-000000000001', 'prj_00000000-0000-4000-8000-000000000002', created.id);
    expect(after?.engagements?.[0]?.state).toBe('WITHDRAWN');
  });

  test('invalid drafts and foreign owners are refused', async () => {
    const store = createMemoryAssessmentStore();
    const created = await store.create({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', title: 'Fixture engagement',
      objectives: ['Review third-party target'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] }, now: NOW,
    });
    if ('outcome' in created) throw new Error('assessment creation failed');
    const base = {
      clientName: 'Acme Corp', targetUrl: 'https://fixture.example.org/',
      inScopeHosts: ['fixture.example.org'], scopePaths: [], allowedScanTypes: ['SAST'] as ScanType[],
      validFrom: '2026-10-01T00:00:00.000Z', validUntil: '2026-12-01T00:00:00.000Z',
      statement: 'Written owner-attested authorization for this engagement window.',
    };
    expect((await store.recordEngagement({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', assessmentId: created.id, now: NOW,
      action: 'DECLARE', engagement: { ...base, validUntil: '2026-09-01T00:00:00.000Z' },
    })).outcome).toBe('invalid');
    expect((await store.recordEngagement({
      ownerId: 'usr_00000000-0000-4000-8000-000000000009', projectId: 'prj_00000000-0000-4000-8000-000000000002', assessmentId: created.id, now: NOW,
      action: 'DECLARE', engagement: base,
    })).outcome).toBe('not-found');
    expect((await store.recordEngagement({
      ownerId: 'usr_00000000-0000-4000-8000-000000000001', projectId: 'prj_00000000-0000-4000-8000-000000000002', assessmentId: created.id, now: NOW,
      action: 'WITHDRAW', engagementId: 'eng_00000000-0000-4000-8000-000000000009',
    })).outcome).toBe('not-declared');
  });
});

describe('engagement HTTP API + scan authorization gate', () => {
  async function setup(): Promise<{ server: TestServer; cookies: Cookies; projectId: string; assessmentId: string }> {
    const server = await startTestServer();
    SERVERS.push(server);
    const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: `eng-${Date.now()}@example.test`, password: PASSWORD, userType: 'SECURITY_PROFESSIONAL' }),
    });
    expect(registered.status).toBe(201);
    const session = sessionCookieFrom(registered);
    const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
    const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
    expect(device).toBeDefined();
    const cookies: Cookies = { session, device: device!.split(';')[0]!.slice('drobon_device='.length) };
    const project = await fetch(`${server.baseUrl}/api/v1/projects`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ name: 'Engagement project' }),
    });
    expect(project.status).toBe(201);
    const projectId = ((await readJson(project)) as { data: { project: { id: string } } }).data.project.id;
    const target = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ targetUrl: 'https://fixture.example.org/' }),
    });
    expect(target.status).toBe(200);
    const created = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({
        title: 'Third-party engagement', objectives: ['Assess the configured target'],
        scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] },
      }),
    });
    expect(created.status).toBe(201);
    const assessmentId = ((await readJson(created)) as { data: { assessment: { id: string } } }).data.assessment.id;
    const active = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ status: 'ACTIVE' }),
    });
    expect(active.status).toBe(200);
    return { server, cookies, projectId, assessmentId };
  }

  function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      clientName: 'Acme Corp', targetUrl: 'https://fixture.example.org/',
      inScopeHosts: ['fixture.example.org'], scopePaths: ['/api/'], allowedScanTypes: ['SAST'],
      validFrom: new Date(Date.now() - 3_600_000).toISOString(),
      validUntil: new Date(Date.now() + 30 * 86_400_000).toISOString(),
      statement: 'Written owner-attested authorization for this engagement window.',
      confirm: true,
      ...overrides,
    };
  }

  test('declare, list, gate by scan type, withdraw and then block — all before quota', async () => {
    const { server, cookies, projectId, assessmentId } = await setup();
    const route = `${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}/engagements`;
    const headers = { 'content-type': 'application/json', cookie: cookieHeader(cookies) };

    expect((await fetch(route)).status).toBe(401);
    const empty = (await readJson(await fetch(route, { headers }))) as { data: unknown };
    expect(isEngagementsResponse(empty.data)).toBe(true);
    expect((empty.data as { engagements: unknown[] }).engagements).toEqual([]);

    const invalid = await fetch(route, { method: 'POST', headers, body: JSON.stringify(body({ inScopeHosts: ['other.example.org'] })) });
    expect(invalid.status).toBe(422);
    const created = await fetch(route, { method: 'POST', headers, body: JSON.stringify(body()) });
    expect(created.status).toBe(200);
    const createdBody = (await readJson(created)) as { data: unknown };
    expect(isEngagementResponse(createdBody.data)).toBe(true);
    const engagement = (createdBody.data as { engagement: { id: string; state: string; status: string } }).engagement;
    expect(engagement.state).toBe('DECLARED');
    expect(engagement.status).toBe('ACTIVE');

    const list = (await readJson(await fetch(route, { headers }))) as { data: { engagements: unknown[] } };
    expect(list.data.engagements).toHaveLength(1);

    // No source snapshot yet: an unauthorized DAST link must be refused by
    // the engagement gate BEFORE the snapshot/quota preflight.
    const blockedType = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers, body: JSON.stringify({ scanType: 'DAST', assessmentId }),
    });
    expect(blockedType.status).toBe(409);

    const sources = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
      method: 'PUT', headers, body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'const x = 1;\n' }] }),
    });
    expect(sources.status).toBe(200);
    const allowed = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers, body: JSON.stringify({ scanType: 'SAST', assessmentId }),
    });
    expect(allowed.status).toBe(201);

    const withdrawn = await fetch(`${route}/${engagement.id}/withdraw`, {
      method: 'POST', headers, body: JSON.stringify({ confirm: true }),
    });
    expect(withdrawn.status).toBe(200);
    const withdrawnBody = (await readJson(withdrawn)) as { data: { engagement: { state: string; status: string } } };
    expect(withdrawnBody.data.engagement.state).toBe('WITHDRAWN');

    const afterWithdraw = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers, body: JSON.stringify({ scanType: 'SAST', assessmentId }),
    });
    expect(afterWithdraw.status).toBe(409);
  });
});
