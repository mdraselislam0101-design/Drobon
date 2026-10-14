import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, register } from './authFixtures.js';

const LOGIN_FIXTURE = 'admin-synthetic-login-1';
const PLATFORM_ID = 'usr_platform_ops';
const MEMBER_ID = 'usr_allowlisted_member';
const PROJECT_ID = 'prj_11111111-1111-4111-8111-111111111111';
const servers: TestServer[] = [];

afterEach(async () => { while (servers.length > 0) await servers.pop()?.stop(); });

async function seed(server: TestServer, id: string, role: UserRecord['role'], email = `${id}@example.test`): Promise<void> {
  const record: UserRecord = {
    id, email, passwordHash: await hashPassword(LOGIN_FIXTURE, 1024), createdAt: '2026-09-01T00:00:00.000Z',
    role, userType: null, subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
  };
  if (!(await server.users.create(record))) throw new Error('Synthetic account collision.');
}

async function cookie(server: TestServer, email: string): Promise<string> {
  return sessionCookieFrom((await login(server, email, LOGIN_FIXTURE)).res);
}

async function data<T>(response: Response): Promise<T> {
  const body = await response.json() as { data: T };
  return body.data;
}

describe('Pump 16 platform operations routes', () => {
  test('requires authentication, allowlisted account id, and live ADMIN role', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID, MEMBER_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, MEMBER_ID, 'MEMBER');
    await seed(server, 'usr_unlisted_admin', 'ADMIN');
    const platformCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const memberCookie = await cookie(server, `${MEMBER_ID}@example.test`);
    const ordinaryAdminCookie = await cookie(server, 'usr_unlisted_admin@example.test');
    const url = `${server.baseUrl}/api/v1/admin/dashboard`;
    expect((await fetch(url)).status).toBe(401);
    expect((await fetch(url, { headers: { cookie: memberCookie } })).status).toBe(403);
    expect((await fetch(url, { headers: { cookie: ordinaryAdminCookie } })).status).toBe(403);
    expect((await fetch(url, { headers: { cookie: platformCookie } })).status).toBe(200);
  });

  test('platform authorization observes the live account role on every request', async () => {
    const base = createMemoryUserRepository();
    let liveRole: UserRecord['role'] = 'ADMIN';
    const liveRecord = async (record: UserRecord | undefined): Promise<UserRecord | undefined> =>
      record === undefined || record.id !== PLATFORM_ID ? record : { ...record, role: liveRole };
    const users: UserRepository = {
      create: base.create,
      findByEmail: async (email) => liveRecord(await base.findByEmail(email)),
      findById: async (id) => liveRecord(await base.findById(id)),
      activatePro: base.activatePro,
      setUserType: base.setUserType,
      adminPage: base.adminPage,
      adminCounts: base.adminCounts,
    };
    const server = await startTestServer({ users, platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const headers = { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) };
    const url = `${server.baseUrl}/api/v1/admin/dashboard`;
    expect((await fetch(url, { headers })).status).toBe(200);
    liveRole = 'MEMBER';
    expect((await fetch(url, { headers })).status).toBe(403);
    liveRole = 'ADMIN';
    expect((await fetch(url, { headers })).status).toBe(200);
  });

  test('dedicated admin rate limit caps operational reads', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID], adminRateLimitMaxRequests: 1, adminRateLimitWindowMs: 60_000 });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const headers = { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) };
    expect((await fetch(`${server.baseUrl}/api/v1/admin/dashboard`, { headers })).status).toBe(200);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/accounts`, { headers })).status).toBe(429);
  });

  test('dashboard reports truthful store and integration states, with persisted counts', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, 'usr_synthetic_member', 'MEMBER', 'synthetic-member@example.test');
    const response = await fetch(`${server.baseUrl}/api/v1/admin/dashboard`, { headers: { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) } });
    expect(response.status).toBe(200);
    const dashboard = await data<Record<string, unknown>>(response);
    expect(dashboard['accounts']).toMatchObject({ state: 'AVAILABLE', total: 2, free: 2 });
    expect(dashboard['system']).toMatchObject({
      api: 'SERVING', web: 'NOT_ASSESSED', separateWorker: 'NOT_INTEGRATED', aiProvider: 'NONE',
      paymentGateway: 'UNAVAILABLE', vulnerabilityDataset: 'NO_DATA_LOADED', securityDataset: 'SEPARATE_NOT_LOADED',
    });
    expect((await fetch(`${server.baseUrl}/api/v1/admin/dashboard?unexpected=1`, { headers: { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) } })).status).toBe(422);
  });

  test('dashboard marks a failed aggregate UNAVAILABLE instead of inventing zero counts', async () => {
    const base = createMemoryUserRepository();
    const users: UserRepository = { ...base, adminCounts: async () => { throw new Error('synthetic unavailable account data'); } };
    const server = await startTestServer({ users, platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const response = await fetch(`${server.baseUrl}/api/v1/admin/dashboard`, { headers: { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) } });
    expect(response.status).toBe(200);
    const dashboard = await data<{ accounts: unknown; projects: unknown }>(response);
    expect(dashboard.accounts).toEqual({ state: 'UNAVAILABLE' });
    expect(dashboard.projects).toMatchObject({ state: 'AVAILABLE', total: 0 });
  });

  test('account pages are validated and redact password hashes; account mutations are not exposed', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, 'usr_synthetic_account', 'MEMBER', 'needle@example.test');
    const headers = { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) };
    const response = await fetch(`${server.baseUrl}/api/v1/admin/accounts?search=needle&page=1&pageSize=1`, { headers });
    expect(response.status).toBe(200);
    const raw = await response.text();
    expect(raw).toContain('needle@example.test');
    expect(raw).not.toContain('passwordHash');
    expect(raw).not.toContain('scrypt$');
    expect(raw).toContain('UNAVAILABLE');
    expect((await fetch(`${server.baseUrl}/api/v1/admin/accounts?page=1001`, { headers })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/accounts?search=x&search=y`, { headers })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/accounts/${PLATFORM_ID}`, { method: 'DELETE', headers })).status).toBe(404);
  });

  test('reviewer projections mask opaque reference strings that resemble credentials', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID], paymentReviewerIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const payer = await register(server, 'reference-owner@example.test', LOGIN_FIXTURE);
    const rawReference = `SYNTHETIC-${'a'.repeat(42)}`;
    const submitted = await fetch(`${server.baseUrl}/api/v1/payments`, {
      method: 'POST', headers: { cookie: sessionCookieFrom(payer.res), 'content-type': 'application/json', 'idempotency-key': 'admin-ref-idem-01' },
      body: JSON.stringify({ plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: rawReference }),
    });
    expect(submitted.status).toBe(201);
    const response = await fetch(`${server.baseUrl}/api/v1/admin/payments?page=1&pageSize=1`, { headers: { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) } });
    expect(response.status).toBe(200);
    const raw = await response.text();
    const envelope = JSON.parse(raw) as { data: { payments: Array<{ reference: string }> } };
    expect(envelope.data.payments[0]?.reference).toBe('REDACTED');
    expect(raw).not.toContain(rawReference);
  });

  test('scan and finding lists are paginated, filterable, and omit private source/evidence/hash data', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const created = await server.scans.createScanWithQuota({
      ownerId: PLATFORM_ID, projectId: PROJECT_ID, scanType: 'SAST', consume: async () => ({ ok: true }),
    });
    expect(created.outcome).toBe('created');
    if (created.outcome !== 'created') throw new Error('Synthetic scan was not created.');
    const running = await server.scans.claimNextQueued();
    expect(running?.id).toBe(created.scan.id);
    const fingerprint = 'a'.repeat(64);
    const finding = {
      id: `fnd_${fingerprint.slice(0, 24)}`, scanId: created.scan.id, ruleId: 'DG-SAST-001', scanner: 'SAST' as const,
      severity: 'HIGH' as const, title: 'Synthetic finding', description: 'synthetic-private-description',
      evidence: 'synthetic-private-evidence', remediation: 'synthetic-private-remediation', fingerprint,
      file: 'src/private-synthetic.ts', line: 12, column: 4, projectId: PROJECT_ID,
    };
    const completed = await server.scans.completeScan(created.scan.id, {
      findingsTotal: 1, findingsBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
    }, [finding]);
    expect(completed?.status).toBe('COMPLETED');
    const headers = { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) };

    const scanResponse = await fetch(`${server.baseUrl}/api/v1/admin/scans?page=1&pageSize=1&status=COMPLETED&type=SAST`, { headers });
    expect(scanResponse.status).toBe(200);
    const scanText = await scanResponse.text();
    expect(scanText).toContain(created.scan.id);
    expect(scanText).not.toContain('private-synthetic.ts');
    expect(scanText).not.toContain(fingerprint);

    const findingResponse = await fetch(`${server.baseUrl}/api/v1/admin/findings?severity=HIGH&scanner=SAST`, { headers });
    expect(findingResponse.status).toBe(200);
    const findingText = await findingResponse.text();
    expect(findingText).toContain('DG-SAST-001');
    expect(findingText).toContain('"findingNumber":1');
    expect(findingText).not.toContain('fnd_');
    expect(findingText).not.toContain('synthetic-private');
    expect(findingText).not.toContain('private-synthetic.ts');
    expect(findingText).not.toContain(fingerprint);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/findings?severity=URGENT`, { headers })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/scans?page=0`, { headers })).status).toBe(422);
  });

  test('admin payment audit pagination returns distinct bounded pages with explicit partial coverage', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID], proPriceMinorUnits: 100_000 });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const member = await register(server, 'synthetic-payer@example.test', LOGIN_FIXTURE);
    const memberCookie = sessionCookieFrom(member.res);
    const submit = async (key: string, reference: string): Promise<void> => {
      const response = await fetch(`${server.baseUrl}/api/v1/payments`, {
        method: 'POST', headers: { cookie: memberCookie, 'content-type': 'application/json', 'idempotency-key': key },
        body: JSON.stringify({ plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference }),
      });
      expect(response.status).toBe(201);
    };
    await submit('synthetic-idem-01', 'SYNTHETIC-TXN-01');
    const another = await register(server, 'synthetic-payer-two@example.test', LOGIN_FIXTURE);
    const anotherCookie = sessionCookieFrom(another.res);
    const second = await fetch(`${server.baseUrl}/api/v1/payments`, {
      method: 'POST', headers: { cookie: anotherCookie, 'content-type': 'application/json', 'idempotency-key': 'synthetic-idem-02' },
      body: JSON.stringify({ plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'SYNTHETIC-TXN-02' }),
    });
    expect(second.status).toBe(201);
    const headers = { cookie: await cookie(server, `${PLATFORM_ID}@example.test`) };
    const firstPageResponse = await fetch(`${server.baseUrl}/api/v1/admin/audit?page=1&pageSize=1`, { headers });
    const secondPageResponse = await fetch(`${server.baseUrl}/api/v1/admin/audit?page=2&pageSize=1`, { headers });
    const firstPage = await data<{ events: Array<{ eventId: string }>; coverage: string; total: number }>(firstPageResponse);
    const secondPage = await data<{ events: Array<{ eventId: string }>; coverage: string; total: number }>(secondPageResponse);
    expect(firstPage.coverage).toBe('PAYMENT_EVENTS_ONLY');
    expect(firstPage.total).toBe(4);
    expect(firstPage.events[0]?.eventId).not.toBe(secondPage.events[0]?.eventId);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/audit?from=2026-04-01&to=2025-01-01`, { headers })).status).toBe(422);
  });
});
