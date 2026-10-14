import { afterEach, describe, expect, test } from 'vitest';
import type { UserType } from '@drobon/shared';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login } from './authFixtures.js';

/**
 * Phase 20 — UserType switching security matrix.
 *
 * UserType is a classification/visibility tag: switching it must change ONLY
 * presentation/workflow. These tests prove the mutation path cannot grant
 * PRO, reset quota, elevate roles, touch ownership or leak another account.
 */

const PW = 'usertype-fixture-password-1';
const servers: TestServer[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()?.stop();
});

async function registerWithType(server: TestServer, email: string, userType?: UserType): Promise<{ cookie: string; userType: string | null }> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW, ...(userType === undefined ? {} : { userType }) }),
  });
  expect(res.status).toBe(201);
  const body = await readJson(res) as { data: { user: { userType: string | null } } };
  return { cookie: sessionCookieFrom(res), userType: body.data.user.userType };
}

async function switchType(server: TestServer, cookie: string, body: unknown): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/me/user-type`, {
    method: 'PATCH',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function me(server: TestServer, cookie: string): Promise<{ status: number; user?: { role: string; userType: string | null } }> {
  const res = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie } });
  if (res.status !== 200) return { status: res.status };
  const body = await readJson(res) as { data: { user: { role: string; userType: string | null } } };
  return { status: 200, user: body.data.user };
}

describe('Phase 20 user-type switching contract', () => {
  test('switches between all four classifications and reflects in /me', async () => {
    const server = await startTestServer();
    servers.push(server);
    const created = await registerWithType(server, 'switcher@example.test', 'DEVELOPER');
    const cookie = created.cookie;
    expect(created.userType).toBe('DEVELOPER');

    for (const next of ['STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER', 'DEVELOPER'] as const) {
      const res = await switchType(server, cookie, { userType: next });
      expect(res.status).toBe(200);
      const body = await readJson(res) as { data: { user: { userType: string } } };
      expect(body.data.user.userType).toBe(next);
      expect((await me(server, cookie)).user?.userType).toBe(next);
    }
  });

  test('anonymous, invalid enum, malformed body, query tampering and mass assignment are rejected', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = (await registerWithType(server, 'boundaries@example.test')).cookie;

    expect((await fetch(`${server.baseUrl}/api/v1/me/user-type`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userType: 'STUDENT' }) })).status).toBe(401);
    expect((await switchType(server, cookie, { userType: 'WIZARD' })).status).toBe(422);
    expect((await switchType(server, cookie, { userType: 123 })).status).toBe(422);
    expect((await switchType(server, cookie, {})).status).toBe(422);
    expect((await switchType(server, cookie, 'STUDENT')).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/me/user-type?userType=STUDENT`, { method: 'PATCH', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ userType: 'STUDENT' }) })).status).toBe(422);
    // Mass assignment: nothing else may ride along on a classification switch.
    expect((await switchType(server, cookie, { userType: 'STUDENT', role: 'ADMIN' })).status).toBe(422);
    expect((await switchType(server, cookie, { userType: 'STUDENT', plan: 'PRO' })).status).toBe(422);
    expect((await switchType(server, cookie, { userType: 'STUDENT', subscription: { plan: 'PRO' } })).status).toBe(422);
    // Rejected attempts changed nothing.
    expect((await me(server, cookie)).user?.userType).toBeNull();
    expect((await me(server, cookie)).user?.role).toBe('MEMBER');
  });

  test('CSRF origin guard covers the switch endpoint', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = (await registerWithType(server, 'csrf-switch@example.test')).cookie;
    const res = await fetch(`${server.baseUrl}/api/v1/me/user-type`, {
      method: 'PATCH',
      headers: { cookie, 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ userType: 'STUDENT' }),
    });
    expect(res.status).toBe(403);
    expect((await me(server, cookie)).user?.userType).toBeNull();
  });

  test('switching never grants PRO, resets usage or elevates role', async () => {
    const server = await startTestServer({ platformAdminIds: [] });
    servers.push(server);
    // FREE member; run one scan-related usage observation through the public usage endpoint.
    const cookie = (await registerWithType(server, 'nofreeslunch@example.test', 'DEVELOPER')).cookie;

    const usageBefore = await readJson(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } })) as { data: unknown };
    const subscriptionBefore = await readJson(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie } })) as { data: unknown };

    expect((await switchType(server, cookie, { userType: 'PENTESTER' })).status).toBe(200);
    expect((await switchType(server, cookie, { userType: 'SECURITY_PROFESSIONAL' })).status).toBe(200);

    const usageAfter = await readJson(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } })) as { data: { used: number; limit: number | null; quotaStatus: string } };
    const subscriptionAfter = await readJson(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie } })) as { data: { subscription: { plan: string } } };
    expect(usageAfter.data.quotaStatus).toBe((usageBefore.data as { quotaStatus: string }).quotaStatus);
    expect(usageAfter.data.used).toBe((usageBefore.data as { used: number }).used);
    expect(subscriptionAfter.data.subscription.plan).toBe((subscriptionBefore.data as { subscription: { plan: string } }).subscription.plan);
    expect(subscriptionAfter.data.subscription.plan).toBe('FREE');
    // Role + capability probe unchanged: still MEMBER, admin capability denied.
    expect((await me(server, cookie)).user?.role).toBe('MEMBER');
    expect((await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, { headers: { cookie } })).status).toBe(403);
  });

  test('switching never strips an existing PRO entitlement', async () => {
    const server = await startTestServer();
    servers.push(server);
    const record: UserRecord = {
      id: 'usr_pro_switcher', email: 'pro-switcher@example.test',
      passwordHash: await hashPassword(PW, 1024), createdAt: '2026-09-01T00:00:00.000Z',
      role: 'MEMBER', userType: 'DEVELOPER',
      subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
    };
    expect(await server.users.create(record)).toBe(true);
    const cookie = sessionCookieFrom((await login(server, 'pro-switcher@example.test', PW)).res);

    for (const next of ['STUDENT', 'PENTESTER'] as const) {
      expect((await switchType(server, cookie, { userType: next })).status).toBe(200);
      const subscription = await readJson(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie } })) as { data: { subscription: { plan: string; status: string }; entitlements: string[] } };
      expect(subscription.data.subscription).toMatchObject({ plan: 'PRO', status: 'ACTIVE' });
      expect(subscription.data.entitlements).toContain('feature:pro');
    }
  });

  test('switching does not change project ownership or expose other accounts', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookieA = (await registerWithType(server, 'owner-a@example.test', 'DEVELOPER')).cookie;
    const projectRes = await fetch(`${server.baseUrl}/api/v1/projects`, {
      method: 'POST', headers: { cookie: cookieA, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Owned before switch' }),
    });
    expect(projectRes.status).toBe(201);
    const project = (await readJson(projectRes) as { data: { project: { id: string } } }).data.project;

    const cookieOther = (await registerWithType(server, 'intruder@example.test', 'STUDENT')).cookie;

    expect((await switchType(server, cookieA, { userType: 'STUDENT' })).status).toBe(200);
    // Ownership unchanged: original owner still reads the project.
    expect((await fetch(`${server.baseUrl}/api/v1/projects/${project.id}`, { headers: { cookie: cookieA } })).status).toBe(200);
    // The other account still cannot see it after the switch (uniform 403).
    expect((await fetch(`${server.baseUrl}/api/v1/projects/${project.id}`, { headers: { cookie: cookieOther } })).status).toBe(403);
    // Cross-account switch attempt is impossible: the endpoint is strictly self-scoped.
    expect((await switchType(server, cookieOther, { userType: 'PENTESTER' })).status).toBe(200);
    expect((await me(server, cookieA)).user?.userType).toBe('STUDENT');
  });
});
