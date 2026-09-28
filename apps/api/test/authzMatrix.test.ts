import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { readJson, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 3 authorization matrix — the six required capability proofs run
 * over REAL HTTP against the real pipeline:
 *
 *  1. MEMBER      can access the MEMBER capability
 *  2. ADMIN       can access the MEMBER capability
 *  3. ACCOUNT_OWNER can access the MEMBER capability
 *  4. MEMBER      cannot access the ADMIN capability        (403)
 *  5. ADMIN       cannot access the ACCOUNT_OWNER capability (403)
 *  6. ACCOUNT_OWNER can access the ACCOUNT_OWNER capability
 *
 * Plus: 401 vs 403 semantics, UserType-never-bypasses, mass-assignment of
 * roles, and the production gating of the probes themselves.
 */

const PW = 'matrix-probe-pw-test';

async function seedUser(
  repo: UserRepository,
  email: string,
  role: UserRecord['role'],
  userType: UserRecord['userType'] = null,
): Promise<UserRecord> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-27T00:00:00.000Z',
    role,
    userType,
  };
  const created = await repo.create(record);
  if (!created) {
    throw new Error(`Seed collision for ${email}`);
  }
  return record;
}

async function cookieFor(server: TestServer, email: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 200) {
    throw new Error(`Login failed with status ${res.status}.`);
  }
  const raw = res.headers.getSetCookie().find((c) => c.startsWith('drobon_session='));
  if (raw === undefined) {
    throw new Error('No session cookie issued.');
  }
  return raw.split(';')[0] ?? '';
}

function probe(server: TestServer, level: string, cookie?: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/authz/capabilities/${level}`, {
    ...(cookie === undefined ? {} : { headers: { cookie } }),
  });
}

const servers: TestServer[] = [];
afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop();
    if (server !== undefined) {
      await server.stop();
    }
  }
});

describe('authorization capability matrix', () => {
  async function matrixServer(): Promise<TestServer> {
    const users = createMemoryUserRepository();
    await seedUser(users, 'member@example.test', 'MEMBER', 'SECURITY_PROFESSIONAL');
    await seedUser(users, 'admin@example.test', 'ADMIN');
    await seedUser(users, 'owner@example.test', 'ACCOUNT_OWNER', 'DEVELOPER');
    const server = await startTestServer({ users });
    servers.push(server);
    return server;
  }

  test('proofs 1–6: role × capability over real HTTP', async () => {
    const server = await matrixServer();
    const member = await cookieFor(server, 'member@example.test');
    const admin = await cookieFor(server, 'admin@example.test');
    const owner = await cookieFor(server, 'owner@example.test');

    // 1–3: MEMBER capability accepts every authenticated role.
    for (const cookie of [member, admin, owner]) {
      const res = await probe(server, 'member', cookie);
      expect(res.status).toBe(200);
      const body = await readJson(res);
      expect(body).toEqual({
        ok: true,
        data: { capability: 'member' },
        meta: { requestId: expect.any(String) },
      });
    }

    // 4: MEMBER cannot reach the ADMIN capability.
    const memberOnAdmin = await probe(server, 'admin', member);
    expect(memberOnAdmin.status).toBe(403);

    // ADMIN and ACCOUNT_OWNER can (2nd and 3rd roles clear ADMIN level).
    expect((await probe(server, 'admin', admin)).status).toBe(200);
    expect((await probe(server, 'admin', owner)).status).toBe(200);

    // 5: ADMIN cannot reach the ACCOUNT_OWNER capability.
    const adminOnOwner = await probe(server, 'owner', admin);
    expect(adminOnOwner.status).toBe(403);

    // 6: ACCOUNT_OWNER can.
    expect((await probe(server, 'owner', owner)).status).toBe(200);
  });

  test('401 means unauthenticated, 403 means authenticated-but-denied', async () => {
    const server = await matrixServer();
    const member = await cookieFor(server, 'member@example.test');

    const anonymous = await probe(server, 'admin');
    expect(anonymous.status).toBe(401);
    const anonBody = await readJson(anonymous);
    expect(anonBody).toEqual({
      ok: false,
      error: { code: 'UNAUTHORIZED', message: 'Authentication required.' },
      meta: { requestId: expect.any(String) },
    });

    const denied = await probe(server, 'admin', member);
    expect(denied.status).toBe(403);
    const deniedBody = await readJson(denied);
    expect(deniedBody).toEqual({
      ok: false,
      error: {
        code: 'FORBIDDEN',
        message: 'You do not have access to this resource.',
      },
      meta: { requestId: expect.any(String) },
    });

    // Neither response hints at role configuration or account existence.
    const raw = `${JSON.stringify(anonBody)} ${JSON.stringify(deniedBody)}`;
    expect(raw).not.toContain('ADMIN');
    expect(raw).not.toContain('MEMBER');
    expect(raw).not.toContain('ACCOUNT_OWNER');
    expect(raw).not.toContain('role');
  });

  test('UserType never grants access (classification ≠ authorization)', async () => {
    const server = await matrixServer();
    // member carries SECURITY_PROFESSIONAL; owner carries DEVELOPER.
    const member = await cookieFor(server, 'member@example.test');
    const owner = await cookieFor(server, 'owner@example.test');
    expect((await probe(server, 'admin', member)).status).toBe(403);
    expect((await probe(server, 'owner', member)).status).toBe(403);
    // …and a "basic" user type does not diminish a real role either.
    expect((await probe(server, 'owner', owner)).status).toBe(200);
  });

  test('sessions never carry role state — authorization reads the live record', async () => {
    // A repository double through the real interface (the injected seam):
    // it can mutate a stored record's role exactly as an operator/future
    // admin console would.
    const byId = new Map<string, UserRecord>();
    const byEmail = new Map<string, UserRecord>();
    const users: UserRepository & { elevate: (id: string) => void } = {
      create: async (record) => {
        if (byEmail.has(record.email)) {
          return false;
        }
        byId.set(record.id, record);
        byEmail.set(record.email, record);
        return true;
      },
      findByEmail: async (email) => byEmail.get(email),
      findById: async (id) => byId.get(id),
      activatePro: async () => 'NOT_FOUND',
      adminPage: async () => ({ accounts: [], total: 0 }),
      adminCounts: async () => ({ total: 0, byPlan: { FREE: 0, PRO: 0 }, bySubscriptionStatus: { ACTIVE: 0, INACTIVE: 0, CANCELLED: 0, EXPIRED: 0 }, byRole: { MEMBER: 0, ADMIN: 0, ACCOUNT_OWNER: 0 }, byUserType: { DEVELOPER: 0, STUDENT: 0, SECURITY_PROFESSIONAL: 0, PENTESTER: 0, NONE: 0 } }),
      elevate: (id) => {
        const current = byId.get(id);
        if (current === undefined) {
          return;
        }
        const elevated: UserRecord = { ...current, role: 'ACCOUNT_OWNER' };
        byId.set(id, elevated);
        byEmail.set(current.email, elevated);
      },
    };

    await users.create({
      id: 'usr_live-elevate',
      email: 'live@example.test',
      passwordHash: await hashPassword(PW, 1024),
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'MEMBER',
      userType: null,
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await cookieFor(server, 'live@example.test');
    expect((await probe(server, 'admin', cookie)).status).toBe(403);

    // The session stores only an opaque token → user id; role lives in
    // the account record, read on every request. Elevate the ACCOUNT and
    // the very next request observes it — no re-login, no cookie change.
    users.elevate('usr_live-elevate');
    expect((await probe(server, 'admin', cookie)).status).toBe(200);
    expect((await probe(server, 'owner', cookie)).status).toBe(200);
  });

  test('register cannot assign roles (mass-assignment rejected)', async () => {
    const server = await matrixServer();
    const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'escalate@example.test',
        password: PW,
        role: 'ACCOUNT_OWNER',
      }),
    });
    expect(res.status).toBe(422);
    const body = await readJson(res);
    expect(JSON.stringify(body)).toContain('Unexpected property');

    // userType is accepted only as a known classification value.
    const badType = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'badtype@example.test',
        password: PW,
        userType: 'ADMIN',
      }),
    });
    expect(badType.status).toBe(422);

    const ok = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'pentester@example.test',
        password: PW,
        userType: 'PENTESTER',
      }),
    });
    expect(ok.status).toBe(201);
    const created = (await readJson(ok)) as { data: { user: Record<string, unknown> } };
    expect(created.data.user.role).toBe('MEMBER'); // never elevated
    expect(created.data.user.userType).toBe('PENTESTER');
  });
});

describe('probe availability', () => {
  test('probes are absent when authzProbeRoutes is off (production posture)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'prod@example.test', 'ADMIN');
    const server = await startTestServer({ users, authzProbeRoutes: false });
    servers.push(server);
    const cookie = await cookieFor(server, 'prod@example.test');
    for (const level of ['member', 'admin', 'owner']) {
      const res = await probe(server, level, cookie);
      // Unknown path: 404 — no registration at all, role irrelevant.
      expect(res.status).toBe(404);
    }
    // The ownership foundation route stays available (not a probe).
    const usersRes = await fetch(`${server.baseUrl}/api/v1/users?id=usr_prod`, {
      headers: { cookie },
    });
    expect(usersRes.status).toBe(200);
  });
});
