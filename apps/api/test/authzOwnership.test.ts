import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { readJson, startTestServer, type TestServer } from './helpers.js';

/**
 * Ownership foundation (Pump 3): `GET /api/v1/users?id=…` proves the
 * reusable access pattern future resources (projects, scans, findings)
 * must copy:
 *
 * - self-read: every authenticated account;
 * - cross-read: ONLY the explicitly-declared `users:read:others`
 *   permission (ADMIN+ via the shared table) — hierarchy is consulted
 *   only through that declaration;
 * - unknown, malformed, oversized and manipulated ids produce the SAME
 *   uniform 403 as a merely-unauthorized id — no IDOR, no existence
 *   oracle, no ID-format side channels.
 */

const PW = 'ownership-probe-pw-1';

async function seed(repo: UserRepository, id: string, email: string, role: UserRecord['role']): Promise<void> {
  const ok = await repo.create({
    id,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-27T00:00:00.000Z',
    role,
    userType: null,
  });
  if (!ok) {
    throw new Error(`Seed collision: ${email}`);
  }
}

async function cookieFor(server: TestServer, email: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 200) {
    throw new Error(`Login failed: ${res.status}`);
  }
  const raw = res.headers.getSetCookie().find((c) => c.startsWith('drobon_session='));
  return raw === undefined ? '' : (raw.split(';')[0] ?? '');
}

function readUser(server: TestServer, id: string, cookie?: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/users?id=${encodeURIComponent(id)}`, {
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

describe('GET /api/v1/users — ownership boundary', () => {
  async function seeded(): Promise<{
    server: TestServer;
    alice: string;
    bob: string;
    admin: string;
    owner: string;
  }> {
    const users = createMemoryUserRepository();
    await seed(users, 'usr_alice', 'alice@example.test', 'MEMBER');
    await seed(users, 'usr_bob', 'bob@example.test', 'MEMBER');
    await seed(users, 'usr_admin1', 'admin@example.test', 'ADMIN');
    await seed(users, 'usr_owner1', 'owner@example.test', 'ACCOUNT_OWNER');
    const server = await startTestServer({ users });
    servers.push(server);
    return {
      server,
      alice: await cookieFor(server, 'alice@example.test'),
      bob: await cookieFor(server, 'bob@example.test'),
      admin: await cookieFor(server, 'admin@example.test'),
      owner: await cookieFor(server, 'owner@example.test'),
    };
  }

  test('self-read works for every role with the exact public shape', async () => {
    const { server, alice, admin, owner } = await seeded();
    for (const [cookie, id] of [
      [alice, 'usr_alice'],
      [admin, 'usr_admin1'],
      [owner, 'usr_owner1'],
    ] as const) {
      const res = await readUser(server, id, cookie);
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { user: Record<string, unknown> } };
      expect(Object.keys(body.data.user).sort()).toEqual([
        'createdAt',
        'email',
        'id',
        'role',
        'userType',
      ]);
    }
  });

  test('horizontal denial: one MEMBER cannot read another MEMBER (IDOR)', async () => {
    const { server, alice, bob } = await seeded();
    const res = await readUser(server, 'usr_bob', alice);
    expect(res.status).toBe(403);
    const body = await readJson(res);
    expect(body).toEqual({
      ok: false,
      error: { code: 'FORBIDDEN', message: 'You do not have access to this resource.' },
      meta: { requestId: expect.any(String) },
    });
    // Even knowing the exact id — id manipulation gains nothing.
    expect((await readUser(server, 'usr_alice', bob)).status).toBe(403);
  });

  test('privileged cross-read is explicit: ADMIN and ACCOUNT_OWNER only', async () => {
    const { server, admin, owner } = await seeded();
    expect((await readUser(server, 'usr_bob', admin)).status).toBe(200);
    expect((await readUser(server, 'usr_bob', owner)).status).toBe(200);
  });

  test('unknown, malformed and manipulated ids are indistinguishable from denials', async () => {
    const { server, alice, admin } = await seeded();
    const denial = await readUser(server, 'usr_bob', alice);
    const denialBody = JSON.stringify(await readJson(denial));

    for (const id of [
      'usr_does-not-exist',
      'usr_ALICE', // case manipulation
      '../etc/passwd',
      'usr_alice/../usr_bob',
      '<script>alert(1)</script>',
      '%2e%2e%2fusr_bob',
    ]) {
      const res = await readUser(server, id, alice);
      expect(res.status).toBe(403);
      const raw = JSON.stringify(await readJson(res));
      // Byte-identical denial envelope (minus requestId) for every id.
      expect(raw.replace(/"requestId":"[^"]*"/, '')).toBe(
        denialBody.replace(/"requestId":"[^"]*"/, ''),
      );
    }
    // ADMIN's cross-read right does not extend to nonexistent accounts:
    // no existence oracle even for privileged roles.
    expect((await readUser(server, 'usr_ghost', admin)).status).toBe(403);
  });

  test('oversized ids are uniformly denied, missing ids are a 422', async () => {
    const { server, alice } = await seeded();
    const oversized = await readUser(server, 'x'.repeat(65), alice);
    expect(oversized.status).toBe(403);

    const missing = await fetch(`${server.baseUrl}/api/v1/users`, { headers: { cookie: alice } });
    expect(missing.status).toBe(422);
    const body = await readJson(missing);
    expect(JSON.stringify(body)).toContain('A resource id is required.');
  });

  test('anonymous access is 401, never 403', async () => {
    const { server } = await seeded();
    const res = await readUser(server, 'usr_alice');
    expect(res.status).toBe(401);
    const body = await readJson(res);
    expect(JSON.stringify(body)).toContain('Authentication required.');
  });

  test('reads return ONLY public fields — never hash, password or session data', async () => {
    const { server, admin } = await seeded();
    const res = await readUser(server, 'usr_alice', admin);
    const raw = JSON.stringify(await readJson(res));
    expect(raw).not.toContain('scrypt$');
    expect(raw).not.toContain('password');
    expect(raw).not.toContain('token');
    expect(raw).not.toContain('session');
  });
});
