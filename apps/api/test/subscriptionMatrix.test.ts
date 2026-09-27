import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { deriveEntitlements, resolveSubscription } from '../src/auth/subscriptions.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 4 commercial matrix — the independence proofs:
 *
 * - AccountRole NEVER grants PRO (MEMBER/ADMIN/ACCOUNT_OWNER × FREE/PRO);
 * - UserType NEVER grants PRO (all four classifications × FREE/PRO);
 * - only (PRO + ACTIVE) holds `feature:pro`; INACTIVE/CANCELLED/EXPIRED
 *   lose it while the plan itself stays PRO;
 * - entitlements are derived from the LIVE account record: an operator
 *   store change takes effect on the very next request (no re-login),
 *   mirroring the Pump 3 live-elevation proof.
 */

const PW = 'matrix-pw-test';

type Subscription = NonNullable<UserRecord['subscription']>;

const FREE_ACTIVE: Subscription = {
  plan: 'FREE',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};

const PRO_ACTIVE: Subscription = {
  plan: 'PRO',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};

function proWithStatus(status: Subscription['status']): Subscription {
  return { ...PRO_ACTIVE, status };
}

async function seedUser(
  repo: UserRepository,
  email: string,
  fields: Partial<Pick<UserRecord, 'role' | 'userType' | 'subscription'>> = {},
): Promise<UserRecord> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-27T00:00:00.000Z',
    role: fields.role ?? 'MEMBER',
    userType: fields.userType ?? null,
    ...(fields.subscription === undefined ? {} : { subscription: fields.subscription }),
  };
  if (!(await repo.create(record))) {
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
  return sessionCookieFrom(res);
}

async function readSubscription(
  server: TestServer,
  cookie: string,
): Promise<{ subscription: Subscription; entitlements: string[] }> {
  const res = await fetch(`${server.baseUrl}/api/v1/subscription`, {
    headers: { cookie },
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    data: { subscription: Subscription; entitlements: string[] };
  };
  return body.data;
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

describe('AccountRole × plan (role never grants PRO)', () => {
  test('the full 3×2 grid: role is invisible to the commercial verdict', async () => {
    const users = createMemoryUserRepository();
    const roles = ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const;
    for (const role of roles) {
      await seedUser(users, `${role.toLowerCase()}-free@example.test`, {
        role,
        subscription: FREE_ACTIVE,
      });
      await seedUser(users, `${role.toLowerCase()}-pro@example.test`, {
        role,
        subscription: PRO_ACTIVE,
      });
    }
    const server = await startTestServer({ users });
    servers.push(server);

    for (const role of roles) {
      const freeCookie = await cookieFor(server, `${role.toLowerCase()}-free@example.test`);
      const free = await readSubscription(server, freeCookie);
      expect(free.subscription.plan).toBe('FREE');
      expect(free.entitlements).toEqual(['plan:view']); // no feature:pro

      const proCookie = await cookieFor(server, `${role.toLowerCase()}-pro@example.test`);
      const pro = await readSubscription(server, proCookie);
      expect(pro.subscription.plan).toBe('PRO');
      expect(pro.entitlements).toEqual(['plan:view', 'feature:pro']);
    }
  });

  test('deriveEntitlements structurally ignores role and userType', () => {
    const base: UserRecord = {
      id: 'usr_unit',
      email: 'unit@example.test',
      passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==', // fixture marker: test
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'MEMBER',
      userType: null,
      subscription: FREE_ACTIVE,
    };
    // Same FREE subscription across every role/userType combination →
    // identical entitlements. The derivation only reads the subscription.
    for (const role of ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const) {
      for (const userType of ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER', null] as const) {
        const record: UserRecord = { ...base, role, userType };
        expect(deriveEntitlements(record)).toEqual(['plan:view']);
      }
    }
    // …and the same PRO record with every role still yields PRO together.
    for (const role of ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const) {
      expect(deriveEntitlements({ ...base, role, subscription: PRO_ACTIVE })).toEqual([
        'plan:view',
        'feature:pro',
      ]);
    }
  });
});

describe('UserType × plan (classification never grants PRO)', () => {
  test('every user type can be FREE or PRO — the plan decides, nothing else', async () => {
    const users = createMemoryUserRepository();
    const types = ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'] as const;
    for (const userType of types) {
      await seedUser(users, `${userType.toLowerCase()}-free@example.test`, {
        userType,
        subscription: FREE_ACTIVE,
      });
      await seedUser(users, `${userType.toLowerCase()}-pro@example.test`, {
        userType,
        subscription: PRO_ACTIVE,
      });
    }
    const server = await startTestServer({ users });
    servers.push(server);

    for (const userType of types) {
      const free = await readSubscription(
        server,
        await cookieFor(server, `${userType.toLowerCase()}-free@example.test`),
      );
      expect(free.subscription.plan).toBe('FREE');
      expect(free.entitlements).toEqual(['plan:view']);

      const pro = await readSubscription(
        server,
        await cookieFor(server, `${userType.toLowerCase()}-pro@example.test`),
      );
      expect(pro.subscription.plan).toBe('PRO');
      expect(pro.entitlements).toEqual(['plan:view', 'feature:pro']);
    }
  });
});

describe('status matrix (fail closed)', () => {
  test('PRO loses feature:pro under INACTIVE, CANCELLED and EXPIRED', async () => {
    const users = createMemoryUserRepository();
    const statuses = ['INACTIVE', 'CANCELLED', 'EXPIRED'] as const;
    for (const status of statuses) {
      await seedUser(users, `pro-${status.toLowerCase()}@example.test`, {
        subscription: proWithStatus(status),
      });
    }
    // Positive + negative controls across FREE statuses as well.
    for (const status of ['ACTIVE', 'INACTIVE', 'CANCELLED', 'EXPIRED'] as const) {
      await seedUser(users, `free-${status.toLowerCase()}@example.test`, {
        subscription: { ...FREE_ACTIVE, status },
      });
    }
    const server = await startTestServer({ users });
    servers.push(server);

    for (const status of statuses) {
      const data = await readSubscription(
        server,
        await cookieFor(server, `pro-${status.toLowerCase()}@example.test`),
      );
      // The PLAN is unchanged (still PRO) — only the entitlement is gone.
      expect(data.subscription.plan).toBe('PRO');
      expect(data.subscription.status).toBe(status);
      expect(data.entitlements).toEqual(['plan:view']);
      expect(data.entitlements).not.toContain('feature:pro');
    }
    for (const status of ['ACTIVE', 'INACTIVE', 'CANCELLED', 'EXPIRED'] as const) {
      const data = await readSubscription(
        server,
        await cookieFor(server, `free-${status.toLowerCase()}@example.test`),
      );
      expect(data.subscription.plan).toBe('FREE');
      expect(data.entitlements).toEqual(['plan:view']);
    }
  });
});

describe('live server state (operator changes apply immediately)', () => {
  test('an operator store flip changes the verdict on the next request — no re-login', async () => {
    // Repository double through the real interface (the injected seam),
    // mirroring the Pump 3 live-elevation proof: it can rewrite a stored
    // record's subscription exactly as the documented operator workflow
    // (store edit + restart) would.
    const byId = new Map<string, UserRecord>();
    const byEmail = new Map<string, UserRecord>();
    const users: UserRepository & { setSubscription: (id: string, sub: Subscription) => void } = {
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
      setSubscription: (id, sub) => {
        const current = byId.get(id);
        if (current === undefined) {
          return;
        }
        const next: UserRecord = { ...current, subscription: sub };
        byId.set(id, next);
        byEmail.set(current.email, next);
      },
    };

    await users.create({
      id: 'usr_live-pro',
      email: 'live-pro@example.test',
      passwordHash: await hashPassword(PW, 1024),
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'MEMBER',
      userType: 'DEVELOPER',
      subscription: FREE_ACTIVE,
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await cookieFor(server, 'live-pro@example.test');

    // FREE + ACTIVE → FREE entitlements only.
    expect((await readSubscription(server, cookie)).entitlements).toEqual(['plan:view']);

    // Operator grants PRO: the very next request (SAME session, no
    // re-login, no cookie change) observes it.
    users.setSubscription('usr_live-pro', PRO_ACTIVE);
    const granted = await readSubscription(server, cookie);
    expect(granted.subscription.plan).toBe('PRO');
    expect(granted.entitlements).toEqual(['plan:view', 'feature:pro']);

    // Operator lets it lapse: the entitlement disappears immediately,
    // while the plan label remains PRO (honest display, closed gate).
    users.setSubscription('usr_live-pro', proWithStatus('EXPIRED'));
    const expired = await readSubscription(server, cookie);
    expect(expired.subscription.plan).toBe('PRO');
    expect(expired.subscription.status).toBe('EXPIRED');
    expect(expired.entitlements).toEqual(['plan:view']);

    // And back to FREE by operator action.
    users.setSubscription('usr_live-pro', FREE_ACTIVE);
    const downgraded = await readSubscription(server, cookie);
    expect(downgraded.subscription.plan).toBe('FREE');
    expect(downgraded.entitlements).toEqual(['plan:view']);
  });

  test('resolveSubscription never invents a subscription for legacy records', () => {
    // A record exactly as Pump 3 stored it: no subscription key at all.
    const legacy: UserRecord = {
      id: 'usr_legacy3',
      email: 'legacy3@example.test',
      passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==', // fixture marker: test
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'ADMIN',
      userType: 'STUDENT',
    };
    expect(resolveSubscription(legacy)).toEqual({
      plan: 'FREE',
      status: 'ACTIVE',
      createdAt: null,
      updatedAt: null,
    });
    expect(deriveEntitlements(legacy)).toEqual(['plan:view']);
  });
});
