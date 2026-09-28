import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import {
  secondsUntilNextPeriod,
  usagePeriodIdAt,
  usagePeriodInfo,
} from '../src/usage/service.js';
import { createMemoryUsageStore } from '../src/usage/store.js';
import {
  cleanupTempStoreDir,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

/**
 * Pump 5 quota mechanics: UTC period math (including the December →
 * January year rollover), atomic concurrent consumption (no
 * read-then-write races on either the account or the device counter),
 * natural month rollover via the injected clock, restart persistence
 * through the durable JSON store, and PRO exemption that never touches
 * the FREE device allowance.
 */

const PW = 'quota-pw-test';

const PRO_ACTIVE = {
  plan: 'PRO' as const,
  status: 'ACTIVE' as const,
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};

const FREE_ACTIVE = { ...PRO_ACTIVE, plan: 'FREE' as const };

async function seedUser(
  repo: UserRepository,
  email: string,
  fields: Partial<Pick<UserRecord, 'role' | 'userType' | 'subscription'>> = {},
): Promise<void> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role: fields.role ?? 'MEMBER',
    userType: fields.userType ?? null,
    ...(fields.subscription === undefined ? {} : { subscription: fields.subscription }),
  };
  if (!(await repo.create(record))) {
    throw new Error(`Seed collision for ${email}`);
  }
}

async function login(server: TestServer, email: string): Promise<string> {
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

async function deviceFor(server: TestServer, session: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
  if (raw === undefined) {
    throw new Error('Expected a drobon_device Set-Cookie header.');
  }
  return raw.split(';')[0] ?? '';
}

async function consume(
  server: TestServer,
  cookie: string,
): Promise<{
  status: number;
  code: string | undefined;
  used: number | undefined;
  remaining: number | null | undefined;
}> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage/consume`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: '{}',
  });
  const body = (await readJson(res)) as {
    data?: { used: number; remaining: number | null };
    error?: { code: string };
  };
  return {
    status: res.status,
    code: body.error?.code,
    used: body.data?.used,
    remaining: body.data?.remaining,
  };
}

describe('UTC period math', () => {
  test('usagePeriodIdAt produces UTC YYYY-MM regardless of local timezone', () => {
    expect(usagePeriodIdAt(Date.UTC(2026, 8, 15, 12))).toBe('2026-09');
    // Last second of September UTC → still September.
    expect(usagePeriodIdAt(Date.UTC(2026, 8, 30, 23, 59, 59, 999))).toBe('2026-09');
    // First millisecond of October UTC → October.
    expect(usagePeriodIdAt(Date.UTC(2026, 9, 1, 0, 0, 0, 0))).toBe('2026-10');
    // December → January year rollover.
    expect(usagePeriodIdAt(Date.UTC(2026, 11, 31, 23, 59, 59, 999))).toBe('2026-12');
    expect(usagePeriodIdAt(Date.UTC(2027, 0, 1, 0, 0, 0, 0))).toBe('2027-01');
  });

  test('usagePeriodInfo returns month-long, end-exclusive windows', () => {
    expect(usagePeriodInfo('2026-09')).toEqual({
      period: '2026-09',
      startUtc: '2026-09-01T00:00:00.000Z',
      endUtc: '2026-10-01T00:00:00.000Z',
    });
    // February (non-leap) and February (leap) window lengths.
    const feb = usagePeriodInfo('2027-02');
    expect(Date.parse(feb.endUtc) - Date.parse(feb.startUtc)).toBe(28 * 86_400_000);
    const febLeap = usagePeriodInfo('2028-02');
    expect(Date.parse(febLeap.endUtc) - Date.parse(febLeap.startUtc)).toBe(29 * 86_400_000);
    // December window spans into the next year.
    expect(usagePeriodInfo('2026-12').endUtc).toBe('2027-01-01T00:00:00.000Z');
  });

  test('secondsUntilNextPeriod is exact and never zero', () => {
    expect(secondsUntilNextPeriod(Date.UTC(2026, 8, 15, 12))).toBe(1_339_200);
    // One millisecond before the boundary: clamps to at least one second.
    expect(secondsUntilNextPeriod(Date.UTC(2026, 8, 30, 23, 59, 59, 999))).toBe(1);
    // Exactly on a boundary: a full period ahead.
    expect(secondsUntilNextPeriod(Date.UTC(2026, 9, 1, 0, 0, 0, 0))).toBe(31 * 86_400);
  });
});

describe('atomic consumption under concurrency', () => {
  test('10 simultaneous consumes on a fresh FREE account → exactly 3 succeed', async () => {
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'race@example.test');
      const session = await login(server, 'race@example.test');
      const device = await deviceFor(server, session);
      const cookie = `${session}; ${device}`;
      const results = await Promise.all(
        Array.from({ length: 10 }, () => consume(server, cookie)),
      );
      const granted = results.filter((r) => r.status === 200);
      const denied = results.filter((r) => r.status === 429);
      expect(granted).toHaveLength(3);
      expect(denied).toHaveLength(7);
      expect(new Set(denied.map((r) => r.code))).toEqual(new Set(['QUOTA_EXCEEDED']));
      // Each grant consumed a distinct slot: 1, 2, 3 — no over- or
      // under-counting, no duplicated slots.
      expect([...granted.map((r) => r.used)].sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual([1, 2, 3]);
      const view = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } });
      const body = (await readJson(view)) as { data: { used: number; remaining: number } };
      expect(body.data).toMatchObject({ used: 3, remaining: 0 });
    } finally {
      await server.stop();
    }
  });

  test('10 simultaneous consumes also hold on the durable file store', async () => {
    const dir = makeTempStoreDir('usage-atomic');
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStoreDir: dir,
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'race@example.test');
      const session = await login(server, 'race@example.test');
      const device = await deviceFor(server, session);
      const cookie = `${session}; ${device}`;
      const results = await Promise.all(
        Array.from({ length: 10 }, () => consume(server, cookie)),
      );
      expect(results.filter((r) => r.status === 200)).toHaveLength(3);
      expect(results.filter((r) => r.status === 429)).toHaveLength(7);
    } finally {
      await server.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('the same device shared by two accounts atomically enforces 3 total', async () => {
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'a@example.test');
      await seedUser(users, 'b@example.test');
      const sessionA = await login(server, 'a@example.test');
      const device = await deviceFor(server, sessionA);
      const sessionB = await login(server, 'b@example.test');
      const cookieA = `${sessionA}; ${device}`;
      const cookieB = `${sessionB}; ${device}`;
      // Both accounts race on the SAME device token: only 3 succeed total.
      const results = await Promise.all([
        ...Array.from({ length: 5 }, () => consume(server, cookieA)),
        ...Array.from({ length: 5 }, () => consume(server, cookieB)),
      ]);
      expect(results.filter((r) => r.status === 200)).toHaveLength(3);
      expect(results.filter((r) => r.status === 429)).toHaveLength(7);
    } finally {
      await server.stop();
    }
  });
});

describe('month boundaries (natural UTC rollover, no manual job)', () => {
  test('September exhaustion never reduces the October allowance', async () => {
    let nowMs = Date.UTC(2026, 8, 30, 23, 0);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'september@example.test');
      const session = await login(server, 'september@example.test');
      const device = await deviceFor(server, session);
      const cookie = `${session}; ${device}`;
      for (let index = 0; index < 3; index += 1) {
        expect((await consume(server, cookie)).status).toBe(200);
      }
      expect((await consume(server, cookie)).status).toBe(429);
      // Cross into October: the allowance resets with no cron job.
      nowMs = Date.UTC(2026, 9, 1, 0, 0, 30);
      const fresh = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } });
      const view = (await readJson(fresh)) as {
        data: { period: { period: string }; used: number; remaining: number };
      };
      expect(view.data.period.period).toBe('2026-10');
      expect(view.data).toMatchObject({ used: 0, remaining: 3 });
      for (let index = 0; index < 3; index += 1) {
        expect((await consume(server, cookie)).status).toBe(200);
      }
      expect((await consume(server, cookie)).status).toBe(429);
    } finally {
      await server.stop();
    }
  });

  test('December → January rollover resets the allowance across the year', async () => {
    let nowMs = Date.UTC(2026, 11, 31, 23, 30);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'nye@example.test');
      const session = await login(server, 'nye@example.test');
      const device = await deviceFor(server, session);
      const cookie = `${session}; ${device}`;
      for (let index = 0; index < 3; index += 1) {
        expect((await consume(server, cookie)).status).toBe(200);
      }
      expect((await consume(server, cookie)).status).toBe(429);
      nowMs = Date.UTC(2027, 0, 1, 0, 1);
      const january = await consume(server, cookie);
      expect(january.status).toBe(200);
      expect(january.used).toBe(1);
    } finally {
      await server.stop();
    }
  });
});

describe('restart persistence (durable JSON store)', () => {
  test('account and device counters survive an API restart', async () => {
    const dir = makeTempStoreDir('usage-durable');
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    await seedUser(users, 'persist@example.test');
    await seedUser(users, 'roommate@example.test');
    const first = await startTestServer({
      users,
      usageStoreDir: dir,
      usageNow: () => nowMs,
    });
    let session = await login(first, 'persist@example.test');
    const device = await deviceFor(first, session);
    const cookie = `${session}; ${device}`;
    expect((await consume(first, cookie)).status).toBe(200);
    expect((await consume(first, cookie)).status).toBe(200);
    await first.stop();

    // The persisted document on disk holds both counters, unhashed-free
    // (only opaque hashes) and versioned.
    const onDisk = JSON.parse(readFileSync(join(dir, 'usage.json'), 'utf8')) as {
      version: number;
    };
    expect(onDisk.version).toBe(1);
    expect(JSON.stringify(onDisk)).not.toContain('persist@example.test');

    const second = await startTestServer({
      users,
      usageStoreDir: dir,
      usageNow: () => nowMs,
    });
    try {
      session = await login(second, 'persist@example.test');
      const view = await fetch(`${second.baseUrl}/api/v1/usage`, {
        headers: { cookie: `${session}; ${device}` },
      });
      const body = (await readJson(view)) as { data: { used: number; remaining: number } };
      expect(body.data).toMatchObject({ used: 2, remaining: 1 });
      // One scan left; the 2nd after restart is denied.
      const granted = await consume(second, `${session}; ${device}`);
      expect(granted.status).toBe(200);
      expect(granted.used).toBe(3);
      const denied = await consume(second, `${session}; ${device}`);
      expect(denied.status).toBe(429);

      // The DEVICE counter persisted too: a second account on the same
      // device has no allowance left even after the restart.
      const roommateSession = await login(second, 'roommate@example.test');
      const roommate = await consume(second, `${roommateSession}; ${device}`);
      expect(roommate.status).toBe(429);
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });
});

describe('PRO exemption and the device allowance', () => {
  test('ACTIVE PRO consumption never counts against the FREE device quota', async () => {
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'pro@example.test', { subscription: PRO_ACTIVE });
      await seedUser(users, 'free@example.test', { subscription: FREE_ACTIVE });
      const proSession = await login(server, 'pro@example.test');
      const device = await deviceFor(server, proSession);
      const proCookie = `${proSession}; ${device}`;
      // The PRO account scans 5 times on the shared device.
      for (let index = 0; index < 5; index += 1) {
        const outcome = await consume(server, proCookie);
        expect(outcome.status).toBe(200);
      }
      const proView = await fetch(`${server.baseUrl}/api/v1/usage`, {
        headers: { cookie: proCookie },
      });
      const proBody = (await readJson(proView)) as {
        data: { used: number; limit: number | null; remaining: number | null; quotaStatus: string };
      };
      expect(proBody.data).toMatchObject({
        used: 5,
        limit: null,
        remaining: null,
        quotaStatus: 'EXEMPT',
      });

      // A FREE account on the same device still has its full allowance —
      // PRO scans are exempt and never eat the shared device quota.
      const freeSession = await login(server, 'free@example.test');
      const freeCookie = `${freeSession}; ${device}`;
      const freeView = await fetch(`${server.baseUrl}/api/v1/usage`, {
        headers: { cookie: freeCookie },
      });
      const freeBody = (await readJson(freeView)) as { data: { remaining: number } };
      expect(freeBody.data.remaining).toBe(3);
      for (let index = 0; index < 3; index += 1) {
        expect((await consume(server, freeCookie)).status).toBe(200);
      }
      expect((await consume(server, freeCookie)).status).toBe(429);
    } finally {
      await server.stop();
    }
  });

  test('a lapsed PRO counts as FREE: limited, and device-tracked', async () => {
    const nowMs = Date.UTC(2026, 8, 15, 12);
    const users = createMemoryUserRepository();
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => nowMs,
    });
    try {
      await seedUser(users, 'lapsed@example.test', {
        subscription: { ...PRO_ACTIVE, status: 'EXPIRED' },
      });
      const session = await login(server, 'lapsed@example.test');
      const device = await deviceFor(server, session);
      const cookie = `${session}; ${device}`;
      const outcomes = [await consume(server, cookie), await consume(server, cookie), await consume(server, cookie)];
      expect(outcomes.map((o) => o.status)).toEqual([200, 200, 200]);
      expect((await consume(server, cookie)).status).toBe(429);
    } finally {
      await server.stop();
    }
  });
});
