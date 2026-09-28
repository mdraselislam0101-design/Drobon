import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import {
  DEVICE_COOKIE_NAME,
  DEVICE_TOKEN_BYTES,
  generateDeviceToken,
  isValidDeviceTokenShape,
} from '../src/usage/devices.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 5 device anti-abuse model: the opaque `drobon_device` cookie is the
 * server-issued, server-validated device identity. Covered here: token
 * shape and randomness, cookie security attributes, shared-device
 * allowance across FREE accounts, malformed/modified/rotated cookies,
 * cross-account behavior, and the honest limits of cookie-based device
 * identity (rotation evasion) — with the documented backstops.
 */

const PW = 'device-pw-test';

async function seedUser(repo: UserRepository, email: string): Promise<void> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role: 'MEMBER',
    userType: null,
    subscription: {
      plan: 'FREE',
      status: 'ACTIVE',
      createdAt: '2026-09-01T00:00:00.000Z',
      updatedAt: '2026-09-01T00:00:00.000Z',
    },
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

function deviceCookieFrom(res: Response): string | undefined {
  return res.headers
    .getSetCookie()
    .find((entry) => entry.startsWith(`${DEVICE_COOKIE_NAME}=`))
    ?.split(';')[0];
}

/** Issue a fresh device identity by making one authenticated request. */
async function freshDevice(server: TestServer, session: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const pair = deviceCookieFrom(res);
  if (pair === undefined) {
    throw new Error('Expected a drobon_device Set-Cookie header.');
  }
  return pair;
}

async function usageView(
  server: TestServer,
  cookie: string,
): Promise<{
  status: number;
  data: { used: number; remaining: number | null; quotaStatus: string } | undefined;
}> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } });
  const body = (await readJson(res)) as {
    data?: { used: number; remaining: number | null; quotaStatus: string };
  };
  return { status: res.status, data: body.data };
}

async function consume(
  server: TestServer,
  cookie: string,
): Promise<{
  status: number;
  code: string | undefined;
  remaining: number | null | undefined;
}> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage/consume`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: '{}',
  });
  const body = (await readJson(res)) as {
    data?: { remaining: number | null };
    error?: { code: string };
  };
  return { status: res.status, code: body.error?.code, remaining: body.data?.remaining };
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

async function deviceServer() {
  const users = createMemoryUserRepository();
  await seedUser(users, 'alpha@example.test');
  await seedUser(users, 'beta@example.test');
  const server = await startTestServer({ users, usageNow: () => Date.UTC(2026, 8, 15, 12) });
  servers.push(server);
  return { server, users };
}

describe('device token contract', () => {
  test('tokens are 32 crypto-random bytes in base64url (43 opaque chars)', () => {
    const seen = new Set<string>();
    for (let index = 0; index < 50; index += 1) {
      const token = generateDeviceToken();
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(token).not.toMatch(/[+/=]/); // base64url, no padding
      expect(isValidDeviceTokenShape(token)).toBe(true);
      seen.add(token);
    }
    expect(seen.size).toBe(50); // collisions would be a security bug
    expect(DEVICE_TOKEN_BYTES).toBe(32);
  });

  test('shape validation rejects every malformed token', () => {
    for (const bad of [
      undefined,
      '',
      'short',
      'a'.repeat(42), // one char short
      'a'.repeat(44), // one char long
      `${'a'.repeat(42)}+`, // standard base64 char
      `${'a'.repeat(42)}=`, // padding
      `.${'a'.repeat(42)}`, // leading dot
      `${'a'.repeat(21)} ${'a'.repeat(21)}`, // whitespace
      `${'a'.repeat(43)}\n`,
    ]) {
      expect(isValidDeviceTokenShape(bad as string | undefined), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('shared-device allowance (the anti-abuse rule)', () => {
  test('two FREE accounts on one device share the same 3 scans', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const device = await freshDevice(server, alpha);
    const beta = await login(server, 'beta@example.test');

    // Alpha burns the shared allowance.
    const alphaCookie = `${alpha}; ${device}`;
    for (let index = 0; index < 3; index += 1) {
      expect((await consume(server, alphaCookie)).status).toBe(200);
    }
    // Beta — different account, SAME device — sees the device exhaustion
    // reflected (its own account usage stays 0).
    const betaView = await usageView(server, `${beta}; ${device}`);
    expect(betaView.data).toMatchObject({ used: 0, remaining: 0, quotaStatus: 'EXHAUSTED' });
    expect((await consume(server, `${beta}; ${device}`)).status).toBe(429);
  });

  test('two accounts on two different devices each get 3 scans', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const beta = await login(server, 'beta@example.test');
    const deviceA = await freshDevice(server, alpha);
    const deviceB = await freshDevice(server, beta);
    for (let index = 0; index < 3; index += 1) {
      expect((await consume(server, `${alpha}; ${deviceA}`)).status).toBe(200);
    }
    // Different device → allowance untouched.
    const first = await consume(server, `${beta}; ${deviceB}`);
    expect(first.status).toBe(200);
    expect(first.remaining).toBe(2);
  });
});

describe('cookie handling and security attributes', () => {
  test('the issued cookie carries HttpOnly/SameSite=Strict/Path/Max-Age', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: alpha } });
    const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
    expect(raw).toBeDefined();
    for (const attribute of ['HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=34560000']) {
      expect(raw).toContain(attribute);
    }
    // Long expiry (~400 days) and no personal information encoded: the
    // value is purely the opaque token.
    const value = raw?.split(';')[0]?.split('=')[1] ?? '';
    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(value).not.toContain('alpha');
    expect(value).not.toContain('usr_');
  });

  test('a valid cookie is accepted and never re-issued', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const device = await freshDevice(server, alpha);
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
      headers: { cookie: `${alpha}; ${device}` },
    });
    expect(res.status).toBe(200);
    expect(deviceCookieFrom(res)).toBeUndefined();
  });

  test('malformed cookies are ignored and replaced by fresh identities', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    for (const malformed of [
      'drobon_device=garbage',
      `drobon_device=${'x'.repeat(10)}`,
      `drobon_device=${'y'.repeat(100)}`,
      'drobon_device=../../etc/passwd',
      'drobon_device=%00null',
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
        headers: { cookie: `${alpha}; ${malformed}` },
      });
      expect(res.status).toBe(200); // never a 500 on malformed input
      const replacement = deviceCookieFrom(res);
      expect(replacement).toBeDefined();
      expect(replacement).toMatch(/^drobon_device=[A-Za-z0-9_-]{43}$/);
    }
  });

  test('a shape-valid but unknown cookie is treated as a new device (no crash, no trust)', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const beta = await login(server, 'beta@example.test');
    // Burn alpha's real device allowance first.
    const realDevice = await freshDevice(server, alpha);
    for (let index = 0; index < 3; index += 1) {
      expect((await consume(server, `${alpha}; ${realDevice}`)).status).toBe(200);
    }
    // A client-forged but correctly-shaped token is simply a device the
    // server has never seen: no error, no special trust — and because the
    // ACCOUNT quota binds independently of the device, alpha is still
    // exhausted even on this "new" device.
    const forged = generateDeviceToken();
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
      headers: { cookie: `${alpha}; drobon_device=${forged}` },
    });
    expect(res.status).toBe(200);
    expect(deviceCookieFrom(res)).toBeUndefined(); // accepted as-is
    const alphaForged = await usageView(server, `${alpha}; drobon_device=${forged}`);
    expect(alphaForged.data).toMatchObject({ used: 3, remaining: 0, quotaStatus: 'EXHAUSTED' });
    expect((await consume(server, `${alpha}; drobon_device=${forged}`)).status).toBe(429);

    // Forged tokens are NOT bound to any account: beta using the same
    // token gets the shared-device semantics (fresh account, device
    // counter is the one alpha... never used — both see a fresh device).
    const betaForged = await usageView(server, `${beta}; drobon_device=${forged}`);
    expect(betaForged.data).toMatchObject({ used: 0, remaining: 3, quotaStatus: 'OK' });
    expect((await consume(server, `${beta}; drobon_device=${forged}`)).status).toBe(200);
    // The device counter is shared: alpha's account is exhausted, but the
    // DEVICE now shows one FREE-plan consumption from beta.
    expect((await usageView(server, `${beta}; drobon_device=${forged}`)).data?.remaining).toBe(2);
  });

  test('cookie rotation does NOT bypass the account quota — the documented backstop', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const device1 = await freshDevice(server, alpha);
    for (let index = 0; index < 3; index += 1) {
      expect((await consume(server, `${alpha}; ${device1}`)).status).toBe(200);
    }
    expect((await consume(server, `${alpha}; ${device1}`)).status).toBe(429);
    // Rotating to a brand-new device token yields a fresh DEVICE counter —
    // but the ACCOUNT quota (3/month) is enforced independently of the
    // device, so rotation cannot buy extra scans for the same account.
    // This is the backstop documented in docs/USAGE.md.
    const device2 = await freshDevice(server, alpha);
    const rotated = await consume(server, `${alpha}; ${device2}`);
    expect(rotated.status).toBe(429);
    expect(rotated.code).toBe('QUOTA_EXCEEDED');
    // The view on the fresh device is honest: account exhausted.
    const view = await usageView(server, `${alpha}; ${device2}`);
    expect(view.data).toMatchObject({ used: 3, remaining: 0, quotaStatus: 'EXHAUSTED' });
    // The original device stays denied too.
    expect((await consume(server, `${alpha}; ${device1}`)).status).toBe(429);
  });

  test('a device cookie alone (no session) grants nothing', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const device = await freshDevice(server, alpha);
    for (const cookie of [device, `drobon_device=${generateDeviceToken()}`]) {
      const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } });
      expect(res.status).toBe(401);
    }
  });

  test('device cookies from one browser do not leak into other responses', async () => {
    const { server } = await deviceServer();
    const alpha = await login(server, 'alpha@example.test');
    const device = await freshDevice(server, alpha);
    // Public/unauthenticated endpoints never set device cookies, and the
    // device value never echoes back in any body.
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
      headers: { cookie: `${alpha}; ${device}` },
    });
    const body = JSON.stringify(await readJson(res));
    expect(body).not.toContain(device.split('=')[1] ?? 'missing');
    expect(body).not.toContain('device');
  });
});
