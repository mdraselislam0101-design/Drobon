import { afterEach, describe, expect, test } from 'vitest';
import { isAppError } from '../src/errors.js';
import {
  AUTHZ_DENIED_MESSAGE,
  assertCanReadUser,
  assertPermission,
  assertRole,
  createAuthzContext,
} from '../src/auth/authorization.js';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { AuthUser } from '@drobon/shared';
import type { Route } from '../src/http.js';
import { readJson, startTestServer, type TestServer } from './helpers.js';

function actor(role: AuthUser['role'], userType: AuthUser['userType'] = null): AuthUser {
  return {
    id: `usr_${role.toLowerCase()}-fixture`,
    email: `${role.toLowerCase()}@example.test`,
    createdAt: '2026-09-27T00:00:00.000Z',
    role,
    userType,
  };
}

describe('authorization context', () => {
  test('derives from the trusted user record only', () => {
    const authz = createAuthzContext(actor('ADMIN', 'STUDENT'));
    expect(authz.role).toBe('ADMIN');
    expect(authz.userType).toBe('STUDENT');
    expect(authz.hasRole('MEMBER')).toBe(true);
    expect(authz.hasRole('ADMIN')).toBe(true);
    expect(authz.hasRole('ACCOUNT_OWNER')).toBe(false);
    expect(authz.hasPermission('users:read:others')).toBe(true);
    expect(authz.hasPermission('authz:capability:owner')).toBe(false);
  });

  test('assert helpers throw the uniform 403 (or 401 for anonymous)', () => {
    expect(() => assertRole(actor('MEMBER'), 'MEMBER')).not.toThrow();
    expect(() => assertRole(actor('ADMIN'), 'MEMBER')).not.toThrow();
    expect(() => assertRole(actor('ACCOUNT_OWNER'), 'ACCOUNT_OWNER')).not.toThrow();

    for (const fn of [
      () => assertRole(actor('MEMBER'), 'ADMIN'),
      () => assertRole(actor('ADMIN'), 'ACCOUNT_OWNER'),
      () => assertRole(actor('MEMBER'), 'ACCOUNT_OWNER'),
      () => assertPermission(actor('MEMBER'), 'users:read:others'),
      () => assertPermission(actor('ADMIN'), 'authz:capability:owner'),
    ]) {
      try {
        fn();
        throw new Error('expected denial');
      } catch (error) {
        expect(isAppError(error)).toBe(true);
        if (isAppError(error)) {
          expect(error.statusCode).toBe(403);
          expect(error.message).toBe(AUTHZ_DENIED_MESSAGE);
        }
      }
    }

    // Anonymous callers are an authentication problem first (401).
    for (const fn of [
      () => assertRole(undefined, 'MEMBER'),
      () => assertPermission(undefined, 'authz:capability:member'),
      () => assertCanReadUser(undefined, 'usr_x'),
    ]) {
      try {
        fn();
        throw new Error('expected 401');
      } catch (error) {
        expect(isAppError(error)).toBe(true);
        if (isAppError(error)) {
          expect(error.statusCode).toBe(401);
        }
      }
    }
  });

  test('ownership: self always, others only via the explicit permission', () => {
    const member = actor('MEMBER');
    const admin = actor('ADMIN');
    const owner = actor('ACCOUNT_OWNER');
    expect(() => assertCanReadUser(member, member.id)).not.toThrow();
    expect(() => assertCanReadUser(member, 'usr_someone-else')).toThrow();
    expect(() => assertCanReadUser(admin, 'usr_someone-else')).not.toThrow();
    expect(() => assertCanReadUser(owner, 'usr_someone-else')).not.toThrow();
  });
});

describe('router enforcement of requireRole / requirePermission', () => {
  const extraRoutes: Route[] = [
    {
      method: 'GET',
      path: '/api/v1/_test/member-only',
      requireRole: 'MEMBER',
      handler: async (_req, res, ctx): Promise<void> => {
        const { sendSuccess } = await import('../src/respond.js');
        sendSuccess(res, ctx, { ok: 'member-route' });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/_test/admin-permission',
      requirePermission: 'users:read:others',
      handler: async (_req, res, ctx): Promise<void> => {
        const { sendSuccess } = await import('../src/respond.js');
        sendSuccess(res, ctx, { ok: 'admin-route' });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/_test/owner-only',
      requireRole: 'ACCOUNT_OWNER',
      handler: async (_req, res, ctx): Promise<void> => {
        const { sendSuccess } = await import('../src/respond.js');
        sendSuccess(res, ctx, { ok: 'owner-route' });
      },
    },
  ];

  const servers: TestServer[] = [];
  afterEach(async () => {
    while (servers.length > 0) {
      const server = servers.pop();
      if (server !== undefined) {
        await server.stop();
      }
    }
  });

  async function withRoles(): Promise<TestServer> {
    const users = createMemoryUserRepository();
    for (const [email, role] of [
      ['m@example.test', 'MEMBER'],
      ['a@example.test', 'ADMIN'],
      ['o@example.test', 'ACCOUNT_OWNER'],
    ] as const) {
      await users.create({
        id: `usr_${role.toLowerCase()}-route`,
        email,
        passwordHash: await hashPassword('route-probe-pw-test-1', 1024),
        createdAt: '2026-09-27T00:00:00.000Z',
        role,
        userType: null,
      });
    }
    const server = await startTestServer({ users, extraRoutes });
    servers.push(server);
    return server;
  }

  async function cookie(server: TestServer, email: string): Promise<string> {
    const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: 'route-probe-pw-test-1' }),
    });
    return (
      res.headers.getSetCookie().find((c) => c.startsWith('drobon_session='))?.split(';')[0] ?? ''
    );
  }

  test('route-level role gates: 401 anonymous, 403 insufficient, 200 granted', async () => {
    const server = await withRoles();
    const m = await cookie(server, 'm@example.test');
    const a = await cookie(server, 'a@example.test');
    const o = await cookie(server, 'o@example.test');

    const anon = await fetch(`${server.baseUrl}/api/v1/_test/member-only`);
    expect(anon.status).toBe(401);
    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/member-only`, { headers: { cookie: m } }))
        .status,
    ).toBe(200);
    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/owner-only`, { headers: { cookie: m } })).status,
    ).toBe(403);
    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/owner-only`, { headers: { cookie: a } })).status,
    ).toBe(403);
    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/owner-only`, { headers: { cookie: o } })).status,
    ).toBe(200);
  });

  test('route-level permission gates read the shared table', async () => {
    const server = await withRoles();
    const m = await cookie(server, 'm@example.test');
    const a = await cookie(server, 'a@example.test');

    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/admin-permission`)).status,
    ).toBe(401); // implies authentication
    expect(
      (await fetch(`${server.baseUrl}/api/v1/_test/admin-permission`, { headers: { cookie: m } }))
        .status,
    ).toBe(403);
    const granted = await fetch(`${server.baseUrl}/api/v1/_test/admin-permission`, {
      headers: { cookie: a },
    });
    expect(granted.status).toBe(200);
    const body = await readJson(granted);
    expect(body).toEqual({
      ok: true,
      data: { ok: 'admin-route' },
      meta: { requestId: expect.any(String) },
    });
  });
});
