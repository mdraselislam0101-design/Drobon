import { describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Operational metrics (P2-15). The endpoint is a privileged operator surface:
 * it must be authorized like the admin API, expose only aggregate state, and
 * never describe findings as a safety or quality verdict.
 */

const PW = 'metrics-pw-test';

async function seedUser(server: TestServer, email: string, role: UserRecord['role']): Promise<string> {
  const id = `usr_${email.split('@')[0] ?? 'seed'}`;
  const record: UserRecord = {
    id, email, passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z', role, userType: null,
  };
  if (!(await server.users.create(record))) throw new Error(`Seed collision for ${email}`);
  return id;
}

async function login(server: TestServer, email: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  expect(res.status).toBe(200);
  return sessionCookieFrom(res);
}

describe('GET /api/v1/metrics', () => {
  test('anonymous and non-platform callers are refused', async () => {
    // Neither seeded account is on the allowlist.
    const server = await startTestServer({ platformAdminIds: ['usr_root'] });
    try {
      await seedUser(server, 'member@example.test', 'MEMBER');
      await seedUser(server, 'admin@example.test', 'ADMIN');
      expect((await fetch(`${server.baseUrl}/api/v1/metrics`)).status).toBe(401);
      const memberCookie = await login(server, 'member@example.test');
      expect((await fetch(`${server.baseUrl}/api/v1/metrics`, { headers: { cookie: memberCookie } })).status).toBe(403);
      // ADMIN role alone is not enough: the platform allowlist must also match.
      const adminCookie = await login(server, 'admin@example.test');
      expect((await fetch(`${server.baseUrl}/api/v1/metrics`, { headers: { cookie: adminCookie } })).status).toBe(403);
    } finally {
      await server.stop();
    }
  });

  test('a platform admin sees aggregate, bounded operational state only', async () => {
    const server = await startTestServer({ platformAdminIds: ['usr_root'] });
    try {
      await seedUser(server, 'root@example.test', 'ADMIN');
      // Seed the allowlisted id.
      await server.users.create({
        id: 'usr_root', email: 'root2@example.test', passwordHash: await hashPassword(PW, 1024),
        createdAt: '2026-09-01T00:00:00.000Z', role: 'ADMIN', userType: null,
      });
      const cookie = await login(server, 'root2@example.test');
      const res = await fetch(`${server.baseUrl}/api/v1/metrics`, { headers: { cookie } });
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: Record<string, unknown> };
      const data = body.data;
      const scans = data['scans'] as Record<string, unknown>;
      expect(data['service']).toBe('drobon-aegis-api');
      expect(typeof data['uptimeSeconds']).toBe('number');
      expect(scans).toMatchObject({
        total: 0, queueDepth: 0,
        byStatus: { QUEUED: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0, TIMED_OUT: 0 },
        byType: { SAST: 0, SCA: 0, SECRETS: 0, DAST: 0 },
      });
      expect(data['processor']).toEqual({ started: false });
      // Growth visibility (P1-6/P1-10): the document shape and its size.
      const store = data['store'] as Record<string, number>;
      expect(store).toMatchObject({
        scans: 0, reports: 0, findingWorkflows: 0, idempotencyEntries: 0,
      });
      expect(store['documentBytes']).toBeGreaterThan(0);
      expect(store['estimatedFullRewriteBytes']).toBe(store['documentBytes']);
      expect(typeof data['notes']).toBe('string');
      // No identifiers, no per-project data, no detection claims.
      const serialized = JSON.stringify(data);
      expect(serialized).not.toMatch(/prj_|scan_|usr_|ownerId|projectId|email/);
      expect(serialized).toMatch(/zero findings never means the target is safe/);
    } finally {
      await server.stop();
    }
  });
});
