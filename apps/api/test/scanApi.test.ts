import { describe, expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { compareScansDesc, type Scan, type ScanResponse } from '@drobon/shared';
import type { ScanEngine } from '../src/scans/engines.js';
import {
  cleanupTempStoreDir,
  configureFixtureDastTarget,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

/**
 * Pump 7 Scan-Job API — the full security matrix over real HTTP:
 *
 * - AUTH: anonymous/forged sessions never reach scan routes;
 * - PROJECT POLICY: unknown/foreign/malformed project ids answer the
 *   SAME uniform 403 (the Pump 6 policy — no existence oracle);
 * - VALIDATION: the body may carry ONLY { scanType }; every
 *   security-sensitive field (id, projectId, requestedBy, status,
 *   timestamps, result, plan/role claims) and the prototype-chain keys
 *   are rejected (422);
 * - QUOTA+ATOMICITY: creation consumes quota exactly once, atomically
 *   with the durable append (10-way concurrency, retries, cross-project
 *   and cross-account races; FREE=3/month; PRO exempt; shared device;
 *   UTC month rollover; archived projects rejected);
 * - IDEMPOTENCY: same key+request replays the original scan (no second
 *   consumption); same key+different request → 409; keys are scoped to
 *   the account;
 * - READS: server-ordered list, detail, uniform 404 inside the caller's
 *   own project, historical scans of archived projects stay readable;
 * - PROCESSOR: the only transition path QUEUED→RUNNING→terminal; no
 *   engine → deterministic FAILED/SCAN_ENGINE_NOT_IMPLEMENTED (never a
 *   fabricated result); duplicate delivery cannot execute a job twice;
 *   crashed engines fail closed; startup recovery fails interrupted
 *   scans with SCAN_INTERRUPTED;
 * - PERSISTENCE: durable scans survive restart; a corrupt store refuses
 *   to start;
 * - TAMPERING: plan/role/entitlement claims never change the verdict;
 * - LOG HYGIENIC: scan logs carry ids only.
 */

const PW = 'scan-pw-test';

type Subscription = NonNullable<UserRecord['subscription']>;
const FREE_ACTIVE: Subscription = {
  plan: 'FREE',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};
const PRO_ACTIVE: Subscription = { ...FREE_ACTIVE, plan: 'PRO' };

const ALL_USER_TYPES = [
  'DEVELOPER',
  'STUDENT',
  'SECURITY_PROFESSIONAL',
  'PENTESTER',
] as const;

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

interface Cookies {
  session: string;
  device?: string;
}

async function login(server: TestServer, email: string, device?: string): Promise<Cookies> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(device === undefined ? {} : { cookie: `drobon_device=${device}` }),
    },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 200) {
    throw new Error(`Login failed for ${email} with status ${res.status}.`);
  }
  const session = sessionCookieFrom(res);
  // The device cookie is issued by the FIRST authenticated response
  // (Pump 5) — probe one, reusing a provided device token when present.
  const probeHeaders: Record<string, string> = { cookie: session };
  if (device !== undefined) {
    probeHeaders['cookie'] = `${session}; drobon_device=${device}`;
  }
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: probeHeaders });
  const rawDevice = probe.headers
    .getSetCookie()
    .find((entry) => entry.startsWith('drobon_device='));
  if (rawDevice !== undefined) {
    const issued = rawDevice.split(';')[0]?.slice('drobon_device='.length) ?? '';
    return { session, device: issued };
  }
  if (device !== undefined) {
    // A valid existing device cookie is reused (no re-issue).
    return { session, device };
  }
  throw new Error('Expected a drobon_device Set-Cookie header.');
}

function cookieHeader(cookies: Cookies): string {
  return cookies.device === undefined
    ? cookies.session
    : `${cookies.session}; drobon_device=${cookies.device}`;
}

async function createProject(
  server: TestServer,
  cookies: Cookies,
  name = 'Target app',
): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  if (res.status !== 201) {
    throw new Error(`Project create failed with status ${res.status}.`);
  }
  const body = (await readJson(res)) as { data: { project: { id: string } } };
  const projectId = body.data.project.id;
  await configureFixtureDastTarget(server, cookieHeader(cookies), projectId);
  return projectId;
}

interface ScanCallResult {
  res: Response;
  body: unknown;
}

/** Upload (replace) a project's source snapshot — the SAST scan target. */
async function uploadSources(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  files: Array<{ path: string; content: string }>,
): Promise<void> {
  const res = await fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`,
    {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
      body: JSON.stringify({ files }),
    },
  );
  if (res.status !== 200) {
    throw new Error(`Source upload failed with status ${res.status}.`);
  }
}

async function requestScan(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  // Pump 9: SCA is a REAL engine (needs a snapshot target). DAST is
  // the engine-less control type for this orchestration suite.
  body: unknown = { scanType: 'DAST' },
  idempotencyKey?: string,
): Promise<ScanCallResult> {
  const res = await fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: cookieHeader(cookies),
        ...(idempotencyKey === undefined ? {} : { 'idempotency-key': idempotencyKey }),
      },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    },
  );
  const json = (await readJson(res)) as unknown;
  return { res, body: json };
}

function scanOf(body: unknown): Scan {
  const data = body as { data: { scan: Scan } };
  return data.data.scan;
}

function errorOf(body: unknown): { code: string; message: string } {
  return (body as { error: { code: string; message: string } }).error;
}

async function listScans(server: TestServer, cookies: Cookies, projectId: string): Promise<Scan[]> {
  const res = await fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
    { headers: { cookie: cookieHeader(cookies) } },
  );
  if (res.status !== 200) {
    throw new Error(`Scan list failed with status ${res.status}.`);
  }
  const body = (await readJson(res)) as { data: { scans: Scan[] } };
  return body.data.scans;
}

async function getUsage(server: TestServer, cookies: Cookies): Promise<{ used: number }> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  const body = (await readJson(res)) as { data: { used: number } };
  return { used: body.data.used };
}

describe('scan routes: authentication', () => {
  test('anonymous requests to every scan route are rejected with 401', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const projectId = 'prj_00000000-0000-4000-8000-000000000000';
      const targets = [
        ['POST', `/api/v1/projects/${projectId}/scans`],
        ['GET', `/api/v1/projects/${projectId}/scans`],
        ['GET', `/api/v1/projects/${projectId}/scans/scan_00000000-0000-4000-8000-000000000000`],
      ] as const;
      for (const [method, path] of targets) {
        const res = await fetch(`${server.baseUrl}${path}`, {
          method,
          headers: { 'content-type': 'application/json' },
          ...(method === 'POST' ? { body: JSON.stringify({ scanType: 'DAST' }) } : {}),
        });
        expect(res.status).toBe(401);
        expect(errorOf(await readJson(res)).code).toBe('UNAUTHORIZED');
      }
      // A forged session cookie never authenticates.
      const forged = await requestScan(
        server,
        { session: 'drobon_session=forged-token-value' },
        projectId,
      );
      expect(forged.res.status).toBe(401);
    } finally {
      await server.stop();
    }
  });
});

describe('scan routes: project policy (no existence oracle)', () => {
  test('unknown, foreign and malformed project ids answer the SAME uniform 403', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const malformed = [
        'not-a-prj-id',
        'prj_SHORT',
        `x${'o'.repeat(80)}`,
        'scan_00000000-0000-4000-8000-000000000000',
      ];
      const cases: Array<[string, Cookies]> = [
        ['prj_ffffffff-ffff-4fff-8fff-ffffffffffff', attacker], // Unknown.
        [projectId, attacker], // Foreign.
        ...malformed.map((id) => [id, owner] as [string, Cookies]),
      ];
      const bodies: unknown[] = [];
      for (const [id, cookies] of cases) {
        for (const method of ['POST', 'GET'] as const) {
          const res = await fetch(
            `${server.baseUrl}/api/v1/projects/${encodeURIComponent(id)}/scans`,
            {
              method,
              headers: {
                'content-type': 'application/json',
                cookie: cookieHeader(cookies),
              },
              ...(method === 'POST' ? { body: JSON.stringify({ scanType: 'DAST' }) } : {}),
            },
          );
          expect(res.status).toBe(403);
          const json = await readJson(res);
          expect(errorOf(json).code).toBe('FORBIDDEN');
          if (method === 'POST') {
            bodies.push((json as { error: unknown }).error);
          }
        }
      }
      // Every POST denial body is byte-identical (modulo requestId, which
      // is not part of `error`).
      for (const body of bodies.slice(1)) {
        expect(JSON.stringify(body)).toBe(JSON.stringify(bodies[0]));
      }
    } finally {
      await server.stop();
    }
  });

  test('roles and user types never grant foreign project scans; ADMIN is not special', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    for (const role of ['ADMIN', 'ACCOUNT_OWNER'] as const) {
      await seedUser(users, `${role.toLowerCase()}@example.test`, { role });
    }
    for (const userType of ALL_USER_TYPES) {
      await seedUser(users, `${userType.toLowerCase()}@example.test`, { userType });
    }
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const actors = [
        'admin@example.test',
        'account_owner@example.test',
        ...ALL_USER_TYPES.map((type) => `${type.toLowerCase()}@example.test`),
      ];
      for (const email of actors) {
        const actor = await login(server, email);
        const outcome = await requestScan(server, actor, projectId);
        expect(outcome.res.status).toBe(403);
        expect(errorOf(outcome.body).code).toBe('FORBIDDEN');
      }
      // …and the owner themselves is allowed (baseline).
      const own = await requestScan(server, owner, projectId);
      expect(own.res.status).toBe(201);
    } finally {
      await server.stop();
    }
  });
});

describe('scan creation: strict input validation', () => {
  test('the body may carry exactly { scanType } — nothing else', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const badBodies: Array<[unknown, string[]]> = [
        [{ scanType: 'SAST', id: 'scan_00000000-0000-4000-8000-000000000000' }, ['id']],
        [{ scanType: 'SAST', projectId: projectId }, ['projectId']],
        [{ scanType: 'SAST', ownerId: 'usr_00000000-0000-4000-8000-000000000000' }, ['ownerId']],
        [{ scanType: 'SAST', accountId: 'usr_1' }, ['accountId']],
        [{ scanType: 'SAST', requestedBy: 'usr_1' }, ['requestedBy']],
        [{ scanType: 'SAST', status: 'COMPLETED' }, ['status']],
        [{ scanType: 'SAST', createdAt: '2026-01-01T00:00:00.000Z' }, ['createdAt']],
        [{ scanType: 'SAST', startedAt: '2026-01-01T00:00:00.000Z' }, ['startedAt']],
        [{ scanType: 'SAST', completedAt: '2026-01-01T00:00:00.000Z' }, ['completedAt']],
        [{ scanType: 'SAST', result: { findings: 9 } }, ['result']],
        [{ scanType: 'SAST', resultSummary: { findingsTotal: 9 } }, ['resultSummary']],
        [{ scanType: 'SAST', subscription: 'PRO' }, ['subscription']],
        [{ scanType: 'SAST', plan: 'PRO' }, ['plan']],
        [{ scanType: 'SAST', role: 'ADMIN' }, ['role']],
        [{ scanType: 'SAST', userType: 'PENTESTER' }, ['userType']],
        // NOTE: `__proto__` in an object LITERAL sets the prototype —
        // the malicious own-property payload must be built via
        // JSON.parse, exactly as a raw attacker request would arrive.
        [
          JSON.parse('{"scanType":"SAST","__proto__":{"polluted":"yes"},"constructor":{"a":1}}'),
          ['__proto__', 'constructor'],
        ],
        [{}, ['scanType']],
        [{ scanType: '' }, ['scanType']],
        [{ scanType: 'EVIL' }, ['scanType']],
        [{ scanType: 'sast' }, ['scanType']],
        [{ scanType: 'SAST '.repeat(10) }, ['scanType']],
        [{ name: 'SAST' }, ['name']],
        // Valid JSON that is not an object (sent raw, as arrived).
        ['"not-an-object"', ['value']],
        ['null', ['value']],
        ['["array"]', ['value']],
      ];
      for (const [body, expectedPaths] of badBodies) {
        const outcome = await requestScan(server, owner, projectId, body);
        expect(outcome.res.status, `body ${JSON.stringify(body)}`).toBe(422);
        const json = outcome.body as {
          error: { code: string; details: Array<{ path: string }> };
        };
        expect(json.error.code).toBe('VALIDATION_ERROR');
        const paths = json.error.details.map((detail) => detail.path);
        for (const expected of expectedPaths) {
          expect(paths, `body ${JSON.stringify(body)}`).toContain(expected);
        }
      }
      // No prototype pollution happened.
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
      // Malformed JSON → 400; wrong media type → 415.
      const malformed = await requestScan(server, owner, projectId, '{not json');
      expect(malformed.res.status).toBe(400);
      const wrongType = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        {
          method: 'POST',
          headers: { 'content-type': 'text/plain', cookie: cookieHeader(owner) },
          body: 'hello',
        },
      );
      expect(wrongType.status).toBe(415);
      // Nothing was created or consumed by any rejected request.
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
      expect(await listScans(server, owner, projectId)).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  test('all four scan types are accepted job types', async () => {
    const users = createMemoryUserRepository();
    // PRO+ACTIVE: an EXEMPT account can create all four in one month
    // (a FREE account is correctly capped at 3 — proven below).
    await seedUser(users, 'pro@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const pro = await login(server, 'pro@example.test');
      const projectId = await createProject(server, pro);
      // Pump 8: SAST creation pre-flights the scan target — attach a
      // snapshot so ALL FOUR job types are accepted.
      await uploadSources(server, pro, projectId, [
        { path: 'src/app.ts', content: 'export const version = 1;\n' },
      ]);
      for (const scanType of ['SAST', 'SCA', 'SECRETS', 'DAST'] as const) {
        const outcome = await requestScan(server, pro, projectId, { scanType });
        expect(outcome.res.status).toBe(201);
        expect(scanOf(outcome.body).scanType).toBe(scanType);
      }
      expect(await getUsage(server, pro)).toEqual({ used: 4 });
    } finally {
      await server.stop();
    }
  });
});

describe('scan routes: strict query rejection (Pump 3)', () => {
  test('unexpected query parameters are rejected (422) before any side effect', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const url = `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`;
      const headers = { 'content-type': 'application/json', cookie: cookieHeader(owner) };
      // POST + junk query: no scan creation, no quota consumption,
      // even for polluting or repeated (HPP) parameters.
      for (const query of ['?status=COMPLETED', '?scanType=SCA', '?role=ADMIN', '?a=1&a=2']) {
        const res = await fetch(`${url}${query}`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ scanType: 'DAST' }),
        });
        expect(res.status, query).toBe(422);
        const json = (await readJson(res)) as {
          error: { code: string; details: Array<{ path: string }> };
        };
        expect(json.error.code).toBe('VALIDATION_ERROR');
        expect(json.error.details.length).toBeGreaterThan(0);
      }
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
      expect(await listScans(server, owner, projectId)).toHaveLength(0);
      // GET list + junk query.
      const list = await fetch(`${url}?order=asc`, { headers: { cookie: cookieHeader(owner) } });
      expect(list.status).toBe(422);
      // GET detail + junk query on a real scan id.
      const created = await requestScan(server, owner, projectId);
      expect(created.res.status).toBe(201);
      const scanId = scanOf(created.body).id;
      const detail = await fetch(`${url}/${scanId}?reveal=true`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(detail.status).toBe(422);
      // The clean request still works (the hardening is opt-out of junk,
      // not a blanket rejection).
      const detailOk = await fetch(`${url}/${scanId}`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(detailOk.status).toBe(200);
    } finally {
      await server.stop();
    }
  });

  test('query rejection is uniform across ownership — no existence oracle is added', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const unknownId = 'prj_00000000-0000-4000-8000-000000000000';
      // With a query string the answer is 422 for a foreign AND an
      // unknown project alike — identical, independent of existence.
      for (const target of [projectId, unknownId]) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(target)}/scans?status=COMPLETED`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status, target).toBe(422);
      }
      // Without a query string the uniform 403 policy still holds.
      for (const target of [projectId, unknownId]) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(target)}/scans`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status, target).toBe(403);
      }
    } finally {
      await server.stop();
    }
  });
});

describe('scan creation: quota consumed exactly once (atomicity)', () => {
  test('FREE account: 10 simultaneous requests → exactly 3 grants, 7 uniform 429s', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const results = await Promise.all(
        Array.from({ length: 10 }, () => requestScan(server, owner, projectId)),
      );
      const created = results.filter((result) => result.res.status === 201);
      const denied = results.filter((result) => result.res.status === 429);
      expect(created).toHaveLength(3);
      expect(denied).toHaveLength(7);
      for (const result of denied) {
        expect(errorOf(result.body).code).toBe('QUOTA_EXCEEDED');
        const retryAfter = result.res.headers.get('retry-after');
        expect(retryAfter !== null && Number(retryAfter) > 0).toBe(true);
      }
      // Exactly 3 durable scans with distinct ids; usage matches.
      const scans = await listScans(server, owner, projectId);
      expect(scans).toHaveLength(3);
      expect(new Set(scans.map((scan) => scan.id)).size).toBe(3);
      expect(await getUsage(server, owner)).toEqual({ used: 3 });
      // A 4th sequential request is denied too (state is durable).
      const fourth = await requestScan(server, owner, projectId);
      expect(fourth.res.status).toBe(429);
    } finally {
      await server.stop();
    }
  });

  test('10 simultaneous requests with the SAME idempotency key → one scan, one consumption', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const key = 'retry-key-0001';
      const results = await Promise.all(
        Array.from({ length: 10 }, () => requestScan(server, owner, projectId, undefined, key)),
      );
      const ids = new Set<string>();
      for (const result of results) {
        expect([200, 201]).toContain(result.res.status);
        ids.add(scanOf(result.body).id);
      }
      expect(ids.size).toBe(1); // THE original scan, every time.
      expect(results.filter((result) => result.res.status === 201)).toHaveLength(1);
      expect(await getUsage(server, owner)).toEqual({ used: 1 });
      expect(await listScans(server, owner, projectId)).toHaveLength(1);
    } finally {
      await server.stop();
    }
  });

  test('parallel scans across projects share the account quota (3 total)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectA = await createProject(server, owner, 'A');
      const projectB = await createProject(server, owner, 'B');
      const calls = [
        ...Array.from({ length: 3 }, () => requestScan(server, owner, projectA)),
        ...Array.from({ length: 3 }, () => requestScan(server, owner, projectB)),
      ];
      const results = await Promise.all(calls);
      expect(results.filter((result) => result.res.status === 201)).toHaveLength(3);
      expect(results.filter((result) => result.res.status === 429)).toHaveLength(3);
      expect(await getUsage(server, owner)).toEqual({ used: 3 });
      // Quota is account-wide: project B is not a bypass.
    } finally {
      await server.stop();
    }
  });

  test('parallel requests from different FREE accounts have isolated quotas', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const server = await startTestServer({ users });
    try {
      const a = await login(server, 'a@example.test');
      const b = await login(server, 'b@example.test');
      const projectA = await createProject(server, a, 'A');
      const projectB = await createProject(server, b, 'B');
      const results = await Promise.all([
        ...Array.from({ length: 3 }, () => requestScan(server, a, projectA)),
        ...Array.from({ length: 3 }, () => requestScan(server, b, projectB)),
      ]);
      expect(results.every((result) => result.res.status === 201)).toBe(true);
      expect(await getUsage(server, a)).toEqual({ used: 3 });
      expect(await getUsage(server, b)).toEqual({ used: 3 });
    } finally {
      await server.stop();
    }
  });

  test('Pump 5 device anti-abuse: a shared device pools the FREE allowance', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const server = await startTestServer({ users });
    try {
      const a = await login(server, 'a@example.test');
      // b logs in FROM THE SAME DEVICE (reuses a's device cookie).
      const b = await login(server, 'b@example.test', a.device);
      const projectA = await createProject(server, a, 'A');
      const projectB = await createProject(server, b, 'B');
      for (let index = 0; index < 3; index += 1) {
        const granted = await requestScan(server, a, projectA);
        expect(granted.res.status).toBe(201);
      }
      const fourth = await requestScan(server, a, projectA);
      expect(fourth.res.status).toBe(429);
      // The second account on the SAME device shares the exhaustion.
      const shared = await requestScan(server, b, projectB);
      expect(shared.res.status).toBe(429);
      expect(errorOf(shared.body).code).toBe('QUOTA_EXCEEDED');
    } finally {
      await server.stop();
    }
  });

  test('PRO + ACTIVE accounts are exempt — concurrent creation is never denied', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'pro@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const pro = await login(server, 'pro@example.test');
      const projectId = await createProject(server, pro);
      const results = await Promise.all(
        Array.from({ length: 6 }, () => requestScan(server, pro, projectId)),
      );
      expect(results.every((result) => result.res.status === 201)).toBe(true);
      const usage = await fetch(`${server.baseUrl}/api/v1/usage`, {
        headers: { cookie: cookieHeader(pro) },
      });
      const usageBody = (await readJson(usage)) as {
        data: { quotaStatus: string; used: number; limit: number | null };
      };
      expect(usageBody.data.quotaStatus).toBe('EXEMPT');
      expect(usageBody.data.used).toBe(6);
      expect(usageBody.data.limit).toBeNull();
    } finally {
      await server.stop();
    }
  });

  test('client plan/role/entitlement tampering never changes the quota verdict', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      for (let index = 0; index < 3; index += 1) {
        const granted = await requestScan(server, owner, projectId);
        expect(granted.res.status).toBe(201);
      }
      const res = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            cookie: `${cookieHeader(owner)}; plan=PRO; role=ADMIN; entitlements=feature:pro`,
            'x-plan': 'PRO',
            'x-role': 'ADMIN',
            'x-entitlements': 'feature:pro',
          },
          body: JSON.stringify({ scanType: 'SCA', plan: 'PRO', role: 'ADMIN' }),
        },
      );
      expect(res.status).toBe(422); // plan/role in the body are unknown props.
      const retry = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            cookie: `${cookieHeader(owner)}; plan=PRO; role=ADMIN`,
            'x-plan': 'PRO',
          },
          body: JSON.stringify({ scanType: 'DAST' }),
        },
      );
      expect(retry.status).toBe(429); // Still FREE/exhausted.
      expect(errorOf(await readJson(retry)).code).toBe('QUOTA_EXCEEDED');
    } finally {
      await server.stop();
    }
  });

  test('UTC month rollover: the allowance resets at the next month boundary', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    let clockMs = Date.UTC(2026, 8, 15, 12); // 2026-09-15 — September.
    const server = await startTestServer({ users, usageNow: () => clockMs });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      for (let index = 0; index < 3; index += 1) {
        const granted = await requestScan(server, owner, projectId);
        expect(granted.res.status).toBe(201);
      }
      const denied = await requestScan(server, owner, projectId);
      expect(denied.res.status).toBe(429);
      // October: a fresh allowance (the scan store keeps history).
      clockMs = Date.UTC(2026, 9, 3, 9);
      const fresh = await requestScan(server, owner, projectId);
      expect(fresh.res.status).toBe(201);
      const scans = await listScans(server, owner, projectId);
      expect(scans).toHaveLength(4);
    } finally {
      await server.stop();
    }
  });

  test('archived projects: new scans rejected 409 PROJECT_ARCHIVED, history readable', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      const scanId = scanOf(created.body).id;
      // Archive, then try to start new scans (sequentially and concurrently).
      const archive = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/archive`,
        { method: 'POST', headers: { cookie: cookieHeader(owner) } },
      );
      expect(archive.status).toBe(200);
      const rejected = await requestScan(server, owner, projectId);
      expect(rejected.res.status).toBe(409);
      expect(errorOf(rejected.body).code).toBe('PROJECT_ARCHIVED');
      const concurrent = await Promise.all(
        Array.from({ length: 5 }, () => requestScan(server, owner, projectId)),
      );
      expect(concurrent.every((result) => result.res.status === 409)).toBe(true);
      // Quota untouched by the rejections.
      expect(await getUsage(server, owner)).toEqual({ used: 1 });
      // Historical scans remain readable (list + detail).
      const scans = await listScans(server, owner, projectId);
      expect(scans).toHaveLength(1);
      const detail = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${scanId}`,
        { headers: { cookie: cookieHeader(owner) } },
      );
      expect(detail.status).toBe(200);
    } finally {
      await server.stop();
    }
  });
});

describe('idempotency keys', () => {
  test('malformed keys are rejected before anything is consumed', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      for (const key of ['short', 'a'.repeat(65), 'has space', 'sl/ash', '']) {
        const outcome = await requestScan(server, owner, projectId, undefined, key);
        expect(outcome.res.status, `key ${JSON.stringify(key)}`).toBe(422);
      }
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
      // Duplicated headers arrive JOINED (", ") — the joined value fails
      // the strict pattern → 422, never a silent merge or a charge.
      const dup = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        {
          method: 'POST',
          headers: [
            ['content-type', 'application/json'],
            ['cookie', cookieHeader(owner)],
            ['idempotency-key', 'duplicate-key-1'],
            ['idempotency-key', 'duplicate-key-2'],
          ],
          body: JSON.stringify({ scanType: 'DAST' }),
        },
      );
      expect(dup.status).toBe(422);
      const dupBody = (await readJson(dup)) as {
        error: { details: Array<{ path: string }> };
      };
      expect(dupBody.error.details[0]?.path).toBe('idempotencyKey');
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
    } finally {
      await server.stop();
    }
  });

  test('same key + different request → 409 conflict; nothing charged for the conflict', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      // Pump 10: SECRETS is a real snapshot-consuming engine — its
      // pre-flight requires an uploaded target like SAST/SCA.
      await uploadSources(server, owner, projectId, [
        { path: 'src/app.js', content: 'export const ok = 1\n' },
      ]);
      const first = await requestScan(server, owner, projectId, { scanType: 'SECRETS' }, 'key-1234');
      expect(first.res.status).toBe(201);
      const otherProject = await createProject(server, owner, 'Other');
      const conflictProject = await requestScan(
        server,
        owner,
        otherProject,
        { scanType: 'SECRETS' },
        'key-1234',
      );
      expect(conflictProject.res.status).toBe(409);
      expect(errorOf(conflictProject.body).code).toBe('CONFLICT');
      const conflictType = await requestScan(
        server,
        owner,
        projectId,
        { scanType: 'DAST' },
        'key-1234',
      );
      expect(conflictType.res.status).toBe(409);
      expect(await getUsage(server, owner)).toEqual({ used: 1 });
      expect(await listScans(server, owner, otherProject)).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  test('keys are scoped to the account — another account using the same key is independent', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const server = await startTestServer({ users });
    try {
      const a = await login(server, 'a@example.test');
      const b = await login(server, 'b@example.test');
      const projectA = await createProject(server, a, 'A');
      const projectB = await createProject(server, b, 'B');
      const first = await requestScan(server, a, projectA, undefined, 'shared-key-1');
      expect(first.res.status).toBe(201);
      const scanA = scanOf(first.body);
      // b reuses the literal same key: it is simply unknown for b's
      // account — b gets its OWN scan (and its own charge).
      const second = await requestScan(server, b, projectB, undefined, 'shared-key-1');
      expect(second.res.status).toBe(201);
      const scanB = scanOf(second.body);
      expect(scanB.id).not.toBe(scanA.id);
      // a's replay still resolves to a's original scan.
      const replay = await requestScan(server, a, projectA, undefined, 'shared-key-1');
      expect(replay.res.status).toBe(200);
      expect(scanOf(replay.body).id).toBe(scanA.id);
      expect(await getUsage(server, a)).toEqual({ used: 1 });
      expect(await getUsage(server, b)).toEqual({ used: 1 });
    } finally {
      await server.stop();
    }
  });
});

describe('scan reads', () => {
  test('list is server-ordered (createdAt DESC, id ASC) and public-shaped', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'other@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const other = await login(server, 'other@example.test');
      const projectId = await createProject(server, owner);
      const otherProject = await createProject(server, other, 'Foreign');
      // Pump 9: SCA pre-flights the scan target like SAST.
      await uploadSources(server, owner, projectId, [
        { path: 'package.json', content: '{"name":"app","version":"1.0.0"}' },
      ]);
      const created: Scan[] = [];
      for (const scanType of ['SCA', 'SECRETS', 'DAST'] as const) {
        const outcome = await requestScan(server, owner, projectId, { scanType });
        created.push(scanOf(outcome.body));
      }
      const scans = await listScans(server, owner, projectId);
      expect(scans).toHaveLength(3);
      // Independent re-implementation of the documented comparator.
      const expected = [...created].sort(compareScansDesc);
      expect(scans.map((scan) => scan.id)).toEqual(expected.map((scan) => scan.id));
      for (const scan of scans) {
        const expectedKeys = ['id', 'projectId', 'scanType', 'status', 'createdAt', 'updatedAt'];
        if (scan.scanType === 'DAST') expectedKeys.push('targetUrl');
        expect(Object.keys(scan).sort()).toEqual(expectedKeys.sort());
        expect(scan.status).toBe('QUEUED');
        expect(scan.id).toMatch(/^scan_[0-9a-f-]{36}$/);
        expect(scan.projectId).toBe(projectId);
      }
      // Another account's project list stays empty (no cross-account
      // leakage through the scans route).
      expect(await listScans(server, other, otherProject)).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  test('detail: uniform 404 for unknown/malformed/foreign scan ids inside the own project', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      const scanId = scanOf(created.body).id;
      const foreignProject = await createProject(server, attacker, 'Foreign');
      const ids = [
        'scan_ffffffff-ffff-4fff-8fff-ffffffffffff', // Unknown.
        'not-a-scan-id', // Malformed.
        `x${'o'.repeat(80)}`, // Oversized.
        scanId, // EXISTS — but requested through the ATTACKER's project.
      ];
      const bodies: unknown[] = [];
      for (const id of ids) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(foreignProject)}/scans/${encodeURIComponent(id)}`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status).toBe(404);
        const json = await readJson(res);
        expect(errorOf(json).code).toBe('NOT_FOUND');
        bodies.push((json as { error: unknown }).error);
      }
      for (const body of bodies.slice(1)) {
        expect(JSON.stringify(body)).toBe(JSON.stringify(bodies[0]));
      }
      // The owner reads the same id through their own project → 200.
      const ok = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${scanId}`,
        { headers: { cookie: cookieHeader(owner) } },
      );
      expect(ok.status).toBe(200);
      const detail = (await readJson(ok)) as { data: { scan: Scan } };
      expect(detail.data.scan.id).toBe(scanId);
      expect(detail.data.scan).toBeInstanceOf(Object);
    } finally {
      await server.stop();
    }
  });

  test('cross-account scan DETAIL answers the SAME uniform 403 as unknown projects', async () => {
    // Final-security-gate regression: the attacker targets the OWNER's
    // project with a REAL scan id. Project authorization must answer
    // 403 BEFORE any scan lookup, indistinguishable from an unknown or
    // malformed project id — no existence oracle at the project level.
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      const scanId = scanOf(created.body).id;
      const targets = [
        projectId, // Foreign (the owner's) — the true cross-account case.
        'prj_ffffffff-ffff-4fff-8fff-ffffffffffff', // Unknown.
        'not-a-prj-id', // Malformed.
      ];
      const bodies: unknown[] = [];
      for (const id of targets) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(id)}/scans/${encodeURIComponent(scanId)}`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status).toBe(403);
        const json = await readJson(res);
        expect(errorOf(json).code).toBe('FORBIDDEN');
        bodies.push((json as { error: unknown }).error);
      }
      for (const body of bodies.slice(1)) {
        expect(JSON.stringify(body)).toBe(JSON.stringify(bodies[0]));
      }
      // Baseline: the same request by the owner → 200 (the scan is
      // only "not found" for those without project access).
      const ok = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`,
        { headers: { cookie: cookieHeader(owner) } },
      );
      expect(ok.status).toBe(200);
    } finally {
      await server.stop();
    }
  });

  test('wrong methods on scan paths answer 405 + Allow; odd paths 404', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      const scanId = scanOf(created.body).id;
      const base = `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}`;
      // No generic scan mutation endpoint exists.
      const patch = await fetch(`${base}/scans/${scanId}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: JSON.stringify({ status: 'COMPLETED' }),
      });
      expect(patch.status).toBe(405);
      expect(patch.headers.get('allow')).toBe('GET');
      const del = await fetch(`${base}/scans/${scanId}`, {
        method: 'DELETE',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(del.status).toBe(405);
      // PUT on the collection → 405 with POST, GET.
      const put = await fetch(`${base}/scans`, {
        method: 'PUT',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(put.status).toBe(405);
      expect(put.headers.get('allow')).toBe('POST, GET');
      // Router edges: empty segments never match; malformed encoding
      // never matches; trailing slash on the collection normalizes.
      const emptySegment = await fetch(`${base}/scans//`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(emptySegment.status).toBe(404);
      const badEncoding = await fetch(`${base}/scans/%zz`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(badEncoding.status).toBe(404);
      const trailing = await fetch(`${base}/scans/`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(trailing.status).toBe(200);
      const deep = await fetch(`${base}/scans/${scanId}/extra`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(deep.status).toBe(404);
    } finally {
      await server.stop();
    }
  });
});

describe('scan processor lifecycle', () => {
  test('an explicitly unavailable engine fails deterministically — never a fake result', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users, scanEngines: [] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      expect(scanOf(created.body).status).toBe('QUEUED');
      await server.scanProcessor.drain();
      const scans = await listScans(server, owner, projectId);
      const failed = scans[0];
      expect(failed).toBeDefined();
      expect(failed?.status).toBe('FAILED');
      expect(failed?.failureCode).toBe('SCAN_ENGINE_NOT_IMPLEMENTED');
      expect(failed?.failureMessage).toContain('not implemented');
      expect(failed?.startedAt).toBeDefined();
      expect(failed?.completedAt).toBeDefined();
      expect(failed?.resultSummary).toBeUndefined(); // NEVER fabricated.
      // Idempotent drain: re-running changes nothing.
      await server.scanProcessor.drain();
      const again = (await listScans(server, owner, projectId))[0];
      expect(again?.updatedAt).toBe(failed?.updatedAt);
    } finally {
      await server.stop();
    }
  });

  test('a registered engine completes the scan with a REAL summary; duplicate delivery cannot run it twice', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const execute = vi.fn(async () => ({
      kind: 'completed' as const,
      resultSummary: { findingsTotal: 2 },
    }));
    const engine: ScanEngine = { scanType: 'SAST', execute };
    const server = await startTestServer({ users, scanEngines: [engine] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      // The injected engine is the SAST one; the Pump 8 pre-flight
      // needs a snapshot attached (the synthetic engine ignores it).
      await uploadSources(server, owner, projectId, [
        { path: 'src/index.ts', content: 'console.log(1);\n' },
      ]);
      const created = await requestScan(server, owner, projectId, { scanType: 'SAST' });
      const scanId = scanOf(created.body).id;
      // Two CONCURRENT drains (duplicate worker delivery): the claim is
      // serialized — the job executes exactly once.
      await Promise.all([server.scanProcessor.drain(), server.scanProcessor.drain()]);
      await server.scanProcessor.drain();
      expect(execute).toHaveBeenCalledTimes(1);
      const detail = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${scanId}`,
        { headers: { cookie: cookieHeader(owner) } },
      );
      const body = (await readJson(detail)) as { data: { scan: Scan } };
      expect(body.data.scan.status).toBe('COMPLETED');
      expect(body.data.scan.resultSummary).toEqual({ findingsTotal: 2 });
      expect(body.data.scan.failureCode).toBeUndefined();
      // Terminal scans are never claimable again (COMPLETED → RUNNING
      // does not exist).
      expect(await server.scans.claimNextQueued()).toBeUndefined();
      await server.scanProcessor.drain();
      expect(execute).toHaveBeenCalledTimes(1);
    } finally {
      await server.stop();
    }
  });

  test('a crashing engine fails the scan closed with SCAN_ENGINE_ERROR', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const engine: ScanEngine = {
      scanType: 'SAST',
      execute: async () => {
        throw new Error('internal engine detail that must never leak');
      },
    };
    const server = await startTestServer({ users, scanEngines: [engine] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await uploadSources(server, owner, projectId, [
        { path: 'src/index.ts', content: 'console.log(1);\n' },
      ]);
      await requestScan(server, owner, projectId, { scanType: 'SAST' });
      await server.scanProcessor.drain();
      const scan = (await listScans(server, owner, projectId))[0];
      expect(scan?.status).toBe('FAILED');
      expect(scan?.failureCode).toBe('SCAN_ENGINE_ERROR');
      expect(scan?.failureMessage).toBe('The scanner engine failed to run.');
      expect(scan?.failureMessage).not.toContain('internal engine detail');
    } finally {
      await server.stop();
    }
  });

  test('startup recovery: interrupted RUNNING scans fail with SCAN_INTERRUPTED, QUEUED ones drain', async () => {
    const dir = makeTempStoreDir('scans-recovery');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const first = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir, // The SAST target must survive the restart too.
      projectStoreDir: dir, // The project must survive the restart too.
    });
    let cookie: Cookies;
    let projectId: string;
    try {
      cookie = await login(first, 'owner@example.test');
      projectId = await createProject(first, cookie);
      await uploadSources(first, cookie, projectId, [
        { path: 'src/index.ts', content: 'export const ok = true;\n' },
      ]);
      await requestScan(first, cookie, projectId, { scanType: 'SAST' }); // → QUEUED (no auto-processing).
      await requestScan(first, cookie, projectId, { scanType: 'DAST' });
      // Simulate a crash mid-execution: claim one scan (→ RUNNING), then
      // "die" without finishing it.
      const claimed = await first.scans.claimNextQueued();
      expect(claimed?.status).toBe('RUNNING');
    } finally {
      await first.stop();
    }
    const second = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir,
      projectStoreDir: dir,
      scanEngines: [],
    });
    try {
      // processor.start(): recovery + drain (the production boot path).
      await second.scanProcessor.start();
      const relogin = await login(second, 'owner@example.test');
      const scans = await listScans(second, relogin, projectId);
      expect(scans).toHaveLength(2);
      const interrupted = scans.find((scan) => scan.scanType === 'SAST');
      const queued = scans.find((scan) => scan.scanType === 'DAST');
      expect(interrupted?.status).toBe('FAILED');
      expect(interrupted?.failureCode).toBe('SCAN_INTERRUPTED');
      expect(queued?.status).toBe('FAILED'); // Drained; no engine → NOT_IMPLEMENTED.
      expect(queued?.failureCode).toBe('SCAN_ENGINE_NOT_IMPLEMENTED');
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('a DAST engine timeout outcome lands in the TIMED_OUT terminal state (Pump 3)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const engine: ScanEngine = {
      scanType: 'DAST',
      execute: async () => ({
        kind: 'timed-out' as const,
        failureCode: 'DAST_SCAN_TIMEOUT' as const,
        failureMessage: 'The DAST scan exceeded its execution deadline.',
      }),
    };
    const server = await startTestServer({ users, scanEngines: [engine] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId);
      expect(created.res.status).toBe(201);
      await server.scanProcessor.drain();
      const scan = (await listScans(server, owner, projectId))[0];
      expect(scan).toBeDefined();
      expect(scan?.status).toBe('TIMED_OUT');
      expect(scan?.failureCode).toBe('DAST_SCAN_TIMEOUT');
      expect(scan?.failureMessage).toContain('deadline');
      expect(scan?.startedAt).toBeDefined();
      expect(scan?.completedAt).toBeDefined();
      expect(scan?.resultSummary).toBeUndefined(); // NEVER fabricated.
      // Terminal: never claimable again and never re-finalizable.
      expect(await server.scans.claimNextQueued()).toBeUndefined();
      expect(await server.scans.completeScan(scan?.id ?? '', { findingsTotal: 0 })).toBeUndefined();
      expect(await server.scans.failScan(scan?.id ?? '', 'SCAN_ENGINE_ERROR', 'late')).toBeUndefined();
      const after = (await listScans(server, owner, projectId))[0];
      expect(after?.status).toBe('TIMED_OUT');
      expect(after?.failureCode).toBe('DAST_SCAN_TIMEOUT');
    } finally {
      await server.stop();
    }
  });

  test('an engine completion rejected by the closed-shape guards never strands a scan RUNNING (Pump 3)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    // A BUGGY/forged engine: SCA-type but its payload violates the
    // shared closed-shape guard, so the durable store MUST refuse it.
    // Before the Pump 3 fix this left the scan RUNNING until restart.
    const engine: ScanEngine = {
      scanType: 'SCA',
      execute: async () => ({
        kind: 'completed' as const,
        resultSummary: { findingsTotal: 0 },
        sca: {
          summary: {},
          dependencies: [],
          manifests: [],
          sbom: {},
          advisories: [],
        } as never,
      }),
    };
    const server = await startTestServer({ users, scanEngines: [engine] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await uploadSources(server, owner, projectId, [
        { path: 'package.json', content: '{"name":"x","version":"1.0.0"}\n' },
      ]);
      const created = await requestScan(server, owner, projectId, { scanType: 'SCA' });
      expect(created.res.status).toBe(201);
      await server.scanProcessor.drain();
      const scan = (await listScans(server, owner, projectId))[0];
      expect(scan).toBeDefined();
      // Deterministic terminal state — never stranded in RUNNING.
      expect(scan?.status).toBe('FAILED');
      expect(scan?.failureCode).toBe('SCAN_ENGINE_ERROR');
      expect(scan?.failureMessage).toBe('The scan result could not be recorded safely.');
      expect(scan?.completedAt).toBeDefined();
      expect(scan?.resultSummary).toBeUndefined(); // NEVER persisted/fabricated.
      // Idempotent: the drain of a terminal scan changes nothing.
      await server.scanProcessor.drain();
      const after = (await listScans(server, owner, projectId))[0];
      expect(after?.updatedAt).toBe(scan?.updatedAt);
    } finally {
      await server.stop();
    }
  });

  test('a timed-out outcome rejected for the scan type never strands a scan RUNNING either (Pump 3)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    // A buggy SAST engine claims a DAST-only timeout code — the store's
    // state machine refuses that pairing; the processor must still land
    // the scan in a terminal FAILED state.
    const engine: ScanEngine = {
      scanType: 'SAST',
      execute: async () => ({
        kind: 'timed-out' as const,
        failureCode: 'DAST_SCAN_TIMEOUT' as const,
        failureMessage: 'The DAST scan exceeded its execution deadline.',
      }),
    };
    const server = await startTestServer({ users, scanEngines: [engine] });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await uploadSources(server, owner, projectId, [
        { path: 'src/index.ts', content: 'console.log(1);\n' },
      ]);
      const created = await requestScan(server, owner, projectId, { scanType: 'SAST' });
      expect(created.res.status).toBe(201);
      await server.scanProcessor.drain();
      const scan = (await listScans(server, owner, projectId))[0];
      expect(scan).toBeDefined();
      expect(scan?.status).toBe('FAILED');
      expect(scan?.failureCode).toBe('SCAN_ENGINE_ERROR');
      expect(scan?.failureMessage).toBe('The scan timeout could not be recorded safely.');
      expect(scan?.completedAt).toBeDefined();
      expect(scan?.resultSummary).toBeUndefined();
    } finally {
      await server.stop();
    }
  });
});

describe('scan persistence', () => {
  test('scans survive an API restart via the durable JSON store (with quota)', async () => {
    const dir = makeTempStoreDir('scans-durable');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const first = await startTestServer({
      users,
      scanStoreDir: dir,
      projectStoreDir: dir,
      usageStoreDir: dir,
      scanEngines: [],
    });
    let cookie: Cookies;
    let projectId: string;
    let failedScanId: string;
    try {
      cookie = await login(first, 'owner@example.test');
      projectId = await createProject(first, cookie, 'Durable');
      const created = await requestScan(first, cookie, projectId, undefined, 'durable-key-1');
      failedScanId = scanOf(created.body).id;
      await first.scanProcessor.drain(); // → FAILED/NOT_IMPLEMENTED.
      // Pump 10: SECRETS needs an uploaded snapshot target too.
      await uploadSources(first, cookie, projectId, [
        { path: 'src/app.js', content: 'export const ok = 1\n' },
      ]);
      await requestScan(first, cookie, projectId, { scanType: 'SECRETS' });
      // The persisted document holds scans + idempotency entries only.
      const onDisk = readFileSync(join(dir, 'scans.json'), 'utf8');
      expect(onDisk).toContain('"version": 1');
      expect(onDisk).toContain(failedScanId);
      expect(onDisk).toContain('durable-key-1');
      expect(onDisk).not.toContain('owner@example.test');
      expect(onDisk).not.toContain(PW);
    } finally {
      await first.stop(); // Exactly once — the finally owns shutdown.
    }
    const second = await startTestServer({
      users,
      scanStoreDir: dir,
      projectStoreDir: dir,
      usageStoreDir: dir,
    });
    try {
      const relogin = await login(second, 'owner@example.test');
      const scans = await listScans(second, relogin, projectId);
      expect(scans).toHaveLength(2);
      const failed = scans.find((scan) => scan.id === failedScanId);
      expect(failed?.status).toBe('FAILED'); // Terminal state persisted.
      expect(failed?.failureCode).toBe('SCAN_ENGINE_NOT_IMPLEMENTED');
      // Quota persisted: 2 used, one remaining, then exhausted.
      const third = await requestScan(second, relogin, projectId, { scanType: 'DAST' });
      expect(third.res.status).toBe(201);
      const fourth = await requestScan(second, relogin, projectId);
      expect(fourth.res.status).toBe(429);
      // Idempotency persisted: the old key still replays (no charge).
      const replay = await requestScan(second, relogin, projectId, undefined, 'durable-key-1');
      expect(replay.res.status).toBe(200);
      expect(scanOf(replay.body).id).toBe(failedScanId);
      expect(await listScans(second, relogin, projectId)).toHaveLength(3);
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('a corrupt scan store refuses to start (no silent repair)', async () => {
    const dir = makeTempStoreDir('scans-corrupt');
    const { writeFileSync } = await import('node:fs');
    writeFileSync(join(dir, 'scans.json'), '{not json', { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(startTestServer({ users, scanStoreDir: dir })).rejects.toThrow(
      /not valid JSON/,
    );
    cleanupTempStoreDir(dir);
  });

  test('an invalid scan record (state-machine violation) refuses to start', async () => {
    const dir = makeTempStoreDir('scans-invalid-record');
    const { writeFileSync } = await import('node:fs');
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000000',
          ownerId: 'usr_00000000-0000-4000-8000-000000000000',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SAST',
          status: 'COMPLETED', // COMPLETED without startedAt/result → invalid.
          createdAt: '2026-09-01T00:00:00.000Z',
          updatedAt: '2026-09-01T00:00:00.000Z',
        },
      ],
      idempotency: [],
    };
    writeFileSync(join(dir, 'scans.json'), JSON.stringify(forged), { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(startTestServer({ users, scanStoreDir: dir })).rejects.toThrow(
      /invalid record/,
    );
    cleanupTempStoreDir(dir);
  });
});

describe('scan log hygiene', () => {
  test('scan log lines carry ids only — no emails, no device material', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users, logLevel: 'info' });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const created = await requestScan(server, owner, projectId, undefined, 'log-key-0001');
      await requestScan(server, owner, projectId); // → 429 later? no: 2nd grant.
      await requestScan(server, owner, projectId); // 3rd grant.
      await requestScan(server, owner, projectId); // 429 denial.
      await requestScan(server, owner, projectId, undefined, 'log-key-0001'); // replay.
      await server.scanProcessor.drain();
      const logs = server.logs.join('\n');
      expect(logs).toContain('Scan created');
      expect(logs).toContain('Scan quota denied');
      expect(logs).toContain('Scan request replayed');
      expect(logs).toContain('Scan completed');
      expect(logs).toContain(scanOf(created.body).id);
      expect(logs).not.toContain('owner@example.test');
      expect(logs).not.toContain(PW);
      if (owner.device !== undefined) {
        expect(logs).not.toContain(owner.device);
      }
    } finally {
      await server.stop();
    }
  });
});

describe('scan creation response shape', () => {
  test('201 responses expose the public scan contract exactly', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const outcome = await requestScan(server, owner, projectId);
      expect(outcome.res.status).toBe(201);
      const scan = scanOf(outcome.body);
      expect(Object.keys(scan).sort()).toEqual([
        'createdAt',
        'id',
        'projectId',
        'scanType',
        'status',
        'targetUrl',
        'updatedAt',
      ]);
      expect(scan.status).toBe('QUEUED');
      // No owner/worker/filesystem fields anywhere in the envelope.
      const serialized = JSON.stringify(outcome.body);
      expect(serialized).not.toContain('ownerId');
      expect(serialized).not.toContain('requestedBy');
      expect(serialized).not.toContain('worker');
      expect(serialized).not.toContain('.json');
      // TypeScript-level sanity: the envelope carries the shared shape.
      const response = (outcome.body as { data: ScanResponse }).data;
      expect(response.scan.id).toBe(scan.id);
    } finally {
      await server.stop();
    }
  });
});
