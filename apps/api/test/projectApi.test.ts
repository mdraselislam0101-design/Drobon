import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { createSessionStore } from '../src/auth/sessions.js';
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
 * Pump 6 Projects API — the full security matrix over real HTTP:
 *
 * - AUTH: anonymous/forged/expired sessions never reach projects;
 * - OWNERSHIP: the authenticated account is the only owner — ADMIN,
 *   ACCOUNT_OWNER and every UserType receive the SAME uniform 403 for
 *   other accounts' projects (no existence oracle);
 * - INPUT: strict validation (unknown properties, injected
 *   ownerId/status/timestamps, prototype pollution, oversized and
 *   control-character text), XSS payloads stored as inert text, NFC
 *   Unicode normalization;
 * - CRUD + lifecycle: create/list/get/update/archive/unarchive,
 *   deterministic ordering, restart persistence, concurrent creation;
 * - USAGE: project CRUD never consumes a scan;
 * - TAMPERING: role/userType/plan/entitlement/ownerId claims from
 *   headers, cookies and queries never change ownership;
 * - LOG HYGIENE: untrusted project text never enters logs.
 */

const PW = 'project-pw-test';

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
    throw new Error(`Login failed for ${email} with status ${res.status}.`);
  }
  return sessionCookieFrom(res);
}

async function createProject(
  server: TestServer,
  cookie: string,
  body: unknown = { name: 'Alpha', description: 'First project' },
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: body === undefined ? '{}' : JSON.stringify(body),
  });
  return { res, body: await readJson(res) };
}

async function listProjects(
  server: TestServer,
  cookie: string,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, { headers: { cookie } });
  return { res, body: await readJson(res) };
}

async function getProject(
  server: TestServer,
  cookie: string,
  projectId: string,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}`, {
    headers: { cookie },
  });
  return { res, body: await readJson(res) };
}

async function patchProject(
  server: TestServer,
  cookie: string,
  projectId: string,
  body: unknown,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}`, {
    method: 'PATCH',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { res, body: await readJson(res) };
}

async function lifecycle(
  server: TestServer,
  cookie: string,
  projectId: string,
  action: 'archive' | 'unarchive',
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/${action}`,
    { method: 'POST', headers: { cookie } },
  );
  return { res, body: await readJson(res) };
}

function projectOf(body: unknown): {
  id: string;
  name: string;
  description: string;
  status: string;
  createdAt: string;
  updatedAt: string;
} {
  const data = (body as { data: { project: Record<string, string> } }).data.project;
  return {
    id: data['id'] ?? '',
    name: data['name'] ?? '',
    description: data['description'] ?? '',
    status: data['status'] ?? '',
    createdAt: data['createdAt'] ?? '',
    updatedAt: data['updatedAt'] ?? '',
  };
}

describe('authentication boundary', () => {
  test('anonymous access to every project route is 401', async () => {
    const server = await startTestServer();
    try {
      const created = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'X' }),
      });
      expect(created.status).toBe(401);
      const listed = await fetch(`${server.baseUrl}/api/v1/projects`);
      expect(listed.status).toBe(401);
      const got = await fetch(`${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-00000000000a`);
      expect(got.status).toBe(401);
      const patched = await fetch(
        `${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-00000000000a`,
        { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: '{}' },
      );
      expect(patched.status).toBe(401);
      const archived = await fetch(
        `${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-00000000000a/archive`,
        { method: 'POST' },
      );
      expect(archived.status).toBe(401);
    } finally {
      await server.stop();
    }
  });

  test('forged and expired sessions never reach projects', async () => {
    let nowMs = 5_000_000;
    const shortSessions = createSessionStore({ ttlSeconds: 60, now: () => nowMs });
    const users = createMemoryUserRepository();
    await seedUser(users, 'victim@example.test');
    const server = await startTestServer({ users, sessions: shortSessions });
    try {
      // Forged cookie: looks structurally valid, was never issued.
      const forged = await fetch(`${server.baseUrl}/api/v1/projects`, {
        headers: { cookie: 'drobon_session=forged-token-value' },
      });
      expect(forged.status).toBe(401);
      // Real session that expires mid-flight.
      const cookie = await login(server, 'victim@example.test');
      expect((await listProjects(server, cookie)).res.status).toBe(200);
      nowMs += 61_000;
      const after = await listProjects(server, cookie);
      expect(after.res.status).toBe(401);
    } finally {
      await server.stop();
    }
  });
});

describe('create — validation and server-controlled fields', () => {
  test('creates a project with server-assigned id, ownership, status, timestamps', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { res, body } = await createProject(server, cookie, {
        name: '  Primary web app  ',
        description: '  Checkout flow  ',
      });
      expect(res.status).toBe(201);
      const project = projectOf(body);
      expect(project.id).toMatch(/^prj_[0-9a-f-]{36}$/);
      expect(project.name).toBe('Primary web app'); // trimmed
      expect(project.description).toBe('Checkout flow');
      expect(project.status).toBe('ACTIVE'); // always server-chosen
      expect(project.createdAt).toBe(project.updatedAt);
      expect(Date.parse(project.createdAt)).not.toBeNaN();
      // The response carries NO owner identifier at all.
      expect(JSON.stringify(body)).not.toContain('ownerId');
      expect(JSON.stringify(body)).not.toContain('usr_owner');
    } finally {
      await server.stop();
    }
  });

  test('name validation: empty, whitespace-only and oversized are rejected', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      for (const name of ['', '   ', '\t\n ', 'x'.repeat(121)]) {
        const { res, body } = await createProject(server, cookie, { name });
        expect(res.status, JSON.stringify(name)).toBe(422);
        expect(JSON.stringify(body)).toContain('VALIDATION_ERROR');
      }
      // Exactly at the bound is allowed.
      const exact = await createProject(server, cookie, { name: 'x'.repeat(120) });
      expect(exact.res.status).toBe(201);
      // Description at/over the bound.
      const okDesc = await createProject(server, cookie, {
        name: 'd',
        description: 'y'.repeat(2000),
      });
      expect(okDesc.res.status).toBe(201);
      const badDesc = await createProject(server, cookie, {
        name: 'd',
        description: 'y'.repeat(2001),
      });
      expect(badDesc.res.status).toBe(422);
    } finally {
      await server.stop();
    }
  });

  test('malformed JSON and non-object bodies are rejected safely', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const malformed = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{"name": "unclosed',
      });
      expect(malformed.status).toBe(400);
      const array = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '["name"]',
      });
      expect(array.status).toBe(422);
      // No content-type at all → the established 415 contract.
      const noType = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST',
        headers: { cookie },
        body: '{"name":"x"}',
      });
      expect(noType.status).toBe(415);
    } finally {
      await server.stop();
    }
  });

  test('ownership, lifecycle and timestamp injection are structurally rejected (422)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'other@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const injections = [
        { name: 'x', ownerId: 'usr_other' },
        { name: 'x', status: 'ARCHIVED' },
        { name: 'x', status: 'ACTIVE' },
        { name: 'x', createdAt: '1999-01-01T00:00:00.000Z' },
        { name: 'x', updatedAt: '1999-01-01T00:00:00.000Z' },
        { name: 'x', id: 'prj_00000000-0000-4000-8000-00000000000a' },
      ];
      for (const payload of injections) {
        const { res, body } = await createProject(server, cookie, payload);
        expect(res.status, JSON.stringify(payload)).toBe(422);
        expect(JSON.stringify(body)).toContain('Unexpected property');
      }
      // Nothing was created by the rejected attempts.
      const list = await listProjects(server, cookie);
      expect(((list.body as { data: { projects: unknown[] } }).data.projects)).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  test('prototype pollution payloads are rejected, never merged', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const payloads = [
        JSON.parse('{"name":"x","__proto__":{"isAdmin":true}}'),
        JSON.parse('{"name":"x","constructor":{"prototype":{"isAdmin":true}}}'),
      ];
      for (const payload of payloads) {
        const { res } = await createProject(server, cookie, payload);
        expect(res.status).toBe(422);
      }
      // The process prototype was not touched by any of it.
      expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('XSS/HTML payloads are stored and returned as inert text', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const payload =
        '<script>alert("xss")</script><img src=x onerror="alert(1)">&"><svg onload=alert(2)>';
      const { res, body } = await createProject(server, cookie, {
        name: payload,
        description: payload,
      });
      expect(res.status).toBe(201);
      const project = projectOf(body);
      // Stored VERBATIM as text — the API never sanitizes into HTML, it
      // stores text; the web renders it as text (tested there). Round-trip
      // must be exact and must not be HTML-escaped (that is a rendering
      // concern, not a storage concern).
      expect(project.name).toBe(payload);
      expect(project.description).toBe(payload);
      // Logs stay clean of untrusted text.
      expect(server.logs.join('\n')).not.toContain('alert');
    } finally {
      await server.stop();
    }
  });

  test('control characters are rejected; NFC normalization is applied', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      for (const bad of ['bad\u0007name', 'bad\u001fname', 'bad\u007fname', 'line\nbreak']) {
        const { res, body } = await createProject(server, cookie, { name: bad });
        expect(res.status, JSON.stringify(bad)).toBe(422);
        expect(JSON.stringify(body)).toContain('control characters');
      }
      // Descriptions may keep tabs/newlines (multi-line by design).
      const multi = await createProject(server, cookie, {
        name: 'ok',
        description: 'line one\nline two\ttabbed',
      });
      expect(multi.res.status).toBe(201);
      expect(projectOf(multi.body).description).toBe('line one\nline two\ttabbed');
      // Unicode: the decomposed form (e + combining accent) is stored in
      // its composed NFC form — one canonical representation for identical
      // visual text.
      const nfc = await createProject(server, cookie, { name: 'cafe\u0301' });
      expect(projectOf(nfc.body).name).toBe('caf\u00e9');
    } finally {
      await server.stop();
    }
  });
});

describe('list — server-side scoping and deterministic ordering', () => {
  test('returns ONLY the caller\u2019s projects, ordered updatedAt DESC then id ASC', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const server = await startTestServer({ users });
    try {
      const cookieA = await login(server, 'a@example.test');
      const cookieB = await login(server, 'b@example.test');
      const createdA: string[] = [];
      for (const name of ['one', 'two', 'three']) {
        const { body } = await createProject(server, cookieA, { name });
        createdA.push(projectOf(body).id);
      }
      await createProject(server, cookieB, { name: 'private-b' });

      const listA = await listProjects(server, cookieA);
      expect(listA.res.status).toBe(200);
      const projectsA = (listA.body as { data: { projects: { id: string; name: string }[] } }).data
        .projects;
      expect(projectsA).toHaveLength(3);
      expect(projectsA.every((p) => createdA.includes(p.id))).toBe(true);

      const listB = await listProjects(server, cookieB);
      const projectsB = (listB.body as { data: { projects: { id: string; name: string }[] } }).data
        .projects;
      expect(projectsB).toHaveLength(1);
      expect(projectsB[0]?.name).toBe('private-b');
      // Cross-contamination is impossible: A's projects never appear.
      expect(JSON.stringify(listB.body)).not.toContain('one');
      expect(JSON.stringify(listB.body)).not.toContain('usr_a');

      // Update the OLDEST project → it must jump to the front (updatedAt
      // DESC). The whole list must satisfy the documented ordering
      // contract, re-implemented here INDEPENDENTLY of the store code:
      // updatedAt DESC, then id ASC as the tie-breaker.
      await patchProject(server, cookieA, createdA[0] ?? '', { name: 'one-updated' });
      const reordered = await listProjects(server, cookieA);
      const entries = (reordered.body as {
        data: { projects: { id: string; updatedAt: string }[] };
      }).data.projects;
      const expectedOrder = [...entries].sort(
        (a, b) =>
          b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id),
      );
      expect(entries.map((p) => p.id)).toEqual(expectedOrder.map((p) => p.id));
      expect(entries[0]?.id).toBe(createdA[0]);
    } finally {
      await server.stop();
    }
  });

  test('empty list is an honest empty array', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'fresh@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'fresh@example.test');
      const { res, body } = await listProjects(server, cookie);
      expect(res.status).toBe(200);
      expect((body as { data: { projects: unknown[] } }).data.projects).toEqual([]);
    } finally {
      await server.stop();
    }
  });
});

describe('ownership across accounts — the uniform 403', () => {
  test('ADMIN, ACCOUNT_OWNER and every UserType all receive the SAME denial', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'member@example.test');
    await seedUser(users, 'admin@example.test', { role: 'ADMIN' });
    await seedUser(users, 'bigowner@example.test', { role: 'ACCOUNT_OWNER' });
    for (const userType of ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'] as const) {
      await seedUser(users, `${userType.toLowerCase()}@example.test`, { userType });
    }
    const server = await startTestServer({ users });
    try {
      const ownerCookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, ownerCookie, { name: 'secret' });
      const projectId = projectOf(body).id;
      expect(projectId).not.toBe('');

      const others = [
        'member@example.test',
        'admin@example.test',
        'bigowner@example.test',
        'developer@example.test',
        'student@example.test',
        'security_professional@example.test',
        'pentester@example.test',
      ];
      for (const email of others) {
        const cookie = await login(server, email);
        // GET: same 403 as a nonexistent id — no existence oracle.
        const got = await getProject(server, cookie, projectId);
        expect(got.res.status, email).toBe(403);
        expect((got.body as { error: { code: string; message: string } }).error.code).toBe('FORBIDDEN');
        expect((got.body as { error: { message: string } }).error.message).toBe(
          'You do not have access to this resource.',
        );
        // PATCH: blocked, project unchanged.
        const patched = await patchProject(server, cookie, projectId, { name: 'hacked' });
        expect(patched.res.status, email).toBe(403);
        // Archive: blocked (the route matches; ownership denies it).
        const archived = await lifecycle(server, cookie, projectId, 'archive');
        expect(archived.res.status, email).toBe(403);
        // The list never contains it.
        const list = await listProjects(server, cookie);
        expect(
          JSON.stringify(list.body).includes(projectId),
          email,
        ).toBe(false);
      }
      // The owner still sees the untouched project.
      const still = await getProject(server, ownerCookie, projectId);
      expect(still.res.status).toBe(200);
      expect(projectOf(still.body).name).toBe('secret');
    } finally {
      await server.stop();
    }
  });

  test('unknown, malformed and oversized ids answer the SAME 403 (no oracle)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const ids = [
        'prj_00000000-0000-4000-8000-0000000000ff', // well-formed, never existed
        'not-an-id',
        'usr_00000000-0000-4000-8000-00000000000a',
        'x'.repeat(200),
        '../../etc/passwd',
        'prj_%20',
      ];
      const denials = new Set<string>();
      for (const id of ids) {
        const got = await getProject(server, cookie, id);
        expect(got.res.status, id).toBe(403);
        const patched = await patchProject(server, cookie, id, { name: 'x' });
        expect(patched.res.status, id).toBe(403);
        // Compare the error contract (requestId is unique per request
        // by design — everything ELSE must be byte-identical).
        denials.add(JSON.stringify((got.body as { error: unknown }).error));
        denials.add(JSON.stringify((patched.body as { error: unknown }).error));
      }
      expect(denials.size).toBe(1);
    } finally {
      await server.stop();
    }
  });
});

describe('update — limited fields, strict validation', () => {
  test('updates name/description; bumps updatedAt; keeps everything else', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, cookie, { name: 'before' });
      const project = projectOf(body);
      const { res, body: updatedBody } = await patchProject(server, cookie, project.id, {
        name: 'after',
        description: 'now with a description',
      });
      expect(res.status).toBe(200);
      const updated = projectOf(updatedBody);
      expect(updated.name).toBe('after');
      expect(updated.description).toBe('now with a description');
      expect(updated.id).toBe(project.id);
      expect(updated.status).toBe('ACTIVE');
      expect(updated.createdAt).toBe(project.createdAt); // immutable
      expect(Date.parse(updated.updatedAt)).toBeGreaterThanOrEqual(Date.parse(project.updatedAt));
    } finally {
      await server.stop();
    }
  });

  test('empty PATCH, unknown properties and status/owner/timestamp injection are rejected', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, cookie, { name: 'base' });
      const projectId = projectOf(body).id;
      for (const payload of [
        {},
        { status: 'ARCHIVED' },
        { status: 'ACTIVE' },
        { ownerId: 'usr_somebodyelse' },
        { id: 'prj_00000000-0000-4000-8000-00000000000a' },
        { createdAt: '1999-01-01T00:00:00.000Z' },
        { updatedAt: '1999-01-01T00:00:00.000Z' },
        { evil: true },
        { name: '' },
        { name: '   ' },
      ]) {
        const { res, body: errBody } = await patchProject(server, cookie, projectId, payload);
        expect(res.status, JSON.stringify(payload)).toBe(422);
        void errBody;
      }
      // The project is untouched after all rejected patches.
      const still = await getProject(server, cookie, projectId);
      expect(projectOf(still.body).name).toBe('base');
      expect(projectOf(still.body).status).toBe('ACTIVE');
    } finally {
      await server.stop();
    }
  });
});

describe('archive / unarchive — the ONLY status transitions', () => {
  test('archive is owner-only, idempotent, and archived projects stay listed and readable', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, cookie, { name: 'lifecycle' });
      const projectId = projectOf(body).id;

      const first = await lifecycle(server, cookie, projectId, 'archive');
      expect(first.res.status).toBe(200);
      expect(projectOf(first.body).status).toBe('ARCHIVED');
      // Idempotent: archiving again is a 200 no-op.
      const second = await lifecycle(server, cookie, projectId, 'archive');
      expect(second.res.status).toBe(200);
      expect(projectOf(second.body).status).toBe('ARCHIVED');

      // Listed (never silently disappears) and readable.
      const list = await listProjects(server, cookie);
      expect(
        (list.body as { data: { projects: { id: string; status: string }[] } }).data.projects,
      ).toEqual([expect.objectContaining({ id: projectId, status: 'ARCHIVED' })]);
      const got = await getProject(server, cookie, projectId);
      expect(got.res.status).toBe(200);
      expect(projectOf(got.body).status).toBe('ARCHIVED');

      // Unarchive restores ACTIVE.
      const back = await lifecycle(server, cookie, projectId, 'unarchive');
      expect(back.res.status).toBe(200);
      expect(projectOf(back.body).status).toBe('ACTIVE');
    } finally {
      await server.stop();
    }
  });
});

describe('persistence and concurrency', () => {
  test('projects survive an API restart via the durable JSON store', async () => {
    const dir = makeTempStoreDir('projects-durable');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const first = await startTestServer({ users, projectStoreDir: dir });
    let cookie = await login(first, 'owner@example.test');
    const { body } = await createProject(first, cookie, { name: 'durable', description: 'survives' });
    const projectId = projectOf(body).id;
    await patchProject(first, cookie, projectId, { name: 'durable-2' });
    await lifecycle(first, cookie, projectId, 'archive');
    await first.stop();

    // The persisted document holds the project with its owner — and no
    // email or password material.
    const onDisk = readFileSync(join(dir, 'projects.json'), 'utf8');
    expect(onDisk).toContain(projectId);
    expect(onDisk).toContain('ARCHIVED');
    expect(onDisk).not.toContain('owner@example.test');
    expect(onDisk).not.toContain(PW);

    const second = await startTestServer({ users, projectStoreDir: dir });
    try {
      cookie = await login(second, 'owner@example.test');
      const got = await getProject(second, cookie, projectId);
      expect(got.res.status).toBe(200);
      const project = projectOf(got.body);
      expect(project.name).toBe('durable-2');
      expect(project.status).toBe('ARCHIVED');
      const list = await listProjects(second, cookie);
      expect((list.body as { data: { projects: unknown[] } }).data.projects).toHaveLength(1);
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('a corrupt project store refuses to start (no silent erase)', async () => {
    const dir = makeTempStoreDir('projects-corrupt');
    const { writeFileSync } = await import('node:fs');
    writeFileSync(join(dir, 'projects.json'), '{not json', { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(startTestServer({ users, projectStoreDir: dir })).rejects.toThrow(
      /not valid JSON/,
    );
    cleanupTempStoreDir(dir);
  });

  // Regression (E2E-found): descriptions may contain tab/newline (the
  // documented multi-line allowance) — the store's fail-fast load
  // validation must accept EXACTLY what the API validation layer allows,
  // or a legitimate write would brick the next startup.
  test('multi-line descriptions (tab/newline) survive a restart', async () => {
    const dir = makeTempStoreDir('projects-multiline');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const first = await startTestServer({ users, projectStoreDir: dir });
    let cookie = await login(first, 'owner@example.test');
    const { body } = await createProject(first, cookie, {
      name: 'multi-line',
      description: 'line1\nline2\tindented',
    });
    const projectId = projectOf(body).id;
    await first.stop();

    const second = await startTestServer({ users, projectStoreDir: dir });
    try {
      cookie = await login(second, 'owner@example.test');
      const got = await getProject(second, cookie, projectId);
      expect(got.res.status).toBe(200);
      expect(projectOf(got.body).description).toBe('line1\nline2\tindented');
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('20 concurrent creates: 20 distinct projects, none lost, none duplicated', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const results = await Promise.all(
        Array.from({ length: 20 }, (_, index) =>
          createProject(server, cookie, { name: `concurrent-${index}` }),
        ),
      );
      expect(results.every((r) => r.res.status === 201)).toBe(true);
      const ids = results.map((r) => projectOf(r.body).id);
      expect(new Set(ids).size).toBe(20); // no duplicate ids
      const list = await listProjects(server, cookie);
      const listed = (list.body as { data: { projects: { id: string }[] } }).data.projects;
      expect(listed).toHaveLength(20);
      expect(new Set(listed.map((p) => p.id)).size).toBe(20); // nothing lost
    } finally {
      await server.stop();
    }
  });

  test('two accounts racing creates stay cleanly separated', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const server = await startTestServer({ users });
    try {
      const cookieA = await login(server, 'a@example.test');
      const cookieB = await login(server, 'b@example.test');
      await Promise.all([
        ...Array.from({ length: 5 }, (_, i) => createProject(server, cookieA, { name: `a-${i}` })),
        ...Array.from({ length: 5 }, (_, i) => createProject(server, cookieB, { name: `b-${i}` })),
      ]);
      const listA = await listProjects(server, cookieA);
      const listB = await listProjects(server, cookieB);
      expect((listA.body as { data: { projects: unknown[] } }).data.projects).toHaveLength(5);
      expect((listB.body as { data: { projects: unknown[] } }).data.projects).toHaveLength(5);
    } finally {
      await server.stop();
    }
  });
});

describe('tampering and claims never change ownership', () => {
  test('role/userType/plan/entitlement/ownerId claims are all ignored', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const ownerCookie = await login(server, 'owner@example.test');
      const attackerCookie = await login(server, 'attacker@example.test');
      const { body } = await createProject(server, ownerCookie, { name: 'target' });
      const projectId = projectOf(body).id;

      const claims = [
        { 'x-role': 'ADMIN' },
        { 'x-user-id': 'usr_owner' },
        { 'x-account-id': 'usr_owner' },
        { 'x-owner-id': 'usr_owner' },
        { 'x-user-type': 'PENTESTER' },
        { 'x-plan': 'PRO' },
        { 'x-entitlement': 'feature:pro' },
        { role: 'ADMIN', plan: 'PRO', entitlements: 'feature:pro' },
      ];
      for (const headers of claims) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}`,
          { headers: { cookie: attackerCookie, ...headers } },
        );
        expect(res.status, JSON.stringify(headers)).toBe(403);
      }
      // Query-parameter ownership is equally inert — and since Pump 4
      // fail-closed: project routes define no query parameters, so ANY
      // query string is rejected uniformly (never silently ignored).
      const query = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}?ownerId=usr_owner&userId=usr_owner`,
        { headers: { cookie: attackerCookie } },
      );
      expect(query.status).toBe(422);
      // And creation with a claimed ownerId still 422s (never honored).
      const inject = await createProject(server, attackerCookie, {
        name: 'stolen',
        ownerId: 'usr_owner',
      });
      expect(inject.res.status).toBe(422);
    } finally {
      await server.stop();
    }
  });
});

describe('strict query rejection on every project route (Pump 4)', () => {
  test('any query string is a fail-closed 422 with no side effect', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, cookie, { name: 'query-target' });
      const projectId = projectOf(body).id;
      const base = `${server.baseUrl}/api/v1/projects`;
      const encId = encodeURIComponent(projectId);
      const cases: Array<{ method: string; url: string; body?: unknown }> = [
        { method: 'POST', url: `${base}?ownerId=usr_x`, body: { name: 'never created' } },
        { method: 'GET', url: `${base}?status=ARCHIVED` },
        { method: 'GET', url: `${base}/${encId}?include=all` },
        { method: 'PATCH', url: `${base}/${encId}?ownerId=usr_x`, body: { name: 'never applied' } },
        { method: 'POST', url: `${base}/${encId}/archive?force=true` },
        { method: 'POST', url: `${base}/${encId}/unarchive?force=true` },
        { method: 'PUT', url: `${base}/${encId}/dast-target?scope=all`, body: { targetUrl: 'https://example.invalid' } },
        { method: 'DELETE', url: `${base}/${encId}/dast-target?confirm=yes` },
      ];
      for (const entry of cases) {
        const res = await fetch(entry.url, {
          method: entry.method,
          headers: {
            cookie,
            ...(entry.body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(entry.body === undefined ? {} : { body: JSON.stringify(entry.body) }),
        });
        expect(res.status, `${entry.method} ${entry.url}`).toBe(422);
        const json = (await readJson(res)) as { error: { code: string; details?: unknown } };
        expect(json.error.code).toBe('VALIDATION_ERROR');
      }
      // No side effects happened: project unchanged, still ACTIVE, one project total.
      const list = await listProjects(server, cookie);
      expect(list.res.status).toBe(200);
      expect((list.body as { data: { projects: unknown[] } }).data.projects).toHaveLength(1);
      const after = await getProject(server, cookie, projectId);
      expect(projectOf(after.body).name).toBe('query-target');
      expect(projectOf(after.body).status).toBe('ACTIVE');
      // Clean requests on the same routes keep working.
      const patched = await patchProject(server, cookie, projectId, { name: 'query-target-2' });
      expect(patched.res.status).toBe(200);
      expect(projectOf(patched.body).name).toBe('query-target-2');
    } finally {
      await server.stop();
    }
  });
});

describe('usage boundary — project CRUD never consumes a scan', () => {
  test('create/list/get/update/archive leave the scan counter untouched', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({
      users,
      usageStore: createMemoryUsageStore(),
      usageNow: () => Date.UTC(2026, 8, 15, 12),
    });
    try {
      const cookie = await login(server, 'owner@example.test');
      const { body } = await createProject(server, cookie, { name: 'quota-neutral' });
      const projectId = projectOf(body).id;
      await listProjects(server, cookie);
      await getProject(server, cookie, projectId);
      await patchProject(server, cookie, projectId, { name: 'still-neutral' });
      await lifecycle(server, cookie, projectId, 'archive');
      await lifecycle(server, cookie, projectId, 'unarchive');

      const usage = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie } });
      const usageBody = (await readJson(usage)) as {
        data: { used: number; remaining: number; quotaStatus: string };
      };
      expect(usageBody.data).toMatchObject({ used: 0, remaining: 3, quotaStatus: 'OK' });
    } finally {
      await server.stop();
    }
  });
});

describe('router integration for parameterized paths', () => {
  test('wrong methods on /api/v1/projects answer 405 with Allow', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      for (const method of ['PUT', 'DELETE', 'PATCH']) {
        const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
          method,
          headers: { cookie, 'content-type': 'application/json' },
          body: '{}',
        });
        expect(res.status).toBe(405);
        expect(res.headers.get('allow')).toContain('GET');
        expect(res.headers.get('allow')).toContain('POST');
      }
      // Unknown sub-paths still 404 (no route capture beyond the API).
      const unknown = await fetch(`${server.baseUrl}/api/v1/projects/x/scan`, {
        headers: { cookie },
      });
      expect(unknown.status).toBe(404);
      // Percent-encoded malformed input decodes safely (never a 500).
      const encoded = await fetch(`${server.baseUrl}/api/v1/projects/%zz`, {
        headers: { cookie },
      });
      expect(encoded.status).toBe(404);
    } finally {
      await server.stop();
    }
  });

  test('trailing slashes and empty params never match project routes', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const cookie = await login(server, 'owner@example.test');
      // Trailing slash on the COLLECTION normalizes to the list route —
      // the Pump 1 pathname normalization (documented: no trailing
      // slash), not a new behavior.
      const trailing = await fetch(`${server.baseUrl}/api/v1/projects/`, {
        headers: { cookie },
      });
      expect(trailing.status).toBe(200);
      // But an EMPTY path parameter never matches a parameterized route:
      // `/projects//archive` has an empty segment → no route → 404.
      const empty = await fetch(`${server.baseUrl}/api/v1/projects//archive`, {
        method: 'POST',
        headers: { cookie },
      });
      expect(empty.status).toBe(404);
    } finally {
      await server.stop();
    }
  });
});

describe('log hygiene', () => {
  test('project requests log ids only — never names, descriptions or emails', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users, logLevel: 'info' });
    try {
      const cookie = await login(server, 'owner@example.test');
      const sensitiveName = 'confidential-blueprint-text';
      const { body } = await createProject(server, cookie, {
        name: sensitiveName,
        description: 'private',
      });
      const projectId = projectOf(body).id;
      await listProjects(server, cookie);
      await getProject(server, cookie, projectId);
      await patchProject(server, cookie, projectId, { name: 'renamed' });
      await lifecycle(server, cookie, projectId, 'archive');

      const logs = server.logs.join('\n');
      expect(logs).toContain('Project created');
      expect(logs).toContain('Project updated');
      expect(logs).toContain('Project archived');
      expect(logs).toContain(projectId);
      expect(logs).not.toContain(sensitiveName);
      expect(logs).not.toContain('private');
      expect(logs).not.toContain('owner@example.test');
      expect(logs).not.toContain(PW);
    } finally {
      await server.stop();
    }
  });
});
