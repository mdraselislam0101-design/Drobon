import { describe, expect, test } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import type { Finding, ScanDetailResponse } from '@drobon/shared';
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
 * Pump 8 SAST + source-snapshot API — the full security matrix over
 * real HTTP:
 *
 * - SOURCE UPLOAD: strict validation (path policy: traversal/absolute/
 *   backslash/NUL/percent/dotfiles/credential extensions all 422;
 *   text-only content; per-file and total size caps 413; file-count
 *   cap; duplicate paths; unknown/prototype properties), uniform
 *   project 403 (no existence oracle), archived projects read-only,
 *   replace/clear semantics, metadata-only responses (no content);
 * - PRE-FLIGHT: SAST without a snapshot → 409, NOTHING consumed;
 * - REAL SCAN: safe source → COMPLETED 0 findings; vulnerable source →
 *   the six real rules with evidence/redaction/remediation; findings
 *   only in the detail response; quota consumed exactly once;
 *   idempotent replay; deterministic fingerprints across rescans;
 * - ISOLATION: cross-account 403/404, concurrent scans of two projects
 *   never leak findings; other scan types still honestly fail with
 *   SCAN_ENGINE_NOT_IMPLEMENTED;
 * - PERSISTENCE: snapshots and findings survive restarts; a corrupt
 *   source store refuses to start;
 * - LOG HYGIENE: no source content or secret values in logs.
 */

const PW = 'sast-pw-test';

type Subscription = NonNullable<UserRecord['subscription']>;
const FREE_ACTIVE: Subscription = {
  plan: 'FREE',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};
const PRO_ACTIVE: Subscription = { ...FREE_ACTIVE, plan: 'PRO' };

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

async function login(server: TestServer, email: string): Promise<Cookies> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 200) {
    throw new Error(`Login failed for ${email} with status ${res.status}.`);
  }
  const session = sessionCookieFrom(res);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const rawDevice = probe.headers.getSetCookie().find((e) => e.startsWith('drobon_device='));
  if (rawDevice === undefined) {
    throw new Error('Expected a drobon_device Set-Cookie header.');
  }
  return { session, device: rawDevice.split(';')[0]?.slice('drobon_device='.length) ?? '' };
}

function cookieHeader(cookies: Cookies): string {
  return cookies.device === undefined
    ? cookies.session
    : `${cookies.session}; drobon_device=${cookies.device}`;
}

async function createProject(server: TestServer, cookies: Cookies, name = 'Target app'): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name, description: 'SAST target' }),
  });
  if (res.status !== 201) {
    throw new Error(`Project create failed with status ${res.status}.`);
  }
  const body = (await readJson(res)) as { data: { project: { id: string } } };
  const projectId = body.data.project.id;
  await configureFixtureDastTarget(server, cookieHeader(cookies), projectId);
  return projectId;
}

interface SourceFile {
  path: string;
  content: string;
}

async function putSources(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  files: SourceFile[],
): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files }),
  });
}

async function getSources(server: TestServer, cookies: Cookies, projectId: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    headers: { cookie: cookieHeader(cookies) },
  });
}

async function requestScan(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  scanType = 'SAST',
  idempotencyKey?: string,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(cookies),
      ...(idempotencyKey === undefined ? {} : { 'idempotency-key': idempotencyKey }),
    },
    body: JSON.stringify({ scanType }),
  });
  return { res, body: await readJson(res) };
}

function scanOf(body: unknown): { id: string; status: string } {
  const scan = (body as { data: { scan: { id: string; status: string } } }).data.scan;
  return scan;
}

async function getScanDetail(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  scanId: string,
): Promise<{ data: ScanDetailResponse }> {
  const res = await fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`,
    { headers: { cookie: cookieHeader(cookies) } },
  );
  if (res.status !== 200) {
    throw new Error(`Scan detail failed with status ${res.status}.`);
  }
  return (await readJson(res)) as { data: ScanDetailResponse };
}

async function getUsage(server: TestServer, cookies: Cookies): Promise<{ used: number }> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(cookies) } });
  const body = (await readJson(res)) as { data: { used: number } };
  return { used: body.data.used };
}

function errorOf(body: unknown): { code: string; message: string } {
  return (body as { error: { code: string; message: string } }).error;
}

const SAFE_SOURCE: SourceFile[] = [
  { path: 'src/index.ts', content: 'export const version = 1;\n' },
  { path: 'src/lib/safe.ts', content: 'export function add(a: number, b: number) {\n  return a + b;\n}\n' },
  { path: 'src/db.ts', content: "db.query('SELECT * FROM users WHERE id = ?', [id]);\n" },
  { path: 'README.md', content: '# Safe project\n' },
];

const VULNERABLE_SOURCE: SourceFile[] = [
  { path: 'src/cmd.ts', content: "export function run(dir: string) {\n  exec(`rm -rf ${dir}`);\n}\n" },
  { path: 'src/db.ts', content: 'db.query(`SELECT * FROM users WHERE id = ${id}`);\n' },
  { path: 'src/html.ts', content: 'el.innerHTML = `<b>${name}</b>`;\n' },
  { path: 'src/eval.ts', content: "eval(`(${expr})`);\n" },
  { path: 'src/config.ts', content: "const apiKey = 'sk_live_abcdef123456';\n" }, // fake
  { path: 'src/hash.ts', content: "createHash('md5');\n" },
];

describe('source snapshot API: auth + project policy', () => {
  test('anonymous requests never reach the source routes', async () => {
    const server = await startTestServer();
    try {
      const put = await fetch(`${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-000000000000/sources`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ files: [{ path: 'a.ts', content: 'x' }] }),
      });
      expect(put.status).toBe(401);
      const get = await fetch(`${server.baseUrl}/api/v1/projects/prj_00000000-0000-4000-8000-000000000000/sources`);
      expect(get.status).toBe(401);
    } finally {
      await server.stop();
    }
  });

  test('foreign/unknown/malformed project ids answer the SAME uniform 403', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const bodies: string[] = [];
      for (const [actor, id] of [
        [attacker, projectId],
        [attacker, 'prj_unknown-malformed-abc'],
        [owner, 'prj_unknown-malformed-abc'],
        [attacker, '../../etc/passwd'],
        [owner, `${projectId}/../..`],
      ] as Array<[Cookies, string]>) {
        const res = await putSources(server, actor, id, [{ path: 'a.ts', content: 'x' }]);
        expect(res.status).toBe(403);
        bodies.push(JSON.stringify(errorOf(await readJson(res)).message));
      }
      expect(new Set(bodies).size).toBe(1); // identical messages — no oracle
    } finally {
      await server.stop();
    }
  });

  test('oversized project ids stay uniform too', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const res = await putSources(server, owner, `prj_${'x'.repeat(200)}`, [{ path: 'a.ts', content: 'x' }]);
      expect(res.status).toBe(403);
    } finally {
      await server.stop();
    }
  });
});

describe('source snapshot API: upload validation (the path policy)', () => {
  async function setup(): Promise<{ server: TestServer; owner: Cookies; projectId: string }> {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    const owner = await login(server, 'owner@example.test');
    const projectId = await createProject(server, owner);
    return { server, owner, projectId };
  }

  test('a valid snapshot is stored; the response is metadata-only', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const res = await putSources(server, owner, projectId, SAFE_SOURCE);
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as {
        data: { snapshot: { fileCount: number; totalBytes: number; files: Array<{ path: string; bytes: number }> } };
      };
      expect(body.data.snapshot.fileCount).toBe(4);
      expect(body.data.snapshot.files.map((file) => file.path).sort()).toEqual(
        ['README.md', 'src/db.ts', 'src/index.ts', 'src/lib/safe.ts'],
      );
      // No content, no owner material in the response.
      expect(JSON.stringify(body)).not.toContain('export const version');
      expect(JSON.stringify(body)).not.toContain('ownerId');
      const meta = await getSources(server, owner, projectId);
      expect(meta.status).toBe(200);
      expect(JSON.stringify(await readJson(meta))).not.toContain('export const version');
    } finally {
      await server.stop();
    }
  });

  test('GET without a snapshot is an honest 404', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const res = await getSources(server, owner, projectId);
      expect(res.status).toBe(404);
      expect(errorOf(await readJson(res)).code).toBe('NOT_FOUND');
    } finally {
      await server.stop();
    }
  });

  test('PUT replaces the snapshot atomically; an empty list clears it', async () => {
    const { server, owner, projectId } = await setup();
    try {
      await putSources(server, owner, projectId, SAFE_SOURCE);
      const replaced = await putSources(server, owner, projectId, [
        { path: 'only.ts', content: 'export const next = true;\n' },
      ]);
      expect(replaced.status).toBe(200);
      const meta = (await readJson(await getSources(server, owner, projectId))) as {
        data: { snapshot: { fileCount: number; files: Array<{ path: string }> } };
      };
      expect(meta.data.snapshot.fileCount).toBe(1);
      expect(meta.data.snapshot.files[0]?.path).toBe('only.ts');
      const cleared = await putSources(server, owner, projectId, []);
      expect(cleared.status).toBe(404); // cleared state, honestly reported
      expect((await getSources(server, owner, projectId)).status).toBe(404);
    } finally {
      await server.stop();
    }
  });

  test('traversal-shaped paths are rejected (422) — ../../, absolute, drive, UNC, backslash, NUL, percent', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const evil = [
        '../../etc/passwd',
        '/etc/passwd',
        'C:/win/system32',
        '\\\\server\\share\\x.ts',
        'src\\app.ts',
        'src/app\u0000.ts',
        'src/%2e%2e/app.ts',
        'src/..%2F..%2Fapp.ts',
        '..',
        'a/../b.ts',
      ];
      for (const path of evil) {
        const res = await putSources(server, owner, projectId, [{ path, content: 'x' }]);
        expect(res.status, JSON.stringify(path)).toBe(422);
      }
      // And nothing was stored.
      expect((await getSources(server, owner, projectId)).status).toBe(404);
    } finally {
      await server.stop();
    }
  });

  test('dotfiles and credential-material files are rejected outright', async () => {
    const { server, owner, projectId } = await setup();
    try {
      for (const path of ['.env', '.git/config', 'config/.env', 'keys/prod.pem', 'keys/id.key', 'auth.p12', 'prod.env']) {
        const res = await putSources(server, owner, projectId, [{ path, content: 'SECRET=1\n' }]);
        expect(res.status, path).toBe(422);
      }
    } finally {
      await server.stop();
    }
  });

  test('binary-shaped content is rejected (text-only snapshots)', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const res = await putSources(server, owner, projectId, [
        { path: 'blob.ts', content: 'const x = 1;\u0000const y = 2;' },
      ]);
      expect(res.status).toBe(422);
      const issue = (await readJson(res)) as { error: { details: Array<{ path: string }> } };
      expect(issue.error.details[0]?.path).toContain('content');
    } finally {
      await server.stop();
    }
  });

  test('duplicate paths, unknown properties and prototype payloads are rejected', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const dup = await putSources(server, owner, projectId, [
        { path: 'a.ts', content: 'x' },
        { path: 'a.ts', content: 'y' },
      ]);
      expect(dup.status).toBe(422);

      const extra = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: JSON.stringify({ files: [{ path: 'a.ts', content: 'x', ownerId: 'usr_1' }] }),
      });
      expect(extra.status).toBe(422);

      // Prototype pollution payload: built via JSON.parse so __proto__
      // is an OWN property that survives the round-trip (an object
      // literal would silently set the prototype instead).
      const protoBody = JSON.parse(
        '{"files":[{"path":"a.ts","content":"x"}],"__proto__":{"admin":true}}',
      ) as unknown;
      const proto = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: JSON.stringify(protoBody),
      });
      expect(proto.status).toBe(422);

      const evilFile = JSON.parse(
        '{"files":[{"path":"a.ts","content":"x","__proto__":{"admin":true},"constructor":{"prototype":{}}}]}',
      ) as unknown;
      const evilRes = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: JSON.stringify(evilFile),
      });
      expect(evilRes.status).toBe(422);
    } finally {
      await server.stop();
    }
  });

  test('file-count and size caps are enforced (422/413) with nothing stored', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const tooMany = await putSources(
        server,
        owner,
        projectId,
        Array.from({ length: 201 }, (_, i) => ({ path: `f${i}.ts`, content: 'x' })),
      );
      expect(tooMany.status).toBe(422);
      const tooManyBody = (await readJson(tooMany)) as {
        error: { details: Array<{ message: string }> };
      };
      expect(tooManyBody.error.details[0]?.message).toContain('at most 200 files');

      // Per-file BYTE cap: multibyte content whose byte size exceeds the
      // cap while staying under the character bound (the two-layer
      // check: schema chars, route bytes).
      const tooBig = await putSources(server, owner, projectId, [
        { path: 'big.ts', content: 'é'.repeat(140_000) }, // 280 000 bytes
      ]);
      expect(tooBig.status).toBe(413);

      const totalTooBig = await putSources(
        server,
        owner,
        projectId,
        Array.from({ length: 4 }, (_, i) => ({ path: `f${i}.ts`, content: 'x'.repeat(220_000) })),
      );
      expect(totalTooBig.status).toBe(413);

      expect((await getSources(server, owner, projectId)).status).toBe(404);
    } finally {
      await server.stop();
    }
  });

  test('archived projects: PUT rejected 409 PROJECT_ARCHIVED, metadata still readable', async () => {
    const { server, owner, projectId } = await setup();
    try {
      await putSources(server, owner, projectId, SAFE_SOURCE);
      const archive = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/archive`, {
        method: 'POST',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(archive.status).toBe(200);
      const res = await putSources(server, owner, projectId, [{ path: 'a.ts', content: 'x' }]);
      expect(res.status).toBe(409);
      expect(errorOf(await readJson(res)).code).toBe('PROJECT_ARCHIVED');
      const meta = await getSources(server, owner, projectId);
      expect(meta.status).toBe(200); // read-only stays readable
    } finally {
      await server.stop();
    }
  });

  test('wrong methods on /sources answer 405 + Allow; non-JSON content type 415', async () => {
    const { server, owner, projectId } = await setup();
    try {
      const del = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'DELETE',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(del.status).toBe(405);
      expect(del.headers.get('allow')).toContain('PUT');
      expect(del.headers.get('allow')).toContain('GET');
      const post = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: '{}',
      });
      expect(post.status).toBe(405);
      const wrongType = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
        method: 'PUT',
        headers: { 'content-type': 'text/plain', cookie: cookieHeader(owner) },
        body: 'files=[]',
      });
      expect(wrongType.status).toBe(415);
    } finally {
      await server.stop();
    }
  });
});

describe('source snapshot API: strict query rejection (Pump 3)', () => {
  test('unexpected query parameters are rejected (422) with nothing stored', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const url = `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`;
      // PUT + junk query: rejected before any body handling; nothing stored.
      for (const query of ['?mode=overwrite', '?scan=true']) {
        const res = await fetch(`${url}${query}`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
          body: JSON.stringify({ files: [{ path: 'src/index.ts', content: 'const x = 1;\n' }] }),
        });
        expect(res.status, query).toBe(422);
        const json = (await readJson(res)) as { error: { code: string } };
        expect(json.error.code).toBe('VALIDATION_ERROR');
      }
      // GET + junk query: rejected too.
      const probe = await fetch(`${url}?include=content`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(probe.status).toBe(422);
      // Nothing was stored by any rejected PUT (metadata → honest 404).
      const cleanGet = await fetch(url, { headers: { cookie: cookieHeader(owner) } });
      expect(cleanGet.status).toBe(404);
      // A clean PUT keeps working (the hardening rejects junk, not traffic).
      const okPut = await putSources(server, owner, projectId, [
        { path: 'src/index.ts', content: 'const x = 1;\n' },
      ]);
      expect(okPut.status).toBe(200);
    } finally {
      await server.stop();
    }
  });
});

describe('SAST scans: the real engine over HTTP', () => {
  test('SAST without a snapshot → 409 pre-flight, NOTHING consumed', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const { res, body } = await requestScan(server, owner, projectId, 'SAST');
      expect(res.status).toBe(409);
      expect(errorOf(body).message).toContain('Upload a source snapshot');
      expect(await getUsage(server, owner)).toEqual({ used: 0 }); // quota protected
      // An EMPTY (cleared) snapshot is equally no target.
      await putSources(server, owner, projectId, [{ path: 'a.ts', content: 'x' }]);
      await putSources(server, owner, projectId, []);
      const again = await requestScan(server, owner, projectId, 'SAST');
      expect(again.res.status).toBe(409);
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
    } finally {
      await server.stop();
    }
  });

  test('SAFE source: scan COMPLETES with zero findings and honest file counts', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, SAFE_SOURCE);
      const { res, body } = await requestScan(server, owner, projectId, 'SAST');
      expect(res.status).toBe(201);
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.scanType).toBe('SAST');
      expect(detail.data.scan.resultSummary).toEqual({
        findingsTotal: 0,
        findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        filesScanned: 3, // README.md is unsupported → skipped
        filesSkipped: 1,
        truncated: false,
        // Pump 16: bounded AST/dataflow pass runs on the supported families.
        astFilesAnalyzed: 3,
        astFlowsFound: 0,
      });
      expect(detail.data.scan.findings).toEqual([]);
      expect(detail.data.scan.failureCode).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('VULNERABLE source: the six real rules fire with evidence, severity and remediation', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const { res, body } = await requestScan(server, owner, projectId, 'SAST');
      expect(res.status).toBe(201);
      expect(scanOf(body).status).toBe('QUEUED');
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(6);
      const findings: Finding[] = detail.data.scan.findings;
      expect(findings.map((finding) => finding.ruleId).sort()).toEqual([
        'DG-SAST-001',
        'DG-SAST-002',
        'DG-SAST-003',
        'DG-SAST-004',
        'DG-SAST-005',
        'DG-SAST-006',
      ]);
      // Deterministic order: severity rank first (HIGH before MEDIUM before LOW).
      expect(findings[0]?.severity).toBe('HIGH');
      expect(findings[5]?.severity).toBe('LOW');
      const secret = findings.find((finding) => finding.ruleId === 'DG-SAST-005');
      expect(secret?.evidence).toContain('<redacted>');
      expect(secret?.evidence).not.toContain('sk_live_abcdef123456');
      expect(secret?.remediation).toContain('secret manager');
      const cmd = findings.find((finding) => finding.ruleId === 'DG-SAST-001');
      expect(cmd?.file).toBe('src/cmd.ts');
      expect(cmd?.line).toBe(2);
      expect(cmd?.cwe).toBe('CWE-78');
      // The LIST response stays lean (no findings inline).
      const list = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        headers: { cookie: cookieHeader(owner) },
      });
      const listBody = (await readJson(list)) as { data: { scans: Array<Record<string, unknown>> } };
      expect(listBody.data.scans[0]?.['findings']).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('quota consumed exactly once; idempotent replay returns the same scan with the same findings', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const first = await requestScan(server, owner, projectId, 'SAST', 'sast-retry-01');
      expect(first.res.status).toBe(201);
      await server.scanProcessor.drain();
      const replay = await requestScan(server, owner, projectId, 'SAST', 'sast-retry-01');
      expect(replay.res.status).toBe(200); // the ORIGINAL scan
      expect(scanOf(replay.body).id).toBe(scanOf(first.body).id);
      expect(await getUsage(server, owner)).toEqual({ used: 1 }); // exactly one charge
      const detail = await getScanDetail(server, owner, projectId, scanOf(first.body).id);
      expect(detail.data.scan.findings.map((f) => f.id).sort()).toEqual(
        (await getScanDetail(server, owner, projectId, scanOf(replay.body).id)).data.scan.findings
          .map((f) => f.id)
          .sort(),
      );
    } finally {
      await server.stop();
    }
  });

  test('rescanning unchanged source reproduces identical finding ids (stable fingerprints)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const first = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      const second = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      const firstFindings = (await getScanDetail(server, owner, projectId, scanOf(first.body).id)).data.scan.findings;
      const secondFindings = (await getScanDetail(server, owner, projectId, scanOf(second.body).id)).data.scan.findings;
      expect(firstFindings.map((f) => `${f.id}:${f.fingerprint}`).sort()).toEqual(
        secondFindings.map((f) => `${f.id}:${f.fingerprint}`).sort(),
      );
    } finally {
      await server.stop();
    }
  });

  test('SCA, SECRETS and limited passive DAST are registered real engines', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      // A manifest-bearing snapshot: SCA has real work to do.
      await putSources(server, owner, projectId, [
        ...SAFE_SOURCE,
        {
          path: 'package.json',
          content: '{"name":"safe-app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}',
        },
      ]);
      const sca = await requestScan(server, owner, projectId, 'SCA');
      expect(sca.res.status).toBe(201);
      await server.scanProcessor.drain();
      const scaDetail = await getScanDetail(server, owner, projectId, scanOf(sca.body).id);
      expect(scaDetail.data.scan.status).toBe('COMPLETED');
      expect(scaDetail.data.scan.findings).toEqual([]);
      expect(scaDetail.data.scan.sca?.summary.dependenciesTotal).toBe(1);
      // PUMP 10: SECRETS is a REAL engine too. Over SAFE_SOURCE it
      // completes with 0 findings — the honest "nothing found in what
      // was inspected", never "risk unknown".
      const secrets = await requestScan(server, owner, projectId, 'SECRETS');
      expect(secrets.res.status).toBe(201);
      await server.scanProcessor.drain();
      const secretsDetail = await getScanDetail(
        server,
        owner,
        projectId,
        scanOf(secrets.body).id,
      );
      expect(secretsDetail.data.scan.status).toBe('COMPLETED');
      expect(secretsDetail.data.scan.findings).toEqual([]);
      // 4 scannable files (3 code + package.json); README.md is an
      // unsupported format → skipped, never interpreted.
      expect(secretsDetail.data.scan.resultSummary?.filesScanned).toBe(4);
      expect(secretsDetail.data.scan.resultSummary?.filesSkipped).toBe(1);
      expect(secretsDetail.data.scan.resultSummary?.truncated).toBe(false);
      expect(secretsDetail.data.scan.sca).toBeUndefined();
      // Pump 11: the bounded passive DAST engine runs only through an
      // injected synthetic response fixture; no target network is used.
      const { res, body } = await requestScan(server, owner, projectId, 'DAST');
      expect(res.status).toBe(201);
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.failureCode).toBeUndefined();
      expect(detail.data.scan.findings.length).toBeGreaterThan(0);
      expect(detail.data.scan.findings.every((finding) => finding.scanner === 'DAST')).toBe(true);
      expect(detail.data.scan.dast?.requestCount).toBe(1);
      expect(detail.data.scan.sca).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('v2: pass-through-only python/java snapshots are analyzed honestly with zero findings', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, [
        { path: 'app.py', content: 'import os\nos.system(user)\n' },
        { path: 'Main.java', content: 'Runtime.getRuntime().exec(user);\n' },
      ]);
      const { res, body } = await requestScan(server, owner, projectId, 'SAST');
      expect(res.status).toBe(201);
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.resultSummary).toEqual({
        findingsTotal: 0,
        findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        filesScanned: 2,
        filesSkipped: 0,
        truncated: false,
        astFilesAnalyzed: 2,
        astFlowsFound: 0,
      });
    } finally {
      await server.stop();
    }
  });

  test('SAST on an ARCHIVED project → 409 PROJECT_ARCHIVED (the lifecycle rule first)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, SAFE_SOURCE);
      const archive = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/archive`, {
        method: 'POST',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(archive.status).toBe(200);
      const { res, body } = await requestScan(server, owner, projectId, 'SAST');
      expect(res.status).toBe(409);
      expect(errorOf(body).code).toBe('PROJECT_ARCHIVED');
    } finally {
      await server.stop();
    }
  });

  test('cross-account isolation: attacker cannot read scans or findings of the owner', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await seedUser(users, 'attacker@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const attackerProject = await createProject(server, attacker, 'Attacker app');
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      const scanId = scanOf(body).id;
      // Project-level: uniform 403.
      expect((await putSources(server, attacker, projectId, [{ path: 'a.ts', content: 'x' }])).status).toBe(403);
      // Scan-level: the owner's scan id inside the attacker's OWN
      // project answers the same 404 as an unknown id (no oracle).
      for (const id of [scanId, 'scan_unknown-malformed', 'scan_00000000-0000-4000-8000-00000000dead']) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(attackerProject)}/scans/${encodeURIComponent(id)}`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status).toBe(404);
        expect(errorOf(await readJson(res)).code).toBe('NOT_FOUND');
      }
    } finally {
      await server.stop();
    }
  });

  test('concurrent SAST scans of two projects stay isolated (no finding leakage)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const safeProject = await createProject(server, owner, 'Safe');
      const vulnProject = await createProject(server, owner, 'Vulnerable');
      await putSources(server, owner, safeProject, SAFE_SOURCE);
      await putSources(server, owner, vulnProject, VULNERABLE_SOURCE);
      const [safeScan, vulnScan] = await Promise.all([
        requestScan(server, owner, safeProject, 'SAST'),
        requestScan(server, owner, vulnProject, 'SAST'),
      ]);
      await Promise.all([server.scanProcessor.drain(), server.scanProcessor.drain()]);
      await server.scanProcessor.drain();
      const safeDetail = await getScanDetail(server, owner, safeProject, scanOf(safeScan.body).id);
      const vulnDetail = await getScanDetail(server, owner, vulnProject, scanOf(vulnScan.body).id);
      expect(safeDetail.data.scan.findings).toEqual([]); // nothing leaked in
      expect(vulnDetail.data.scan.findings).toHaveLength(6); // nothing lost
    } finally {
      await server.stop();
    }
  });

  test('scan detail responses are validated shapes; findings only via the detail route', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      const res = await fetch(
        `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanOf(body).id)}`,
        { headers: { cookie: cookieHeader(owner) } },
      );
      const payload = (await readJson(res)) as { data: unknown };
      // The envelope carries exactly { scan } and the scan carries the
      // public fields + findings (validated by the shared guard).
      const detail = payload.data as { scan: ScanDetailResponse['scan'] };
      expect(Object.keys(payload.data as Record<string, unknown>)).toEqual(['scan']);
      expect(Object.keys(detail.scan).sort()).toEqual([
        'completedAt',
        'createdAt',
        'findings',
        'id',
        'projectId',
        'resultSummary',
        'scanType',
        'startedAt',
        'status',
        'updatedAt',
      ]);
      expect(detail.scan.findings.every((finding) => finding.scanId === detail.scan.id)).toBe(true);
    } finally {
      await server.stop();
    }
  });

  test('log hygiene: no source content or secret values in logs', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    // Opt into info logging to assert what IS and IS NOT logged.
    const server = await startTestServer({ users, logLevel: 'info' });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULNERABLE_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      await getScanDetail(server, owner, projectId, scanOf(body).id);
      const logs = server.logs.join('\n');
      expect(logs).not.toContain('sk_live_abcdef123456');
      expect(logs).not.toContain('exec(`rm -rf');
      expect(logs).not.toContain('SELECT * FROM users');
      expect(logs).toContain('Scan completed'); // the lifecycle IS logged (ids only)
    } finally {
      await server.stop();
    }
  });
});

describe('SAST persistence and corruption', () => {
  test('snapshots AND findings survive an API restart (durable stores)', async () => {
    const dir = makeTempStoreDir('sast-restart');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const first = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir,
      projectStoreDir: dir,
    });
    let scanId: string;
    let projectId: string;
    try {
      const owner = await login(first, 'owner@example.test');
      projectId = await createProject(first, owner);
      await putSources(first, owner, projectId, VULNERABLE_SOURCE);
      const { body } = await requestScan(first, owner, projectId, 'SAST');
      scanId = scanOf(body).id;
      await first.scanProcessor.drain();
    } finally {
      await first.stop();
    }
    const second = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir,
      projectStoreDir: dir,
    });
    try {
      const relogin = await login(second, 'owner@example.test');
      // Snapshot metadata survives.
      const meta = await getSources(second, relogin, projectId);
      expect(meta.status).toBe(200);
      // Findings survive byte-identically.
      const detail = await getScanDetail(second, relogin, projectId, scanId);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.findings).toHaveLength(6);
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(6);
      // A NEW scan on the restored snapshot produces identical finding ids.
      const { body } = await requestScan(second, relogin, projectId, 'SAST');
      await second.scanProcessor.drain();
      const secondDetail = await getScanDetail(second, relogin, projectId, scanOf(body).id);
      expect(secondDetail.data.scan.findings.map((f) => f.id).sort()).toEqual(
        detail.data.scan.findings.map((f) => f.id).sort(),
      );
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('the source store file contains no account material and is 0600', async () => {
    const dir = makeTempStoreDir('sast-store-hygiene');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users, sourceStoreDir: dir });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, SAFE_SOURCE);
      const raw = readFileSync(join(dir, 'sources.json'), 'utf8');
      expect(raw).not.toContain('owner@example.test');
      expect(raw).toContain('ownerId'); // internal field, but no account identifiers
      expect(raw).not.toContain('password');
    } finally {
      await server.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('a corrupt source store refuses to start (no silent repair)', async () => {
    const dir = makeTempStoreDir('sast-corrupt');
    writeFileSync(join(dir, 'sources.json'), 'NOT JSON {{{', { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(
      startTestServer({ users, sourceStoreDir: dir }),
    ).rejects.toThrow(/not valid JSON|refusing to start/);
    cleanupTempStoreDir(dir);
  });

  test('a traversal-shaped path in a stored snapshot refuses to start (containment at load)', async () => {
    const dir = makeTempStoreDir('sast-poisoned');
    const poisoned = {
      version: 1,
      snapshots: [
        {
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          ownerId: 'usr_1',
          files: [{ path: '../../etc/passwd', bytes: 4, content: 'root' }],
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
        },
      ],
    };
    writeFileSync(join(dir, 'sources.json'), JSON.stringify(poisoned), { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(startTestServer({ users, sourceStoreDir: dir })).rejects.toThrow(/refusing to start/);
    cleanupTempStoreDir(dir);
  });

  test('a findings-injected scan record refuses to start (cross-scan findings = corrupt)', async () => {
    const dir = makeTempStoreDir('sast-finding-inject');
    const finding = {
      id: `fnd_${'a'.repeat(24)}`,
      scanId: 'scan_00000000-0000-4000-8000-000000000009',
      ruleId: 'DG-SAST-001',
      severity: 'HIGH',
      title: 't',
      description: 'd',
      file: 'a.ts',
      line: 1,
      column: 1,
      evidence: 'exec(`x ${y}`)',
      remediation: 'r',
      fingerprint: 'b'.repeat(64),
    };
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000001',
          ownerId: 'usr_1',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SAST',
          status: 'COMPLETED',
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
          startedAt: '2026-09-28T10:00:00.000Z',
          completedAt: '2026-09-28T10:00:01.000Z',
          resultSummary: { findingsTotal: 1 },
          findings: [finding], // scanId mismatch → corrupt, refuse to boot
        },
      ],
      idempotency: [],
    };
    writeFileSync(join(dir, 'scans.json'), JSON.stringify(forged), { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(startTestServer({ users, scanStoreDir: dir })).rejects.toThrow(/refusing to start/);
    cleanupTempStoreDir(dir);
  });
});
