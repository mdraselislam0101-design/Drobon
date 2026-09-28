import { describe, expect, test } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import type { ScanDetailResponse } from '@drobon/shared';
import {
  cleanupTempStoreDir,
  configureFixtureDastTarget,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

interface Cookies {
  session: string;
  device?: string;
}

/**
 * Pump 9 SCA API — the dependency-analysis surface over real HTTP.
 *
 * - PRE-FLIGHT: SCA without a snapshot → 409, NOTHING consumed;
 * - REAL SCANS: manifests → COMPLETED with a validated SCA payload
 *   (inventory, SBOM, NOT_ASSESSED honesty); payload ONLY in the
 *   detail route; quota consumed exactly once; idempotent replay;
 * - HONESTY: a fixture that LOOKS vulnerable yields ZERO advisories
 *   (no dataset → no fabricated CVE/GHSA/EPSS ever);
 * - ISOLATION: cross-account 403/404 — no inventory leakage;
 * - TAMPER GUARDS: client-injected `sca` payloads are not possible
 *   via the API, and forged ones on disk refuse to boot;
 * - PERSISTENCE: SCA payloads survive restarts byte-identically;
 * - REGRESSION: SAST still works with the SCA engine registered.
 */

const PW = 'sca-pw-test';

type Subscription = NonNullable<UserRecord['subscription']>;
const PRO_ACTIVE: Subscription = {
  plan: 'PRO',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};

async function seedUser(
  repo: UserRepository,
  email: string,
  subscription: Subscription | undefined = undefined,
): Promise<void> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role: 'MEMBER',
    userType: null,
    ...(subscription === undefined ? {} : { subscription }),
  };
  if (!(await repo.create(record))) {
    throw new Error(`Seed collision for ${email}`);
  }
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
  const rawDevice = probe.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
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
    body: JSON.stringify({ name }),
  });
  if (res.status !== 201) {
    throw new Error(`Project creation failed with status ${res.status}.`);
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

async function requestScan(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  scanType = 'SCA',
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ scanType }),
  });
  return { res, body: await readJson(res) };
}

function scanOf(body: unknown): { id: string; status: string } {
  return (body as { data: { scan: { id: string; status: string } } }).data.scan;
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

/**
 * A realistic dependency snapshot that LOOKS like a vulnerable stack
 * (old express/lodash pins). The honesty tests assert ZERO advisories:
 * without a real dataset, nothing is ever fabricated.
 */
const VULN_LOOKING_SOURCE: SourceFile[] = [
  {
    path: 'package.json',
    content: JSON.stringify({
      name: 'demo-app',
      version: '1.4.2',
      dependencies: { express: '^4.18.0', lodash: '^4.17.15' },
    }),
  },
  {
    path: 'package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'demo-app',
          version: '1.4.2',
          dependencies: { express: '^4.18.0', lodash: '^4.17.15' },
        },
        'node_modules/express': { version: '4.17.1' },
        'node_modules/lodash': { version: '4.17.15' },
        'node_modules/accepts': { version: '1.3.7' },
      },
    }),
  },
  { path: 'requirements.txt', content: 'flask==1.1.1\nrequests==2.25.0\n' },
  { path: 'src/index.ts', content: 'export const version = 1;\n' },
  // A hostile manifest that must be treated as pure data.
  {
    path: 'tools/package.json',
    content: JSON.stringify({
      name: 'tools',
      scripts: { postinstall: 'touch /tmp/pump9-sca-api-marker' },
      dependencies: { lodash: '^3.0.0' },
    }),
  },
];

describe('SCA API: pre-flight and lifecycle', () => {
  test('SCA without a source snapshot → 409 pre-flight, quota NOT consumed', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const before = await getUsage(server, owner);
      const { res, body } = await requestScan(server, owner, projectId, 'SCA');
      expect(res.status).toBe(409);
      expect(errorOf(body).code).toBe('CONFLICT');
      expect(errorOf(body).message).toContain('Upload a source snapshot');
      expect(errorOf(body).message).toContain('SCA');
      expect(await getUsage(server, owner)).toEqual(before); // nothing consumed
    } finally {
      await server.stop();
    }
  });

  test('a real SCA scan: COMPLETED, validated payload, detail-route only', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const before = await getUsage(server, owner);
      const { res, body } = await requestScan(server, owner, projectId, 'SCA');
      expect(res.status).toBe(201);
      await server.scanProcessor.drain();

      // LIST responses stay lean: no sca payload there.
      const list = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        headers: { cookie: cookieHeader(owner) },
      });
      const listBody = (await readJson(list)) as { data: { scans: unknown[] } };
      expect(list.status).toBe(200);
      expect(listBody.data.scans).toHaveLength(1);
      expect(JSON.stringify(listBody)).not.toContain('"sbom"');
      expect(JSON.stringify(listBody)).not.toContain('"advisories"');

      // The detail route carries the full SCA result.
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      const sca = detail.data.scan.sca;
      expect(sca).toBeDefined();
      if (sca === undefined) {
        return;
      }
      // HONESTY: the snapshot looks vulnerable, but no dataset is
      // loaded — zero advisories, NOT_ASSESSED, nothing fabricated.
      expect(sca.summary.assessmentState).toBe('NOT_ASSESSED');
      expect(sca.summary.datasetStatus).toBe('NO_DATA_LOADED');
      expect(sca.summary.advisoriesTotal).toBe(0);
      expect(sca.advisories).toEqual([]);
      // …and the real dependency analysis is intact.
      expect(sca.summary.dependenciesTotal).toBe(5); // express, lodash, accepts, flask, requests
      expect(sca.summary.directDependencies).toBe(4);
      expect(sca.summary.transitiveDependencies).toBe(1); // accepts
      expect(sca.summary.transitiveGraph).toBe('AVAILABLE');
      const byName = new Map(sca.dependencies.map((dep) => [dep.name, dep]));
      expect(byName.get('express')).toMatchObject({
        declaredVersion: '^4.18.0',
        resolvedVersion: '4.17.1',
        dependencyClass: 'direct',
      });
      expect(byName.get('flask')).toMatchObject({
        declaredVersion: '==1.1.1',
        ecosystem: 'pypi',
      });
      // The SBOM is present and anchored at the root component.
      expect(sca.sbom.metadata.component).toMatchObject({ name: 'demo-app', version: '1.4.2' });
      // Manifest evidence includes both ecosystems.
      const manifestPaths = sca.manifests.map((manifest) => manifest.path).sort();
      expect(manifestPaths).toEqual([
        'package-lock.json',
        'package.json',
        'requirements.txt',
        'tools/package.json',
      ]);
      // Findings stay empty — SCA reports advisories, not SAST findings.
      expect(detail.data.scan.findings).toEqual([]);
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(0);
      // Quota consumed exactly once.
      expect((await getUsage(server, owner)).used).toBe(before.used + 1);

      // The postinstall marker NEVER ran (manifests are data).
      const { existsSync, rmSync } = await import('node:fs');
      expect(existsSync('/tmp/pump9-sca-api-marker')).toBe(false);
      rmSync('/tmp/pump9-sca-api-marker', { force: true });
    } finally {
      await server.stop();
    }
  });

  test('idempotent replay: same key returns the SAME scan, no new quota', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const first = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner), 'idempotency-key': 'sca-once' },
        body: JSON.stringify({ scanType: 'SCA' }),
      });
      expect(first.status).toBe(201);
      await server.scanProcessor.drain();
      const replay = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner), 'idempotency-key': 'sca-once' },
        body: JSON.stringify({ scanType: 'SCA' }),
      });
      expect(replay.status).toBe(200);
      expect(scanOf(await readJson(replay)).id).toBe(scanOf(await readJson(first)).id);
    } finally {
      await server.stop();
    }
  });

  test('SCA on an ARCHIVED project → 409 PROJECT_ARCHIVED (lifecycle first)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const archive = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/archive`, {
        method: 'POST',
        headers: { cookie: cookieHeader(owner) },
      });
      expect(archive.status).toBe(200);
      const { res, body } = await requestScan(server, owner, projectId, 'SCA');
      expect(res.status).toBe(409);
      expect(errorOf(body).code).toBe('PROJECT_ARCHIVED');
    } finally {
      await server.stop();
    }
  });
});

describe('SCA API: isolation and honesty', () => {
  test('cross-account isolation: no inventory leakage to another account', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    await seedUser(users, 'attacker@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner, 'Owner app');
      const attackerProject = await createProject(server, attacker, 'Attacker app');
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SCA');
      await server.scanProcessor.drain();
      const scanId = scanOf(body).id;
      // Uniform 403 at the project level (no existence oracle).
      expect(
        (
          await putSources(server, attacker, projectId, [
            { path: 'package.json', content: '{"name":"evil"}' },
          ])
        ).status,
      ).toBe(403);
      // The owner's scan id inside the attacker's project: uniform 404.
      for (const id of [scanId, 'scan_unknown', 'scan_00000000-0000-4000-8000-00000000dead']) {
        const res = await fetch(
          `${server.baseUrl}/api/v1/projects/${encodeURIComponent(attackerProject)}/scans/${encodeURIComponent(id)}`,
          { headers: { cookie: cookieHeader(attacker) } },
        );
        expect(res.status).toBe(404);
      }
      // And the attacker's OWN SCA scan on their own (empty) project is
      // honestly pre-flighted, not fed the owner's snapshot.
      const attackerScan = await requestScan(server, attacker, attackerProject, 'SCA');
      expect(attackerScan.res.status).toBe(409);
      expect(errorOf(attackerScan.body).message).toContain('SCA');
    } finally {
      await server.stop();
    }
  });

  test('no manifest content and no SBOM serial leak into LIST responses or usage', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SCA');
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      const list = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        headers: { cookie: cookieHeader(owner) },
      });
      const listText = JSON.stringify(await readJson(list));
      expect(listText).not.toContain('demo-app'); // inventory stays in the detail route
      expect(listText).not.toContain('flask');
      // The DETAIL response carries the inventory but never raw file
      // content (paths and dependency names only).
      const detailText = JSON.stringify(detail);
      expect(detailText).toContain('demo-app'); // the SBOM root name (a public name)
      expect(detailText).not.toContain('postinstall'); // scripts are NOT part of the inventory
      expect(detailText).not.toContain('touch /tmp');
    } finally {
      await server.stop();
    }
  });
});

describe('SCA API: persistence and tamper guards', () => {
  test('SCA payloads survive an API restart byte-identically; rescans are deterministic', async () => {
    const dir = makeTempStoreDir('sca-restart');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const first = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir,
      projectStoreDir: dir,
    });
    let scanId = '';
    let projectId = '';
    let firstSca: unknown;
    try {
      const owner = await login(first, 'owner@example.test');
      projectId = await createProject(first, owner);
      await putSources(first, owner, projectId, VULN_LOOKING_SOURCE);
      const { body } = await requestScan(first, owner, projectId, 'SCA');
      scanId = scanOf(body).id;
      await first.scanProcessor.drain();
      firstSca = (await getScanDetail(first, owner, projectId, scanId)).data.scan.sca;
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
      const restored = await getScanDetail(second, relogin, projectId, scanId);
      expect(restored.data.scan.status).toBe('COMPLETED');
      expect(restored.data.scan.sca).toEqual(firstSca); // byte-identical
      // A rescan on the restored snapshot reproduces identical ids.
      const { body } = await requestScan(second, relogin, projectId, 'SCA');
      await second.scanProcessor.drain();
      const rescan = await getScanDetail(second, relogin, projectId, scanOf(body).id);
      const before = (firstSca as { dependencies: Array<{ dependencyId: string }> }).dependencies;
      const after = rescan.data.scan.sca?.dependencies;
      expect(after?.map((dep) => dep.dependencyId)).toEqual(before.map((dep) => dep.dependencyId));
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('a forged sca payload on a NON-SCA scan refuses to start', async () => {
    const dir = makeTempStoreDir('sca-tamper-sast');
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000001',
          ownerId: 'usr_1',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SAST', // SCA payload on a SAST scan = corrupt
          status: 'COMPLETED',
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
          startedAt: '2026-09-28T10:00:00.000Z',
          completedAt: '2026-09-28T10:00:01.000Z',
          sca: { summary: {}, dependencies: [], advisories: [], manifests: [], sbom: {} },
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

  test('a forged sca payload on a QUEUED (never-run) SCA scan refuses to start', async () => {
    const dir = makeTempStoreDir('sca-tamper-queued');
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000001',
          ownerId: 'usr_1',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SCA',
          status: 'QUEUED', // a queued scan can never carry engine output
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
          sca: { summary: {}, dependencies: [], advisories: [], manifests: [], sbom: {} },
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

  test('a structurally-invalid sca payload (fabricated advisories) refuses to start', async () => {
    const dir = makeTempStoreDir('sca-tamper-shape');
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000001',
          ownerId: 'usr_1',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SCA',
          status: 'COMPLETED',
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
          startedAt: '2026-09-28T10:00:00.000Z',
          completedAt: '2026-09-28T10:00:01.000Z',
          // Malformed summary + fabricated advisory — both invalid.
          sca: {
            summary: { assessmentState: 'ASSESSED', datasetStatus: 'LOADED', advisoriesTotal: 1 },
            dependencies: [],
            advisories: [{ id: 'CVE-FAKE-0001', severity: 'CRITICAL' }],
            manifests: [],
            sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [], dependencies: [] },
          },
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

  test('clients cannot inject an sca payload: the request body accepts only scanType', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
        body: JSON.stringify({
          scanType: 'SCA',
          sca: { summary: { assessmentState: 'ASSESSED', advisoriesTotal: 99 }, advisories: [] },
          resultSummary: { findingsTotal: 42 },
        }),
      });
      expect(res.status).toBe(422); // unknown properties are rejected
      const detail = errorOf(await readJson(res));
      expect(detail.code).toBe('VALIDATION_ERROR');
    } finally {
      await server.stop();
    }
  });
});

describe('SCA API: SAST regression with the SCA engine registered', () => {
  test('SAST scans still complete with findings; SCA payload stays undefined there', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, [
        { path: 'package.json', content: '{"name":"app","dependencies":{"lodash":"^4.0.0"}}' },
        { path: 'src/cmd.ts', content: 'export function run(dir: string) {\n  exec(`rm -rf ${dir}`);\n}\n' },
      ]);
      const sast = await requestScan(server, owner, projectId, 'SAST');
      expect(sast.res.status).toBe(201);
      await server.scanProcessor.drain();
      const sastDetail = await getScanDetail(server, owner, projectId, scanOf(sast.body).id);
      expect(sastDetail.data.scan.status).toBe('COMPLETED');
      expect(sastDetail.data.scan.findings).toHaveLength(1);
      expect(sastDetail.data.scan.sca).toBeUndefined(); // SAST ≠ SCA
      // And the reverse: an SCA scan of the same project carries no findings.
      const sca = await requestScan(server, owner, projectId, 'SCA');
      expect(sca.res.status).toBe(201);
      await server.scanProcessor.drain();
      const scaDetail = await getScanDetail(server, owner, projectId, scanOf(sca.body).id);
      expect(scaDetail.data.scan.findings).toEqual([]);
      expect(scaDetail.data.scan.sca?.dependencies.map((dep) => dep.name)).toEqual(['lodash']);
    } finally {
      await server.stop();
    }
  });

  test('SECRETS and limited passive DAST are registered real engines', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', PRO_ACTIVE);
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, VULN_LOOKING_SOURCE);
      // PUMP 10: the secrets engine really runs over the snapshot.
      // Manifest JSON carries no credential material → honest 0
      // findings, ANALYZED (not NOT_ASSESSED, not "risk unknown").
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
      expect(secretsDetail.data.scan.failureCode).toBeUndefined();
      expect(secretsDetail.data.scan.findings).toEqual([]);
      expect(secretsDetail.data.scan.resultSummary?.filesScanned).toBeGreaterThan(0);
      expect(secretsDetail.data.scan.resultSummary?.truncated).toBe(false);
      expect(secretsDetail.data.scan.resultSummary?.partial).toBeUndefined();
      expect(secretsDetail.data.scan.sca).toBeUndefined();
      // Pump 11 DAST uses a test-only synthetic transport fixture; it
      // performs no real network request and keeps SCA state separate.
      const { res, body } = await requestScan(server, owner, projectId, 'DAST');
      expect(res.status).toBe(201);
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.dast?.requestCount).toBe(1);
      expect(detail.data.scan.findings.every((finding) => finding.scanner === 'DAST')).toBe(true);
      expect(detail.data.scan.sca).toBeUndefined();
    } finally {
      await server.stop();
    }
  });
});
