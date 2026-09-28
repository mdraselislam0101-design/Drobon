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
  startTestServer,
  type TestServer,
} from './helpers.js';

/**
 * Pump 10 SECRETS API — the full HTTP security matrix over the real
 * engine:
 *
 * - PRE-FLIGHT: SECRETS without a snapshot → 409, NOTHING consumed;
 * - REAL SCAN: the §29 adversarial file (every category + every
 *   false-positive defense) → only the correct rules fire, and the raw
 *   values are absent from EVERY layer: response, durable scan store,
 *   and logs;
 * - §30 NO-FAKE: a clean snapshot → ANALYZED with 0 findings (never
 *   NOT_ASSESSED, never "risk unknown");
 * - FINDINGS CAP: >200 matches → truncated + partial, visible over
 *   HTTP;
 * - ISOLATION: cross-account 404 with no oracle;
 * - PERSISTENCE: findings survive restarts with identical ids;
 * - TAMPER/FAIL-FAST: a forged finding (closed-vocabulary violations)
 *   refuses to start; a corrupt scan store refuses to start;
 * - REGRESSION: SAST and SCA still run over the same snapshot.
 *
 * Every fixture value is SYNTHETIC and carries no credential power.
 */

const PW = 'secrets-pw-test';

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

function cookieHeader(cookies: Cookies): string {
  return cookies.device === undefined
    ? cookies.session
    : `${cookies.session}; drobon_device=${cookies.device}`;
}

async function login(server: TestServer, email: string): Promise<Cookies> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  const cookie = res.headers.get('set-cookie');
  if (res.status !== 200 || cookie === null) {
    throw new Error(`Login failed for ${email}: ${res.status}`);
  }
  return { session: cookie.split(';')[0] ?? '' };
}

async function createProject(server: TestServer, cookies: Cookies, name = 'Target app'): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  if (res.status !== 201) {
    throw new Error(`Project creation failed: ${res.status}`);
  }
  const body = (await readJson(res)) as { data: { project: { id: string } } };
  const projectId = body.data.project.id;
  await configureFixtureDastTarget(server, cookieHeader(cookies), projectId);
  return projectId;
}

async function putSources(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  files: Array<{ path: string; content: string }>,
): Promise<void> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ files }),
  });
  if (res.status !== 200) {
    throw new Error(`Source upload failed: ${res.status} ${await res.text()}`);
  }
}

async function requestScan(
  server: TestServer,
  cookies: Cookies,
  projectId: string,
  scanType = 'SECRETS',
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
  return (body as { data: { scan: { id: string; status: string } } }).data.scan;
}

function errorOf(body: unknown): { code: string; message: string } {
  return (body as { error: { code: string; message: string } }).error;
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
  const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
    headers: { cookie: cookieHeader(cookies) },
  });
  if (res.status !== 200) {
    throw new Error(`Usage failed: ${res.status}`);
  }
  return { used: ((await readJson(res)) as { data: { used: number } }).data.used };
}

// ---------------------------------------------------------------------------
// Synthetic fixtures (denylist-dodging on purpose: the POSITIVE paths
// must fire). PEM headers are CONCATENATED so no literal key-block
// header string exists in this file.
// ---------------------------------------------------------------------------

const SYNTH = {
  awsKey: 'AKIAP10QZ9WM7XK2BR4J', // fake-test fixture
  githubToken: 'ghp_P10aBcDeFgHiJkLmNoPqRsTuVwXyZ123456A', // fake-test fixture
  bearer: 'P10AbCdEfGhIjKlMnOpQrStUvWx40', // fake-test fixture
  dbPassword: 'P10-sUp3r-Pg', // fake-test fixture
  apiKeyValue: 'P10ApiKeyZx9Qw8Er7Ty6Uio5Pl', // fake-test fixture
  passwordValue: 'P10-C0rr3ct-Horse-Stapl3-Batt3ry', // fake-test fixture
} as const;

const PEM_HEADER = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join(''); // fake-test fixture

/** §29-style adversarial snapshot: every category AND every FP defense. */
const ADVERSARIAL_SOURCE = [
  {
    path: 'src/cloud.ts',
    content:
      `export const aws = "${SYNTH.awsKey}";\n` +
      `export const gh = "${SYNTH.githubToken}";\n`,
  },
  {
    path: 'src/auth.py',
    content:
      `HEADER = "Authorization: Bearer ${SYNTH.bearer}"\n` +
      `PASSWORD = "${SYNTH.passwordValue}"\n`, // fake
  },
  {
    path: 'src/inline-key.ts',
    // A private key pasted INTO code (`.pem` uploads are blocked).
    content: `export const key = \`${PEM_HEADER}\\nZml4dHVyZQ==\\n-----END RSA PRIVATE KEY-----\`;\n`,
  },
  {
    path: 'config/prod.yaml',
    content: `api_key: ${SYNTH.apiKeyValue}\ndb_url: postgres://svc:${SYNTH.dbPassword}@db.host:5432/app\n`,
  },
  {
    path: 'docs/examples.md',
    content:
      'Use `AKIAIOSFODNN7EXAMPLE` from the AWS docs.\n' +
      'Set apiKey = \'<YOUR_API_KEY>\' first.\n' +
      'Id: 550e8400-e29b-41d4-a716-446655440000\n' +
      'Sha: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n' +
      '-----BEGIN PUBLIC KEY-----\n',
  },
  {
    path: 'src/normal.ts',
    content: 'export const ids = [1, 2, 3];\nexport const name = "drobon";\n',
  },
];

/** §30 no-fake snapshot: plenty of secret-LOOKING, non-secret content. */
const CLEAN_BUT_TRICKY_SOURCE = [
  {
    path: 'src/ids.ts',
    content:
      '// A UUID is an identifier, not a credential.\n' +
      'export const session = "550e8400-e29b-41d4-a716-446655440000";\n' +
      'export const build = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";\n',
  },
  {
    path: 'config/example.yaml',
    content:
      'api_key: <YOUR_API_KEY>\n' +
      'password: "changeme12345"\n' +
      'docs: "see https://example.com docs"\n' +
      'key_hint: "sk_live_ExampleDocValueNotARealKeyAAA"\n',
  },
  { path: 'src/ordinary.ts', content: 'export const total = 42;\nexport const label = "user";\n' },
];

describe('SECRETS scans: the real engine over HTTP', () => {
  test('pre-flight: no snapshot → 409 CONFLICT and NOTHING consumed', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      const { res, body } = await requestScan(server, owner, projectId, 'SECRETS');
      expect(res.status).toBe(409);
      expect(errorOf(body).code).toBe('CONFLICT');
      expect(await getUsage(server, owner)).toEqual({ used: 0 });
      const list = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect(((await readJson(list)) as { data: { scans: unknown[] } }).data.scans).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  test('§29 adversarial snapshot: only the correct rules fire; redaction holds in response, store and logs', async () => {
    const dir = makeTempStoreDir('secrets-adversarial');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({
      users,
      logLevel: 'info',
      scanStoreDir: dir,
      sourceStoreDir: dir,
    });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, ADVERSARIAL_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SECRETS');
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);

      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.failureCode).toBeUndefined();

      // Exactly the eight real findings — the docs file (AWS example
      // key, <YOUR_API_KEY>, UUID, sha256, public key) fires NOTHING,
      // and ordinary code fires nothing.
      const keys = detail.data.scan.findings.map((f) => `${f.file}:${f.line}:${f.ruleId}`).sort();
      expect(keys).toEqual([
        'config/prod.yaml:1:DG-SEC-005',
        'config/prod.yaml:2:DG-SEC-004',
        'src/auth.py:1:DG-SEC-003',
        'src/auth.py:2:DG-SEC-006',
        'src/cloud.ts:1:DG-SEC-002',
        'src/cloud.ts:2:DG-SEC-002',
        'src/inline-key.ts:1:DG-SEC-001',
      ]);
      for (const finding of detail.data.scan.findings) {
        expect(finding.evidence.length).toBeLessThanOrEqual(200);
        if (finding.ruleId !== 'DG-SEC-001') {
          // Every value-bearing rule redacts; the PEM-header rule's
          // evidence IS the safe header text (matchOnlyEvidence).
          expect(finding.evidence).toContain('<redacted>');
        }
        expect(finding.title.toLowerCase()).not.toContain('valid');
        expect(finding.title.toLowerCase()).not.toContain('active');
        expect(finding.remediation).not.toContain('revoked');
      }
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(7);
      expect(detail.data.scan.resultSummary?.partial).toBeUndefined();

      // REDACTION LAYER 1 — the HTTP response.
      const responseJson = JSON.stringify(detail);
      for (const value of [SYNTH.awsKey, SYNTH.githubToken, SYNTH.bearer, SYNTH.apiKeyValue, SYNTH.passwordValue, SYNTH.dbPassword]) {
        expect(responseJson).not.toContain(value);
      }
      // REDACTION LAYER 2 — the durable scan store (findings at rest).
      const storeJson = readFileSync(join(dir, 'scans.json'), 'utf8');
      for (const value of [SYNTH.awsKey, SYNTH.githubToken, SYNTH.bearer, SYNTH.apiKeyValue, SYNTH.passwordValue, SYNTH.dbPassword]) {
        expect(storeJson).not.toContain(value);
      }
      // REDACTION LAYER 3 — the logs.
      const logs = server.logs.join('\n');
      for (const value of [SYNTH.awsKey, SYNTH.githubToken, SYNTH.bearer, SYNTH.apiKeyValue, SYNTH.passwordValue, SYNTH.dbPassword]) {
        expect(logs).not.toContain(value);
      }
      expect(logs).toContain('Scan completed'); // Lifecycle logged — ids only.
      // The PEM body never appears anywhere either (header-only match).
      expect(responseJson).not.toContain('Zml4dHVyZQ==');
    } finally {
      await server.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('§30 no-fake snapshot: ANALYZED with 0 findings — never NOT_ASSESSED, never "risk unknown"', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, CLEAN_BUT_TRICKY_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SECRETS');
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.findings).toEqual([]);
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(0);
      expect(detail.data.scan.resultSummary?.filesScanned).toBe(3);
      expect(detail.data.scan.resultSummary?.filesSkipped).toBe(0); // .ts/.yaml all scan
      expect(detail.data.scan.resultSummary?.partial).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('the findings cap is visible over HTTP: >200 matches → truncated + partial', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      // 205 lines × one finding per line > MAX_FINDINGS_PER_SCAN (200).
      const lines = Array.from(
        { length: 205 },
        (_, i) => `export const key${i} = "${SYNTH.awsKey}";`,
      ).join('\n');
      await putSources(server, owner, projectId, [
        { path: 'src/many.ts', content: `${lines}\n` },
      ]);
      const { body } = await requestScan(server, owner, projectId, 'SECRETS');
      await server.scanProcessor.drain();
      const detail = await getScanDetail(server, owner, projectId, scanOf(body).id);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.findings).toHaveLength(200);
      expect(detail.data.scan.resultSummary?.findingsTotal).toBe(200);
      expect(detail.data.scan.resultSummary?.truncated).toBe(true);
      expect(detail.data.scan.resultSummary?.partial).toBe(true);
      expect(detail.data.scan.resultSummary?.partialReason).toContain('findings cap');
      expect(JSON.stringify(detail)).not.toContain(SYNTH.awsKey);
    } finally {
      await server.stop();
    }
  });

  test('cross-account isolation: the attacker gets a uniform 404 (no oracle)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    await seedUser(users, 'attacker@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const attacker = await login(server, 'attacker@example.test');
      const projectId = await createProject(server, owner);
      const attackerProject = await createProject(server, attacker, 'Attacker app');
      await putSources(server, owner, projectId, ADVERSARIAL_SOURCE);
      const { body } = await requestScan(server, owner, projectId, 'SECRETS');
      await server.scanProcessor.drain();
      const scanId = scanOf(body).id;
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

  test('persistence: redacted findings survive a restart with identical identities', async () => {
    const dir = makeTempStoreDir('secrets-restart');
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const first = await startTestServer({
      users,
      scanStoreDir: dir,
      sourceStoreDir: dir,
      projectStoreDir: dir,
    });
    let scanId: string;
    let projectId: string;
    let before: Finding[];
    try {
      const owner = await login(first, 'owner@example.test');
      projectId = await createProject(first, owner);
      await putSources(first, owner, projectId, ADVERSARIAL_SOURCE);
      const { body } = await requestScan(first, owner, projectId, 'SECRETS');
      scanId = scanOf(body).id;
      await first.scanProcessor.drain();
      before = (await getScanDetail(first, owner, projectId, scanId)).data.scan.findings;
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
      const detail = await getScanDetail(second, relogin, projectId, scanId);
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.findings).toEqual(before); // Same ids, fingerprints, evidence.
      expect(JSON.stringify(detail)).not.toContain(SYNTH.awsKey);
    } finally {
      await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('tamper fail-fast: a forged finding with a non-vocabulary confidence refuses to start', async () => {
    const dir = makeTempStoreDir('secrets-tamper');
    const forged = {
      version: 1,
      scans: [
        {
          id: 'scan_00000000-0000-4000-8000-000000000001',
          ownerId: 'usr_owner',
          projectId: 'prj_00000000-0000-4000-8000-000000000000',
          scanType: 'SECRETS',
          status: 'COMPLETED',
          createdAt: '2026-09-28T10:00:00.000Z',
          updatedAt: '2026-09-28T10:00:00.000Z',
          startedAt: '2026-09-28T10:00:00.000Z',
          completedAt: '2026-09-28T10:00:01.000Z',
          resultSummary: {
            findingsTotal: 1,
            findingsBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
            filesScanned: 1,
            filesSkipped: 0,
            truncated: false,
          },
          findings: [
            {
              id: `fnd_${'a'.repeat(24)}`,
              scanId: 'scan_00000000-0000-4000-8000-000000000001',
              ruleId: 'DG-SEC-002',
              severity: 'HIGH',
              // 'CERTAIN' is NOT in the closed confidence vocabulary —
              // the store must refuse the whole file.
              confidence: 'CERTAIN',
              title: 't',
              description: 'd',
              file: 'a.ts',
              line: 1,
              column: 1,
              evidence: 'aws = "<redacted>"',
              remediation: 'r',
              fingerprint: 'b'.repeat(64),
            },
          ],
        },
      ],
    };
    writeFileSync(join(dir, 'scans.json'), JSON.stringify(forged), { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(
      startTestServer({ users, scanStoreDir: dir, sourceStoreDir: dir, projectStoreDir: dir }),
    ).rejects.toThrow(/refusing to start|not valid/i);
    cleanupTempStoreDir(dir);
  });

  test('a corrupt scan store refuses to start (no silent repair)', async () => {
    const dir = makeTempStoreDir('secrets-corrupt');
    writeFileSync(join(dir, 'scans.json'), 'NOT JSON {{{', { mode: 0o600 });
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test');
    await expect(
      startTestServer({ users, scanStoreDir: dir, sourceStoreDir: dir, projectStoreDir: dir }),
    ).rejects.toThrow(/not valid JSON|refusing to start/);
    cleanupTempStoreDir(dir);
  });

  test('regression: SAST and SCA still run over the same snapshot (three real engines)', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'owner@example.test', { subscription: PRO_ACTIVE });
    const server = await startTestServer({ users });
    try {
      const owner = await login(server, 'owner@example.test');
      const projectId = await createProject(server, owner);
      await putSources(server, owner, projectId, [
        ...ADVERSARIAL_SOURCE,
        { path: 'package.json', content: '{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}' },
      ]);
      // SAST still finds its own (different) issues over the same files.
      const sast = await requestScan(server, owner, projectId, 'SAST');
      await server.scanProcessor.drain();
      const sastDetail = await getScanDetail(server, owner, projectId, scanOf(sast.body).id);
      expect(sastDetail.data.scan.status).toBe('COMPLETED');
      expect(sastDetail.data.scan.findings.every((f) => f.ruleId.startsWith('DG-SAST-'))).toBe(true);
      // SCA still builds its inventory (unaffected by secrets content).
      const sca = await requestScan(server, owner, projectId, 'SCA');
      await server.scanProcessor.drain();
      const scaDetail = await getScanDetail(server, owner, projectId, scanOf(sca.body).id);
      expect(scaDetail.data.scan.status).toBe('COMPLETED');
      expect(scaDetail.data.scan.sca?.summary.dependenciesTotal).toBe(1);
    } finally {
      await server.stop();
    }
  });
});
