import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { isFinding, findingScanner } from '@drobon/shared';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import {
  ADVISORY_SCHEMA_VERSION,
  compareVersions,
  compileAdvisoryPack,
  createAdvisoryService,
  evaluateAdvisories,
  lintAdvisoryPattern,
  classifyAdvisory,
  type AdvisoryRecord,
} from '../src/external/advisory.js';

/**
 * Pump 15 — GENERIC advisory engine. Language-agnostic by construction:
 * the same evaluator handles PHP headers, composer.json, go.mod,
 * requirements.txt and package.json with ZERO language-specific code.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';

function scanRecord(scanType: 'SCA' | 'DAST' = 'SCA'): ScanRecord {
  return {
    id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType, status: 'RUNNING',
    createdAt: '2026-10-26T10:00:00.000Z', updatedAt: '2026-10-26T10:00:00.000Z',
    startedAt: '2026-10-26T10:00:00.000Z',
    ...(scanType === 'DAST' ? { dastTargetUrl: 'https://app.example.org/' } : {}),
  };
}

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    projectId: PROJECT, ownerId: OWNER,
    files: files.map((file) => ({ path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), content: file.content })),
    createdAt: '2026-10-26T09:00:00.000Z', updatedAt: '2026-10-26T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

const ctx = { signal: new AbortController().signal };

const PHP_FP = {
  source: 'response-header' as const,
  header: 'x-powered-by',
  pattern: 'PHP/([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)',
  selfTest: 'PHP/8.1.2',
};

/** Overrides are intentionally loose so tests can also remove optional keys. */
function phpRecord(overrides: Record<string, unknown> = {}): AdvisoryRecord {
  return {
    id: 'CVE-2026-109618',
    ruleId: 'ADV-0001',
    title: 'PHP core memory-corruption RCE',
    description: 'Critical RCE in the PHP engine. Patch immediately.',
    severity: 'CRITICAL',
    cwe: 'CWE-787',
    ecosystem: 'php',
    component: 'php',
    remediation: 'Update PHP to a patched release.',
    limitation: 'Version signal only, not proof of exploitability.',
    introduced: '5.4',
    branches: [
      { branch: '8.5', fixedVersion: '8.5.12' },
      { branch: '8.4', fixedVersion: '8.4.27' },
      { branch: '8.3', fixedVersion: '8.3.36' },
      { branch: '8.2', fixedVersion: '8.2.35' },
    ],
    eolBranches: ['7.4', '8.0', '8.1'],
    fingerprints: [PHP_FP],
    ...overrides,
  } as AdvisoryRecord;
}

function pack(records: unknown[]): unknown {
  return {
    schemaVersion: ADVISORY_SCHEMA_VERSION,
    packId: 'fixture-advisories',
    version: '1.0.0',
    generatedAt: '2026-10-26T00:00:00.000Z',
    advisories: records,
  };
}

function serviceFor(records: unknown[], now = Date.parse('2026-10-26T12:00:00.000Z')) {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-advisory-'));
  const path = join(dir, 'pack.json');
  writeFileSync(path, JSON.stringify(pack(records)), 'utf8');
  return { service: createAdvisoryService({ path, now: () => now }), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe('generic version comparator', () => {
  test('compares dotted numeric versions and fails closed on suffixes', () => {
    expect(compareVersions('8.4.3', '8.4.27')).toBe(-1);
    expect(compareVersions('8.4.27', '8.4.27')).toBe(0);
    expect(compareVersions('8.5.12', '8.4.27')).toBe(1);
    expect(compareVersions('v8.2.35', '8.2.35')).toBe(0);
    expect(compareVersions('8.1.2-1ubuntu4', '8.1.2')).toBeUndefined();
    expect(compareVersions('not-a-version', '8.1.2')).toBeUndefined();
  });

  test('the purpose-built lint accepts version patterns and rejects catastrophic ones', () => {
    expect(lintAdvisoryPattern('PHP/([0-9]+\\.[0-9]+\\.[0-9]+)')).toBeNull();
    expect(lintAdvisoryPattern('(a+)+')).toContain('nested quantifier');
    expect(lintAdvisoryPattern('.*.*')).toContain('repeated unbounded wildcard');
    expect(lintAdvisoryPattern('(x)\\1')).toContain('backreference');
    expect(lintAdvisoryPattern('(?=x)x')).toContain('lookaround');
  });
});

describe('advisory classification (never guesses)', () => {
  test('branch-aware fixed versions, EOL branches and UNKNOWN', () => {
    const record = phpRecord();
    expect(classifyAdvisory(record, '8.4.3').verdict).toBe('AFFECTED');
    expect(classifyAdvisory(record, '8.4.27').verdict).toBe('NOT_AFFECTED');
    expect(classifyAdvisory(record, '8.1.2').verdict).toBe('AFFECTED'); // EOL
    expect(classifyAdvisory(record, '9.0.1').verdict).toBe('UNKNOWN'); // branch not covered
    expect(classifyAdvisory(record, '5.3.0').verdict).toBe('NOT_AFFECTED'); // introduced 5.4
    expect(classifyAdvisory(record, 'garbage').verdict).toBe('UNKNOWN');
  });

  test('generic min/maxExclusive ranges work for ANY ecosystem', () => {
    const record = phpRecord({
      ruleId: 'ADV-0009', ecosystem: 'go', component: 'go',
      introduced: undefined, branches: undefined, eolBranches: undefined,
      constraints: [{ min: '1.0', maxExclusive: '1.21.0' }],
    });
    expect(classifyAdvisory(record, '1.20.4').verdict).toBe('AFFECTED');
    expect(classifyAdvisory(record, '1.21.0').verdict).toBe('NOT_AFFECTED');
    expect(classifyAdvisory(record, '0.9.0').verdict).toBe('UNKNOWN');
  });
});

describe('pack validation (fail closed, self-tested)', () => {
  test('a valid multi-ecosystem pack compiles', () => {
    const compiled = compileAdvisoryPack(pack([
      phpRecord(),
      phpRecord({
        id: 'EXAMPLE-GO', ruleId: 'ADV-0002', ecosystem: 'go', component: 'go',
        branches: undefined, eolBranches: undefined, introduced: undefined,
        constraints: [{ min: '0', maxExclusive: '1.21.0' }],
        fingerprints: [{ source: 'manifest-text', artifact: 'go.mod', pattern: 'go\\s+([0-9]+\\.[0-9]+)', selfTest: 'go 1.20.4' }],
      }),
    ]));
    expect(compiled).toBeDefined();
    expect(compiled?.compiled).toHaveLength(2);
    expect(compiled?.refused).toEqual([]);
  });

  test('bad regex, missing capture group, failed selfTest, duplicate ids and extra fields are refused', () => {
    const cases: Array<[string, unknown]> = [
      ['invalid regex', phpRecord({ fingerprints: [{ ...PHP_FP, pattern: 'PHP/([0-9' }] })],
      ['no capture group', phpRecord({ fingerprints: [{ ...PHP_FP, pattern: 'PHP/[0-9]+' }] })],
      ['failed selfTest', phpRecord({ fingerprints: [{ ...PHP_FP, selfTest: 'nothing here' }] })],
      ['unknown field', { ...phpRecord(), extra: true }],
      ['bad ruleId', phpRecord({ ruleId: 'CVE-1' })],
      ['no version policy', phpRecord({ branches: undefined, eolBranches: undefined, introduced: undefined })],
    ];
    for (const [label, record] of cases) {
      const result = compileAdvisoryPack(pack([record]));
      expect(result?.compiled ?? [], label).toHaveLength(0);
      expect(result?.refused.length ?? 0, label).toBeGreaterThan(0);
    }
    const duplicate = compileAdvisoryPack(pack([phpRecord(), phpRecord({ id: 'CVE-2026-109619' })]));
    expect(duplicate?.compiled).toHaveLength(1);
    expect(duplicate?.refused[0]).toContain('duplicate ruleId');
  });
});

describe('language-agnostic signal evaluation', () => {
  test('PHP header: vulnerable, patched and unknown branches', () => {
    const compiled = compileAdvisoryPack(pack([phpRecord()]));
    if (compiled === undefined) return;
    const vulnerable = evaluateAdvisories(compiled, { headers: { 'x-powered-by': 'PHP/8.4.3' } });
    expect(vulnerable.matches).toHaveLength(1);
    expect(vulnerable.matches[0]?.verdict).toBe('AFFECTED');
    expect(vulnerable.matches[0]?.severity).toBe('CRITICAL');
    expect(vulnerable.matches[0]?.evidence.length ?? 0).toBeLessThanOrEqual(200);
    const patched = evaluateAdvisories(compiled, { headers: { 'x-powered-by': 'PHP/8.4.27' } });
    expect(patched.matches).toHaveLength(0);
    expect(patched.notAffected).toBe(1);
    const unknown = evaluateAdvisories(compiled, { headers: { 'x-powered-by': 'PHP/9.0.1' } });
    expect(unknown.matches[0]?.verdict).toBe('UNKNOWN');
    expect(unknown.matches[0]?.severity).toBe('CRITICAL'); // advisory severity retained; UNKNOWN is not a confirmed finding
    expect(unknown.matches[0]?.title).toContain('NEEDS REVIEW');
    expect(unknown.needsReview).toBe(1);
  });

  test('partial version captures and distribution suffixes require review', () => {
    const fullPattern = compileAdvisoryPack(pack([phpRecord()]));
    if (fullPattern === undefined) throw new Error('fixture failed to compile');
    const distro = evaluateAdvisories(fullPattern, { headers: { 'x-powered-by': 'PHP/8.4.3-1vendor' } });
    expect(distro.matches[0]?.verdict).toBe('UNKNOWN');
    expect(distro.matches[0]?.reason).toContain('verification');
    expect(compareVersions('8.4.3-1vendor', '8.4.27')).toBeUndefined();
    const partial = compileAdvisoryPack(pack([phpRecord({ fingerprints: [{
      ...PHP_FP, pattern: 'PHP/([0-9]+\\.[0-9]+)', selfTest: 'PHP/8.4',
    }] })]));
    if (partial === undefined) throw new Error('fixture failed to compile');
    const result = evaluateAdvisories(partial, { headers: { 'x-powered-by': 'PHP/8.4.27' } });
    expect(result.matches[0]?.verdict).toBe('UNKNOWN');
    expect(result.notAffected).toBe(0);
  });

  test('ONE evaluator handles PHP, Node, Go and Python manifests', () => {
    const records = [
      phpRecord({
        fingerprints: [{
          source: 'manifest-json', artifact: 'composer.json', path: 'require.php',
          pattern: '([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)', selfTest: '^8.1',
        }],
      }),
      phpRecord({
        id: 'EXAMPLE-NODE', ruleId: 'ADV-0002', ecosystem: 'nodejs', component: 'node',
        severity: 'MEDIUM', introduced: undefined, branches: undefined, eolBranches: undefined,
        constraints: [{ min: '0', maxExclusive: '20.11.1' }],
        fingerprints: [{
          source: 'manifest-json', artifact: 'package.json', path: 'engines.node',
          pattern: '([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)', selfTest: '>=18.0.0',
        }],
      }),
      phpRecord({
        id: 'EXAMPLE-GO', ruleId: 'ADV-0003', ecosystem: 'go', component: 'go',
        severity: 'LOW', introduced: undefined, branches: undefined, eolBranches: undefined,
        constraints: [{ min: '0', maxExclusive: '1.21.0' }],
        fingerprints: [{
          source: 'manifest-text', artifact: 'go.mod',
          pattern: 'go\\s+([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)', selfTest: 'go 1.20.4',
        }],
      }),
      phpRecord({
        id: 'EXAMPLE-PY', ruleId: 'ADV-0004', ecosystem: 'python', component: 'django',
        severity: 'LOW', introduced: undefined, branches: undefined, eolBranches: undefined,
        constraints: [{ min: '0', maxExclusive: '4.2.0' }],
        fingerprints: [{
          source: 'manifest-text', artifact: 'requirements.txt',
          pattern: '[Dd]jango==([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)', selfTest: 'Django==3.2.1',
        }],
      }),
    ];
    const compiled = compileAdvisoryPack(pack(records));
    if (compiled === undefined) return;
    const result = evaluateAdvisories(compiled, {
      files: [
        { path: 'composer.json', content: JSON.stringify({ require: { php: '^8.1' } }) },
        { path: 'package.json', content: JSON.stringify({ engines: { node: '>=18.0.0' } }) },
        { path: 'go.mod', content: 'module example.com/app\n\ngo 1.20.4\n' },
        { path: 'requirements.txt', content: 'Django==3.2.1\nrequests>=2.28\n' },
      ],
    });
    expect(result.recordsEvaluated).toBe(4);
    expect(new Set(result.matches.map((m) => m.ecosystem))).toEqual(new Set(['php', 'nodejs', 'go', 'python']));
    expect(result.matches.every((m) => m.verdict === 'UNKNOWN')).toBe(true); // manifest declarations are not installed versions
  });
});

describe('runtime service', () => {
  test('no pack configured → honest NOT_CONFIGURED, zero findings', async () => {
    const service = createAdvisoryService({});
    const status = await service.status();
    expect(status.configured).toBe(false);
    expect(status.loaded).toBe(false);
    const result = await service.evaluate({ headers: { 'x-powered-by': 'PHP/8.1.2' } });
    expect(result.matches).toEqual([]);
    expect(result.unavailableReason).toBeDefined();
  });

  test('loads an operator pack, detects stale data and refuses an invalid file', async () => {
    const fixture = serviceFor([phpRecord()]);
    const status = await fixture.service.status();
    expect(status.configured).toBe(true);
    expect(status.loaded).toBe(true);
    expect(status.recordCount).toBe(1);
    expect(status.refused).toEqual([]);
    const result = await fixture.service.evaluate({ headers: { 'x-powered-by': 'PHP/8.1.2' } });
    expect(result.matches[0]?.verdict).toBe('AFFECTED');
    fixture.cleanup();

    const old = serviceFor([phpRecord()], Date.parse('2027-01-30T00:00:00.000Z'));
    expect((await old.service.status()).stale).toBe(true);
    old.cleanup();

    const dir = mkdtempSync(join(tmpdir(), 'drobon-advisory-bad-'));
    const bad = join(dir, 'pack.json');
    writeFileSync(bad, '{not json');
    const broken = createAdvisoryService({ path: bad });
    expect((await broken.status()).loaded).toBe(false);
    expect((await broken.evaluate({})).unavailableReason).toContain('could not be read');
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('engine integration: advisory findings are real, contract-valid findings', () => {
  test('SCA scan with composer.json emits a persisted scanner:SCA advisory finding', async () => {
    const fixture = serviceFor([phpRecord({
      fingerprints: [{
        source: 'manifest-json', artifact: 'composer.json', path: 'require.php',
        pattern: '([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)', selfTest: '^8.1',
      }],
    })]);
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'composer.json', content: JSON.stringify({ name: 'acme/app', require: { php: '^8.1' } }, null, 2) }])),
      advisory: fixture.service,
    });
    const outcome = await engine.execute(scanRecord('SCA'), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const advisory = (outcome.findings ?? []).filter((f) => f.ruleId.startsWith('ADV-'));
    expect(advisory).toHaveLength(1);
    const first = advisory[0];
    if (first === undefined) return;
    expect(first.scanner).toBe('SCA');
    expect(findingScanner(first)).toBe('SCA');
    expect(isFinding(first)).toBe(true);
    expect(outcome.resultSummary.findingsTotal).toBe((outcome.findings ?? []).length);
    expect(first.evidence).not.toContain('"php"');
    fixture.cleanup();
  });

  test('passive DAST scan emits a DAST advisory finding with NO extra HTTP request', async () => {
    const fixture = serviceFor([phpRecord()]);
    const targetPolicy = createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
    const response: DastProbeResponse = {
      status: 200,
      headers: { 'content-type': 'text/html', 'x-powered-by': 'PHP/8.1.2' },
      body: '<html>fixture</html>',
      bodyTruncated: false,
      elapsedMs: 12,
    };
    let calls = 0;
    const transport: DastTransport = { probe: async () => { calls += 1; return response; } };
    const engine = createDastEngine({ targetPolicy, transport, advisory: fixture.service, now: () => Date.parse('2026-10-26T10:00:00.000Z') });
    const outcome = await engine.execute(scanRecord('DAST'), ctx);
    expect(calls).toBe(1); // passive budget unchanged
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const advisory = (outcome.findings ?? []).filter((f) => f.ruleId.startsWith('ADV-'));
    expect(advisory).toHaveLength(1);
    expect(advisory[0]?.scanner).toBe('DAST');
    expect(isFinding(advisory[0])).toBe(true);
    expect(outcome.resultSummary.findingsTotal).toBe((outcome.findings ?? []).length);
    fixture.cleanup();
  });
});


describe('advisory HTTP routes', () => {
  const servers: TestServer[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => server.stop()));
  });

  test('status + analyze are authenticated, bounded and return real analysis', async () => {
    const fixture = serviceFor([phpRecord()]);
    const server = await startTestServer({ advisory: fixture.service });
    servers.push(server);
    const base = server.baseUrl;

    expect((await fetch(`${base}/api/v1/advisory/status`)).status).toBe(401);
    const password = 'advisory-route-fake-test'; // fake test fixture, never a real credential
    const registered = await fetch(`${base}/api/v1/auth/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'adv-route@arena.local', password }),
    });
    expect(registered.status).toBe(201);
    const login = await fetch(`${base}/api/v1/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'adv-route@arena.local', password }),
    });
    const session = sessionCookieFrom(login);
    const probe = await fetch(`${base}/api/v1/me`, { headers: { cookie: session } });
    const device = probe.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
    const cookie = device === undefined ? session : `${session}; ${device.split(';')[0]}`;

    const statusResponse = await fetch(`${base}/api/v1/advisory/status`, { headers: { cookie } });
    expect(statusResponse.status).toBe(200);
    const statusBody = (await readJson(statusResponse)) as { data: { advisory: { loaded: boolean; recordCount: number } } };
    expect(statusBody.data.advisory.loaded).toBe(true);
    expect(statusBody.data.advisory.recordCount).toBe(1);

    const analyze = await fetch(`${base}/api/v1/advisory/analyze`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ headers: { 'x-powered-by': 'PHP/8.4.3' } }),
    });
    expect(analyze.status).toBe(200);
    const analysis = (await readJson(analyze)) as { data: { analysis: { matches: Array<{ ruleId: string; verdict: string }> } } };
    expect(analysis.data.analysis.matches[0]?.ruleId).toBe('ADV-0001');
    expect(analysis.data.analysis.matches[0]?.verdict).toBe('AFFECTED');

    const malformed = await fetch(`${base}/api/v1/advisory/analyze`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ files: 'not-an-array' }),
    });
    expect(malformed.status).toBe(422);
    fixture.cleanup();
  });
});
