import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { parsePackManifest, type PackFamily } from '../src/external/conformance.js';
import { createDatasetService } from '../src/external/service.js';
import { getMergedSastRules, hasRejectedPackRules } from '../src/external/packIntegration.js';
import { createMemorySourceStore } from '../src/scans/sources.js';
import type { ScanRecord } from '../src/scans/store.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { createNullIntelligenceProvider } from '../src/scans/sca/provider.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import { readJson, sessionCookieFrom, startTestServer } from './helpers.js';

/** Entirely synthetic negative fixtures: never the separate Drobon-Dataset. */
const families: readonly PackFamily[] = ['sast', 'secrets', 'dast', 'sca'];
const directories: string[] = [];
const ownerId = 'usr_00000000-0000-4000-8000-000000000001';
const projectId = 'prj_00000000-0000-4000-8000-000000000002';
const context = { signal: new AbortController().signal };
const common = { title: 'Synthetic audit rule', description: 'A local fixture.', severity: 'MEDIUM',
  category: 'fixture', remediation: 'Review.', limitation: 'A synthetic test only.', patternRefs: ['DPK-PAT-9901'] };
const rules: Record<PackFamily, Record<string, unknown>> = {
  sast: { ...common, schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-990', languages: ['javascript'],
    patterns: [{ source: '\\beval\\s*\\(' }],
    tests: [{ line: 'eval(input);', match: true }, { line: 'const x = 1;', match: false }] },
  secrets: { ...common, schemaVersion: 'drobon.pack.secrets/v1', id: 'DPK-SEC-990', confidence: 'MEDIUM',
    redact: true, matchOnlyEvidence: true, patterns: [{ source: 'AUDIT_MARKER' }],
    tests: [{ line: 'AUDIT_MARKER', match: true }, { line: 'no match', match: false }] },
  dast: { ...common, schemaVersion: 'drobon.pack.dast/v1', id: 'DPK-DAST-990',
    check: { type: 'missing-response-header', header: 'content-security-policy' },
    tests: [
      { observation: { url: 'https://fixture.example.org/', status: 200, headers: {} }, match: true },
      { observation: { url: 'https://fixture.example.org/', status: 200, headers: { 'content-security-policy': "default-src 'self'" } }, match: false },
    ] },
  sca: { ...common, schemaVersion: 'drobon.pack.sca/v1', id: 'DPK-SCA-9901',
    ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
    check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
    tests: [
      { file: 'package.json', document: { dependencies: { fixture: '*' } }, match: true },
      { file: 'package.json', document: { dependencies: { fixture: '1.0.0' } }, match: false },
    ] },
};

function put(root: string, path: string, value: unknown): void {
  const file = join(root, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value));
}

function syntheticCatalog(schemaVersion: (family: PackFamily) => string | undefined, includeManifests = true): string {
  const root = mkdtempSync(join(tmpdir(), 'drobon-synthetic-manifest-audit-'));
  directories.push(root);
  for (const family of families) {
    put(root, `packs/${family}/v1/rules/rule.json`, rules[family]);
    if (includeManifests) put(root, `packs/${family}/v1/pack.json`, {
      ...(schemaVersion(family) === undefined ? {} : { schemaVersion: schemaVersion(family) }),
      packId: `synthetic-${family}`, version: '2.3.4',
    });
  }
  return root;
}

function record(scanType: ScanRecord['scanType']): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000003', ownerId, projectId, scanType, status: 'RUNNING',
    createdAt: '2026-10-31T00:00:00.000Z', updatedAt: '2026-10-31T00:00:00.000Z',
    ...(scanType === 'DAST' ? { dastTargetUrl: 'https://fixture.example.org/', assessmentId: 'asm_00000000-0000-4000-8000-000000000004' } : {}),
  };
}

afterEach(() => { for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe('synthetic incompatible pack manifest schemas', () => {
  test('family-aware manifest validation preserves the legacy identity-only helper', () => {
    const identity = { packId: 'synthetic-sast', version: '2.3.4' };
    expect(parsePackManifest({ ...identity, schemaVersion: 'drobon.pack.sast/v1' }, 'sast')).toEqual(identity);
    expect(parsePackManifest({ ...identity, schemaVersion: 'drobon.pack.sast/v9' }, 'sast')).toBeUndefined();
    expect(parsePackManifest({ ...identity, schemaVersion: 'drobon.pack.dast/v1' }, 'sast')).toBeUndefined();
    expect(parsePackManifest(identity, 'sast')).toBeUndefined();
    expect(parsePackManifest({ ...identity, schemaVersion: 'legacy-anything' })).toEqual(identity);
  });

  test('unknown manifest schemas are visible as incomplete and make all four scanners partial', async () => {
    const root = syntheticCatalog((family) => `drobon.pack.${family}/v9`);
    const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: root });
    const status = await dataset.status();
    for (const family of families) {
      const report = status.conformance[family];
      expect(report).toMatchObject({ filesSeen: 1, accepted: 1, enumerationFailures: 0, manifestIssue: expect.any(String) });
      expect(status[`${family}Packs`]).toMatchObject({ status: 'AVAILABLE', count: 1, incomplete: true });
      expect(await dataset.packMetadata(family)).toBeUndefined();
      expect(await hasRejectedPackRules(dataset, family)).toBe(true);
    }
    // A valid rule remains usable; it is not silently presented as a complete pack.
    expect(await getMergedSastRules(dataset)).toHaveLength(1);
    const sources = createMemorySourceStore();
    await sources.replace({ ownerId, projectId, files: [{ path: 'src/audit.js', content: 'eval(input);\nAUDIT_MARKER\n' },
      { path: 'package.json', content: '{"dependencies":{"fixture":"*"}}' }] });
    const engines = [
      createSastEngine({ sources, dataset }),
      createSecretsEngine({ sources, dataset }),
      createScaEngine({ sources, dataset, provider: createNullIntelligenceProvider() }),
      createDastEngine({ dataset, targetPolicy: createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] }),
        authorize: async () => true,
        transport: { probe: async () => ({ status: 200, headers: {}, body: '', bodyTruncated: false, elapsedMs: 1 }) } }),
    ];
    for (const engine of engines) {
      const outcome = await engine.execute(record(engine.scanType), context);
      expect(outcome.kind).toBe('completed');
      if (outcome.kind !== 'completed') throw new Error('Synthetic fixture scan did not complete');
      expect(outcome.resultSummary.partial).toBe(true);
      expect(outcome.resultSummary.partialReason?.toLowerCase()).toContain(`configured ${engine.scanType.toLowerCase()} rules`);
      expect(outcome.findings?.some((finding) => finding.ruleId === rules[engine.scanType.toLowerCase() as PackFamily]['id'])).toBe(true);
    }
  });

  test('a present manifest must identify its family/schema; content versions are not pinned', async () => {
    const root = syntheticCatalog((family) => `drobon.pack.${family}/v1`);
    put(root, 'packs/sast/v1/pack.json', { schemaVersion: 'drobon.pack.dast/v1', packId: 'wrong-family', version: '2.3.4' });
    put(root, 'packs/secrets/v1/pack.json', { packId: 'missing-schema', version: '2.3.4' });
    put(root, 'packs/dast/v1/pack.json', { schemaVersion: 'drobon.pack.dast/v1', packId: 'bad-version', version: 'not-semver' });
    const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: root });
    const status = await dataset.status();
    for (const family of ['sast', 'secrets', 'dast'] as const) {
      expect(status.conformance[family].manifestIssue).toBeDefined();
      expect(status[`${family}Packs`].incomplete).toBe(true);
      expect(await dataset.packMetadata(family)).toBeUndefined();
    }
    expect(status.conformance.sca.manifestIssue).toBeUndefined();
    expect(status.scaPacks.incomplete).toBeUndefined();
    expect(await dataset.packMetadata('sca')).toEqual({ packId: 'synthetic-sca', version: '2.3.4' });
  });

  test('a rejected rule also marks an otherwise available pack incomplete', async () => {
    const root = syntheticCatalog((family) => `drobon.pack.${family}/v1`);
    put(root, 'packs/sast/v1/rules/rejected.json', { ...rules.sast, id: 'DPK-SAST-991', unexpected: true });
    const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: root });
    const status = await dataset.status();
    expect(status.conformance.sast).toMatchObject({ filesSeen: 2, accepted: 1, enumerationFailures: 0 });
    expect(status.sastPacks).toMatchObject({ status: 'AVAILABLE', count: 1, incomplete: true });
    expect(await hasRejectedPackRules(dataset, 'sast')).toBe(true);
    expect(status.secretsPacks.incomplete).toBeUndefined();
  });

  test('absent optional manifests retain prior compatibility; no identity is invented', async () => {
    const root = syntheticCatalog(() => undefined, false);
    const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: root });
    const status = await dataset.status();
    for (const family of families) {
      expect(status.conformance[family].manifestIssue).toBeUndefined();
      expect(status[`${family}Packs`].incomplete).toBeUndefined();
      expect(await dataset.packMetadata(family)).toBeUndefined();
    }
  });

  test('authenticated status exposes the incomplete pack without leaking the configured path', async () => {
    const root = syntheticCatalog((family) => `drobon.pack.${family}/v9`);
    const server = await startTestServer({ vulnIntelProvider: 'filesystem', datasetPath: root });
    try {
      const registration = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'synthetic-manifest-audit@example.test', password: 'synthetic manifest audit password', userType: 'SECURITY_PROFESSIONAL' }), // synthetic test account
      });
      expect(registration.status).toBe(201);
      const response = await fetch(`${server.baseUrl}/api/v1/dataset/status`, { headers: { cookie: sessionCookieFrom(registration) } });
      expect(response.status).toBe(200);
      const status = ((await readJson(response)) as { data: { dataset: Record<string, unknown> } }).data.dataset;
      expect(status['datasetPath']).toBeUndefined();
      expect(status['sastPacks']).toMatchObject({ status: 'AVAILABLE', count: 1, incomplete: true });
      expect(status['conformance']).toMatchObject({ sast: { manifestIssue: expect.any(String) } });
    } finally { await server.stop(); }
  });
});
