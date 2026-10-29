import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { isDastResult, isFinding, isScanResultSummary, isScaResult } from '@drobon/shared';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { AdvisoryMatch, AdvisoryService } from '../src/external/advisory.js';
import type { DastTransport } from '../src/scans/dast/http.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { exactDeclaredVersion } from '../src/scans/sca/exactVersion.js';
import { createFilesystemIntelligenceProvider } from '../src/scans/sca/filesystemProvider.js';
import { buildInventory } from '../src/scans/sca/inventory.js';
import { parsePackageLock } from '../src/scans/sca/parsers.js';
import type { DependencyCoordinate, VulnerabilityIntelligenceProvider } from '../src/scans/sca/provider.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createMemoryScanStore, type ScanRecord } from '../src/scans/store.js';
import { TEST_SAST_FLOW_RULES, TEST_SECRETS_RULES } from './fixtures/testData.js';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const NOW = '2026-10-29T10:00:00.000Z';
const ctx = { signal: new AbortController().signal };
const rec = (scanType: ScanRecord['scanType']): ScanRecord => ({
  id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType, status: 'RUNNING',
  createdAt: NOW, updatedAt: NOW, startedAt: NOW,
});
function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return { projectId: PROJECT, ownerId: OWNER, files: files.map((f) => ({ ...f, bytes: Buffer.byteLength(f.content) })), createdAt: NOW, updatedAt: NOW };
}
const sources = (files: Array<{ path: string; content: string }>) => ({ findByProject: async () => snapshot(files) });
const json = (value: unknown) => JSON.stringify(value);

describe('SCA evidence and partial-coverage regressions', () => {
  test.each([1, 2, 3])('npm v%i keeps an older nested version distinct and transitive', (lockfileVersion) => {
    const lock = lockfileVersion === 1
      ? { lockfileVersion, dependencies: {
        alpha: { version: '2.0.0' },
        wrapper: { version: '3.0.0', dependencies: { alpha: { version: '1.0.0' } } },
      } }
      : { lockfileVersion, packages: {
        // The companion manifest is also valid evidence of root directness.
        '': {},
        'node_modules/alpha': { version: '2.0.0' },
        'node_modules/wrapper': { version: '3.0.0' },
        'node_modules/wrapper/node_modules/alpha': { version: '1.0.0' },
      } };
    const inventory = buildInventory([
      { path: 'package.json', content: json({ name: 'root', version: '1.0.0', dependencies: { alpha: '^2.0.0', wrapper: '^3.0.0' } }) },
      { path: 'package-lock.json', content: json(lock) },
    ]);
    const copies = inventory.dependencies.filter((item) => item.name === 'alpha');
    expect(copies).toHaveLength(2);
    expect(copies.find((item) => item.resolvedVersion === '2.0.0')).toMatchObject({ dependencyClass: 'direct', declaredVersion: '^2.0.0' });
    expect(copies.find((item) => item.resolvedVersion === '1.0.0')).toMatchObject({ dependencyClass: 'transitive', versionSource: 'lockfile' });
    expect(copies.find((item) => item.resolvedVersion === '1.0.0')?.declaredVersion).toBeUndefined();
    expect(new Set(copies.map((item) => item.dependencyId)).size).toBe(2);
  });

  test('npm v1 depth limits produce PARTIAL rather than silently losing the remainder', () => {
    let nested: Record<string, unknown> = { version: '1.0.0' };
    for (let depth = 0; depth < 35; depth += 1) nested = { version: '1.0.0', dependencies: { [`pkg-${depth}`]: nested } };
    const parsed = parsePackageLock(json({ lockfileVersion: 1, dependencies: { root: nested } }), 'package-lock.json');
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.dependencies.length).toBeLessThanOrEqual(33);
  });

  test('multi-root manifests keep version/path evidence and do not invent an SBOM root', async () => {
    const files = ['a', 'b'].flatMap((path, index) => [
      { path: `${path}/package.json`, content: json({ name: `root-${path}`, dependencies: { alpha: index === 0 ? '^2.0.0' : '^1.0.0' } }) },
      { path: `${path}/package-lock.json`, content: json({ lockfileVersion: 3, packages: { '': { dependencies: { alpha: '*' } }, 'node_modules/alpha': { version: index === 0 ? '2.0.0' : '1.0.0' } } }) },
    ]);
    const outcome = await createScaEngine({ sources: sources(files) }).execute(rec('SCA'), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) throw new Error('missing SCA result');
    expect(isScaResult(outcome.sca)).toBe(true);
    expect(outcome.sca.dependencies.map((dep) => [dep.manifestPath, dep.resolvedVersion]).sort()).toEqual([
      ['a/package.json', '2.0.0'], ['b/package.json', '1.0.0'],
    ]);
    expect(outcome.sca.sbom.metadata.component).toBeUndefined();
    expect(outcome.sca.sbom.dependencies).toEqual([]);
    expect(outcome.sca.sbom.components).toHaveLength(2);
  });

  test('single-root SBOM does not attach independent Python declarations as npm edges', async () => {
    const outcome = await createScaEngine({ sources: sources([
      { path: 'package.json', content: json({ name: 'app', dependencies: { alpha: '^2.0.0' } }) },
      { path: 'package-lock.json', content: json({ lockfileVersion: 3, packages: { '': { dependencies: { alpha: '^2.0.0' } }, 'node_modules/alpha': { version: '2.0.0' } } }) },
      { path: 'requirements.txt', content: 'flask==2.3.2\n' },
    ]) }).execute(rec('SCA'), ctx);
    if (outcome.kind !== 'completed' || outcome.sca === undefined) throw new Error('missing SCA result');
    const { sca } = outcome;
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(sca.sbom.dependencies).toHaveLength(1);
    expect(sca.sbom.dependencies[0]?.dependsOn).toEqual([sca.dependencies.find((dep) => dep.name === 'alpha')?.fingerprint]);
    expect(sca.sbom.components.find((component) => component.name === 'flask')?.version).toBe('2.3.2');
    expect(sca.dependencies.find((dep) => dep.name === 'flask')?.resolvedVersion).toBeUndefined();
  });

  test('exact Python pins reach advisory matching, unlike ranges, wildcards and arbitrary equality', async () => {
    let coordinates: readonly DependencyCoordinate[] = [];
    const provider: VulnerabilityIntelligenceProvider = { id: 'fixture', assess: async (input) => {
      coordinates = input;
      return { providerId: 'fixture', datasetStatus: 'DATASET_AVAILABLE', advisories: input.filter((item) => item.name === 'flask' && item.version !== undefined).map((item) => ({ id: 'GHSA-aaaa-bbbb-cccc', severity: 'HIGH' as const, summary: 'Synthetic match.', dependencyId: item.dependencyId })) };
    } };
    const outcome = await createScaEngine({ provider, sources: sources([{ path: 'requirements.txt', content: [
      'flask==1.1.4', 'Flask==2.3.2', 'django==4.2.4; python_version >= "3.9"',
      'requests>=2.0', 'urllib3==1.26.*', 'boto3===1.2.3', 'pip==1.0,!=1.0',
    ].join('\n') }]) }).execute(rec('SCA'), ctx);
    if (outcome.kind !== 'completed' || outcome.sca === undefined) throw new Error('missing SCA result');
    expect(coordinates.filter((item) => item.name === 'flask').map((item) => item.version)).toEqual(['1.1.4', '2.3.2']);
    expect(coordinates.find((item) => item.name === 'django')?.version).toBe('4.2.4');
    for (const name of ['requests', 'urllib3', 'boto3', 'pip']) expect(coordinates.find((item) => item.name === name)?.version).toBeUndefined();
    expect(outcome.sca.advisories.map((item) => item.version)).toEqual(['1.1.4', '2.3.2']);
    expect(outcome.sca.dependencies.every((item) => item.resolvedVersion === undefined)).toBe(true);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('Declared versions do not prove');
    expect(isScaResult(outcome.sca)).toBe(true);
  });

  test('the declared-version helper rejects unsupported ranges instead of guessing', () => {
    expect(exactDeclaredVersion('pypi', '==1.2.3')).toBe('1.2.3');
    expect(exactDeclaredVersion('npm', '1.2.3')).toBe('1.2.3');
    for (const range of ['==1.2.*', '===1.2.3', '>=1.2', '==1.0,!=1.0', '~=1.2']) expect(exactDeclaredVersion('pypi', range)).toBeUndefined();
    for (const range of ['^1.2.3', '~1.2.3', '1.2.x', '>=1.0.0']) expect(exactDeclaredVersion('npm', range)).toBeUndefined();
  });

  test('sparse, malformed and unsupported advisory data never imply complete coverage', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-advisory-test-'));
    try {
      const dir = join(root, 'vuln-intel', 'npm');
      mkdirSync(dir, { recursive: true });
      const record = { fixture: false, id: 'GHSA-aaaa-bbbb-cccc', ecosystem: 'npm', package: 'alpha', summary: 'Synthetic advisory.', severity: 'HIGH', affected: [{ range: '<2.0.0' }] };
      writeFileSync(join(dir, 'valid.json'), json(record));
      writeFileSync(join(dir, 'bad.json'), json({ ...record, package: 'broken', affected: [] }));
      writeFileSync(join(dir, 'range.json'), json({ ...record, id: 'GHSA-dddd-eeee-ffff', affected: [{ range: 'not-a-range' }] }));
      const provider = createFilesystemIntelligenceProvider({ datasetPath: root });
      const [result, concurrent] = await Promise.all([
        provider.assess([
          { dependencyId: 'one', ecosystem: 'npm', name: 'alpha', version: '1.0.0' },
          { dependencyId: 'two', ecosystem: 'npm', name: 'unlisted', version: '1.0.0' },
          { dependencyId: 'three', ecosystem: 'npm', name: 'alpha' },
        ]),
        provider.assess([{ dependencyId: 'other', ecosystem: 'npm', name: 'alpha', version: '1.0.0' }]),
      ]);
      expect(result.advisories.map((item) => item.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
      expect(result.incomplete).toBe(true);
      expect(concurrent.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(concurrent.advisories.map((item) => item.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('an unavailable or null provider cannot claim simultaneously that it matched an advisory', async () => {
    for (const state of ['DATASET_UNAVAILABLE', 'NO_DATA_LOADED'] as const) {
      const provider: VulnerabilityIntelligenceProvider = { id: 'fixture', assess: async (items) => ({
        providerId: state === 'NO_DATA_LOADED' ? 'none' : 'fixture', datasetStatus: state,
        advisories: [{ id: 'SYNTHETIC-1', severity: 'HIGH', summary: 'Fixture only.', dependencyId: items[0]?.dependencyId ?? '' }],
      }) };
      const outcome = await createScaEngine({ provider, sources: sources([{ path: 'requirements.txt', content: 'fixture==1.0.0\n' }]) }).execute(rec('SCA'), ctx);
      if (outcome.kind !== 'completed' || outcome.sca === undefined) throw new Error('missing SCA result');
      expect(outcome.sca.summary.assessmentState).toBe('NOT_ASSESSED');
      expect(outcome.sca.advisories).toEqual([]);
      expect(outcome.resultSummary.partial).toBe(true);
      expect(isScaResult(outcome.sca)).toBe(true);
    }
  });

  test('source advisory findings omitted at the cap are reported as truncated', async () => {
    const matches: AdvisoryMatch[] = Array.from({ length: 201 }, (_, index) => ({
      ruleId: `ADV-${1000 + index}`, advisoryId: `SYNTHETIC-${index}`, title: 'Synthetic source advisory',
      description: 'Fixture only.', severity: 'HIGH', remediation: 'Review.', limitation: 'Fixture only.', references: [],
      ecosystem: 'fixture', component: 'fixture', observedVersion: '1.0.0', verdict: 'AFFECTED',
      reason: 'Synthetic.', evidence: 'Fixture evidence.', location: 'package.json engines.node',
    }));
    const advisory: AdvisoryService = { configured: true,
      status: async () => ({ configured: true, loaded: true, recordCount: matches.length, stale: false, refused: [] }),
      evaluate: async () => ({ matches, recordsEvaluated: matches.length, signalsFound: 1, affected: matches.length, needsReview: 0, notAffected: 0 }),
    };
    const outcome = await createScaEngine({ advisory, sources: sources([{ path: 'package.json', content: json({ name: 'fixture', engines: { node: '1.0.0' } }) }]) }).execute(rec('SCA'), ctx);
    if (outcome.kind !== 'completed') throw new Error('missing SCA result');
    expect(outcome.findings).toHaveLength(200);
    expect(outcome.findings?.every(isFinding)).toBe(true);
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('source finding details');
  });

  test('advisory cap keeps later critical records and reports malformed/truncated output', async () => {
    const provider: VulnerabilityIntelligenceProvider = { id: 'fixture', assess: async (items) => ({
      providerId: 'fixture', datasetStatus: 'DATASET_AVAILABLE', advisories: [
        ...Array.from({ length: 201 }, (_, index) => ({ id: `SYNTHETIC-${index}`, severity: 'LOW' as const, summary: 'Fixture advisory.', dependencyId: items[0]?.dependencyId ?? '' })),
        { id: 'SYNTHETIC-CRITICAL', severity: 'CRITICAL' as const, summary: 'Critical fixture advisory.', dependencyId: items[0]?.dependencyId ?? '' },
        { id: 'invalid\nname', severity: 'HIGH' as const, summary: 'Invalid advisory.', dependencyId: items[0]?.dependencyId ?? '' },
      ],
    }) };
    const outcome = await createScaEngine({ provider, sources: sources([{ path: 'requirements.txt', content: 'flask==2.3.2\n' }]) }).execute(rec('SCA'), ctx);
    if (outcome.kind !== 'completed' || outcome.sca === undefined) throw new Error('missing SCA result');
    expect(outcome.sca.advisories).toHaveLength(200);
    expect(outcome.sca.advisories[0]?.id).toBe('SYNTHETIC-CRITICAL');
    expect(outcome.sca.advisories.every((item) => item.id !== 'invalid\nname')).toBe(true);
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('advisory detail limit');
    expect(isScaResult(outcome.sca)).toBe(true);
  });
});

describe('SAST and Secrets coverage regressions', () => {
  test('one lexical plus flow match at the same rule and line produces one finding', async () => {
    const base = TEST_SAST_FLOW_RULES[0];
    if (base === undefined) throw new Error('missing fixture rule');
    const outcome = await createSastEngine({ sources: sources([{ path: 'src/app.js', content: 'const command = req.query.cmd;\nexec(command);\nexec(command);\n' }]), rules: [{ ...base, patterns: [/\bexec\s*\(/] }] }).execute(rec('SAST'), ctx);
    if (outcome.kind !== 'completed') throw new Error('missing SAST result');
    const matches = (outcome.findings ?? []).filter((finding) => finding.ruleId === base.id);
    expect(matches.map((item) => item.line)).toEqual([2, 3]);
    expect(new Set(matches.map((item) => item.id)).size).toBe(matches.length);
    expect(matches.every(isFinding)).toBe(true);
  });

  test('a missing Secrets ruleset is partial and does not claim files were scanned', async () => {
    const outcome = await createSecretsEngine({ sources: sources([{ path: 'sample.conf', content: 'nothing here' }]), rules: [] }).execute(rec('SECRETS'), ctx);
    if (outcome.kind !== 'completed') throw new Error('missing Secrets result');
    expect(outcome.resultSummary).toMatchObject({ partial: true, filesScanned: 0, filesSkipped: 1 });
    expect(outcome.resultSummary.partialReason).toContain('No secrets rules');
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('Secrets counts only reached files when the finding cap stops the scan', async () => {
    const fake = ['AKIA', 'P10QZ9WM7XK2BR4J'].join('');
    const outcome = await createSecretsEngine({ sources: sources([
      { path: 'a.js', content: `const key="${fake}";\n` },
      { path: 'b.js', content: 'const safe = true;\n' },
    ]), rules: TEST_SECRETS_RULES, limits: { maxFindings: 1 } }).execute(rec('SECRETS'), ctx);
    if (outcome.kind !== 'completed') throw new Error('missing Secrets result');
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(1);
    expect(outcome.resultSummary.astSupplement?.parsed).toBe(1);
    expect(JSON.stringify(outcome)).not.toContain(fake);
  });
});

describe('DAST coverage and persisted active findings', () => {
  const target = 'https://app.example.org/api/';
  const policy = () => createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
  const response = (body = '') => ({ status: 200, headers: { 'content-type': 'text/html' }, body, bodyTruncated: false, elapsedMs: 3 });

  test('passive response with no rules is explicitly partial', async () => {
    const transport: DastTransport = { probe: async () => response('<p>synthetic</p>') };
    const outcome = await createDastEngine({ targetPolicy: policy(), transport, packRules: [] }).execute({ ...rec('DAST'), dastTargetUrl: target }, ctx);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.dast.partial).toBe(true);
    expect(outcome.dast.partialReason).toContain('No DAST response rules');
    expect(isDastResult(outcome.dast)).toBe(true);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('advisory findings omitted exactly at the cap are marked partial and truncated', async () => {
    const matches: AdvisoryMatch[] = Array.from({ length: 201 }, (_, index) => ({
      ruleId: `ADV-${1000 + index}`, advisoryId: `SYNTHETIC-${index}`, title: 'Synthetic advisory',
      description: 'Fixture only.', severity: 'HIGH', remediation: 'Review.', limitation: 'Fixture only.', references: [],
      ecosystem: 'fixture', component: 'fixture', observedVersion: '1.0.0', verdict: 'AFFECTED',
      reason: 'Synthetic.', evidence: 'Fixture evidence.', location: 'response header',
    }));
    const advisory: AdvisoryService = { configured: true,
      status: async () => ({ configured: true, loaded: true, recordCount: matches.length, stale: false, refused: [] }),
      evaluate: async () => ({ matches, recordsEvaluated: matches.length, signalsFound: 1, affected: matches.length, needsReview: 0, notAffected: 0 }),
    };
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: { probe: async () => response('fixture') }, advisory }).execute({ ...rec('DAST'), dastTargetUrl: target }, ctx);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.findings).toHaveLength(200);
    expect(outcome.findings?.every(isFinding)).toBe(true);
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(outcome.dast.partial).toBe(true);
    expect(outcome.dast.partialReason).toContain('cap');
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('active marker observations satisfy shared guards and are accepted by the scan store', async () => {
    const calls: string[] = [];
    const transport: DastTransport = { probe: async (resolved) => {
      calls.push(resolved.url);
      return resolved.url.includes('drobon-xss-1337') ? response('drobon-xss-1337') : response('<a href="/api/item">fixture</a>');
    } };
    const store = createMemoryScanStore();
    await store.createScanWithQuota({ ownerId: OWNER, projectId: PROJECT, scanType: 'DAST', targetUrl: target, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, consume: async () => ({ ok: true }) });
    const running = await store.claimNextQueued();
    if (running === undefined) throw new Error('scan missing');
    const outcome = await createDastEngine({ targetPolicy: policy(), transport }).execute(running, ctx);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(calls.some((url) => url.includes('drobon-xss-1337'))).toBe(true);
    const finding = outcome.findings?.find((item) => item.ruleId === 'DG-DAST-990001');
    expect(finding).toBeDefined();
    expect(isFinding(finding)).toBe(true);
    expect(outcome.dast.partial).toBe(true); // no dataset response rules
    expect(isDastResult(outcome.dast)).toBe(true);
    const persisted = await store.completeScan(running.id, outcome.resultSummary, outcome.findings, undefined, outcome.dast);
    expect(persisted?.status).toBe('COMPLETED');
    expect(persisted?.findings?.some((item) => item.ruleId === 'DG-DAST-990001')).toBe(true);
  });

  test('an active request failing after the baseline is disclosed as incomplete', async () => {
    let requests = 0;
    const transport: DastTransport = { probe: async () => {
      requests += 1;
      if (requests > 1) throw new Error('synthetic transport failure');
      return response('<a href="/api/item">fixture</a>');
    } };
    const outcome = await createDastEngine({ targetPolicy: policy(), transport }).execute({ ...rec('DAST'), dastTargetUrl: target, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, ctx);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(requests).toBeGreaterThan(1);
    expect(outcome.dast.partial).toBe(true);
    expect(outcome.dast.partialReason).toContain('request failed');
  });
});
