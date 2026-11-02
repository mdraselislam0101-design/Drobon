import { afterEach, describe, expect, test } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  aggregateContractVerdict, contractProblemMessage, declaredPackSchemaVersion, emptyContractState,
  evaluatePackContract, parsePackLayoutVersion, selectSupportedLayoutVersion,
  DATASET_CONTRACT_VERSION, SUPPORTED_PACK_LAYOUT_VERSIONS, SUPPORTED_PACK_SCHEMA_VERSIONS,
} from '../src/external/contract.js';
import { createDatasetService } from '../src/external/service.js';
import { datasetContractProblem, hasRejectedPackRules } from '../src/external/packIntegration.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { createNullIntelligenceProvider } from '../src/scans/sca/provider.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import { createMemorySourceStore } from '../src/scans/sources.js';
import { SAST_RULES } from '../src/scans/sast/rules.js';
import { SECRETS_RULES } from '../src/scans/secrets/rules.js';
import { evaluateDastObservation } from '../src/scans/dast/rules.js';
import type { ScanRecord } from '../src/scans/store.js';

/**
 * Every directory here is a synthetic temp directory created by this test.
 * NOTHING in this file reads, writes or references the separate
 * Drobon-Dataset repository: the integration contract is exercised with
 * hand-written fixture files only.
 */

const dirs: string[] = [];
const silent = { info: () => {}, warn: () => {}, error: () => {} };
const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const context = { signal: new AbortController().signal };

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function put(root: string, path: string, value: unknown): void {
  const file = join(root, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value));
}

const sastRule = (id = 'DPK-SAST-900') => ({
  schemaVersion: 'drobon.pack.sast/v1', id, title: 'Fixture', description: 'Synthetic fixture.',
  severity: 'LOW', category: 'fixture', remediation: 'Review.', limitation: 'Fixture only.',
  patternRefs: ['DPK-PAT-9001'], languages: ['javascript'],
  patterns: [{ source: '\\beval\\s*\\(' }],
  tests: [{ line: 'eval(x);', match: true }, { line: 'const x = 1;', match: false }],
});

const secretsRule = () => ({
  schemaVersion: 'drobon.pack.secrets/v1', id: 'DPK-SEC-900', title: 'Fixture',
  description: 'Synthetic fixture.', severity: 'LOW', category: 'fixture', remediation: 'Rotate.',
  limitation: 'Fixture only.', confidence: 'MEDIUM', redact: true, matchOnlyEvidence: true,
  patternRefs: ['DPK-PAT-9002'], patterns: [{ source: 'FIXTURE_MARKER' }],
  tests: [{ line: 'FIXTURE_MARKER', match: true }, { line: 'nothing', match: false }],
});

/** A synthetic dataset tree with an explicitly chosen pack layout version. */
function datasetTree(layout: 'v1' | 'v2' | 'both', options: { manifests?: boolean; manifestSchema?: string } = {}): string {
  const root = mkdtempSync(join(tmpdir(), 'drobon-contract-fixture-'));
  dirs.push(root);
  const families = ['sast', 'secrets', 'dast', 'sca'] as const;
  for (const family of families) {
    const versions = layout === 'both' ? ['v1', 'v2'] : [layout];
    for (const version of versions) {
      // Only v1 carries a loadable rule shape; v2 is deliberately opaque to
      // this app, exactly like a future Dataset release would be.
      if (version === 'v1') {
        const rule = family === 'sast' ? sastRule() : family === 'secrets' ? secretsRule() : {
          ...sastRule(family === 'dast' ? 'DPK-DAST-900' : 'DPK-SCA-9001'),
          schemaVersion: `drobon.pack.${family}/v1`,
          ...(family === 'dast'
            ? { check: { type: 'missing-response-header', header: 'content-security-policy' } }
            : { ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
                check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' } }),
        };
        put(root, `packs/${family}/v1/rules/rule.json`, rule);
      } else {
        put(root, `packs/${family}/v2/rules/rule.json`, { format: 'future', ...sastRule('DPK-SAST-999') });
      }
      if (options.manifests !== false) {
        put(root, `packs/${family}/${version}/pack.json`, {
          schemaVersion: options.manifestSchema ?? `drobon.pack.${family}/v1`,
          packId: `fixture-${family}`, version: '1.0.0',
        });
      }
    }
  }
  put(root, 'vuln-intel/npm/ADV-900.json', {
    schemaVersion: 'drobon.vuln-intel/v1', fixture: false, id: 'ADV-900', ecosystem: 'npm',
    package: 'fixture-pkg', summary: 'Fixture only', severity: 'LOW',
    affected: [{ range: '< 2.0.0' }], provenance: { source: 'FIXTURE' },
  });
  return root;
}

function sastRecord(): ScanRecord {
  return { id: 'scan_00000000-0000-4000-8000-000000000021', ownerId: OWNER, projectId: PROJECT,
    scanType: 'SAST', status: 'RUNNING', createdAt: '2026-10-01T00:00:00.000Z',
    updatedAt: '2026-10-01T00:00:00.000Z', startedAt: '2026-10-01T00:00:00.000Z' };
}

function sources() {
  const store = createMemorySourceStore();
  return {
    store,
    seed: async () => { await store.replace({ ownerId: OWNER, projectId: PROJECT,
      files: [{ path: 'src/app.js', content: 'const x = 1;\neval(input);\n' }] }); },
  };
}

describe('contract primitives', () => {
  test('only an explicit v<major> directory name is a layout version', () => {
    expect(parsePackLayoutVersion('v1')).toBe(1);
    expect(parsePackLayoutVersion('v2')).toBe(2);
    expect(parsePackLayoutVersion('v12')).toBe(12);
    for (const invalid of ['v0', 'v01', '1', 'v1x', 'V1', '', 'rules', 'v9999']) {
      expect(parsePackLayoutVersion(invalid), invalid).toBeUndefined();
    }
    expect(parsePackLayoutVersion(undefined as never)).toBeUndefined();
  });

  test('manifest schema version is parsed only for its own family', () => {
    expect(declaredPackSchemaVersion({ schemaVersion: 'drobon.pack.sast/v1' }, 'sast')).toBe(1);
    expect(declaredPackSchemaVersion({ schemaVersion: 'drobon.pack.sast/v2' }, 'sast')).toBe(2);
    // A SAST-schema manifest never describes the secrets family.
    expect(declaredPackSchemaVersion({ schemaVersion: 'drobon.pack.sast/v1' }, 'secrets')).toBeUndefined();
    expect(declaredPackSchemaVersion({ schemaVersion: 'drobon.pack.sast' }, 'sast')).toBeUndefined();
    expect(declaredPackSchemaVersion({ schemaVersion: 1 }, 'sast')).toBeUndefined();
    expect(declaredPackSchemaVersion(null, 'sast')).toBeUndefined();
  });

  test('the app declares exactly one supported layout and schema version', () => {
    expect(DATASET_CONTRACT_VERSION).toBe(1);
    expect([...SUPPORTED_PACK_LAYOUT_VERSIONS]).toEqual([1]);
    expect([...SUPPORTED_PACK_SCHEMA_VERSIONS]).toEqual([1]);
    expect(selectSupportedLayoutVersion([2, 3])).toBeUndefined();
    expect(selectSupportedLayoutVersion([1, 2])).toBe(1);
  });

  test('a supported layout is COMPATIBLE, an unsupported one is INCOMPATIBLE', () => {
    const configured = true;
    expect(evaluatePackContract({ family: 'sast', configured: false, observedLayoutVersions: [] }).verdict)
      .toBe('NOT_CONFIGURED');
    expect(evaluatePackContract({ family: 'sast', configured, observedLayoutVersions: [1] }))
      .toMatchObject({ verdict: 'COMPATIBLE', layoutVersion: 1, issues: [] });
    expect(evaluatePackContract({ family: 'sast', configured, observedLayoutVersions: [2] }))
      .toMatchObject({ verdict: 'INCOMPATIBLE', unsupportedLayoutVersions: 1,
        issues: ['pack-layout-version-unsupported'] });
    // Absent family = format not contradicted, coverage reported separately.
    // It is never INCOMPATIBLE, and the issue code still marks it incomplete.
    expect(evaluatePackContract({ family: 'sast', configured, observedLayoutVersions: [] }))
      .toMatchObject({ verdict: 'COMPATIBLE', issues: ['no-supported-pack-layout'] });
    expect(contractProblemMessage(evaluatePackContract({ family: 'sast', configured,
      observedLayoutVersions: [] }))).toBeUndefined();
  });

  test('a newer layout next to a supported one is loaded but flagged as incomplete coverage', () => {
    const state = evaluatePackContract({ family: 'secrets', configured: true, observedLayoutVersions: [1, 2] });
    expect(state.verdict).toBe('COMPATIBLE');
    expect(state.layoutVersion).toBe(1);
    expect(state.unsupportedLayoutVersions).toBe(1);
    expect(state.issues).toEqual(['pack-layout-version-newer-ignored']);
  });

  test('a manifest that declares a future schema version is INCOMPATIBLE even with a v1 directory', () => {
    const state = evaluatePackContract({ family: 'dast', configured: true, observedLayoutVersions: [1],
      manifest: { schemaVersion: 'drobon.pack.dast/v2' } });
    expect(state.verdict).toBe('INCOMPATIBLE');
    expect(state.issues).toContain('manifest-schema-version-unsupported');
    expect(state.manifestSchemaVersion).toBe(2);
  });

  test('an unreadable directory or manifest is UNKNOWN, never COMPATIBLE', () => {
    expect(evaluatePackContract({ family: 'sca', configured: true, observedLayoutVersions: [1],
      directoryUnreadable: true }).verdict).toBe('UNKNOWN');
    expect(evaluatePackContract({ family: 'sca', configured: true, observedLayoutVersions: [1],
      manifestUnreadable: true }).verdict).toBe('UNKNOWN');
  });

  test('aggregation prefers incompatibility and the aggregate state is path-free', () => {
    const compatible = evaluatePackContract({ family: 'sast', configured: true, observedLayoutVersions: [1] });
    const unknown = evaluatePackContract({ family: 'sca', configured: true, observedLayoutVersions: [1],
      directoryUnreadable: true });
    const incompatible = evaluatePackContract({ family: 'dast', configured: true, observedLayoutVersions: [3] });
    expect(aggregateContractVerdict([compatible])).toBe('COMPATIBLE');
    expect(aggregateContractVerdict([compatible, unknown])).toBe('UNKNOWN');
    expect(aggregateContractVerdict([compatible, unknown, incompatible])).toBe('INCOMPATIBLE');
    expect(aggregateContractVerdict([emptyContractState(false).families.sast])).toBe('NOT_CONFIGURED');
    const text = contractProblemMessage(incompatible) ?? '';
    expect(text.length).toBeGreaterThan(0);
    // No path, filename or rule text may appear in an operator-facing reason.
    expect(text).not.toContain('/');
    expect(text).not.toContain('DPK-');
    expect(contractProblemMessage(compatible)).toBeUndefined();
    expect(contractProblemMessage(emptyContractState(false).families.sast)).toBeUndefined();
  });
});

describe('dataset service applies the contract', () => {
  test('a v1 dataset stays fully compatible and loadable (existing connection preserved)', async () => {
    const root = datasetTree('v1');
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.contract.verdict).toBe('COMPATIBLE');
    expect(status.contract.contractVersion).toBe(DATASET_CONTRACT_VERSION);
    expect(status.contract.families.sast).toMatchObject({ verdict: 'COMPATIBLE', layoutVersion: 1, issues: [] });
    expect(status.sastPacks.status).toBe('AVAILABLE');
    expect(status.sastPacks.incomplete).toBeUndefined();
    expect(await service.sastPacks()).toHaveLength(1);
    expect(await datasetContractProblem(service, 'sast')).toBeUndefined();
    expect(await hasRejectedPackRules(service, 'sast')).toBe(false);
  });

  test('a v2-only dataset fails closed: no rules, INCOMPATIBLE, category unavailable', async () => {
    const root = datasetTree('v2');
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.contract.verdict).toBe('INCOMPATIBLE');
    expect(status.contract.families.sast.verdict).toBe('INCOMPATIBLE');
    expect(status.contract.issues).toContain('pack-layout-version-unsupported');
    expect(status.sastPacks.status).toBe('UNAVAILABLE');
    expect(status.sastPacks.count).toBe(0);
    expect(status.sastPacks.incomplete).toBe(true);
    expect(await service.sastPacks()).toEqual([]);
    expect(await datasetContractProblem(service, 'sast')).toContain('not compatible');
    expect(await hasRejectedPackRules(service, 'sast')).toBe(true);
  });

  test('v1 and v2 side by side load v1 and disclose the ignored newer layout', async () => {
    const root = datasetTree('both');
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.contract.verdict).toBe('COMPATIBLE');
    expect(status.contract.families.sast).toMatchObject({ verdict: 'COMPATIBLE', layoutVersion: 1,
      observedLayoutVersions: 2, unsupportedLayoutVersions: 1, issues: ['pack-layout-version-newer-ignored'] });
    expect(await service.sastPacks()).toHaveLength(1);
    expect(status.sastPacks.incomplete).toBe(true);
    // Not incompatible: the supported version really did load.
    expect(await datasetContractProblem(service, 'sast')).toBeUndefined();
  });

  test('a manifest declaring a future schema version refuses the whole family', async () => {
    const root = datasetTree('v1', { manifestSchema: 'drobon.pack.sast/v2' });
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.contract.families.sast.verdict).toBe('INCOMPATIBLE');
    expect(status.contract.families.sast.issues).toContain('manifest-schema-version-unsupported');
    expect(await datasetContractProblem(service, 'sast')).toContain('not compatible');
    // The secrets family keeps its own valid v1 manifest and is unaffected.
    expect(status.contract.families.secrets.verdict).toBe('COMPATIBLE');
  });

  test('an unreadable family directory is UNKNOWN and loads nothing', async () => {
    const root = datasetTree('v1');
    rmSync(join(root, 'packs', 'dast'), { recursive: true, force: true });
    symlinkSync('/nonexistent-drobon-contract-fixture', join(root, 'packs', 'dast'));
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.contract.families.dast.verdict).toBe('UNKNOWN');
    expect(status.contract.verdict).toBe('UNKNOWN');
    expect(await service.dastPacks()).toEqual([]);
    expect(await datasetContractProblem(service, 'dast')).toContain('could not be validated');
  });

  test('an unconfigured service reports NOT_CONFIGURED with no fabricated issues', async () => {
    const service = createDatasetService({ providerId: 'none', logger: silent });
    const status = await service.status();
    expect(status.contract.verdict).toBe('NOT_CONFIGURED');
    expect(status.contract.families.sast.verdict).toBe('NOT_CONFIGURED');
    expect(status.contract.issues).toEqual([]);
    expect(await datasetContractProblem(service, 'sast')).toBeUndefined();
  });
});

describe('engines report PARTIAL instead of claiming detection without rules', () => {
  test('SAST with an incompatible dataset completes as partial and finds nothing', async () => {
    const root = datasetTree('v2');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const source = sources();
    await source.seed();
    const engine = createSastEngine({ sources: source.store, dataset });
    const outcome = await engine.execute(sastRecord(), context);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.findings).toBeUndefined();
    expect(outcome.resultSummary.findingsTotal).toBe(0);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('not compatible');
  });

  test('Secrets with an incompatible dataset never implies "no secrets"', async () => {
    const root = datasetTree('v2');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const source = sources();
    await source.seed();
    const engine = createSecretsEngine({ sources: source.store, dataset });
    const outcome = await engine.execute({ ...sastRecord(), scanType: 'SECRETS' }, context);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('not compatible');
    expect(outcome.resultSummary.findingsTotal).toBe(0);
  });

  test('SCA marks declaration coverage partial when the pack version is unsupported', async () => {
    const root = datasetTree('v2');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const source = sources();
    await source.seed();
    const engine = createScaEngine({ sources: source.store, dataset,
      provider: createNullIntelligenceProvider() });
    const outcome = await engine.execute({ ...sastRecord(), scanType: 'SCA' }, context);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('not compatible');
    expect(outcome.resultSummary.declarationRulesEvaluated).toBe(0);
  });

  test('DAST reports the incompatible pack version as a partial observation', async () => {
    const root = datasetTree('v2');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const engine = createDastEngine({
      targetPolicy: createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] }),
      dataset,
      transport: { probe: async () => ({ status: 200, headers: { 'content-type': 'text/html' },
        body: '<html></html>', bodyTruncated: false, elapsedMs: 5 }) },
    });
    const record: ScanRecord = { id: 'scan_00000000-0000-4000-8000-000000000022', ownerId: OWNER,
      projectId: PROJECT, scanType: 'DAST', status: 'RUNNING', dastTargetUrl: 'https://fixture.example.org/',
      createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z', startedAt: '2026-10-01T00:00:00.000Z' };
    const outcome = await engine.execute(record, context);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('not compatible');
    expect(outcome.findings).toEqual([]);
  });
});

describe('strict separation invariants asserted in code', () => {
  test('the Main App ships no embedded scanner rules or signatures', () => {
    // Rule data lives in the external Dataset only; these registries must stay
    // empty so a missing Dataset can never be papered over by built-in rules.
    expect(SAST_RULES).toEqual([]);
    expect(SECRETS_RULES).toEqual([]);
    expect(evaluateDastObservation({ url: 'https://fixture.example.org/', status: 200, headers: {}, body: 'x' }))
      .toEqual([]);
  });

  test('every engine reads the contract rather than inferring compatibility from an empty list', async () => {
    const root = datasetTree('v2');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    for (const family of ['sast', 'secrets', 'dast', 'sca'] as const) {
      expect(await datasetContractProblem(dataset, family), family).toContain('not compatible');
    }
  });
});
