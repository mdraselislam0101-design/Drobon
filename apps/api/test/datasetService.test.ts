import { afterEach, describe, expect, test } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDatasetService } from '../src/external/service.js';

const dirs: string[] = [];
const silent = { info: () => {}, warn: () => {}, error: () => {} };

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixtureDataset(): string {
  const root = mkdtempSync(join(tmpdir(), 'drobon-dataset-fixture-'));
  dirs.push(root);
  const put = (path: string, value: unknown) => {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), JSON.stringify(value));
  };
  // Two FILES, one advisory id, one identity item (sharded record).
  const record = {
    schemaVersion: 'drobon.vuln-intel/v1', fixture: false, id: 'ADV-900',
    ecosystem: 'npm', package: 'fixture-pkg', summary: 'Fixture only', severity: 'LOW',
    affected: [{ range: '< 2.0.0' }], provenance: { source: 'FIXTURE' },
  };
  put('vuln-intel/npm/ADV-900.json', record);
  put('vuln-intel/npm/ADV-900--2.json', record);
  put('vuln-intel/npm/samples/ADV-SAMPLE.json', { ...record, id: 'ADV-SAMPLE', fixture: true });
  put('packs/sast/v1/pack.json', { schemaVersion: 'drobon.pack.sast/v1', packId: 'fixture-sast', version: '2.3.4' });
  put('packs/sast/v1/rules/DPK-SAST-900.json', {
    schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-900', title: 'Fixture',
    description: 'Fixture', severity: 'LOW', category: 'fixture', remediation: 'Fix',
    limitation: 'Fixture', patternRefs: ['DPK-PAT-9001'], languages: ['javascript'],
    patterns: [{ source: '\\beval\\s*\\(' }],
    tests: [{ line: 'eval(x);', match: true }, { line: 'const x = 1;', match: false }],
  });
  put('packs/sast/v1/rules/DPK-SAST-901.json', {
    schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-901', title: 'Bad',
    description: 'Bad', severity: 'LOW', category: 'fixture', remediation: 'Fix',
    limitation: 'Fixture', patternRefs: ['DPK-PAT-9002'], inventedField: true,
    patterns: [{ source: 'x' }], tests: [{ line: 'x', match: true }, { line: 'y', match: false }],
  });
  put('knowledge/remediation/DPK-SAST-900.json', {
    schemaVersion: 'drobon.knowledge.remediation/v1', ruleId: 'DPK-SAST-900',
    whyItMatters: 'Fixture', actions: ['Fix it'], verification: 'Rerun the scan',
  });
  return root;
}

describe('unified dataset service', () => {
  test('an unconfigured service reports honest NOT_CONFIGURED everywhere', async () => {
    const service = createDatasetService({ providerId: 'none', logger: silent });
    const status = await service.status();
    expect(status.configured).toBe(false);
    expect(status.sastPacks.status).toBe('NOT_CONFIGURED');
    expect(status.vulnIntel.status).toBe('NOT_CONFIGURED');
    expect(status.vulnIntelCounts).toEqual({ files: 0, identityItems: 0, advisoryIds: 0 });
    expect(status.conformance.sast.accepted).toBe(0);
    expect(await service.sastPacks()).toEqual([]);
  });

  test('SCA eligible rule count excludes artifacts blocked by source-path policy', async () => {
    const root = fixtureDataset();
    const dir = join(root, 'packs', 'sca', 'v1', 'rules');
    mkdirSync(dir, { recursive: true });
    const rule = {
      schemaVersion: 'drobon.pack.sca/v1', id: 'DPK-SCA-9001', title: 'Fixture',
      description: 'Fixture declaration.', severity: 'LOW', category: 'fixture',
      remediation: 'Review.', limitation: 'Fixture.', ecosystems: ['npm'],
      artifact: 'package.json', parser: 'json', patternRefs: ['DPK-PAT-9001'],
      check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
      tests: [
        { file: 'package.json', document: { dependencies: { x: '*' } }, match: true },
        { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: false },
      ],
    };
    writeFileSync(join(dir, 'allowed.json'), JSON.stringify(rule));
    writeFileSync(join(dir, 'blocked.json'), JSON.stringify({ ...rule, id: 'DPK-SCA-9002', artifact: '.npmrc' }));
    const status = await createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent }).status();
    expect(status.scaPacks.count).toBe(2);
    expect(status.conformance.scaDeclarationScanReachableRules).toBe(1);
  });

  test('configured service deduplicates vuln-intel identity and refuses invalid packs', async () => {
    const root = fixtureDataset();
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger: silent });
    const status = await service.status();
    expect(status.configured).toBe(true);
    expect(status.vulnIntel.count).toBe(2);
    expect(status.vulnIntelCounts).toEqual({ files: 2, identityItems: 1, advisoryIds: 1 });
    expect(status.sastPacks.count).toBe(1);
    expect(status.sastPacks.packId).toBe('fixture-sast');
    expect(status.sastPacks.version).toBe('2.3.4');
    expect(status.conformance.sast).toMatchObject({ filesSeen: 2, accepted: 1, declaredTests: 2, executedTests: 2, failedTests: 0 });
    expect(status.conformance.sast.rejected[0]?.id).toBe('DPK-SAST-901');
    expect(status.conformance.scaDeclarationEvaluator).toBe('AVAILABLE');
    expect(status.conformance.scaDeclarationScanParsers).toContain('json');
    expect(status.conformance.scaDeclarationScanReachableRules).toBeGreaterThanOrEqual(0);
    expect(await service.remediation()).toHaveLength(1);
    expect(await service.packMetadata('sast')).toEqual({ packId: 'fixture-sast', version: '2.3.4' });
  });
});
