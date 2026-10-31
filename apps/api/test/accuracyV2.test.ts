import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, test } from 'vitest';
import { addedCases, cases, manifest, manifestDigest, syntheticSecrets } from '../../../benchmarks/accuracy-v2/fixtures.mjs';
import { verifyExpandedOracle } from '../../../benchmarks/accuracy-v2/verify-oracle.mjs';
import { scoreExpandedExternal } from '../../../benchmarks/accuracy-v2/score-external.mjs';

const ROOT = resolve(import.meta.dirname, '../../..');
const DIGEST = '8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6';

describe('expanded, provisional local accuracy corpus', () => {
  test('freezes the old 21 and 41 additional, uniquely named cases with rule and target hashes', () => {
    expect(cases).toHaveLength(62);
    expect(addedCases).toHaveLength(41);
    expect(new Set(cases.map((item) => item.id)).size).toBe(62);
    expect(manifestDigest()).toBe(DIGEST);
    expect(manifest().cases).toHaveLength(62);
    expect(manifest().testRulesSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest().extraRulesSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest().targetSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  test('an independent mechanical implementation verifies all labels without claiming human review', async () => {
    const oracle = await verifyExpandedOracle();
    expect(oracle.independentHumanReview).toBe(false);
    expect(oracle.fixtureManifestSha256).toBe(DIGEST);
    expect(oracle.observations).toHaveLength(62);
    expect(oracle.observations.every((item: { matches: boolean }) => item.matches)).toBe(true);
    for (const value of syntheticSecrets) expect(JSON.stringify(oracle)).not.toContain(value);
  });

  test('strict external scoring accepts an unrun template and refuses unsupported claims', () => {
    const input = { schemaVersion: 'drobon.vendor-observations/v1', product: 'SNYK', version: null, executed: false,
      fixtureManifestSha256: DIGEST, unmappedAlertCount: null, observations: [] };
    const result = scoreExpandedExternal(input);
    expect(result.executed).toBe(false);
    expect(result.scores.rows).toHaveLength(62);
    expect(result.scores.families['SAST']).toMatchObject({ unassessed: 20, unknownTruth: 1 });
    expect(() => scoreExpandedExternal({ ...input, fixtureManifestSha256: '0'.repeat(64) })).toThrow();
    expect(() => scoreExpandedExternal({ ...input, observations: [{ id: 'AX-SCA-07', status: 'NOT_DETECTED',
      coverage: 'COMPLETE', reasonCode: null, mappingReviewed: true, evidenceReviewed: true, matchingFindings: 0 }] })).toThrow();
  });

  test('materializes only a new private directory outside any Git checkout', () => {
    const temp = mkdtempSync(join(tmpdir(), 'drobon-accuracy-v2-'));
    try {
      const output = join(temp, 'lab');
      const args = [resolve(ROOT, 'benchmarks/accuracy-v2/materialize.mjs'), output];
      const first = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8' });
      expect(first.status, first.stderr).toBe(0);
      expect(statSync(output).mode & 0o777).toBe(0o700);
      const file = join(output, 'AX-SCA-07', 'nuget.config');
      const before = readFileSync(file, 'utf8');
      expect(statSync(file).mode & 0o777).toBe(0o600);
      expect(JSON.parse(readFileSync(join(output, 'MANIFEST.json'), 'utf8')).fixtureManifestSha256).toBe(DIGEST);
      expect(spawnSync(process.execPath, args, { cwd: ROOT }).status).not.toBe(0);
      expect(readFileSync(file, 'utf8')).toBe(before);
      const alias = join(temp, 'checkout-alias');
      symlinkSync(ROOT, alias, 'dir');
      expect(spawnSync(process.execPath, [args[0] as string, join(alias, 'never-create')], { cwd: ROOT }).status).not.toBe(0);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  });

  test('the engine runner preserves coverage gaps and result/report privacy', () => {
    const run = spawnSync(process.execPath, ['--import', 'tsx', resolve(ROOT, 'benchmarks/accuracy-v2/run.mjs')],
      { cwd: ROOT, encoding: 'utf8', timeout: 100_000, maxBuffer: 2_000_000 });
    expect(run.status, run.stderr).toBe(0);
    const result = JSON.parse(run.stdout) as { fixtureManifestSha256: string; observations: Array<{ internalError?: boolean;
      report?: { integrity: boolean; countMatches: boolean; sourceOrSyntheticSecretPresent: boolean } }>;
      scores: { rows: Array<{ id: string; verdict: string }>; families: Record<string, { cases: number; unassessed: number; unknownTruth: number }> } };
    expect(result.fixtureManifestSha256).toBe(DIGEST);
    expect(result.scores.rows).toHaveLength(62);
    const verdict = (id: string) => result.scores.rows.find((row) => row.id === id)?.verdict;
    expect(verdict('SECRET-02')).toBe('TP');
    expect(verdict('SAST-02')).toBe('FP');
    expect(verdict('SAST-04')).toBe('FP');
    expect(verdict('SCA-03')).toBe('FN');
    expect(verdict('DAST-02')).toBe('FN');
    expect(verdict('AX-SCA-07')).toBe('TP');
    expect(verdict('AX-SCA-10')).toBe('UNKNOWN_TRUTH');
    expect(verdict('AX-SEC-06')).toBe('UNASSESSED');
    expect(verdict('AX-DAST-06')).toBe('UNASSESSED');
    expect(result.observations.some((item) => item.internalError)).toBe(false);
    const reports = result.observations.flatMap((item) => item.report === undefined ? [] : [item.report]);
    expect(reports).toHaveLength(59);
    expect(reports.every((item) => item.integrity && item.countMatches && !item.sourceOrSyntheticSecretPresent)).toBe(true);
    for (const value of syntheticSecrets) expect(run.stdout).not.toContain(value);
  }, 110_000);
});
