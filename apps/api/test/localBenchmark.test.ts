import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { describe, expect, test } from 'vitest';
import { cases, fixtureManifest, fixtureManifestDigest } from '../../../benchmarks/local/fixtures.mjs';
import { labResponse } from '../../../benchmarks/local/target.mjs';
import { scoreCases } from '../../../benchmarks/local/scoring.mjs';
import { scoreExternal } from '../../../benchmarks/local/score-external.mjs';
import { verifyOracle } from '../../../benchmarks/local/verify-oracle.mjs';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';

const ROOT = resolve(import.meta.dirname, '../../..');

describe('controlled local benchmark fixtures', () => {
  test('the separate mechanical oracle checks all fixed cases without independent-review claims', async () => {
    const result = await verifyOracle();
    expect(result.fixtureManifestSha256).toBe(fixtureManifestDigest());
    expect(result.independentHumanReview).toBe(false);
    expect(result.observations).toHaveLength(cases.length);
    expect(result.observations.every((entry) => entry.matches)).toBe(true);
    const targetHash = createHash('sha256').update(readFileSync(resolve(ROOT, 'benchmarks/local/target.mjs'))).digest('hex');
    expect(fixtureManifest().filter((entry) => entry.family === 'DAST').every((entry) => entry.targetSha256 === targetHash)).toBe(true);
  });

  test('the lab is a bounded GET/HEAD-only responder and keeps unknown routes inert', () => {
    expect(labResponse('/lab/header-missing').headers).not.toHaveProperty('x-content-type-options');
    expect(labResponse('/lab/header-invalid').headers).toHaveProperty('x-content-type-options', 'invalid');
    expect(labResponse('/lab/header-safe').headers).toHaveProperty('x-content-type-options', 'nosniff');
    const marker = encodeURIComponent('<b>synthetic</b>');
    expect(labResponse(`/lab/reflect-unsafe?input=${marker}`).body).toContain('<b>synthetic</b>');
    expect(labResponse(`/lab/reflect-safe?input=${marker}`).body).toContain('&lt;b&gt;synthetic&lt;/b&gt;');
    expect(labResponse('/lab/header-safe', 'POST').status).toBe(405);
    expect(labResponse('/outside').status).toBe(404);
    expect(labResponse('x'.repeat(2049)).status).toBe(400);
  });

  test('the real production DAST policy still rejects loopback', async () => {
    await expect(createDastTargetPolicy().prepare('http://127.0.0.1/')).rejects.toMatchObject({ code: 'DAST_TARGET_BLOCKED' });
  });

  test('case scoring excludes unknown, missing and incomplete observations rather than converting them to negatives', () => {
    const inputs = [
      { id: 'one', family: 'SAST', expected: true }, { id: 'two', family: 'SAST', expected: false },
      { id: 'three', family: 'SAST', expected: true }, { id: 'four', family: 'SAST', expected: null },
      { id: 'five', family: 'SAST', expected: false },
    ];
    const result = scoreCases(inputs, [
      { id: 'one', status: 'DETECTED' }, { id: 'two', status: 'DETECTED' },
      { id: 'three', status: 'UNASSESSED', reason: 'timeout' }, { id: 'four', status: 'NOT_DETECTED' },
    ]);
    expect(result.families['SAST']).toMatchObject({ cases: 5, assessed: 2, truePositive: 1, falsePositive: 1,
      trueNegative: 0, falseNegative: 0, unassessed: 2, unknownTruth: 1, precision: 0.5, recall: 1 });
    expect(result.rows.map((row: { verdict: string }) => row.verdict)).toEqual(['TP', 'FP', 'UNASSESSED', 'UNKNOWN_TRUTH', 'UNASSESSED']);
    expect(() => scoreCases(inputs, [{ id: 'one', status: 'DETECTED' }, { id: 'one', status: 'NOT_DETECTED' }])).toThrow();
    expect(() => scoreCases(inputs, [{ id: 'unknown', status: 'DETECTED' }])).toThrow();
    expect(() => scoreCases(inputs, [{ id: 'one', status: 'DONE' }])).toThrow();
  });

  test('external scoring rejects unreviewed, incomplete or fabricated negatives and keeps unavailable products unassessed', () => {
    const input = { schemaVersion: 'drobon.vendor-observations/v1', product: 'SNYK', version: null, executed: false,
      fixtureManifestSha256: fixtureManifestDigest(), unmappedAlertCount: null, observations: [] };
    const empty = scoreExternal(input);
    expect(empty.executed).toBe(false);
    expect(empty.unmappedAlertCount).toBeNull();
    expect(empty.scores.families['SAST'].unassessed).toBe(8);
    expect(empty.scores.families['SCA'].unknownTruth).toBe(1);
    const claim = { id: 'SAST-01', status: 'NOT_DETECTED', coverage: 'PARTIAL', reasonCode: null,
      mappingReviewed: true, evidenceReviewed: true, matchingFindings: 0 };
    expect(() => scoreExternal({ ...input, observations: [claim] })).toThrow();
    expect(() => scoreExternal({ ...input, executed: true, version: '1.2.3', observations: [claim] })).toThrow();
    expect(() => scoreExternal({ ...input, executed: true, version: '1.2.3', observations: [{ ...claim, coverage: 'COMPLETE', evidenceReviewed: false }] })).toThrow();
    expect(() => scoreExternal({ ...input, executed: true, version: '1.2.3', observations: [{ ...claim, status: 'DETECTED', coverage: 'COMPLETE' }] })).toThrow();
    expect(() => scoreExternal({ ...input, product: 'OTHER_VENDOR' })).toThrow();
    expect(() => scoreExternal({ ...input, unmappedAlertCount: 1 })).toThrow();
    expect(() => scoreExternal({ ...input, observations: [{ ...claim, status: 'UNASSESSED', reasonCode: 'NOT_RUN', coverage: 'NONE', matchingFindings: 1 }] })).toThrow();
    expect(() => scoreExternal({ ...input, rawReport: 'must not be imported' })).toThrow();
  });

  test('materialization refuses an existing directory and never overwrites its contents', () => {
    const temp = mkdtempSync(join(tmpdir(), 'drobon-lab-test-'));
    try {
      const output = join(temp, 'new-corpus');
      const args = [resolve(ROOT, 'benchmarks/local/materialize.mjs'), output];
      const first = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8' });
      expect(first.status).toBe(0);
      expect(statSync(output).mode & 0o777).toBe(0o700);
      const file = join(output, 'SAST-01', 'src', 'case.js');
      const content = readFileSync(file, 'utf8');
      expect(statSync(file).mode & 0o777).toBe(0o600);
      const second = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8' });
      expect(second.status).not.toBe(0);
      expect(readFileSync(file, 'utf8')).toBe(content);
      const forbidden = spawnSync(process.execPath, [resolve(ROOT, 'benchmarks/local/materialize.mjs'), join(temp, 'Drobon-Dataset', 'new')], { cwd: ROOT, encoding: 'utf8' });
      expect(forbidden.status).not.toBe(0);
      const alias = join(temp, 'checkout-alias');
      symlinkSync(ROOT, alias, 'dir');
      const aliasedCheckout = spawnSync(process.execPath, [resolve(ROOT, 'benchmarks/local/materialize.mjs'), join(alias, 'never-create')], { cwd: ROOT, encoding: 'utf8' });
      expect(aliasedCheckout.status).not.toBe(0);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  test('an isolated case runs alone and an unknown case fails closed', () => {
    const command = ['--import', 'tsx', resolve(ROOT, 'benchmarks/local/run-drobon.mjs')];
    const run = spawnSync(process.execPath, command, {
      cwd: ROOT, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, DROBON_BENCHMARK_CASE_ID: 'SAST-02' },
    });
    expect(run.status, run.stderr).toBe(0);
    const result = JSON.parse(run.stdout) as { cases: Array<{ id: string }>; observations: Array<{ id: string }>; scores: { rows: Array<{ id: string }> } };
    expect(result.cases.map((item) => item.id)).toEqual(['SAST-02']);
    expect(result.observations.map((item) => item.id)).toEqual(['SAST-02']);
    expect(result.scores.rows.map((item) => item.id)).toEqual(['SAST-02']);
    const unknown = spawnSync(process.execPath, command, {
      cwd: ROOT, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, DROBON_BENCHMARK_CASE_ID: 'NOT-A-CASE' },
    });
    expect(unknown.status).not.toBe(0);
  }, 40_000);

  test('Drobon engine run is case-accounted and checks report integrity without leaking source', () => {
    const run = spawnSync(process.execPath, ['--import', 'tsx', resolve(ROOT, 'benchmarks/local/run-drobon.mjs')],
      { cwd: ROOT, encoding: 'utf8', timeout: 90_000, maxBuffer: 1_000_000 });
    expect(run.status, run.stderr).toBe(0);
    const result = JSON.parse(run.stdout) as {
      fixtureManifestSha256: string; groundTruthReview: string;
      observations: Array<{ internalError?: boolean; report?: { integrity: boolean; countMatches: boolean; sourceOrSyntheticSecretPresent: boolean } }>;
      scores: { rows: Array<{ id: string; verdict: string }> };
    };
    expect(result.fixtureManifestSha256).toBe(fixtureManifestDigest());
    expect(result.groundTruthReview).toBe('AUTHOR_DEFINED_NOT_INDEPENDENTLY_REVIEWED');
    expect(result.scores.rows).toHaveLength(cases.length);
    expect(result.scores.rows.find((row) => row.id === 'SCA-04')?.verdict).toBe('UNKNOWN_TRUTH');
    expect(result.scores.rows.find((row) => row.id === 'DAST-04')?.verdict).toBe('UNASSESSED');
    expect(result.observations.some((entry) => entry.internalError)).toBe(false);
    const reports = result.observations.flatMap((entry) => entry.report === undefined ? [] : [entry.report]);
    expect(reports).toHaveLength(19);
    expect(reports.every((entry) => entry.integrity && entry.countMatches && !entry.sourceOrSyntheticSecretPresent)).toBe(true);
  }, 100_000);
});
