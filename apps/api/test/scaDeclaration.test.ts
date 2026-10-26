import { describe, expect, test } from 'vitest';
import {
  findingScanner,
  isFinding,
  isScanResultSummary,
  MAX_FINDINGS_PER_SCAN,
} from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import type { DatasetService } from '../src/external/service.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';
import {
  compileScaDeclarationRule,
  evaluateScaDeclarationCheck,
  boundedScaDistance,
  resolveScaPath,
  scaKeysAtPath,
  SCA_READABLE_PARSERS,
} from '../src/external/scaDeclaration.js';
import { evaluateScaDeclarations } from '../src/scans/sca/declarationScan.js';

/**
 * Pump 14 — SCA declaration-document evaluator (MAIN-APP ONLY).
 * The dataset repo is NOT edited here: these fixtures are small, fake,
 * self-contained declaration rules that exercise the app's own engine.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';

function scanRecord(): ScanRecord {
  return {
    id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: 'SCA', status: 'RUNNING',
    createdAt: '2026-10-26T10:00:00.000Z', updatedAt: '2026-10-26T10:00:00.000Z',
    startedAt: '2026-10-26T10:00:00.000Z',
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

const RULE_BASE = {
  schemaVersion: 'drobon.pack.sca/v1',
  title: 'Fixture declaration rule',
  description: 'Test-only declaration classification.',
  severity: 'MEDIUM',
  category: 'dependency-hygiene',
  remediation: 'Pin the dependency to a narrow range.',
  limitation: 'Fixture only; does not prove an installed version is affected.',
  cwe: 'CWE-1104',
  ecosystems: ['npm'],
  artifact: 'package.json',
  parser: 'json',
  patternRefs: ['DPK-PAT-9001'],
  tests: [
    { file: 'package.json', document: { dependencies: { fixture: '*' } }, match: true },
    { file: 'package.json', document: { dependencies: { fixture: '1.0.0' } }, match: false },
  ],
};

function rule(id: string, check: Record<string, unknown>, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { ...RULE_BASE, id, check, ...overrides };
}

describe('declaration evaluator: six closed predicates', () => {
  test('field-matches / field-not-matches / field-absent', () => {
    const matches = compileScaDeclarationRule(rule('DPK-SCA-9001', { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' }));
    const notMatches = compileScaDeclarationRule(rule('DPK-SCA-9002', { type: 'sca-field-not-matches', path: 'dependencies.*', valuePattern: '^\\*$' }));
    const absent = compileScaDeclarationRule(rule('DPK-SCA-9003', { type: 'sca-field-absent', path: 'lockfileVersion' }));
    expect(matches).toBeDefined();
    expect(notMatches).toBeDefined();
    expect(absent).toBeDefined();
    if (matches === undefined || notMatches === undefined || absent === undefined) return;
    const doc = { dependencies: { left: '*', right: '1.0.0' } };
    expect(evaluateScaDeclarationCheck(matches, doc)).toBe(true);
    expect(evaluateScaDeclarationCheck(notMatches, doc)).toBe(false);
    expect(evaluateScaDeclarationCheck(notMatches, { dependencies: { left: '1.0.0' } })).toBe(true);
    expect(evaluateScaDeclarationCheck(absent, doc)).toBe(true);
    expect(evaluateScaDeclarationCheck(absent, { ...doc, lockfileVersion: 3 })).toBe(false);
  });

  test('entry-missing-field / key-matches / name-distance', () => {
    const missing = compileScaDeclarationRule(rule('DPK-SCA-9004', { type: 'sca-entry-missing-field', path: 'packages', field: 'integrity' }));
    const keyMatch = compileScaDeclarationRule(rule('DPK-SCA-9005', { type: 'sca-key-matches', path: 'dependencies', keyPattern: '^http://' }));
    const distance = compileScaDeclarationRule(rule('DPK-SCA-9006', {
      type: 'sca-name-distance', path: 'dependencies', target: 'lodash', maxDistance: 1,
    }));
    expect(missing).toBeDefined();
    expect(keyMatch).toBeDefined();
    expect(distance).toBeDefined();
    if (missing === undefined || keyMatch === undefined || distance === undefined) return;
    expect(evaluateScaDeclarationCheck(missing, { packages: [{ name: 'a', version: '1' }] })).toBe(true);
    expect(evaluateScaDeclarationCheck(missing, { packages: [{ name: 'a', integrity: 'x' }] })).toBe(false);
    expect(evaluateScaDeclarationCheck(keyMatch, { dependencies: { 'http://evil.example/x': '1' } })).toBe(true);
    expect(evaluateScaDeclarationCheck(distance, { dependencies: { lodas: '1.0.0', lodash: '1.0.0' } })).toBe(true);
    expect(evaluateScaDeclarationCheck(distance, { dependencies: { lodash: '1.0.0', react: '18' } })).toBe(false);
    expect(boundedScaDistance('lodash', 'lodas', 1)).toBe(1);
    expect(boundedScaDistance('lodash', 'completely-different', 1)).toBe(2);
  });

  test('path resolver honours wildcards and array segments with hard bounds', () => {
    const doc = { packages: { a: { version: '1' }, b: { version: '2' } }, items: [{ name: 'x' }] };
    expect(resolveScaPath(doc, 'packages.*.version')).toHaveLength(2);
    expect(resolveScaPath(doc, 'items[].name')).toHaveLength(1);
    expect(scaKeysAtPath(doc, 'packages').map((entry) => entry.key)).toEqual(['a', 'b']);
    expect(resolveScaPath(doc, 'a.b.c.d.e.f.g.h.i.j.k.l.m')).toEqual([]);
  });

  test('an invalid regex, unknown check type or bad distance is refused (fail closed)', () => {
    expect(compileScaDeclarationRule(rule('DPK-SCA-9007', { type: 'sca-field-matches', path: 'a', valuePattern: '(' }))).toBeUndefined();
    expect(compileScaDeclarationRule(rule('DPK-SCA-9008', { type: 'invented', path: 'a' }))).toBeUndefined();
    expect(compileScaDeclarationRule(rule('DPK-SCA-9009', { type: 'sca-name-distance', path: 'a', target: 'foo', maxDistance: 9 }))).toBeUndefined();
    expect(compileScaDeclarationRule(rule('DPK-SCA-9010', { type: 'sca-field-absent', path: 'a', unexpected: true }))).toBeUndefined();
  });

  test('the scan-time reader honestly declares its JSON-only parser coverage', () => {
    expect(SCA_READABLE_PARSERS).toEqual(['json']);
  });
});

describe('declaration scan layer: real findings, honest coverage', () => {
  const wildcardRule = rule('DPK-SCA-9001', { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' });

  test('a matching JSON manifest produces one contract-valid SCA finding', () => {
    const result = evaluateScaDeclarations({
      rawRules: [wildcardRule],
      files: [{ path: 'package.json', content: JSON.stringify({ dependencies: { fixture: '*' } }) }],
      record: scanRecord(),
    });
    expect(result.findings).toHaveLength(1);
    expect(result.rulesEvaluated).toBe(1);
    expect(result.rulesNotEvaluated).toBe(0);
    expect(result.truncated).toBe(false);
    const finding = result.findings[0];
    expect(finding).toBeDefined();
    if (finding === undefined) return;
    expect(isFinding(finding)).toBe(true);
    expect(findingScanner(finding)).toBe('SCA');
    expect(finding.scanner).toBe('SCA');
    expect(finding.ruleId).toBe('DPK-SCA-9001');
    expect(finding.scanId).toBe(SCAN);
    expect(finding.file).toBe('package.json');
    expect(finding.evidence).toContain('values withheld');
    // The declared VALUE is never copied into a finding (registry tokens!).
    expect(finding.evidence).not.toContain('"fixture": "*"');
    expect(result.severityCounts.MEDIUM).toBe(1);
  });

  test('a parser kind the app cannot read is counted, never pretended', () => {
    const tomlRule = rule('DPK-SCA-9011', { type: 'sca-field-matches', path: 'project.dependencies[]', valuePattern: '^x$' }, { parser: 'toml', artifact: 'pyproject.toml' });
    const result = evaluateScaDeclarations({
      rawRules: [wildcardRule, tomlRule],
      files: [{ path: 'package.json', content: JSON.stringify({ dependencies: { fixture: '*' } }) }],
      record: scanRecord(),
    });
    expect(result.rulesEvaluated).toBe(1);
    expect(result.rulesNotEvaluated).toBe(1);
    expect(result.findings).toHaveLength(1);
  });

  test('a malformed artifact is not a "no match": it stays unevaluated', () => {
    const result = evaluateScaDeclarations({
      rawRules: [wildcardRule],
      files: [{ path: 'package.json', content: '{not json' }],
      record: scanRecord(),
    });
    expect(result.findings).toHaveLength(0);
    expect(result.rulesEvaluated).toBe(0);
    expect(result.rulesNotEvaluated).toBe(1);
  });

  test('findings are hard-capped and the cap is reported', () => {
    const many = Array.from({ length: 12 }, (_, index) =>
      rule(`DPK-SCA-${String(9100 + index)}`, { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' }));
    const result = evaluateScaDeclarations({
      rawRules: many,
      files: [{ path: 'package.json', content: JSON.stringify({ dependencies: { fixture: '*' } }) }],
      record: scanRecord(),
      maxFindings: 3,
    });
    expect(result.findings).toHaveLength(3);
    expect(result.truncated).toBe(true);
    expect(result.findings.length).toBeLessThanOrEqual(MAX_FINDINGS_PER_SCAN);
  });

  test('the SCA ENGINE stays additive: no dataset → no declaration findings', async () => {
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'package.json', content: JSON.stringify({ dependencies: { fixture: '*' } }) }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.findings).toBeUndefined();
    expect(outcome.resultSummary.findingsTotal).toBe(0);
    expect(outcome.resultSummary.declarationRulesEvaluated).toBe(0);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('the SCA ENGINE emits declaration findings when a dataset is configured', async () => {
    const dataset = {
      configured: true,
      scaPacks: async () => [wildcardRule],
    } as unknown as DatasetService;
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'package.json', content: JSON.stringify({ dependencies: { fixture: '*' } }) }])),
      dataset,
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.findingsTotal).toBe(1);
    expect(outcome.resultSummary.declarationRulesEvaluated).toBe(1);
    expect(outcome.resultSummary.declarationRulesNotEvaluated).toBe(0);
    expect(outcome.resultSummary.findingsBySeverity?.MEDIUM).toBe(1);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings?.[0]?.scanner).toBe('SCA');
    expect(outcome.findings?.every(isFinding)).toBe(true);
    // Inventory/SBOM/advisory path is untouched.
    expect(outcome.sca?.summary.dependenciesTotal).toBe(1);
  });
});
