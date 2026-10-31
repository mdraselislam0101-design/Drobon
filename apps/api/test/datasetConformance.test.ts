import { describe, expect, test } from 'vitest';
import { lintRedos, parsePackManifest, validatePackRules } from '../src/external/conformance.js';

const base = {
  schemaVersion: 'drobon.pack.sast/v1',
  id: 'DPK-SAST-900',
  title: 'Fixture rule',
  description: 'Test-only rule.',
  severity: 'MEDIUM',
  category: 'fixture',
  remediation: 'Fix it.',
  limitation: 'Test only.',
  patternRefs: ['DPK-PAT-9001'],
};

const sastRule = {
  ...base,
  languages: ['javascript'],
  patterns: [{ source: '\\beval\\s*\\(' }],
  tests: [
    { line: 'eval(userInput);', match: true },
    { line: 'const evaluation = score();', match: false },
  ],
};

const dastRule = {
  ...base,
  schemaVersion: 'drobon.pack.dast/v1',
  id: 'DPK-DAST-900',
  check: { type: 'missing-response-header', header: 'content-security-policy' },
  patterns: undefined,
  languages: undefined,
  tests: [
    { observation: { url: 'https://app.example/', status: 200, headers: {} }, match: true },
    { observation: { url: 'https://app.example/', status: 200, headers: { 'Content-Security-Policy': "default-src 'self'" } }, match: false },
  ],
};
delete (dastRule as Record<string, unknown>)['patterns'];
delete (dastRule as Record<string, unknown>)['languages'];

describe('dataset loader conformance', () => {
  test('a valid SAST pack is accepted and its declared tests are executed', () => {
    const result = validatePackRules([sastRule], 'sast');
    expect(result.rules).toHaveLength(1);
    expect(result.report.accepted).toBe(1);
    expect(result.report.declaredTests).toBe(2);
    expect(result.report.executedTests).toBe(2);
    expect(result.report.failedTests).toBe(0);
    expect(result.report.rejected).toEqual([]);
  });

  test('duplicate IDs and unresolved language mappings are reported, never silently dropped', () => {
    const result = validatePackRules([sastRule, sastRule, { ...sastRule, id: 'DPK-SAST-901', languages: ['not-a-language'] }], 'sast');
    expect(result.report).toMatchObject({ filesSeen: 3, accepted: 1, enumerationFailures: 0 });
    expect(result.report.rejected.map((issue) => issue.reason)).toEqual([
      expect.stringContaining('duplicate rule id'),
      expect.stringContaining('unresolved language'),
    ]);
  });

  test('DAST checks cannot silently inspect unavailable headers or unsafe patterns', () => {
    const uninspected = { ...dastRule, check: { type: 'missing-response-header', header: 'x-uninspected-fixture' } };
    const unknownFlag = { ...dastRule, id: 'DPK-DAST-901', check: { type: 'cookie-missing-flag', flag: 'invented' } };
    const slow = { ...dastRule, id: 'DPK-DAST-902', check: { type: 'response-body-matches', valuePattern: '(a+)+' } };
    const result = validatePackRules([uninspected, unknownFlag, slow], 'dast');
    expect(result.report).toMatchObject({ filesSeen: 3, accepted: 0 });
    expect(result.report.rejected.map((issue) => issue.reason)).toEqual([
      expect.stringContaining('inspected response-header'),
      expect.stringContaining('supported cookie flag'),
      expect.stringContaining('ReDoS'),
    ]);
  });

  test('unknown fields and unknown schemas are refused (fail closed)', () => {
    const unknownField = validatePackRules([{ ...sastRule, unexpected: true }], 'sast');
    expect(unknownField.rules).toHaveLength(0);
    expect(unknownField.report.rejected[0]?.reason).toContain('unknown field');
    const badSchema = validatePackRules([{ ...sastRule, schemaVersion: 'drobon.pack.sast/v9' }], 'sast');
    expect(badSchema.rules).toHaveLength(0);
    expect(badSchema.report.rejected[0]?.reason).toContain('schemaVersion');
  });

  test('a rule whose declared test disagrees is refused', () => {
    const wrong = { ...sastRule, tests: [{ line: 'eval(userInput);', match: false }, { line: 'const x = 1;', match: true }] };
    const result = validatePackRules([wrong], 'sast');
    expect(result.rules).toHaveLength(0);
    expect(result.report.failedTests).toBeGreaterThan(0);
    expect(result.report.rejected[0]?.reason).toContain('declared tests failed');
  });

  test('an unknown DAST check type is refused instead of silently evaluating false', () => {
    const unknownCheck = { ...dastRule, check: { type: 'invented-check-type' } };
    const result = validatePackRules([unknownCheck], 'dast');
    expect(result.rules).toHaveLength(0);
    expect(result.report.rejected[0]?.reason).toContain('unknown DAST check type');
  });

  test('SCA declaration tests are EXECUTED through the app evaluator (Pump 14)', () => {
    const scaRule = {
      ...base,
      schemaVersion: 'drobon.pack.sca/v1',
      id: 'DPK-SCA-9001',
      languages: undefined,
      patterns: undefined,
      ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
      check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
      tests: [
        { file: 'package.json', document: { dependencies: { x: '*' } }, match: true },
        { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: false },
      ],
    };
    delete (scaRule as Record<string, unknown>)['languages'];
    delete (scaRule as Record<string, unknown>)['patterns'];
    const result = validatePackRules([scaRule], 'sca');
    expect(result.rules).toHaveLength(1);
    expect(result.report.accepted).toBe(1);
    expect(result.report.declaredTests).toBe(2);
    expect(result.report.executedTests).toBe(2);
    expect(result.report.skippedTests).toBe(0);
    expect(result.report.failedTests).toBe(0);
    expect(result.report.rejected).toEqual([]);
  });

  test('an SCA rule whose declared test disagrees is refused, never skipped', () => {
    const scaRule = {
      ...base,
      schemaVersion: 'drobon.pack.sca/v1',
      id: 'DPK-SCA-9001',
      ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
      check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
      tests: [
        { file: 'package.json', document: { dependencies: { x: '*' } }, match: false },
        { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: true },
      ],
    };
    const result = validatePackRules([scaRule], 'sca');
    expect(result.rules).toHaveLength(0);
    expect(result.report.failedTests).toBeGreaterThan(0);
    expect(result.report.skippedTests).toBe(0);
    expect(result.report.rejected[0]?.reason).toContain('declared tests failed');
  });

  test('an unknown SCA check type is refused instead of silently matching false', () => {
    const scaRule = {
      ...base,
      schemaVersion: 'drobon.pack.sca/v1',
      id: 'DPK-SCA-9001',
      ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
      check: { type: 'invented-sca-check', path: 'dependencies.*' },
      tests: [
        { file: 'package.json', document: { dependencies: { x: '*' } }, match: true },
        { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: false },
      ],
    };
    const result = validatePackRules([scaRule], 'sca');
    expect(result.rules).toHaveLength(0);
    expect(result.report.rejected[0]?.reason).toContain('invalid SCA declaration rule');
  });

  test('a slow SCA declaration pattern is refused by the ReDoS lint', () => {
    const scaRule = {
      ...base,
      schemaVersion: 'drobon.pack.sca/v1',
      id: 'DPK-SCA-9001',
      ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
      check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '(a+)+' },
      tests: [
        { file: 'package.json', document: { dependencies: { x: 'aaaa' } }, match: true },
        { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: false },
      ],
    };
    const result = validatePackRules([scaRule], 'sca');
    expect(result.rules).toHaveLength(0);
    expect(result.report.rejected[0]?.reason).toContain('ReDoS');
  });

  test('static ReDoS lint rejects nested quantifiers and repeated wildcards', () => {
    expect(lintRedos('\\beval\\s*\\(')).toBeNull();
    expect(lintRedos('(a+)+')).toContain('nested quantifier');
    expect(lintRedos('.*.*')).toContain('repeated unbounded wildcard');
    const slow = validatePackRules([{ ...sastRule, patterns: [{ source: '(a+)+' }] }], 'sast');
    expect(slow.rules).toHaveLength(0);
    expect(slow.report.rejected[0]?.reason).toContain('ReDoS');
  });

  test('pack manifest identity is parsed only from a valid shape', () => {
    expect(parsePackManifest({ packId: 'drobon-sast-starter', version: '1.0.0', schemaVersion: 'x' })).toEqual({ packId: 'drobon-sast-starter', version: '1.0.0' });
    expect(parsePackManifest({ packId: 'Bad Id', version: '1.0.0' })).toBeUndefined();
    expect(parsePackManifest(null)).toBeUndefined();
  });
});
