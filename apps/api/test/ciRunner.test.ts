import { afterEach, describe, expect, test } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { collectSources } from '../../../scripts/ci/collector.js';
import { runCiCheck } from '../../../scripts/ci/runner.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true }); });

function makeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'drobon-ci-fixture-'));
  roots.push(root);
  const dataset = join(root, 'dataset');
  const source = join(root, 'project');
  mkdirSync(source);
  const put = (path: string, value: unknown) => {
    const file = join(dataset, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, JSON.stringify(value));
  };
  const common = {
    description: 'Synthetic rule only', severity: 'HIGH', category: 'fixture',
    remediation: 'Review the fixture.', limitation: 'Not real intelligence.', patternRefs: ['DPK-PAT-9001'],
  };
  put('packs/sast/v1/rules/rule.json', {
    ...common, schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-900', title: 'Synthetic eval',
    languages: ['javascript'], patterns: [{ source: '\\beval\\s*\\(' }],
    tests: [{ line: 'eval(x);', match: true }, { line: 'const x = 1;', match: false }],
  });
  put('packs/secrets/v1/rules/rule.json', {
    ...common, schemaVersion: 'drobon.pack.secrets/v1', id: 'DPK-SEC-900', title: 'Synthetic marker',
    confidence: 'HIGH', redact: true, denylist: [], patterns: [{ source: 'ZTEST[A-Z]{16}' }],
    tests: [{ line: 'ZTESTABCDEFGHIJKLMNOP', match: true }, { line: 'ordinary text', match: false }],
  });
  put('packs/sca/v1/rules/rule.json', {
    ...common, schemaVersion: 'drobon.pack.sca/v1', id: 'DPK-SCA-9001', title: 'Synthetic dependency declaration',
    ecosystems: ['npm'], artifact: 'package.json', parser: 'json',
    check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
    tests: [
      { file: 'package.json', document: { dependencies: { x: '*' } }, match: true },
      { file: 'package.json', document: { dependencies: { x: '1.0.0' } }, match: false },
    ],
  });
  put('vuln-intel/npm/ADV-900.json', {
    schemaVersion: 'drobon.vuln-intel/v1', fixture: false, id: 'ADV-900', ecosystem: 'npm', package: 'fixture-pkg',
    summary: 'Synthetic advisory only', severity: 'HIGH', affected: [{ range: '< 2.0.0' }], provenance: { source: 'FIXTURE' },
  });
  return { root, source, dataset };
}

const options = (source: string, dataset: string) => ({ root: source, datasetPath: dataset, scanners: ['SAST', 'SECRETS', 'SCA'] as const, threshold: 'HIGH' as const, allowIncomplete: false });

describe('CI adapter over existing engines', () => {
  test('discovers bounded eligible files, refuses sensitive paths and symlinks, and never reads their content', async () => {
    const { root, source } = makeFixture();
    writeFileSync(join(source, 'app.js'), 'const x = 1;');
    writeFileSync(join(source, '.env'), 'never collected');
    writeFileSync(join(source, 'cert.pem'), 'never collected');
    writeFileSync(join(source, 'oversized.js'), Buffer.alloc(256 * 1024 + 1));
    writeFileSync(join(source, 'binary.js'), Buffer.from([0xff, 0xfe]));
    mkdirSync(join(source, '.github'));
    writeFileSync(join(source, '.github', 'workflow.yml'), 'never collected');
    const outside = join(root, 'outside.js');
    writeFileSync(outside, 'never collected');
    symlinkSync(outside, join(source, 'linked.js'));
    const collected = await collectSources(source);
    expect(collected.batches.flat().map((file) => file.path)).toEqual(['app.js']);
    expect(collected.omitted.sensitiveOrHidden).toBe(3);
    expect(collected.omitted.symlink).toBe(1);
    expect(collected.omitted.oversized).toBe(1);
    expect(collected.omitted.nonText).toBe(1);
    expect(JSON.stringify(collected)).not.toContain('never collected');
  });

  test('runs all three real engines, gates SAST, secrets and matched SCA advisories without exporting the marker', async () => {
    const { source, dataset } = makeFixture();
    const marker = ['ZTEST', 'ABCDEFGHIJKLMNOP'].join('');
    writeFileSync(join(source, 'app.js'), `eval(userInput);\nconst token = "${marker}";\n`);
    writeFileSync(join(source, 'package.json'), JSON.stringify({ dependencies: { 'fixture-pkg': '1.0.0' } }));
    const result = await runCiCheck(options(source, dataset));
    expect(result.exitCode).toBe(1);
    expect(result.summary.status).toBe('FINDINGS');
    expect(result.summary.thresholdHits).toBeGreaterThanOrEqual(3);
    expect(result.summary.advisoryMatches).toBe(1);
    expect(result.summary.scaAssessmentStates).toContain('ASSESSED');
    expect(result.sarif).toContain('DPK-SAST-900');
    expect(result.sarif).toContain('DPK-SEC-900');
    expect(result.sarif).toContain('ADV-900');
    expect(result.sarif).not.toContain(marker);
    expect(JSON.stringify(result.summary)).not.toContain(marker);
    const parsed = JSON.parse(result.sarif) as { version: string; runs: Array<{ automationDetails: { id: string }; results: Array<{ ruleId: string; fingerprints: Record<string, string> }> }> };
    expect(parsed.version).toBe('2.1.0');
    expect(new Set(parsed.runs.map((run) => run.automationDetails.id)).size).toBe(parsed.runs.length);
    const repeat = await runCiCheck(options(source, dataset));
    const other = JSON.parse(repeat.sarif) as typeof parsed;
    const fingerprints = (doc: typeof parsed) => doc.runs.flatMap((run) => run.results.map((item) => `${item.ruleId}:${JSON.stringify(item.fingerprints)}`)).sort();
    expect(fingerprints(parsed)).toEqual(fingerprints(other));
  }, 15_000);

  test('an explicit project key preserves fingerprints across checkout paths and separates repositories', async () => {
    const { root, source, dataset } = makeFixture();
    const second = join(root, 'another-checkout');
    mkdirSync(second);
    writeFileSync(join(source, 'app.js'), 'eval(userInput);');
    writeFileSync(join(second, 'app.js'), 'eval(userInput);');
    const base = { ...options(source, dataset), scanners: ['SAST'] as const, projectKey: 'example/project' };
    const first = await runCiCheck(base);
    const cloned = await runCiCheck({ ...base, root: second });
    const separate = await runCiCheck({ ...base, root: second, projectKey: 'example/other' });
    const fingerprint = (value: string) => (JSON.parse(value) as { runs: Array<{ results: Array<{ fingerprints: Record<string, string> }> }> }).runs[0]?.results[0]?.fingerprints['drobon/v1'];
    expect(fingerprint(first.sarif)).toBeDefined();
    expect(fingerprint(first.sarif)).toBe(fingerprint(cloned.sarif));
    expect(fingerprint(first.sarif)).not.toBe(fingerprint(separate.sarif));
  }, 15_000);

  test('does not turn missing rules or SCA intelligence into a successful check, even with explicit gap acceptance', async () => {
    const { source, dataset } = makeFixture();
    writeFileSync(join(source, 'app.js'), 'const x = 1;');
    const emptyDataset = join(dataset, 'missing');
    mkdirSync(emptyDataset);
    const unavailable = await runCiCheck({ ...options(source, emptyDataset), allowIncomplete: true });
    expect(unavailable.exitCode).toBe(2);
    expect(unavailable.summary.status).toBe('INCOMPLETE');
    expect(unavailable.summary.incompleteReasons.join(' ')).toContain('rules are unavailable');
    const noMatch = await runCiCheck({ ...options(source, dataset), scanners: ['SCA'], allowIncomplete: false });
    expect(noMatch.summary.scaAssessmentStates).toContain('NOT_ASSESSED');
    expect(noMatch.exitCode).toBe(2);
  });

  test('refuses dataset symlinks and malformed rule files rather than silently omitting rules', async () => {
    const { root, source, dataset } = makeFixture();
    writeFileSync(join(source, 'app.js'), 'const x = 1;');
    writeFileSync(join(dataset, 'packs', 'sast', 'v1', 'rules', 'broken.json'), '{not json');
    const malformed = await runCiCheck({ ...options(source, dataset), scanners: ['SAST'], allowIncomplete: true });
    expect(malformed.exitCode).toBe(2);
    expect(malformed.summary.incompleteReasons.join(' ')).toContain('malformed rule files');
    const outside = join(root, 'external.json');
    writeFileSync(outside, '{}');
    symlinkSync(outside, join(dataset, 'packs', 'sast', 'v1', 'rules', 'linked.json'));
    await expect(runCiCheck({ ...options(source, dataset), scanners: ['SAST'], allowIncomplete: true })).rejects.toThrow(/symlinks/);
  });

  test('CLI refuses overwrites and output inside the read-only dataset', () => {
    const { root, source, dataset } = makeFixture();
    writeFileSync(join(source, 'app.js'), 'eval(userInput);');
    const script = join(process.cwd(), '..', '..', 'scripts', 'drobon-ci.mjs');
    const invoke = (output: string) => spawnSync(process.execPath, ['--import', 'tsx', script, '--root', source, '--dataset', dataset, '--scanners', 'SAST', '--sarif', output], { encoding: 'utf8', timeout: 30_000 });
    const existing = join(root, 'existing.sarif');
    writeFileSync(existing, 'do not overwrite');
    expect(invoke(existing).status).toBe(2);
    expect(invoke(join(dataset, 'forbidden.sarif')).status).toBe(2);
  }, 60_000);
});
