import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, test } from 'vitest';
import { createDatasetService } from '../src/external/service.js';
import { hasRejectedPackRules } from '../src/external/packIntegration.js';
import { validatePackRules } from '../src/external/conformance.js';
import { createJsonByteBudget, parseBoundedJson, readBoundedJsonFile } from '../src/external/boundedJson.js';
import { createFilesystemIntelligenceProvider } from '../src/scans/sca/filesystemProvider.js';
import { createAdvisoryService } from '../src/external/advisory.js';
import { inspectDataset } from '../../../scripts/ci/datasetPreflight.js';

// All inputs here are disposable synthetic Main App fixtures, not Dataset files.
const roots: string[] = [];
const PRIVATE_NAME = 'q7z-bounds-private-name'; // test-only synthetic fixture
function root(): string {
  const result = mkdtempSync(join(tmpdir(), 'main-app-loader-bounds-'));
  roots.push(result);
  return result;
}
function put(base: string, relative: string, text: string): string {
  const path = join(base, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  return path;
}
function advisory(id: string, extra = ''): string {
  return `{"fixture":false,"id":"${id}","ecosystem":"npm","package":"fixture-pkg","summary":"Synthetic","severity":"HIGH","affected":[{"range":"<2.0.0"}]${extra}}`;
}
const coordinate = [{ dependencyId: 'dep_fixture', ecosystem: 'npm' as const, name: 'fixture-pkg', version: '1.0.0' }];

afterEach(() => { for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe('bounded JSON parsing', () => {
  test('limits nesting and token count while respecting quoted brackets and escaped keys', () => {
    expect(parseBoundedJson('{"text":"[{}]\\"","nested":[1]}', { maxDepth: 2, maxTokens: 10 }))
      .toEqual({ text: '[{}]"', nested: [1] });
    expect(() => parseBoundedJson('{"a":{"b":{"c":1}}}', { maxDepth: 2, maxTokens: 30 })).toThrow();
    expect(() => parseBoundedJson('[1,2,3,4,5]', { maxDepth: 3, maxTokens: 4 })).toThrow();
    expect(() => parseBoundedJson('{"a":1,"\\u0061":2}', { maxDepth: 3, maxTokens: 20 })).toThrow();
    expect(() => parseBoundedJson(`{"${PRIVATE_NAME}":`, { maxDepth: 3, maxTokens: 20 })).toThrow();
    try { parseBoundedJson(`{"${PRIVATE_NAME}":`, { maxDepth: 3, maxTokens: 20 }); } catch (error) {
      expect(String(error)).not.toContain(PRIVATE_NAME);
    }
  });

  test('accepts varied valid JSON without interpreting escaped punctuation as structure', () => {
    let seed = 123456;
    const next = (): number => { seed = (seed * 16_807) % 2_147_483_647; return seed; };
    for (let index = 0; index < 500; index += 1) {
      const value = { [`key,${next()}`]: [next(), true, null, { text: `quote " brace } slash \\ ${next()}`, float: next() / 10_000 }] };
      const text = JSON.stringify(value);
      expect(parseBoundedJson(text)).toEqual(JSON.parse(text));
    }
  });

  test('failed parsing and concurrent readers cannot evade a shared byte budget', async () => {
    const base = root();
    const bad = put(base, 'bad.json', '{"a":');
    const good = put(base, 'good.json', '{"b":1}');
    const budget = createJsonByteBudget(10);
    await expect(readBoundedJsonFile(bad, { maxFileBytes: 100, budget })).rejects.toThrow();
    expect(budget.readBytes).toBe(5);
    await expect(readBoundedJsonFile(good, { maxFileBytes: 100, budget })).rejects.toThrow('TOTAL_LIMIT');
    expect(budget.readBytes).toBe(5);
    const shared = createJsonByteBudget(10);
    const results = await Promise.allSettled([readBoundedJsonFile(good, { maxFileBytes: 100, budget: shared }), readBoundedJsonFile(good, { maxFileBytes: 100, budget: shared })]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(shared.readBytes).toBeLessThanOrEqual(10);
    expect(shared.reservedBytes).toBe(0);
  });
});

describe('general Dataset loader resource bounds', () => {
  test('limits declared-test work without counting unexecuted cases as passed', () => {
    const rule = { schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-900', title: 'Fixture', description: 'Fixture',
      severity: 'HIGH', category: 'fixture', remediation: 'Review', limitation: 'Fixture', patternRefs: ['DPK-PAT-9001'],
      languages: ['javascript'], patterns: [{ source: 'fixture' }], tests: Array.from({ length: 257 }, () => ({ line: 'fixture', match: true })) };
    const many = validatePackRules([rule], 'sast');
    expect(many.report).toMatchObject({ accepted: 0, declaredTests: 257, executedTests: 0, skippedTests: 257 });
    expect(many.report.rejected[0]?.reason).toContain('test limit');
    const large = validatePackRules([{ ...rule, tests: [{ line: 'x'.repeat(20_000), match: false }] }], 'sast');
    expect(large.report).toMatchObject({ accepted: 0, declaredTests: 1, executedTests: 0, skippedTests: 1 });
    expect(large.report.rejected[0]?.reason).toContain('test limit');
  });

  test('refuses oversized, over-nested, malformed and duplicate-key JSON, reports each omission, and leaves fixtures unchanged', async () => {
    const base = root();
    const good = put(base, 'knowledge/remediation/1-good.json', '{"ruleId":"good"}');
    const large = put(base, `knowledge/remediation/${PRIVATE_NAME}-large.json`, JSON.stringify({ ruleId: 'large', body: 'x'.repeat(600) }));
    put(base, 'knowledge/remediation/2-deep.json', '{"ruleId":"deep","x":{"y":{"z":{"q":1}}}}');
    put(base, 'knowledge/remediation/3-duplicate.json', '{"ruleId":"one","ruleId":"two"}');
    put(base, 'knowledge/remediation/4-broken.json', '{invalid');
    const beforeGood = readFileSync(good, 'utf8');
    const beforeLarge = readFileSync(large, 'utf8');
    const messages: string[] = [];
    const logger = { info: (s: string) => messages.push(s), warn: (s: string) => messages.push(s), error: (s: string) => messages.push(s) };
    const service = createDatasetService({ datasetPath: base, providerId: 'filesystem', logger, limits: { maxFileBytes: 300, maxJsonDepth: 3 } });
    const status = await service.status();
    expect(await service.remediation()).toEqual([{ ruleId: 'good' }]);
    expect(status.remediation).toMatchObject({ status: 'AVAILABLE', count: 1, incomplete: true,
      loadIssues: { filesSeen: 5, unreadableFiles: 4 } });
    expect(status.remediation.loadIssues?.resourceLimitFailures).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(status.remediation) + messages.join('\n')).not.toContain(PRIVATE_NAME);
    expect(readFileSync(good, 'utf8')).toBe(beforeGood);
    expect(readFileSync(large, 'utf8')).toBe(beforeLarge);
  });

  test('shares one cumulative byte and file budget across distinct categories', async () => {
    const base = root();
    put(base, 'vuln-intel/npm/first.json', '{"id":"a"}');
    mkdirSync(join(base, 'vuln-intel', 'pypi'), { recursive: true });
    put(base, 'knowledge/remediation/second.json', '{"ruleId":"b"}');
    const byteLimited = createDatasetService({ datasetPath: base, providerId: 'filesystem', limits: { maxTotalBytes: 15 } });
    const bytesStatus = await byteLimited.status();
    expect(bytesStatus.vulnIntelCounts.identityItems).toBe(1);
    expect(bytesStatus.remediation).toMatchObject({ count: 0, incomplete: true, loadIssues: { resourceLimitFailures: 1 } });
    const fileLimited = createDatasetService({ datasetPath: base, providerId: 'filesystem', limits: { maxFiles: 1 } });
    const filesStatus = await fileLimited.status();
    expect(filesStatus.vulnIntel.count).toBe(1);
    expect(filesStatus.remediation).toMatchObject({ count: 0, incomplete: true, loadIssues: { enumerationFailures: 1, resourceLimitFailures: 1 } });
  });

  test('enforces traversal depth and entry ceilings and discloses unknown hidden cardinality', async () => {
    const base = root();
    put(base, 'knowledge/cwe/good.json', '{"id":"CWE-999"}');
    put(base, 'knowledge/cwe/nested/deeper/hidden.json', '{"id":"CWE-998"}');
    const depth = await createDatasetService({ datasetPath: base, providerId: 'filesystem', limits: { maxDepth: 1 } }).status();
    expect(depth.cwe).toMatchObject({ count: 1, incomplete: true, loadIssues: { enumerationFailures: 1, resourceLimitFailures: 1 } });
    const entries = await createDatasetService({ datasetPath: base, providerId: 'filesystem', limits: { maxEntries: 1 } }).status();
    expect(entries.cwe.incomplete).toBe(true);
    expect(entries.cwe.loadIssues?.enumerationFailures).toBeGreaterThan(0);
  });

  test('a configured root inside a directory named samples does not hide ordinary advisory files', async () => {
    const parent = root();
    const base = join(parent, 'samples', 'dataset');
    put(base, 'vuln-intel/npm/valid.json', '{"id":"ordinary"}');
    put(base, 'vuln-intel/npm/samples/ignored.json', '{"id":"sample"}');
    mkdirSync(join(base, 'vuln-intel', 'pypi'), { recursive: true });
    const status = await createDatasetService({ datasetPath: base, providerId: 'filesystem' }).status();
    expect(status.vulnIntel.count).toBe(1);
    expect(status.vulnIntelCounts.identityItems).toBe(1);
  });

  test('identifies repeated knowledge identities without changing the raw records returned to existing callers', async () => {
    const base = root();
    put(base, 'knowledge/remediation/a.json', '{"ruleId":"duplicate","actions":["one"]}');
    put(base, 'knowledge/remediation/b.json', '{"ruleId":"duplicate","actions":["two"]}');
    const service = createDatasetService({ datasetPath: base, providerId: 'filesystem' });
    expect(await service.remediation()).toEqual([{ ruleId: 'duplicate', actions: ['one'] }, { ruleId: 'duplicate', actions: ['two'] }]);
    expect((await service.status()).remediation).toMatchObject({ count: 2, incomplete: true, loadIssues: { duplicateRecords: 1 } });
  });

  test('does not follow a symlinked category parent or manifest', async () => {
    const base = root();
    const outside = root();
    mkdirSync(join(outside, 'remediation'), { recursive: true });
    put(outside, 'remediation/secret.json', '{"ruleId":"outside"}');
    symlinkSync(outside, join(base, 'knowledge'));
    const path = put(outside, 'pack.json', '{"packId":"external","version":"1.0.0"}');
    mkdirSync(join(base, 'packs', 'sast', 'v1', 'rules'), { recursive: true });
    symlinkSync(path, join(base, 'packs', 'sast', 'v1', 'pack.json'));
    const service = createDatasetService({ datasetPath: base, providerId: 'filesystem' });
    const status = await service.status();
    expect(await service.remediation()).toEqual([]);
    expect(status.remediation).toMatchObject({ count: 0, incomplete: true, loadIssues: { enumerationFailures: 1 } });
    expect(await service.packMetadata('sast')).toBeUndefined();
    expect(status.conformance.sast.manifestIssue).toBeDefined();
    expect(await hasRejectedPackRules(service, 'sast')).toBe(true);
  });
});

describe('bounded verification and CI traversal', () => {
  test('RAM-only harness does not treat an incomplete synthetic corpus as success or echo fixture content', () => {
    const script = join(process.cwd(), '..', '..', 'scripts', 'verify-dataset-memory.mjs');
    const input = JSON.stringify({ category: 'remediation', path: `${PRIVATE_NAME}.json`, base64: Buffer.from(`{"ruleId":"${PRIVATE_NAME}"}`).toString('base64') });
    const result = spawnSync(process.execPath, ['--import', 'tsx', script], { input: `${input}\n`, encoding: 'utf8', timeout: 20_000 });
    expect(result.status).toBe(1);
    expect(result.stdout).not.toContain(PRIVATE_NAME);
    const evidence = JSON.parse(result.stdout) as { parsed: boolean; evaluatorAccountingComplete: boolean; readerCoverage: string; selectedFiles: number };
    expect(evidence).toMatchObject({ parsed: true, evaluatorAccountingComplete: false, readerCoverage: 'PARTIAL', selectedFiles: 1 });
  }, 30_000);

  test('verification uses bounded loader results and reports incomplete data without exposing the configured path', () => {
    const base = root();
    put(base, 'knowledge/remediation/oversized.json', ' '.repeat(2 * 1024 * 1024 + 1));
    put(base, 'interop/provider-vectors.json', '{"vectors":[]}');
    const script = join(process.cwd(), '..', '..', 'scripts', 'verify-dataset.mjs');
    const result = spawnSync(process.execPath, ['--import', 'tsx', script, '--path', base], { encoding: 'utf8', timeout: 30_000 });
    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain(base);
    const evidence = JSON.parse(result.stdout.split('\nverify-dataset:')[0] ?? '') as { dataset: { path: string }; failures: string[]; categoryCompleteness: { remediation: { incomplete: boolean; loadIssues: { resourceLimitFailures: number } } } };
    expect(evidence.dataset.path).toBe('(withheld)');
    expect(evidence.failures).toContain('remediation: category could not be completely read or enumerated');
    expect(evidence.categoryCompleteness.remediation).toMatchObject({ incomplete: true, loadIssues: { resourceLimitFailures: 1 } });
  }, 40_000);

  test('CI preflight and the check-only utility reject overly deep trees', async () => {
    const base = root();
    const deep = Array.from({ length: 18 }, (_, index) => `d${index}`).join('/');
    mkdirSync(join(base, 'vuln-intel', deep), { recursive: true });
    await expect(inspectDataset(base)).rejects.toThrow(/depth limit/);
    const script = join(process.cwd(), '..', '..', 'scripts', 'sync-dataset.mjs');
    const result = spawnSync(process.execPath, [script, '--check', '--path', base], { encoding: 'utf8', timeout: 10_000 });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('bounded dataset inspection failed');
    expect(`${result.stdout}\n${result.stderr}`).not.toContain(base);
  });
});

describe('other local JSON readers cannot bypass parse and file limits', () => {
  test('SCA provider refuses deep and duplicate-key advisories but still returns a valid one as incomplete', async () => {
    const base = root();
    put(base, 'vuln-intel/npm/valid.json', advisory('ADV-VALID'));
    put(base, 'vuln-intel/npm/deep.json', advisory('ADV-DEEP', `,"nested":${'['.repeat(70)}0${']'.repeat(70)}`));
    put(base, 'vuln-intel/npm/duplicate.json', advisory('ADV-DUP', ',"id":"ADV-OTHER"'));
    const result = await createFilesystemIntelligenceProvider({ datasetPath: base }).assess(coordinate);
    expect(result.datasetStatus).toBe('DATASET_AVAILABLE');
    expect(result.incomplete).toBe(true);
    expect(result.advisories.map((item) => item.id)).toEqual(['ADV-VALID']);
  });

  test('generic advisory service refuses oversized, deeply nested and duplicate-key packs without exposing input', async () => {
    const base = root();
    const values = [
      ' '.repeat(1_048_577),
      `{"x":${'['.repeat(70)}0${']'.repeat(70)}}`,
      `{"${PRIVATE_NAME}":1,"${PRIVATE_NAME}":2}`,
    ];
    for (const [index, text] of values.entries()) {
      const path = put(base, `${index}.json`, text);
      const service = createAdvisoryService({ path });
      const status = await service.status();
      expect(status.loaded).toBe(false);
      expect((await service.evaluate({})).unavailableReason).toBeDefined();
      expect(JSON.stringify(status)).not.toContain(PRIVATE_NAME);
    }
  });
});
