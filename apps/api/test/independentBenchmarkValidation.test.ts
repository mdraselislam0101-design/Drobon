import { spawnSync } from 'node:child_process';
import { describe, expect, test } from 'vitest';
import { checkCorpus, checkJs, shellMarkerReached } from '../../../benchmarks/independent-validation/fixture-check.mjs';
import { isFrozenShellFlow } from '../../../benchmarks/local/verify-oracle.mjs';
import { isExpandedShellFlow } from '../../../benchmarks/accuracy-v2/verify-oracle.mjs';
import { assertBenchmarkScaRuleUnchanged, scaRule, sourceLocationCorrect, sourceLocationInFile } from '../../../benchmarks/local/run-drobon.mjs';
import { scoreCases } from '../../../benchmarks/local/scoring.mjs';
import { syntheticSecrets } from '../../../benchmarks/accuracy-v2/fixtures.mjs';

// Python and offline pip packaging are optional for the independent cross-check;
// the adversarial benchmark tests themselves do not depend on them.
const hasIndependentTools = spawnSync('python3', ['-c', 'import xml.dom.minidom; from pip._vendor.packaging.requirements import Requirement'],
  { timeout: 5_000 }).status === 0;
const MARK = 'DROBON_REVIEW_MARKER';

describe('scanner-free fixture validation and adversarial oracle controls', () => {
  test.skipIf(!hasIndependentTools)('checks 62 cases deterministically, without claiming independent human review', async () => {
    const a = await checkCorpus();
    const b = await checkCorpus();
    expect(a).toEqual(b);
    expect(a.scannerOutputUsed).toBe(false);
    expect(a.independentHumanReview).toBe(false);
    expect(a.blindedHumanReview).toBe(false);
    expect(a.rows).toHaveLength(62);
    expect(a.rows.every((row: { agrees: boolean }) => row.agrees)).toBe(true);
    expect(a.rows.filter((row: { observed: boolean | null }) => row.observed === null)).toHaveLength(6);
    expect(a.rows.find((row: { id: string }) => row.id === 'AX-SEC-05')).toMatchObject({
      controlledEmptyEnvironment: true, nonEmptyEnvironmentChangesResult: true,
    });
    for (const value of syntheticSecrets) expect(JSON.stringify(a)).not.toContain(value);
  }, 30_000);

  test('fixed argv under shell true is not an input-to-shell flow', () => {
    const calls = [{ type: 'execFile', program: 'echo', args: ['constant'], options: { shell: true } }];
    expect(isFrozenShellFlow(calls, MARK)).toBe(false);
    expect(isFrozenShellFlow([{ ...calls[0], args: [MARK] }], MARK)).toBe(true);
  });

  test('a shell positional argument is unassessed, not automatically shell-command text', () => {
    const calls = [{ kind: 'execFile', program: 'sh', args: ['-c', 'printf "%s" "$1"', 'fixture', MARK] }];
    expect(isExpandedShellFlow(calls, MARK)).toBeNull();
    expect(isExpandedShellFlow([{ ...calls[0], args: ['-c', 'eval "$1"', 'fixture', MARK] }], MARK)).toBeNull();
    expect(isExpandedShellFlow([{ ...calls[0], args: ['-c', 'echo constant'] }], MARK)).toBe(false);
    expect(isExpandedShellFlow([{ ...calls[0], args: ['-c', `echo ${MARK}`] }], MARK)).toBe(true);
  });

  test('separate fake-sink checker keeps dynamic and shell controls distinct', () => {
    expect(shellMarkerReached([{ kind: 'execFile', program: 'echo', args: [MARK] }])).toBe(false);
    expect(shellMarkerReached([{ kind: 'execFile', program: MARK, args: [] }])).toBe(true);
    expect(shellMarkerReached([{ kind: 'execFile', program: 'echo', args: [MARK], options: { shell: true } }])).toBe(true);
    expect(shellMarkerReached([{ kind: 'execFile', program: 'sh', args: ['-c', 'printf "%s" "$1"', 'arg0', MARK] }])).toBeNull();
    expect(shellMarkerReached([{ kind: 'execFile', program: 'sh', args: ['-c', 'eval "$1"', 'arg0', MARK] }])).toBeNull();
    expect(shellMarkerReached([{ kind: 'execFile', program: 'sh', args: ['-c', 'echo constant'] }])).toBe(false);
    expect(shellMarkerReached([{ kind: 'execFile', program: 'sh', args: ['-c', `echo ${MARK}`] }])).toBe(true);
    expect(checkJs('export const credential = getSecret();', 'key')).toBeNull();
    expect(checkJs('function run(req) { if (req.query.name) exec(req.query.name); }', 'shell')).toBeNull();
    expect(checkJs('function run(req) { execFile("echo", [req.query.name], {shell: process.env.OPTION}); }', 'shell')).toBeNull();
    expect(checkJs('function run(req) { execFile("sh", ["-c", "eval x", "arg0", req.query.name]); }', 'shell')).toBeNull();
  });

  test('the inherited runtime SCA rule has a separate fail-closed pin', () => {
    expect(assertBenchmarkScaRuleUnchanged(scaRule)).toBe('b9ee26e96f5022c8e113cbd7430cde44321e7c78ecbc964d3f4cf84aecbd8e2b');
    const altered = { ...scaRule, check: { ...scaRule.check, path: 'devDependencies.*' } };
    expect(() => assertBenchmarkScaRuleUnchanged(altered)).toThrow();
    const helper = new URL('../../../benchmarks/local/run-drobon.mjs', import.meta.url).href;
    const fixtures = new URL('../../../benchmarks/accuracy-v2/fixtures.mjs', import.meta.url).href;
    const runner = new URL('../../../benchmarks/accuracy-v2/run.mjs', import.meta.url).href;
    // Mutate only an isolated process's in-memory test rule, never a file.
    const script = `import { scaRule } from ${JSON.stringify(helper)}; import { manifestDigest } from ${JSON.stringify(fixtures)}; ` +
      `const before=manifestDigest(); scaRule.check.path='devDependencies.*'; ` +
      `if (manifestDigest()!==before) throw Error('unexpected manifest change'); await import(${JSON.stringify(runner)});`;
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], { encoding: 'utf8', timeout: 15_000 });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('differs from its reviewed pin');
  });

  test('in-range file position alone is not an independently verified source location', () => {
    const item = { path: 'src/case.js', content: 'import x;\nconst ignored = 1;\nexec(input);\n' };
    expect(sourceLocationCorrect(item, { file: 'src/case.js', line: 1 })).toBeNull();
    expect(sourceLocationInFile(item, { file: 'src/case.js', line: 1 })).toBe(true);
    expect(sourceLocationInFile(item, { file: 'other.js', line: 3 })).toBe(false);
    expect(sourceLocationCorrect(item, { file: 'other.js', line: 3 })).toBe(false);
    expect(sourceLocationCorrect(item, { file: 'src/case.js', line: 99 })).toBe(false);
    expect(sourceLocationCorrect({}, { file: 'src/case.js', line: 3 })).toBeNull();
  });

  test('multiple matched alerts count once for one binary case', () => {
    const result = scoreCases([{ id: 'one', family: 'SAST', expected: true }],
      [{ id: 'one', status: 'DETECTED', matchingFindings: 2 }]);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({ verdict: 'TP', matchingFindings: 2 });
    expect(result.families['SAST']).toMatchObject({ truePositive: 1, falsePositive: 0 });
  });
});
