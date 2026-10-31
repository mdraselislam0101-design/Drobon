import { spawnSync } from 'node:child_process';
import { describe, expect, test } from 'vitest';
import { parseDeclarationDocument } from '../src/scans/sca/declarationReaders.js';
import { evaluateScaDeclarations } from '../src/scans/sca/declarationScan.js';
import type { ScanRecord } from '../src/scans/store.js';
import { scaRules } from '../../../benchmarks/accuracy-v2/rules.mjs';

const record: ScanRecord = {
  id: 'scan_00000000-0000-4000-8000-000000000003',
  ownerId: 'usr_00000000-0000-4000-8000-000000000001',
  projectId: 'prj_00000000-0000-4000-8000-000000000002',
  scanType: 'SCA', status: 'RUNNING', createdAt: '2026-10-31T00:00:00.000Z', updatedAt: '2026-10-31T00:00:00.000Z',
};
const rule = scaRules.find((entry: { id: string }) => entry.id === 'DPK-SCA-9003');
const wrap = (inside: string) => `<configuration><packageSources>${inside}</packageSources></configuration>`;
const source = 'http://registry.invalid/v3';
const python = `import sys,xml.etree.ElementTree as E
try:
 E.fromstring(sys.stdin.read()); print('ACCEPT')
except E.ParseError: print('REJECT')`;
// Python is an optional independent cross-check, not a new runtime or test
// dependency for the parser regressions themselves. An absent tool is visible
// as a skipped cross-check; all Main App assertions still run.
const hasIndependentParser = spawnSync('python3', ['-c', 'import xml.etree.ElementTree'], { timeout: 5_000 }).status === 0;

function independentXml(text: string): string {
  const result = spawnSync('python3', ['-c', python], { input: text, encoding: 'utf8', timeout: 5_000 });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}
function evaluate(content: string) {
  expect(rule).toBeDefined();
  return evaluateScaDeclarations({ rawRules: [rule], files: [{ path: 'nuget.config', content }], record });
}

describe('XML subset rejects malformed syntax without inventing completed SCA evaluation', () => {
  const invalid = [
    ['adjacent attributes', wrap(`<add key="synthetic"value="${source}"/>`)],
    ['non-XML whitespace between attributes', wrap(`<add key="synthetic"\u00a0value="${source}"/>`)],
    ['non-XML whitespace around equals', wrap(`<add key\u00a0="synthetic" value="${source}"/>`)],
    ['non-XML whitespace before root', `\u00a0${wrap(`<add key="synthetic" value="${source}"/>`)}`],
    ['non-XML whitespace after root', `${wrap(`<add key="synthetic" value="${source}"/>`)}\u00a0`],
    ['non-XML whitespace in closing tag', `<configuration><packageSources><add key="synthetic" value="${source}"/></packageSources></configuration\u00a0>`],
    ['forbidden character-data terminator', wrap(`<add key="synthetic" value="${source}"/><note>before]]>after</note>`)],
  ] as const;
  test.each(invalid)('%s: declaration check remains partial', (_name, content) => {
    expect(parseDeclarationDocument('xml', 'nuget.config', content)).toBeUndefined();
    const result = evaluate(content);
    expect(result).toMatchObject({ rulesEvaluated: 0, rulesNotEvaluated: 1, partial: true, findings: [] });
  });

  test.each([' ', '\t', '\n', '\r'])('valid XML whitespace %j is still accepted', (separator) => {
    const content = wrap(`<add key="synthetic"${separator}value="${source}"/>`);
    expect(parseDeclarationDocument('xml', 'nuget.config', content)).toBeDefined();
    const result = evaluate(content);
    expect(result.rulesEvaluated).toBe(1);
    expect(result.findings).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain(source);
  });

  test('escaped greater-than in character data and a comment are not falsely rejected', () => {
    const content = wrap(`<add key="synthetic" value="${source}"/><note>before]]&gt;after</note><!-- ]]> -->`);
    expect(parseDeclarationDocument('xml', 'nuget.config', content)).toBeDefined();
    expect(evaluate(content).findings).toHaveLength(1);
  });

  test.skipIf(!hasIndependentParser)('independent Python parser agrees with all malformed and valid controls', () => {
    for (const [, content] of invalid) expect(independentXml(content)).toBe('REJECT');
    for (const separator of [' ', '\t', '\n', '\r']) {
      expect(independentXml(wrap(`<add key="synthetic"${separator}value="${source}"/>`))).toBe('ACCEPT');
    }
    expect(independentXml(wrap(`<add key="synthetic" value="${source}"/><note>before]]&gt;after</note><!-- ]]> -->`))).toBe('ACCEPT');
  });
});
