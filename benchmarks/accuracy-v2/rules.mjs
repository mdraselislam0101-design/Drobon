/** Benchmark-only rule metadata. These are NOT Dataset rules or a replacement
 * scanner engine; no production catalog is changed. */
import { TEST_DAST_RULES } from '../../apps/api/test/fixtures/testData.ts';
import { scaRule } from '../local/run-drobon.mjs';

const devRule = { ...scaRule, id: 'DPK-SCA-9002', title: 'Unrestricted development dependency',
  description: 'A development dependency has a wildcard declaration.',
  check: { type: 'sca-field-matches', path: 'devDependencies.*', valuePattern: '^\\*$' } };
const nugetRule = { ...scaRule, id: 'DPK-SCA-9003', title: 'Plain HTTP package source',
  description: 'A normalized source uses plain HTTP.', artifact: 'nuget.config', parser: 'xml', ecosystems: ['nuget'],
  check: { type: 'sca-field-matches', path: 'sources[].value', valuePattern: '^http:' },
  tests: [{ file: 'nuget.config', document: { sources: [{ value: 'http://registry.invalid/' }] }, match: true },
    { file: 'nuget.config', document: { sources: [{ value: 'https://registry.invalid/' }] }, match: false }] };
const valueRule = { id: 'DG-DAST-900', title: 'Invalid nosniff value', severity: 'LOW',
  description: 'A non-empty content-type-options value differs from nosniff.',
  remediation: 'Review and set a valid header value.',
  check: { type: 'response-header-matches', header: 'x-content-type-options', valuePattern: '^(?!nosniff$).+' } };
export const scaRules = [scaRule, devRule, nugetRule];
export const dastRules = [...TEST_DAST_RULES, valueRule];
