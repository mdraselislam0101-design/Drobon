/** Run existing engines directly with test-only rules. No real target is contacted. */
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isFinding, isScanResultSummary } from '@drobon/shared';
import { createSastEngine } from '../../apps/api/src/scans/sast/engine.ts';
import { createSecretsEngine } from '../../apps/api/src/scans/secrets/engine.ts';
import { createScaEngine } from '../../apps/api/src/scans/sca/engine.ts';
import { createDastEngine } from '../../apps/api/src/scans/dast/engine.ts';
import { createDastTargetPolicy } from '../../apps/api/src/scans/dast/target.ts';
import { buildSecurityReport, verifySecurityReportIntegrity } from '../../apps/api/src/reports/build.ts';
import { ALL_TEST_SAST_RULES, TEST_SECRETS_RULES, TEST_DAST_RULES } from '../../apps/api/test/fixtures/testData.ts';
import { cases, fixtureManifest, fixtureManifestDigest } from './fixtures.mjs';
import { labResponse } from './target.mjs';
import { scoreCases } from './scoring.mjs';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const TIME = '2026-10-31T00:00:00.000Z';
const project = { id: PROJECT, ownerId: OWNER, name: 'Local synthetic case', description: '', status: 'ACTIVE', createdAt: TIME, updatedAt: TIME };
export const scaRule = {
  schemaVersion: 'drobon.pack.sca/v1', id: 'DPK-SCA-9001', title: 'Unrestricted runtime dependency',
  description: 'A runtime dependency has a wildcard declaration.', severity: 'MEDIUM', category: 'dependency-hygiene',
  remediation: 'Select and verify a bounded version.', limitation: 'Test-only runtime path; no advisory validation.',
  cwe: 'CWE-1104', ecosystems: ['npm'], artifact: 'package.json', parser: 'json', patternRefs: ['DPK-PAT-9001'],
  check: { type: 'sca-field-matches', path: 'dependencies.*', valuePattern: '^\\*$' },
  tests: [
    { file: 'package.json', document: { dependencies: { fixture: '*' } }, match: true },
    { file: 'package.json', document: { dependencies: { fixture: '1.0.0' } }, match: false },
  ],
};

// The v2 corpus manifest pins the file that imports this rule, but not this
// inherited object itself. Guard it separately without changing the frozen
// corpus digest; a deliberate rule change requires a reviewed new pin.
const REVIEWED_SCA_RULE_SHA256 = 'b9ee26e96f5022c8e113cbd7430cde44321e7c78ecbc964d3f4cf84aecbd8e2b';
export function assertBenchmarkScaRuleUnchanged(rule = scaRule) {
  const digest = createHash('sha256').update(JSON.stringify(rule)).digest('hex');
  if (digest !== REVIEWED_SCA_RULE_SHA256) throw new Error('Inherited benchmark SCA rule differs from its reviewed pin');
  return digest;
}

const manifest = fixtureManifest();
// Optional isolation keeps the default corpus and output unchanged. Each
// invocation still uses a fresh engine and the same digest-pinned fixture.
// Case selection is applied only when invoked directly, not when the
// independent extended corpus imports the existing observation helper.

function recordFor(item) {
  return { id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: item.family, status: 'RUNNING',
    createdAt: TIME, updatedAt: TIME, startedAt: TIME,
    ...(item.route === undefined ? {} : { dastTargetUrl: `http://bench.example.org${item.route}` }) };
}

function engineFor(item, options = {}) {
  if (item.family === 'DAST') {
    // Resolver returns a public example address for policy validation; the
    // injected transport never performs DNS or opens a socket. This is not a
    // production HTTP/authorization test and does not change localhost policy.
    return createDastEngine({ targetPolicy: createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] }),
      transport: { probe: async (target) => {
        const answer = labResponse(target.url);
        return { ...answer, bodyTruncated: false, elapsedMs: 1 };
      } },
      packRules: (options.dastRules ?? TEST_DAST_RULES).filter((rule) => rule.id === item.rule), now: () => Date.parse(TIME) });
  }
  const snapshot = { ownerId: OWNER, projectId: PROJECT,
    files: [{ path: item.path, content: item.content, bytes: Buffer.byteLength(item.content, 'utf8') }], createdAt: TIME, updatedAt: TIME };
  const sources = { findByProject: async () => snapshot };
  if (item.family === 'SAST') return createSastEngine({ sources, rules: ALL_TEST_SAST_RULES });
  if (item.family === 'SECRETS') return createSecretsEngine({ sources, rules: TEST_SECRETS_RULES });
  if (item.family === 'SCA') return createScaEngine({ sources, dataset: { configured: true,
    scaPacks: async () => (options.scaRules ?? [scaRule]).filter((rule) => rule.id === item.rule) } });
  throw new Error('Unexpected benchmark family');
}

function reportCheck(item, record, outcome, findings, options) {
  const completed = { ...record, status: 'COMPLETED', completedAt: TIME, resultSummary: outcome.resultSummary, findings,
    ...(outcome.sca === undefined ? {} : { sca: outcome.sca }), ...(outcome.dast === undefined ? {} : { dast: outcome.dast }) };
  const report = buildSecurityReport(project, completed, TIME);
  const serialized = JSON.stringify(report);
  const completeSecret = cases.find((entry) => entry.id === 'SECRET-01')?.content.match(/"([^"]+)"/)?.[1];
  return { integrity: verifySecurityReportIntegrity(report), countMatches: report.findings.length === findings.length,
    sourceOrSyntheticSecretPresent: (item.content !== undefined && item.content.trim() !== '' && serialized.includes(item.content.trim())) ||
      (completeSecret !== undefined && serialized.includes(completeSecret)) ||
      (options.syntheticSecrets ?? []).some((value) => serialized.includes(value)) };
}

// Being inside the case file is not proof that a finding points to the actual
// sink. This corpus has no independently adjudicated expected line locations.
export function sourceLocationInFile(item, finding) {
  return item.path === undefined ? null : finding.file === item.path && typeof item.content === 'string' &&
    Number.isInteger(finding.line) && finding.line >= 1 && finding.line <= item.content.split('\n').length;
}
export function sourceLocationCorrect(item, finding) {
  return sourceLocationInFile(item, finding) === false ? false : null;
}

export async function observe(item, options = {}) {
  if (item.rule === null) return { id: item.id, status: 'UNASSESSED', reason: 'Reflection cases require active query testing; this run is passive only.' };
  const record = recordFor(item);
  const outcome = await engineFor(item, options).execute(record, { signal: new AbortController().signal });
  if (outcome.kind !== 'completed') return { id: item.id, status: 'UNASSESSED', reason: `Engine ${outcome.kind}: ${outcome.failureCode}` };
  const findings = outcome.findings ?? [];
  if (!isScanResultSummary(outcome.resultSummary) || findings.some((finding) => !isFinding(finding))) {
    return { id: item.id, status: 'UNASSESSED', reason: 'Engine result failed the shared contract.', internalError: true };
  }
  const matched = findings.filter((finding) => finding.ruleId === item.rule ||
    (item.family === 'SAST' && item.cwe !== undefined && finding.cwe === item.cwe));
  const report = reportCheck(item, record, outcome, findings, options);
  const quality = matched.map((finding) => ({ ruleId: finding.ruleId, severity: finding.severity,
    evidencePresent: finding.evidence.length > 0,
    sourceLocationCorrect: sourceLocationCorrect(item, finding),
    sourceLocationInFile: sourceLocationInFile(item, finding),
    sourceLine: item.path === undefined || !Number.isInteger(finding.line) ? null : finding.line,
    targetLocationCorrect: item.route === undefined ? null : finding.endpoint === `http://bench.example.org${item.route}` }));
  const fingerprints = matched.map((finding) => finding.fingerprint);
  const uniqueMatchingFingerprints = fingerprints.every((value) => typeof value === 'string' && value.length > 0)
    ? new Set(fingerprints).size : null;
  const common = { id: item.id, matchingFindings: matched.length, uniqueMatchingFingerprints,
    otherFindingsUnjudged: findings.length - matched.length, quality, report, partial: outcome.resultSummary.partial === true };
  if (!report.integrity || !report.countMatches || report.sourceOrSyntheticSecretPresent) {
    return { ...common, status: 'UNASSESSED', reason: 'Synthetic report consistency/privacy check failed.', internalError: true };
  }
  if (matched.length > 0) return { ...common, status: 'DETECTED', reason: null };
  if (item.unsupported === true || (item.requiresLiteralFold === true && outcome.resultSummary.astSupplement?.status !== 'RAN')) {
    return { ...common, status: 'UNASSESSED', reason: 'The specific format or literal-fold analysis was not completely covered.' };
  }
  if (item.family === 'SCA') {
    // Overall SCA is PARTIAL because there is no advisory feed. Count only
    // this JSON declaration check when that specific rule was evaluated.
    if (outcome.resultSummary.declarationRulesEvaluated === 1 && outcome.resultSummary.declarationRulesNotEvaluated === 0 &&
        outcome.resultSummary.truncated !== true && outcome.sca?.summary.manifestsInvalid === 0) {
      return { ...common, status: 'NOT_DETECTED', reason: 'Declaration rule evaluated; advisory assessment remains unavailable.' };
    }
  } else if (outcome.resultSummary.partial !== true && outcome.resultSummary.truncated !== true &&
      (item.family === 'DAST' ? outcome.resultSummary.requestsMade === 1 : outcome.resultSummary.filesScanned === 1)) {
    return { ...common, status: 'NOT_DETECTED', reason: null };
  }
  return { ...common, status: 'UNASSESSED', reason: 'Incomplete, skipped, invalid or truncated evaluation.' };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const inheritedScaRuleSha256 = assertBenchmarkScaRuleUnchanged();
  const requestedCase = process.env.DROBON_BENCHMARK_CASE_ID;
  const selectedCases = requestedCase === undefined ? cases : cases.filter((item) => item.id === requestedCase);
  if (selectedCases.length === 0) throw new Error('Unknown benchmark case ID');
  const observations = [];
  for (const item of selectedCases) {
    try { observations.push(await observe(item)); }
    catch { observations.push({ id: item.id, status: 'UNASSESSED', reason: 'Unexpected local benchmark error.', internalError: true }); }
  }
  const scores = scoreCases(selectedCases, observations);
  const selectedIds = new Set(selectedCases.map((item) => item.id));
  const output = { schemaVersion: 'drobon.local-benchmark/v1', fixtureManifestSha256: fixtureManifestDigest(), inheritedScaRuleSha256,
    node: process.version, groundTruthReview: 'AUTHOR_DEFINED_NOT_INDEPENDENTLY_REVIEWED',
    scope: 'Direct production engines with test-only rules; DAST mock resolver/transport; declaration-only SCA; not a vendor comparison.',
    cases: manifest.filter((item) => selectedIds.has(item.id)), observations, scores };
  console.log(JSON.stringify(output, null, 2));
  if (observations.some((observation) => observation.internalError)) process.exitCode = 1;
}
