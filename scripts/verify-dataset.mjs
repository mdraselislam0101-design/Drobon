#!/usr/bin/env node
/**
 * verify-dataset.mjs — REAL integration verification against an external
 * Drobon-Dataset checkout (never committed to this repo).
 *
 *   npm run verify:dataset -- --path ../Drobon-Dataset
 *   npm run verify:dataset -- --path ../Drobon-Dataset --write
 *
 * Requires `tsx` (dev dependency) so the SAME application modules that run in
 * production are exercised — this is not a parallel re-implementation.
 * Reads nothing from the network. Writes an optional evidence JSON containing
 * COUNTS ONLY (no advisory records, no rule bodies, no dataset bytes).
 */
import { writeFileSync } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve, join } from 'node:path';

import { createDatasetService, DATASET_LOADER_LIMITS } from '../apps/api/src/external/service.ts';
import { createJsonByteBudget, readBoundedJsonFile } from '../apps/api/src/external/boundedJson.ts';
import { evaluatePackDastCheck } from '../apps/api/src/external/evaluator.ts';
import { compileScaDeclarationRule, evaluateScaDeclarationCheck } from '../apps/api/src/external/scaDeclaration.ts';
import { SAST_LANGUAGE_CATALOG, isAnalyzedMaturity } from '../apps/api/src/scans/sast/languages.ts';
import { resolvePackLanguages, unresolvedPackLanguageIds } from '../apps/api/src/external/languageAliases.ts';
import { convertSastPackToRule } from '../apps/api/src/external/packProvider.ts';
import { matchRuleLine } from '../apps/api/src/scans/sast/rules.ts';
import { maskComments } from '../apps/api/src/scans/sast/semantic.ts';
import { INSPECTED_RESPONSE_HEADERS } from '../apps/api/src/scans/dast/observedHeaders.ts';
import { createGuidanceLookup } from '../apps/api/src/external/guidance.ts';
import { remediationGuidanceForFinding } from '../apps/api/src/scans/remediationGuidance.ts';
import { createFilesystemIntelligenceProvider } from '../apps/api/src/scans/sca/filesystemProvider.ts';
import { isValidSourcePath } from '@drobon/shared';
import { parseDeclarationDocument, DECLARATION_READER_PARSERS } from '../apps/api/src/scans/sca/declarationReaders.ts';
import { evaluateScaDeclarations } from '../apps/api/src/scans/sca/declarationScan.ts';
import { renderDeclarationDocument } from './sca-reader-fixtures.mjs';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const args = process.argv.slice(2);
const pathIndex = args.indexOf('--path');
const datasetPath = resolve(pathIndex === -1 ? (process.env['DATASET_PATH'] ?? '../Drobon-Dataset') : (args[pathIndex + 1] ?? '../Drobon-Dataset'));
const WRITE = args.includes('--write');
const failures = [];
const check = (ok, label) => { if (!ok) failures.push(label); };

const silent = { info: () => {}, warn: () => {}, error: () => {} };
const dataset = createDatasetService({ datasetPath, providerId: 'filesystem', logger: silent });
const status = await dataset.status();

// ---- 1. loader: every category loads, every pack passes conformance ----
const counts = {
  vulnIntelFiles: status.vulnIntel.count,
  vulnIntelIdentityItems: status.vulnIntelCounts.identityItems,
  vulnIntelAdvisoryIds: status.vulnIntelCounts.advisoryIds,
  sast: status.sastPacks.count,
  secrets: status.secretsPacks.count,
  dast: status.dastPacks.count,
  sca: status.scaPacks.count,
  remediation: status.remediation.count,
  cwe: status.cwe.count,
  lessons: status.lessons.count,
  assessmentTemplates: status.assessmentTemplates.count,
  engagementTemplates: status.engagementTemplates.count,
};
check(status.configured, 'dataset service not configured');
for (const key of ['vulnIntel', 'remediation', 'cwe', 'lessons', 'assessmentTemplates', 'engagementTemplates']) {
  check(status[key].incomplete !== true, `${key}: category could not be completely read or enumerated`);
}
for (const [key, min] of [['sast', 1000], ['secrets', 1000], ['dast', 1007], ['sca', 1000], ['remediation', 4007], ['cwe', 102], ['lessons', 6]]) {
  check(counts[key] >= min, `${key} pack count ${counts[key]} < ${min}`);
}
const conformance = {};
for (const family of ['sast', 'secrets', 'dast', 'sca']) {
  const r = status.conformance[family];
  conformance[family] = {
    filesSeen: r.filesSeen, enumerationFailures: r.enumerationFailures, accepted: r.accepted, declaredTests: r.declaredTests,
    executedTests: r.executedTests, skippedTests: r.skippedTests, failedTests: r.failedTests,
    rejected: r.rejected.length,
    ...(r.manifestIssue === undefined ? {} : { manifestIssue: r.manifestIssue }),
    ...(r.resourceLimitFailures === undefined ? {} : { resourceLimitFailures: r.resourceLimitFailures }),
  };
  check(r.manifestIssue === undefined, `${family}: optional manifest could not be safely loaded`);
  check(r.accepted === r.filesSeen, `${family}: ${r.filesSeen - r.accepted} discovered rules refused`);
  check(r.enumerationFailures === 0, `${family}: ${r.enumerationFailures} enumeration failures; undiscovered file count is unknown`);
  check(r.failedTests === 0, `${family}: ${r.failedTests} declared-test failures`);
  check(r.skippedTests === 0, `${family}: ${r.skippedTests} skipped declared tests`);
}
check(status.conformance.scaDeclarationEvaluator === 'AVAILABLE', 'SCA declaration evaluator not available');
check(status.conformance.scaDeclarationScanReachableRules > 0, 'no scan-reachable SCA declaration rules');

// ---- 2. DAST declared-test parity through the APP evaluator ----
const URL_OR_BODY = new Set(['response-body-matches', 'http-url', 'cookie-missing-flag']);
// Reuse the bounded production loader rather than reading the same corpus
// again through an unrestricted verification-only filesystem path.
const dastRules = await dataset.dastPacks();
let dastParityTests = 0;
let dastParityMismatches = 0;
let dastUnreachable = 0;
for (const rule of dastRules) {
  for (const test of rule.tests ?? []) {
    const hit = evaluatePackDastCheck(rule.check, {
      url: test.observation?.url ?? '', status: test.observation?.status ?? 0,
      headers: test.observation?.headers ?? {}, body: test.observation?.body,
    });
    dastParityTests += 1;
    if (hit !== test.match) dastParityMismatches += 1;
  }
  const type = rule.check?.type;
  const header = typeof rule.check?.header === 'string' ? rule.check.header.toLowerCase() : undefined;
  if (!URL_OR_BODY.has(type) && (header === undefined || !INSPECTED_RESPONSE_HEADERS.has(header))) dastUnreachable += 1;
}
check(dastParityMismatches === 0, `DAST parity: ${dastParityMismatches} mismatches`);
check(dastUnreachable === 0, `DAST reachability: ${dastUnreachable} unreachable rules`);

// ---- 2b. SCA declaration parity through the APP evaluator (Pump 14) ----
// Re-run every declared test independently of the loader. This proves the
// app's evaluator reproduces the dataset's check semantics, not merely that
// the loader counted the tests as executed.
const scaRules = await dataset.scaPacks();
let scaParityTests = 0;
let scaParityMismatches = 0;
let scaUncompilable = 0;
for (const rule of scaRules) {
  const compiled = compileScaDeclarationRule(rule);
  if (compiled === undefined) { scaUncompilable += 1; continue; }
  for (const test of rule.tests ?? []) {
    const hit = evaluateScaDeclarationCheck(compiled, test.document);
    scaParityTests += 1;
    if (hit !== test.match) scaParityMismatches += 1;
  }
}
check(scaUncompilable === 0, `SCA: ${scaUncompilable} rules failed to compile`);
check(scaParityMismatches === 0, `SCA parity: ${scaParityMismatches} mismatches`);

// ---- 2c. SCA raw-file pipeline: render → reader → real scan layer ----
// Documents are synthetic renderings of the declared tests, not examples of
// real-world accuracy. JSON is included. Upload-blocked paths, unrenderable or
// unreadable fixtures, and false-positive/negative verdicts are separate.
const readerStats = {};
for (const parser of DECLARATION_READER_PARSERS) {
  readerStats[parser] = { declaredTests: 0, rendered: 0, parsed: 0, correct: 0,
    verdictMismatches: 0, falsePositive: 0, falseNegative: 0, blocked: 0, notRendered: 0, parseFailures: 0 };
}
const fixtureRecord = { id: 'scan_00000000-0000-4000-8000-000000000003',
  projectId: 'prj_00000000-0000-4000-8000-000000000002', ownerId: 'usr_00000000-0000-4000-8000-000000000001',
  scanType: 'SCA', status: 'RUNNING', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z' };
const readerIncompleteCases = [];
let readerUnsupported = 0;
for (const rule of scaRules) {
  const compiled = compileScaDeclarationRule(rule);
  const stat = readerStats[rule.parser];
  for (const [index, test] of (rule.tests ?? []).entries()) {
    // IDs are already pack-validated. Do not include fixture contents or paths.
    const recordGap = (category) => readerIncompleteCases.push({ ruleId: rule.id, testIndex: index, category });
    if (stat === undefined) { readerUnsupported += 1; recordGap('unsupported-reader'); continue; }
    stat.declaredTests += 1;
    if (!isValidSourcePath(rule.artifact)) { stat.blocked += 1; recordGap('path-policy-blocked'); continue; }
    if (compiled === undefined) { stat.parseFailures += 1; recordGap('compile-failure'); continue; }
    const raw = rule.parser === 'json' ? JSON.stringify(test.document) : renderDeclarationDocument(rule.parser, rule.artifact, test.document);
    if (raw === undefined) { stat.notRendered += 1; recordGap('unrenderable'); continue; }
    stat.rendered += 1;
    const text = typeof raw === 'string' ? raw : raw.text;
    if (parseDeclarationDocument(rule.parser, rule.artifact.split('/').pop(), text) === undefined) { stat.parseFailures += 1; recordGap('reader-parse-failure'); continue; }
    const result = evaluateScaDeclarations({ rawRules: [rule], files: [{ path: rule.artifact, content: text }], record: fixtureRecord });
    if (result.rulesEvaluated !== 1) { stat.parseFailures += 1; recordGap('scan-not-evaluated'); continue; }
    stat.parsed += 1;
    const hit = result.findings.length > 0;
    if (hit === test.match) stat.correct += 1;
    else { stat.verdictMismatches += 1; if (hit) stat.falsePositive += 1; else stat.falseNegative += 1; recordGap(hit ? 'false-positive' : 'false-negative'); }
  }
}
const readerParsers = Object.keys(readerStats);
const readerDeclaredTests = readerParsers.reduce((sum, key) => sum + readerStats[key].declaredTests, 0);
const readerMismatches = readerParsers.reduce((sum, key) => sum + readerStats[key].verdictMismatches, 0);
const readerParseFailures = readerParsers.reduce((sum, key) => sum + readerStats[key].parseFailures, 0);
const readerNotRendered = readerParsers.reduce((sum, key) => sum + readerStats[key].notRendered, 0);
const readerBlocked = readerParsers.reduce((sum, key) => sum + readerStats[key].blocked, 0);
const readerCorrect = readerParsers.reduce((sum, key) => sum + readerStats[key].correct, 0);
const readerFalsePositive = readerParsers.reduce((sum, key) => sum + readerStats[key].falsePositive, 0);
const readerFalseNegative = readerParsers.reduce((sum, key) => sum + readerStats[key].falseNegative, 0);
const readerFailures = readerMismatches + readerParseFailures + readerNotRendered + readerUnsupported;
const readerAccounted = readerCorrect + readerMismatches + readerParseFailures + readerNotRendered + readerBlocked + readerUnsupported;
check(readerAccounted === scaParityTests && readerIncompleteCases.length === readerAccounted - readerCorrect,
  `SCA reader accounting: ${readerAccounted}/${scaParityTests} evaluator cases classified`);
// Readers are bounded subsets. A verdict mismatch may also be a silently
// misinterpreted document, not necessarily an explicitly unevaluated rule.
// This is a regression threshold, NOT evidence of complete coverage.
const readerMismatchBudget = Math.ceil(readerDeclaredTests * 0.08);
check(readerParsers.length === 9, `SCA reader registry: only ${readerParsers.length}/9 parsers registered`);
const eligibleRules = scaRules.filter((rule) =>
  isValidSourcePath(rule.artifact) && readerParsers.includes(rule.parser)).length;
check(status.conformance.scaDeclarationScanReachableRules === eligibleRules,
  `SCA eligible rule count ${status.conformance.scaDeclarationScanReachableRules} != ${eligibleRules}`);
check(readerFailures <= readerMismatchBudget,
  `SCA reader round-trip: ${readerFailures} mismatches or parse failures exceeds the ${readerMismatchBudget} residual budget`);
// Honest structural limit: the shared source-path policy rejects dotfiles,
// so these artifacts can never be uploaded into a snapshot. They are counted,
// never silently treated as reachable.
const unuploadableArtifacts = [...new Set(scaRules.filter((rule) => !isValidSourcePath(rule.artifact)).map((rule) => rule.artifact))].sort();
const rulesWithUnuploadableArtifact = scaRules.filter((rule) => !isValidSourcePath(rule.artifact)).length;

// ---- 3. SAST language reachability through the APP catalog ----
const catalogIds = new Set(SAST_LANGUAGE_CATALOG.map((f) => f.id));
const analyzedIds = new Set(SAST_LANGUAGE_CATALOG.filter((f) => isAnalyzedMaturity(f.maturity)).map((f) => f.id));
const sastRules = await dataset.sastPacks();
const allPackLanguageIds = [...new Set(sastRules.flatMap((r) => r.languages ?? []))];
const unresolved = unresolvedPackLanguageIds(allPackLanguageIds, catalogIds);
let sastUnreachable = 0;
let sastViaDatasetRule = 0;
const commentContext = { declaredTests: 0, correct: 0, expectedPositiveSuppressed: 0, expectedNegativeMatched: 0, affectedRules: 0 };
for (const rawRule of sastRules) {
  const mapped = convertSastPackToRule(rawRule);
  if (mapped === undefined) continue; // Already counted as a loader/conversion error.
  const family = mapped.languages?.[0] ?? 'javascript';
  let different = false;
  for (const test of rawRule.tests ?? []) {
    const input = mapped.category === 'hardcoded-credential' ? test.line : maskComments(test.line, family);
    const hit = matchRuleLine(mapped, input) !== undefined;
    commentContext.declaredTests += 1;
    if (hit === test.match) commentContext.correct += 1;
    else { different = true; if (hit) commentContext.expectedNegativeMatched += 1; else commentContext.expectedPositiveSuppressed += 1; }
  }
  if (different) commentContext.affectedRules += 1;
}
for (const rule of sastRules) {
  if (rule.languages === undefined) continue; // universal
  const resolved = resolvePackLanguages(rule.languages, catalogIds) ?? [];
  if (resolved.length === 0) { sastUnreachable += 1; continue; }
  // Families the bare app marks SYNTAX_ONLY / UNSUPPORTED are analyzed only
  // because a loaded dataset rule targets them (engine.ts `ruleFamilies`).
  if (!resolved.some((id) => analyzedIds.has(id))) sastViaDatasetRule += 1;
}
check(unresolved.length === 0, `SAST unresolved language ids: ${unresolved.join(', ')}`);
check(sastUnreachable === 0, `SAST reachability: ${sastUnreachable} unreachable rules`);

// ---- 4. SCA provider vectors through the APP filesystem provider (GAP-044) ----
let vectors = [];
try {
  const root = await realpath(datasetPath);
  const interop = join(root, 'interop');
  const info = await lstat(interop);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('unsafe interop directory');
  const data = await readBoundedJsonFile(join(interop, 'provider-vectors.json'), {
    maxFileBytes: DATASET_LOADER_LIMITS.maxFileBytes,
    budget: createJsonByteBudget(DATASET_LOADER_LIMITS.maxFileBytes),
  });
  if (typeof data !== 'object' || data === null || !Array.isArray(data.vectors) || data.vectors.length > 1_000) throw new Error('invalid vector list');
  vectors = data.vectors;
} catch { check(false, 'provider vectors could not be safely read or parsed'); }
const provider = createFilesystemIntelligenceProvider({ datasetPath, logger: silent });
let vectorsPassed = 0;
for (const vector of vectors) {
  if (typeof vector !== 'object' || vector === null || typeof vector.coordinate !== 'object' || vector.coordinate === null || !Array.isArray(vector.expect)) continue;
  const result = await provider.assess([{ ...vector.coordinate, dependencyId: `dep_${vector.id}` }]);
  const got = [...new Set(result.advisories.map((a) => a.id))].sort();
  const want = [...vector.expect].sort();
  if (JSON.stringify(got) === JSON.stringify(want)) vectorsPassed += 1;
}
check(vectors.length > 0 && vectorsPassed === vectors.length, `provider vectors ${vectorsPassed}/${vectors.length}`);
check(status.vulnIntelCounts.files === status.vulnIntel.count, 'vuln-intel file counter mismatch');
check(status.vulnIntelCounts.identityItems <= status.vulnIntelCounts.files, 'identity items exceed files');

// ---- 5. remediation actually surfaces to users (0/4007 → 4007/4007) ----
const lookup = createGuidanceLookup(dataset);
const sampleIds = ['DPK-SAST-001', 'DPK-SEC-001', 'DPK-DAST-002', 'DPK-SCA-0001'];
let guidanceSpecific = 0;
for (const ruleId of sampleIds) {
  const entry = await lookup(ruleId);
  const finding = { ruleId, scanner: 'SAST', evidence: 'fixture', severity: 'MEDIUM', title: '', description: '', remediation: '' };
  const guidance = remediationGuidanceForFinding(finding, entry);
  if (guidance.status === 'RULE_SPECIFIC' && guidance.actions.length > 0) guidanceSpecific += 1;
}
check(guidanceSpecific === sampleIds.length, `remediation surfaced ${guidanceSpecific}/${sampleIds.length}`);

let appBranch = null;
try { appBranch = execFileSync('git', ['branch', '--show-current'], { cwd: ROOT, encoding: 'utf8' }).trim() || null; } catch { /* Branch information is optional. */ }
const evidence = {
  schemaVersion: 'drobon.integration-evidence/v1',
  generatedAt: new Date().toISOString(),
  app: { repo: 'mdraselislam0101-design/Drobon', branch: appBranch },
  // Configured paths may contain sensitive text; retain the field without exposing it.
  dataset: { repo: 'mdraselislam0101-design/Drobon-Dataset', path: '(withheld)' },
  counts,
  categoryCompleteness: Object.fromEntries(['vulnIntel', 'remediation', 'cwe', 'lessons', 'assessmentTemplates', 'engagementTemplates']
    .map((key) => [key, { incomplete: status[key].incomplete === true, ...(status[key].loadIssues === undefined ? {} : { loadIssues: status[key].loadIssues }) }])),

  packs: status.packs,
  conformance,
  dast: { declaredTests: dastParityTests, parityMismatches: dastParityMismatches, unreachable: dastUnreachable, inspectedHeaders: INSPECTED_RESPONSE_HEADERS.size },
  sast: { rules: sastRules.length, unreachable: sastUnreachable, viaDatasetRuleFamily: sastViaDatasetRule, distinctLanguageIds: allPackLanguageIds.length,
    unresolvedLanguageIds: unresolved, commentContext, commentContextScope: 'Simulated per line using the first resolved family; not a whole-project scan.' },
  sca: {
    providerVectors: vectors.length, vectorsPassed,
    declarationEvaluator: status.conformance.scaDeclarationEvaluator,
    declaredTests: scaParityTests, parityMismatches: scaParityMismatches, uncompilable: scaUncompilable,
    scanParsers: status.conformance.scaDeclarationScanParsers ?? [],
    scanReachableRules: status.conformance.scaDeclarationScanReachableRules ?? 0,
    loadedRules: scaRules.length,
    readerDeclaredTests, readerCorrect, readerVerdictMismatches: readerMismatches, readerFalsePositive, readerFalseNegative, readerMismatchBudget,
    readerParseFailures, readerNotRendered, readerBlocked, readerUnsupported, readerAccounted, readerFailures,
    readerIncompleteCases, unuploadableArtifacts, rulesWithUnuploadableArtifact,
    readerCoverageStatus: readerFailures > 0 || readerBlocked > 0 ? 'PARTIAL' : 'ALL_FIXTURES_PASSED',
    readerCorrectOfAllPercent: Number((100 * readerCorrect / Math.max(1, readerDeclaredTests)).toFixed(2)),
    readers: readerStats,
  },
  remediation: { sampleRuleIds: sampleIds, surfaced: guidanceSpecific },
  checks: failures.length === 0 ? 'PASS' : 'FAIL',
  failures,
};

if (WRITE) writeFileSync(join(ROOT, 'docs/DATASET_INTEGRATION_EVIDENCE.json'), `${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`\nverify-dataset: ${evidence.checks}${failures.length === 0 ? '' : `\n - ${failures.join('\n - ')}`}\n`);
if (failures.length > 0) process.exitCode = 1;
