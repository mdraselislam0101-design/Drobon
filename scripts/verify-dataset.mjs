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
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve, join, relative } from 'node:path';

import { createDatasetService } from '../apps/api/src/external/service.ts';
import { evaluatePackDastCheck } from '../apps/api/src/external/evaluator.ts';
import { compileScaDeclarationRule, evaluateScaDeclarationCheck } from '../apps/api/src/external/scaDeclaration.ts';
import { SAST_LANGUAGE_CATALOG, isAnalyzedMaturity } from '../apps/api/src/scans/sast/languages.ts';
import { resolvePackLanguages, unresolvedPackLanguageIds } from '../apps/api/src/external/languageAliases.ts';
import { INSPECTED_RESPONSE_HEADERS } from '../apps/api/src/scans/dast/observedHeaders.ts';
import { createGuidanceLookup } from '../apps/api/src/external/guidance.ts';
import { remediationGuidanceForFinding } from '../apps/api/src/scans/remediationGuidance.ts';
import { createFilesystemIntelligenceProvider } from '../apps/api/src/scans/sca/filesystemProvider.ts';
import { parseDeclarationDocument, DECLARATION_READER_PARSERS } from '../apps/api/src/scans/sca/declarationReaders.ts';
import { renderDeclarationDocument, unwrapXml } from './sca-reader-fixtures.mjs';

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
for (const [key, min] of [['sast', 1000], ['secrets', 1000], ['dast', 1007], ['sca', 1000], ['remediation', 4007], ['cwe', 102], ['lessons', 6]]) {
  check(counts[key] >= min, `${key} pack count ${counts[key]} < ${min}`);
}
const conformance = {};
for (const family of ['sast', 'secrets', 'dast', 'sca']) {
  const r = status.conformance[family];
  conformance[family] = {
    filesSeen: r.filesSeen, accepted: r.accepted, declaredTests: r.declaredTests,
    executedTests: r.executedTests, skippedTests: r.skippedTests, failedTests: r.failedTests,
    rejected: r.rejected.length,
  };
  check(r.rejected.length === 0, `${family}: ${r.rejected.length} rules refused`);
  check(r.failedTests === 0, `${family}: ${r.failedTests} declared-test failures`);
  check(r.skippedTests === 0, `${family}: ${r.skippedTests} skipped declared tests`);
}
check(status.conformance.scaDeclarationEvaluator === 'AVAILABLE', 'SCA declaration evaluator not available');
check(status.conformance.scaDeclarationScanReachableRules > 0, 'no scan-reachable SCA declaration rules');

// ---- 2. DAST declared-test parity through the APP evaluator ----
const URL_OR_BODY = new Set(['response-body-matches', 'http-url', 'cookie-missing-flag', 'response-header-host-differs']);
const dastRules = readdirSync(join(datasetPath, 'packs/dast/v1/rules')).filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(readFileSync(join(datasetPath, 'packs/dast/v1/rules', f), 'utf8')));
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
const scaRules = readdirSync(join(datasetPath, 'packs/sca/v1/rules')).filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(readFileSync(join(datasetPath, 'packs/sca/v1/rules', f), 'utf8')));
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

// ---- 2c. READER ROUND-TRIP (Pump 18): raw text → document → evaluator ----
// For every non-JSON declared test we render the dataset's PARSED document
// back into realistic manifest text, parse it with the APP reader, and check
// the rule still reaches the same verdict. Reports honest per-parser coverage.
const readerStats = {};
for (const parser of DECLARATION_READER_PARSERS) {
  readerStats[parser] = { declaredTests: 0, rendered: 0, parsed: 0, verdictMismatches: 0, parseFailures: 0 };
}
for (const rule of scaRules) {
  if (rule.parser === 'json') continue; // JSON is round-tripped by JSON.parse directly
  const compiled = compileScaDeclarationRule(rule);
  const stat = readerStats[rule.parser];
  if (compiled === undefined || stat === undefined) continue;
  for (const test of rule.tests ?? []) {
    stat.declaredTests += 1;
    const raw = renderDeclarationDocument(rule.parser, rule.artifact, test.document);
    if (raw === undefined) { stat.parseFailures += 1; continue; }
    stat.rendered += 1;
    const text = typeof raw === 'string' ? raw : raw.text;
    let parsed = parseDeclarationDocument(rule.parser, rule.artifact, text);
    if (typeof raw !== 'string') parsed = unwrapXml(rule.parser, rule.artifact, test.document, parsed);
    if (parsed === undefined) { stat.parseFailures += 1; continue; }
    stat.parsed += 1;
    const hit = evaluateScaDeclarationCheck(compiled, parsed);
    if (hit !== test.match) stat.verdictMismatches += 1;
  }
}
const readerParsers = Object.keys(readerStats);
const readerDeclaredTests = readerParsers.reduce((sum, key) => sum + readerStats[key].declaredTests, 0);
const readerMismatches = readerParsers.reduce((sum, key) => sum + readerStats[key].verdictMismatches, 0);
const readerParseFailures = readerParsers.reduce((sum, key) => sum + readerStats[key].parseFailures, 0);
// The readers are deliberately BOUNDED subset parsers. A small residual of
// dataset-declared document shapes is richer than those subsets (deeply
// nested Gradle/lockfile/INI structures). Those shapes are NOT guessed: in a
// real scan the rule is counted as `declarationRulesNotEvaluated`. This gate
// is a REGRESSION guard (>=92% verdict parity), not a completeness claim.
const readerMismatchBudget = Math.ceil(readerDeclaredTests * 0.08);
check(readerParsers.length === 9, `SCA reader registry: only ${readerParsers.length}/9 parsers registered`);
check(status.conformance.scaDeclarationScanReachableRules === scaRules.length,
  `SCA scan-reachable rules ${status.conformance.scaDeclarationScanReachableRules} != ${scaRules.length}`);
check(readerMismatches <= readerMismatchBudget,
  `SCA reader round-trip: ${readerMismatches} verdict mismatches exceeds the ${readerMismatchBudget} residual budget`);
// Honest structural limit: the shared source-path policy rejects dotfiles,
// so these artifacts can never be uploaded into a snapshot. They are counted,
// never silently treated as reachable.
const unuploadableArtifacts = [...new Set(scaRules.filter((rule) => rule.artifact.startsWith('.')).map((rule) => rule.artifact))].sort();
const rulesWithUnuploadableArtifact = scaRules.filter((rule) => rule.artifact.startsWith('.')).length;

// ---- 3. SAST language reachability through the APP catalog ----
const catalogIds = new Set(SAST_LANGUAGE_CATALOG.map((f) => f.id));
const analyzedIds = new Set(SAST_LANGUAGE_CATALOG.filter((f) => isAnalyzedMaturity(f.maturity)).map((f) => f.id));
const sastRules = readdirSync(join(datasetPath, 'packs/sast/v1/rules')).filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(readFileSync(join(datasetPath, 'packs/sast/v1/rules', f), 'utf8')));
const allPackLanguageIds = [...new Set(sastRules.flatMap((r) => r.languages ?? []))];
const unresolved = unresolvedPackLanguageIds(allPackLanguageIds, catalogIds);
let sastUnreachable = 0;
let sastViaDatasetRule = 0;
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
const vectors = JSON.parse(readFileSync(join(datasetPath, 'interop/provider-vectors.json'), 'utf8')).vectors;
const provider = createFilesystemIntelligenceProvider({ datasetPath, logger: silent });
let vectorsPassed = 0;
for (const vector of vectors) {
  const result = await provider.assess([{ ...vector.coordinate, dependencyId: `dep_${vector.id}` }]);
  const got = [...new Set(result.advisories.map((a) => a.id))].sort();
  const want = [...vector.expect].sort();
  if (JSON.stringify(got) === JSON.stringify(want)) vectorsPassed += 1;
}
check(vectorsPassed === vectors.length, `provider vectors ${vectorsPassed}/${vectors.length}`);
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

const evidence = {
  schemaVersion: 'drobon.integration-evidence/v1',
  generatedAt: new Date().toISOString(),
  app: { repo: 'mdraselislam0101-design/Drobon', branch: 'arena/5bb07bd8-drobon' },
  dataset: { repo: 'mdraselislam0101-design/Drobon-Dataset', path: relative(ROOT, datasetPath) || '.' },
  counts,
  packs: status.packs,
  conformance,
  dast: { declaredTests: dastParityTests, parityMismatches: dastParityMismatches, unreachable: dastUnreachable, inspectedHeaders: INSPECTED_RESPONSE_HEADERS.size },
  sast: { rules: sastRules.length, unreachable: sastUnreachable, viaDatasetRuleFamily: sastViaDatasetRule, distinctLanguageIds: allPackLanguageIds.length, unresolvedLanguageIds: unresolved },
  sca: {
    providerVectors: vectors.length, vectorsPassed,
    declarationEvaluator: status.conformance.scaDeclarationEvaluator,
    declaredTests: scaParityTests, parityMismatches: scaParityMismatches, uncompilable: scaUncompilable,
    scanParsers: status.conformance.scaDeclarationScanParsers ?? [],
    scanReachableRules: status.conformance.scaDeclarationScanReachableRules ?? 0,
    loadedRules: scaRules.length,
    readerDeclaredTests, readerVerdictMismatches: readerMismatches, readerMismatchBudget,
    readerParseFailures, unuploadableArtifacts, rulesWithUnuploadableArtifact,
    readerVerdictParityPercent: Number((100 * (1 - readerMismatches / Math.max(1, readerDeclaredTests))).toFixed(2)),
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
