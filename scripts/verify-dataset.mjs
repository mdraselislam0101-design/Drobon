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
import { SAST_LANGUAGE_CATALOG, isAnalyzedMaturity } from '../apps/api/src/scans/sast/languages.ts';
import { resolvePackLanguages, unresolvedPackLanguageIds } from '../apps/api/src/external/languageAliases.ts';
import { INSPECTED_RESPONSE_HEADERS } from '../apps/api/src/scans/dast/observedHeaders.ts';
import { createGuidanceLookup } from '../apps/api/src/external/guidance.ts';
import { remediationGuidanceForFinding } from '../apps/api/src/scans/remediationGuidance.ts';
import { createFilesystemIntelligenceProvider } from '../apps/api/src/scans/sca/filesystemProvider.ts';

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
}

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
  sca: { providerVectors: vectors.length, vectorsPassed, declarationEvaluator: status.conformance.scaDeclarationEvaluator },
  remediation: { sampleRuleIds: sampleIds, surfaced: guidanceSpecific },
  checks: failures.length === 0 ? 'PASS' : 'FAIL',
  failures,
};

if (WRITE) writeFileSync(join(ROOT, 'docs/DATASET_INTEGRATION_EVIDENCE.json'), `${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`\nverify-dataset: ${evidence.checks}${failures.length === 0 ? '' : `\n - ${failures.join('\n - ')}`}\n`);
if (failures.length > 0) process.exitCode = 1;
