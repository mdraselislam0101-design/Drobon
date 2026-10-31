#!/usr/bin/env node
/** Read-only verification over JSONL supplied on stdin by audit-dataset-archive.py.
 * No dataset files are created or written. This checks the bounded parser,
 * app conformance and SCA reader classifications, not mounted-filesystem E2E
 * or independent scanner accuracy. Input payloads never appear in output. */
import { parseBoundedJson } from '../apps/api/src/external/boundedJson.ts';
import { DATASET_LOADER_LIMITS } from '../apps/api/src/external/service.ts';
import { validatePackRules } from '../apps/api/src/external/conformance.ts';
import { compileScaDeclarationRule, evaluateScaDeclarationCheck } from '../apps/api/src/external/scaDeclaration.ts';
import { parseDeclarationDocument, DECLARATION_READER_PARSERS } from '../apps/api/src/scans/sca/declarationReaders.ts';
import { evaluateScaDeclarations } from '../apps/api/src/scans/sca/declarationScan.ts';
import { diagnoseReaderFixture, renderDeclarationDocument } from './sca-reader-fixtures.mjs';
import { isValidSourcePath } from '@drobon/shared';
import { isDeepStrictEqual } from 'node:util';
import { cases as localCases } from '../benchmarks/local/fixtures.mjs';
import { convertSastPackToRule, convertSecretsPackToRule } from '../apps/api/src/external/packProvider.ts';
import { matchRuleLine } from '../apps/api/src/scans/sast/rules.ts';
import { astReporterRules } from '../apps/api/src/scans/sast/astAnalyzer.ts';
import { matchSecretsRuleLine } from '../apps/api/src/scans/secrets/rules.ts';
import { evaluatePackDastCheck } from '../apps/api/src/external/evaluator.ts';
import { createSastEngine } from '../apps/api/src/scans/sast/engine.ts';
import { createSecretsEngine } from '../apps/api/src/scans/secrets/engine.ts';
import { createScaEngine } from '../apps/api/src/scans/sca/engine.ts';
import { createDastEngine } from '../apps/api/src/scans/dast/engine.ts';
import { createDastTargetPolicy } from '../apps/api/src/scans/dast/target.ts';

const expected = { sast: 1000, secrets: 1000, dast: 1007, sca: 1000 };
const packs = { sast: [], secrets: [], dast: [], sca: [] };
const allowedCategories = new Set([...Object.keys(packs), 'vulnIntel', 'remediation', 'cwe', 'lessons', 'assessmentTemplates', 'engagementTemplates', 'interop']);
const summary = Object.create(null);

async function* boundedLines(stream) {
  const maxLine = Math.ceil(DATASET_LOADER_LIMITS.maxFileBytes * 4 / 3) + 16_384;
  let pending = '';
  for await (const chunk of stream) {
    pending += chunk.toString('utf8');
    let end;
    while ((end = pending.indexOf('\n')) >= 0) {
      if (end > maxLine) throw new Error('memory-verification input line exceeds the limit');
      yield pending.slice(0, end);
      pending = pending.slice(end + 1);
    }
    if (pending.length > maxLine) throw new Error('memory-verification input line exceeds the limit');
  }
  if (pending.length > 0) yield pending;
}

let selectedFiles = 0;
let selectedBytes = 0;
let largestFile = 0;
let invalid = 0;
let linesSeen = 0;
for await (const line of boundedLines(process.stdin)) {
  if (++linesSeen > DATASET_LOADER_LIMITS.maxEntries) throw new Error('memory-verification input entry limit exceeded');
  let item;
  try { item = JSON.parse(line); } catch { invalid += 1; continue; }
  if (typeof item !== 'object' || item === null || !allowedCategories.has(item.category) ||
      typeof item.path !== 'string' || typeof item.base64 !== 'string') { invalid += 1; continue; }
  const raw = Buffer.from(item.base64, 'base64');
  selectedFiles += 1;
  selectedBytes += raw.length;
  if (selectedFiles > DATASET_LOADER_LIMITS.maxFiles || selectedBytes > DATASET_LOADER_LIMITS.maxTotalBytes) {
    throw new Error('memory-verification input exceeds aggregate limits');
  }
  largestFile = Math.max(largestFile, raw.length);
  const counts = summary[item.category] ??= { files: 0, bytes: 0, rejected: 0 };
  counts.files += 1;
  counts.bytes += raw.length;
  if (raw.length > DATASET_LOADER_LIMITS.maxFileBytes) { counts.rejected += 1; continue; }
  try {
    const parsed = parseBoundedJson(raw.toString('utf8'), {
      maxDepth: DATASET_LOADER_LIMITS.maxJsonDepth, maxTokens: DATASET_LOADER_LIMITS.maxJsonTokens,
    });
    if (Object.hasOwn(packs, item.category) && item.path.includes('/rules/')) packs[item.category].push(parsed);
  } catch { counts.rejected += 1; }
}

const conformance = {};
const acceptedPacks = {};
let allAccepted = true;
for (const family of Object.keys(packs)) {
  const result = validatePackRules(packs[family], family);
  const r = result.report;
  acceptedPacks[family] = result.rules;
  conformance[family] = { files: packs[family].length, accepted: r.accepted, declaredTests: r.declaredTests,
    executedTests: r.executedTests, skippedTests: r.skippedTests, failedTests: r.failedTests };
  if (r.accepted !== expected[family] || r.filesSeen !== r.accepted || r.declaredTests !== r.executedTests || r.skippedTests !== 0 || r.failedTests !== 0) allAccepted = false;
}

const fixtureRecord = { id: 'scan_00000000-0000-4000-8000-000000000003',
  projectId: 'prj_00000000-0000-4000-8000-000000000002', ownerId: 'usr_00000000-0000-4000-8000-000000000001',
  scanType: 'SCA', status: 'RUNNING', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z' };
const reader = { evaluatorCases: 0, evaluatorMismatches: 0, correct: 0, falsePositive: 0, falseNegative: 0,
  pathBlocked: 0, unrenderable: 0, parseFailures: 0, scanNotEvaluated: 0, unsupported: 0, compileFailures: 0,
  blockedByRule: {}, otherGaps: [] };
// Diagnostic bypasses only the fixture harness's path check to exercise the
// reader in memory. These cases remain blocked in the production upload/scan.
const blockedReaderDiagnostic = { matches: 0, 'false-positive': 0, 'false-negative': 0,
  unrenderable: 0, 'parse-failure': 0, 'compile-failure': 0, cases: [] };
// Structural explanation only; never serialize document values or credentials.
function unrenderableReason(rule, test) {
  if (rule.artifact.toLowerCase() !== 'nuget.config') return { code: 'NO_SAFE_RENDERING' };
  const doc = test.document;
  const declared = typeof doc?.packageSources === 'object' && doc.packageSources !== null && !Array.isArray(doc.packageSources)
    ? doc.packageSources : undefined;
  const sources = Array.isArray(doc?.sources) ? doc.sources : undefined;
  const add = declared?.add;
  const added = add === undefined ? undefined : Array.isArray(add) ? add : [add];
  const code = sources?.length > 0 && declared !== undefined && add === undefined
    ? 'DERIVED_SOURCES_WITHOUT_ADD' : sources !== undefined && added !== undefined && !isDeepStrictEqual(sources, added)
      ? 'CONFLICTING_SOURCE_ALIASES' : 'NO_SAFE_RENDERING';
  return { code, sourcesCount: sources?.length ?? null, addPresent: add !== undefined, addCount: added?.length ?? null };
}
for (const rule of acceptedPacks.sca) {
  const compiled = compileScaDeclarationRule(rule);
  for (const [index, test] of (rule.tests ?? []).entries()) {
    reader.evaluatorCases += 1;
    if (compiled === undefined) { reader.compileFailures += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'compile-failure' }); continue; }
    if (evaluateScaDeclarationCheck(compiled, test.document) !== test.match) reader.evaluatorMismatches += 1;
    if (!DECLARATION_READER_PARSERS.includes(rule.parser)) { reader.unsupported += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'unsupported-reader' }); continue; }
    if (!isValidSourcePath(rule.artifact)) {
      reader.pathBlocked += 1;
      (reader.blockedByRule[rule.id] ??= []).push(index);
      const category = diagnoseReaderFixture(rule, test, compiled, parseDeclarationDocument, evaluateScaDeclarationCheck);
      blockedReaderDiagnostic[category] += 1;
      blockedReaderDiagnostic.cases.push({ ruleId: rule.id, testIndex: index, artifact: rule.artifact, parser: rule.parser,
        expected: test.match, pathReason: rule.artifact.split('/').some((segment) => segment.startsWith('.'))
          ? 'HIDDEN_PATH_SEGMENT' : 'OTHER_SOURCE_PATH_POLICY', productionStatus: 'PATH_BLOCKED', category });
      continue;
    }
    const rendered = rule.parser === 'json' ? JSON.stringify(test.document) : renderDeclarationDocument(rule.parser, rule.artifact, test.document);
    if (rendered === undefined) { reader.unrenderable += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index,
      artifact: rule.artifact, parser: rule.parser, expected: test.match, category: 'unrenderable', reason: unrenderableReason(rule, test) }); continue; }
    const text = typeof rendered === 'string' ? rendered : rendered.text;
    if (parseDeclarationDocument(rule.parser, rule.artifact.split('/').pop(), text) === undefined) {
      reader.parseFailures += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'reader-parse-failure' }); continue;
    }
    const result = evaluateScaDeclarations({ rawRules: [rule], files: [{ path: rule.artifact, content: text }], record: fixtureRecord });
    if (result.rulesEvaluated !== 1) { reader.scanNotEvaluated += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'scan-not-evaluated' }); continue; }
    const hit = result.findings.length > 0;
    if (hit === test.match) reader.correct += 1;
    else if (hit) { reader.falsePositive += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'false-positive' }); }
    else { reader.falseNegative += 1; reader.otherGaps.push({ ruleId: rule.id, testIndex: index, category: 'false-negative' }); }
  }
}
const accounted = reader.correct + reader.falsePositive + reader.falseNegative + reader.pathBlocked + reader.unrenderable +
  reader.parseFailures + reader.scanNotEvaluated + reader.unsupported + reader.compileFailures;
reader.accounted = accounted;
reader.blockedRules = Object.keys(reader.blockedByRule).length;
const parsed = invalid === 0 && Object.values(summary).every((item) => item.rejected === 0);
const bounds = selectedFiles <= DATASET_LOADER_LIMITS.maxFiles && selectedBytes <= DATASET_LOADER_LIMITS.maxTotalBytes &&
  largestFile <= DATASET_LOADER_LIMITS.maxFileBytes;
const evaluatorAccountingComplete = allAccepted && reader.evaluatorCases === 4001 && reader.evaluatorMismatches === 0 && accounted === 4001;
const readerCoverage = reader.evaluatorCases > 0 && reader.correct === reader.evaluatorCases ? 'ALL_FIXTURES_PASSED' : 'PARTIAL';
const blockedDiagnosticAccountingComplete = blockedReaderDiagnostic.cases.length === reader.pathBlocked &&
  ['matches', 'false-positive', 'false-negative', 'unrenderable', 'parse-failure', 'compile-failure']
    .reduce((sum, key) => sum + blockedReaderDiagnostic[key], 0) === reader.pathBlocked;
// Inspect only the exact synthetic scope implicated by the 21-case run. This is
// an in-memory rule/evaluator probe, NOT a production Dataset engine scan.
const getCase = (id) => {
  const item = localCases.find((entry) => entry.id === id);
  if (!item) throw new Error('Missing fixed synthetic scope fixture');
  return item;
};
const convertedSast = acceptedPacks.sast.map(convertSastPackToRule).filter(Boolean);
const convertedSecrets = acceptedPacks.secrets.map(convertSecretsPackToRule).filter(Boolean);
const sastConstantLine = getCase('SAST-02').content.split('\n')[1];
const secretSingleLine = getCase('SECRET-01').content.trim();
const secretSplitLine = getCase('SECRET-02').content.trim();
const devDocument = JSON.parse(getCase('SCA-03').content);
const syntheticScope = {
  sastConstantLexicalRuleIds: convertedSast.filter((rule) => (!rule.languages || rule.languages.includes('javascript')) &&
    matchRuleLine(rule, sastConstantLine) !== undefined).map((rule) => rule.id),
  sastJavascriptReporters: astReporterRules(convertedSast, 'javascript'),
  secretSingleLiteralRuleIds: convertedSecrets.filter((rule) => matchSecretsRuleLine(rule, secretSingleLine) !== undefined).map((rule) => rule.id),
  secretSplitLiteralRuleIds: convertedSecrets.filter((rule) => matchSecretsRuleLine(rule, secretSplitLine) !== undefined).map((rule) => rule.id),
  scaDevWildcardRuleIds: acceptedPacks.sca.filter((rule) => {
    if (rule.artifact !== 'package.json' || rule.parser !== 'json') return false;
    const compiled = compileScaDeclarationRule(rule);
    return compiled !== undefined && evaluateScaDeclarationCheck(compiled, devDocument);
  }).map((rule) => ({ id: rule.id, type: rule.check.type, path: rule.check.path })),
  dastNosniffChecks: acceptedPacks.dast.filter((rule) => typeof rule.check?.header === 'string' &&
    rule.check.header.toLowerCase() === 'x-content-type-options').map((rule) => {
      const base = { url: 'https://bench.example.org/', status: 200, body: '' };
      return { id: rule.id, type: rule.check.type,
        missing: evaluatePackDastCheck(rule.check, { ...base, headers: {} }),
        invalid: evaluatePackDastCheck(rule.check, { ...base, headers: { 'x-content-type-options': 'invalid' } }),
        safe: evaluatePackDastCheck(rule.check, { ...base, headers: { 'x-content-type-options': 'nosniff' } }) };
    }),
};
// Real app engines, full accepted pack in RAM, separate synthetic input per
// invocation. Only rule/location metadata is returned; DAST does not contact
// DNS or open a socket. This remains different from a mounted Dataset E2E.
const inMemoryDataset = { configured: true,
  sastPacks: async () => acceptedPacks.sast, secretsPacks: async () => acceptedPacks.secrets,
  scaPacks: async () => acceptedPacks.sca, dastPacks: async () => acceptedPacks.dast };
const syntheticRuntime = [];
for (const id of ['SAST-02', 'SAST-04', 'SECRET-01', 'SECRET-02', 'SCA-03', 'SCA-04', 'DAST-02']) {
  const item = getCase(id);
  const record = { ...fixtureRecord, scanType: item.family,
    ...(item.route ? { dastTargetUrl: `https://bench.example.org${item.route}` } : {}) };
  const snapshot = { ownerId: record.ownerId, projectId: record.projectId, createdAt: record.createdAt, updatedAt: record.updatedAt,
    files: item.content === undefined ? [] : [{ path: item.path, content: item.content, bytes: Buffer.byteLength(item.content) }] };
  const options = { sources: { findByProject: async () => snapshot }, dataset: inMemoryDataset };
  let engine;
  if (item.family === 'SAST') engine = createSastEngine(options);
  else if (item.family === 'SECRETS') engine = createSecretsEngine(options);
  else if (item.family === 'SCA') engine = createScaEngine(options);
  else engine = createDastEngine({ dataset: inMemoryDataset,
    targetPolicy: createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] }),
    transport: { probe: async () => ({ status: 200, headers: { 'x-content-type-options': 'invalid' },
      body: '', bodyTruncated: false, elapsedMs: 1 }) } });
  const outcome = await engine.execute(record, { signal: new AbortController().signal });
  const findings = outcome.kind === 'completed' ? outcome.findings ?? [] : [];
  syntheticRuntime.push({ id, kind: outcome.kind,
    partial: outcome.kind === 'completed' ? outcome.resultSummary.partial === true : null,
    truncated: outcome.kind === 'completed' ? outcome.resultSummary.truncated === true : null,
    findings: findings.map((finding) => ({ id: finding.ruleId, severity: finding.severity,
      ...(finding.astFlow ? { astMode: finding.astFlow.mode, astCategory: finding.astFlow.category } : {}) })) });
}
const result = { parsed, bounds, allAccepted, evaluatorAccountingComplete, readerCoverage, blockedDiagnosticAccountingComplete, selectedFiles, selectedBytes, largestFile, invalid, summary, conformance, reader, blockedReaderDiagnostic, syntheticScope, syntheticRuntime,
  limitations: ['RAM-only archive verification; no mounted Dataset filesystem test', 'Reader fixtures are synthetic, not real-world accuracy', 'Blocked-reader diagnostics do not bypass the real source path policy', 'Blocked and unrenderable cases are not scan passes', 'Synthetic runtime uses in-memory packs and mock DAST transport'] };
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!parsed || !bounds || !evaluatorAccountingComplete || !blockedDiagnosticAccountingComplete) process.exitCode = 1;
