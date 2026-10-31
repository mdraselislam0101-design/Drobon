#!/usr/bin/env node
/**
 * Exercise one declared POSITIVE fixture per accepted SAST, Secrets and DAST
 * dataset rule through the actual scanner engines. Read-only: writes no source,
 * dataset or result files. DAST uses only a fake DNS resolver and fake HTTP
 * transport; no network target is contacted. This is a reachability regression
 * test, not an accuracy benchmark or a replacement for negative/real tests.
 *
 *   node --import tsx scripts/verify-dataset-runtime.mjs --path /path/to/dataset
 */
import { resolve } from 'node:path';
import { isDastResult, isFinding, isScanResultSummary, isValidSourcePath } from '@drobon/shared';
import { createDatasetService } from '../apps/api/src/external/service.ts';
import { convertSastPackToRule, convertSecretsPackToRule, convertDastPackToRule } from '../apps/api/src/external/packProvider.ts';
import { evaluatePackDastCheck } from '../apps/api/src/external/evaluator.ts';
import { detectLanguageFamily, SAST_LANGUAGE_CATALOG } from '../apps/api/src/scans/sast/languages.ts';
import { matchRuleLine } from '../apps/api/src/scans/sast/rules.ts';
import { maskComments } from '../apps/api/src/scans/sast/semantic.ts';
import { createSastEngine } from '../apps/api/src/scans/sast/engine.ts';
import { matchSecretsRuleLine } from '../apps/api/src/scans/secrets/rules.ts';
import { createSecretsEngine } from '../apps/api/src/scans/secrets/engine.ts';
import { createActiveDastEngine } from '../apps/api/src/scans/dast/activeEngine.ts';
import { createDastTargetPolicy } from '../apps/api/src/scans/dast/target.ts';

const index = process.argv.indexOf('--path');
const inputPath = index < 0 ? process.env.DATASET_PATH : process.argv[index + 1];
if (typeof inputPath !== 'string' || inputPath.length === 0) throw new Error('Specify --path or DATASET_PATH.');
const dataset = createDatasetService({ datasetPath: resolve(inputPath), providerId: 'filesystem' });
const status = await dataset.status();
const raw = { sast: await dataset.sastPacks(), secrets: await dataset.secretsPacks(), dast: await dataset.dastPacks() };
const loadedIncomplete = ['sast', 'secrets', 'dast'].filter((family) => {
  const report = status.conformance[family];
  return report.enumerationFailures > 0 || report.manifestIssue !== undefined || report.filesSeen !== report.accepted || report.accepted === 0;
});
const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const NOW = '2026-10-30T00:00:00.000Z';
const record = (scanType) => ({ id: 'scan_00000000-0000-4000-8000-000000000003', ownerId: OWNER, projectId: PROJECT,
  scanType, status: 'RUNNING', createdAt: NOW, updatedAt: NOW, startedAt: NOW });
const summary = (count) => ({ rules: count, prepared: 0, batches: 0, completed: 0, detected: 0,
  missed: [], invalidSummaries: 0, invalidFindings: 0, truncated: 0 });
const outcomes = { sast: summary(raw.sast.length), secrets: summary(raw.secrets.length), dast: { ...summary(raw.dast.length), invalidDast: 0, mockRequests: 0 } };

// Pick an actually detectable representative path for each app language family.
const families = new Map();
for (const family of SAST_LANGUAGE_CATALOG) {
  const paths = [...(family.filenames ?? []), ...(family.extensions ?? []).map((ext) => `fixture${ext}`),
    ...(family.shebangs ?? []).map(() => 'fixture')];
  if (family.id === 'github-actions') paths.push('workflow.yml');
  if (family.id === 'matlab') paths.push('fixture.m');
  const prefixes = ['', `#!/usr/bin/env ${family.shebangs?.[0] ?? ''}\n`, 'jobs:\n  runs-on: linux\n', 'function x = f(x)\n% matlab\n'];
  for (const path of paths) for (const prefix of prefixes) {
    if (!families.has(family.id) && isValidSourcePath(path) && detectLanguageFamily(path, prefix)?.family === family.id) {
      families.set(family.id, { path, prefix });
    }
  }
}
const sastCases = [];
for (const entry of raw.sast) {
  const rule = convertSastPackToRule(entry);
  let chosen;
  if (rule !== undefined) for (const family of rule.languages ?? ['javascript']) {
    const fixture = families.get(family);
    if (fixture === undefined) continue;
    for (const test of entry.tests ?? []) {
      if (test.match !== true || typeof test.line !== 'string') continue;
      const content = `${fixture.prefix}${test.line}\n`;
      if (detectLanguageFamily(fixture.path, content)?.family !== family) continue;
      const masked = maskComments(content, family).split('\n')[fixture.prefix.split('\n').length - 1] ?? '';
      if (matchRuleLine(rule, rule.category === 'hardcoded-credential' ? test.line : masked) !== undefined) {
        chosen = { rule, path: `case${sastCases.length}/${fixture.path}`, content }; break;
      }
    }
    if (chosen !== undefined) break;
  }
  if (chosen === undefined) outcomes.sast.missed.push({ id: entry.id, reason: 'no detectable positive fixture' });
  else sastCases.push(chosen);
}
const secretCases = [];
for (const entry of raw.secrets) {
  const rule = convertSecretsPackToRule(entry);
  const test = (entry.tests ?? []).find((item) => item.match === true && typeof item.line === 'string' && rule !== undefined && matchSecretsRuleLine(rule, item.line) !== undefined);
  if (rule === undefined || test === undefined) outcomes.secrets.missed.push({ id: entry.id, reason: 'no convertible positive fixture' });
  else secretCases.push({ rule, path: `case${secretCases.length}/fixture.js`, content: `${test.line}\n` });
}

async function sourceBatches(cases, family) {
  const result = outcomes[family];
  result.prepared = cases.length;
  for (let i = 0; i < cases.length; i += 10) {
    const batch = cases.slice(i, i + 10);
    const snapshot = { ownerId: OWNER, projectId: PROJECT, createdAt: NOW, updatedAt: NOW,
      files: batch.map(({ path, content }) => ({ path, content, bytes: Buffer.byteLength(content) })) };
    const options = { sources: { findByProject: async () => snapshot }, rules: batch.map((item) => item.rule) };
    const engine = family === 'sast' ? createSastEngine(options) : createSecretsEngine(options);
    result.batches += 1;
    const outcome = await engine.execute(record(family === 'sast' ? 'SAST' : 'SECRETS'), { signal: AbortSignal.timeout(30_000) });
    if (outcome.kind !== 'completed') {
      for (const item of batch) result.missed.push({ id: item.rule.id, reason: `engine ${outcome.kind}` });
      continue;
    }
    result.completed += 1;
    if (!isScanResultSummary(outcome.resultSummary)) result.invalidSummaries += 1;
    if (outcome.resultSummary.truncated) result.truncated += 1;
    result.invalidFindings += (outcome.findings ?? []).filter((item) => !isFinding(item)).length;
    for (const item of batch) {
      if ((outcome.findings ?? []).some((finding) => finding.ruleId === item.rule.id && finding.file === item.path)) result.detected += 1;
      else result.missed.push({ id: item.rule.id, reason: 'no finding on representative file' });
    }
  }
}
await sourceBatches(sastCases, 'sast');
await sourceBatches(secretCases, 'secrets');

const dastCases = [];
for (const entry of raw.dast) {
  const rule = convertDastPackToRule(entry);
  const test = (entry.tests ?? []).find((item) => item.match === true && rule !== undefined && evaluatePackDastCheck(rule.check, item.observation));
  if (rule === undefined || test === undefined) outcomes.dast.missed.push({ id: entry.id, reason: 'no convertible positive fixture' });
  else dastCases.push({ rule, observation: test.observation, scheme: test.observation.url.startsWith('http:') ? 'http' : 'https' });
}
outcomes.dast.prepared = dastCases.length;
for (const scheme of ['http', 'https']) {
  const group = dastCases.filter((item) => item.scheme === scheme);
  for (let i = 0; i < group.length; i += 9) {
    const batch = group.slice(i, i + 9), base = `${scheme}://app.example.org/case/`, target = `${scheme}://app.example.org/control/`;
    const links = batch.map((_, j) => `<a href="/case/${j}/">x</a>`).join('');
    const transport = { probe: async (resolved) => {
      outcomes.dast.mockRequests += 1;
      const pathname = new URL(resolved.url).pathname;
      if (pathname === '/control/') return { status: 200, headers: {}, body: links, bodyTruncated: false, elapsedMs: 1 };
      const position = Number(pathname.match(/^\/case\/(\d+)\/$/)?.[1] ?? -1);
      const item = batch[position];
      if (item === undefined) throw new Error('Unexpected mock request.');
      const headers = {};
      for (const [name, value] of Object.entries(item.observation.headers ?? {})) {
        if (typeof value === 'string' || Array.isArray(value)) headers[name.toLowerCase()] = value;
      }
      return { status: item.observation.status, headers, body: String(item.observation.body ?? ''), bodyTruncated: false, elapsedMs: 1 };
    } };
    const targetPolicy = createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
    const engine = createActiveDastEngine({ targetPolicy, transport, throttleMs: 0, maxRequests: batch.length + 1, packRules: batch.map((item) => item.rule) });
    outcomes.dast.batches += 1;
    const outcome = await engine.execute({ ...record('DAST'), dastTargetUrl: target, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal: AbortSignal.timeout(30_000) });
    if (outcome.kind !== 'completed') {
      for (const item of batch) outcomes.dast.missed.push({ id: item.rule.id, reason: `engine ${outcome.kind}` });
      continue;
    }
    outcomes.dast.completed += 1;
    if (!isScanResultSummary(outcome.resultSummary)) outcomes.dast.invalidSummaries += 1;
    if (!isDastResult(outcome.dast)) outcomes.dast.invalidDast += 1;
    if (outcome.resultSummary.truncated) outcomes.dast.truncated += 1;
    outcomes.dast.invalidFindings += (outcome.findings ?? []).filter((item) => !isFinding(item)).length;
    for (const [j, item] of batch.entries()) {
      if ((outcome.findings ?? []).some((finding) => finding.ruleId === item.rule.id && finding.endpoint === `${base}${j}/`)) outcomes.dast.detected += 1;
      else outcomes.dast.missed.push({ id: item.rule.id, reason: 'no finding on representative response' });
    }
  }
}
const incomplete = loadedIncomplete.length > 0 || Object.values(outcomes).some((result) =>
  result.missed.length > 0 || result.invalidSummaries > 0 || result.invalidFindings > 0 || result.truncated > 0 || ('invalidDast' in result && result.invalidDast > 0));
console.log(JSON.stringify({ loadedIncomplete, outcomes, result: incomplete ? 'INCOMPLETE' : 'ALL_REPRESENTATIVE_POSITIVES_DETECTED',
  limitation: 'One positive fixture per rule only; not real-world accuracy, negative coverage, or proof of exploitability.' }, null, 2));
if (incomplete) process.exitCode = 1;
