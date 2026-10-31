#!/usr/bin/env node
/** Reuse the production-engine observation helper with the expanded synthetic
 * corpus and test-only rules. DAST transport is mock; no target is contacted. */
import { assertBenchmarkScaRuleUnchanged, observe } from '../local/run-drobon.mjs';
import { scoreCases } from '../local/scoring.mjs';
import { cases, manifest, manifestDigest, syntheticSecrets } from './fixtures.mjs';
import { dastRules, scaRules } from './rules.mjs';

const inheritedScaRuleSha256 = assertBenchmarkScaRuleUnchanged();
const requestedCase = process.env.DROBON_BENCHMARK_CASE_ID;
const selected = requestedCase === undefined ? cases : cases.filter((item) => item.id === requestedCase);
if (selected.length === 0) throw new Error('Unknown benchmark case ID');
const observations = [];
for (const item of selected) {
  try { observations.push(await observe(item, { scaRules, dastRules, syntheticSecrets })); }
  catch { observations.push({ id: item.id, status: 'UNASSESSED', reason: 'Unexpected local benchmark error.', internalError: true }); }
}
const output = { schemaVersion: 'drobon.local-benchmark/v2', fixtureManifestSha256: manifestDigest(), inheritedScaRuleSha256, node: process.version,
  groundTruthReview: 'AUTHOR_DEFINED_NOT_INDEPENDENTLY_REVIEWED',
  scope: 'Existing Drobon engines, test-only rules, mock DAST transport, declaration-only SCA; not vendor comparison.',
  cases: manifest().cases.filter((item) => selected.some((entry) => entry.id === item.id)),
  observations, scores: scoreCases(selected, observations) };
console.log(JSON.stringify(output, null, 2));
if (observations.some((entry) => entry.internalError)) process.exitCode = 1;
