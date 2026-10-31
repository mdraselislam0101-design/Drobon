#!/usr/bin/env node
/** Reproduce each frozen local case in a separate process. No sockets to a target,
 * no vendor products, no customer code and no independently reviewed labels.
 * Output is sanitized JSON; fixture contents and secret values are not printed. */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { cases, fixtureManifest, fixtureManifestDigest } from './fixtures.mjs';
import { scoreCases } from './scoring.mjs';

const runner = fileURLToPath(new URL('./run-drobon.mjs', import.meta.url));
const digest = fixtureManifestDigest();
const observations = [];
for (const item of cases) {
  const child = spawnSync(process.execPath, ['--import', 'tsx', runner], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)),
    env: { ...process.env, DROBON_BENCHMARK_CASE_ID: item.id },
    encoding: 'utf8', timeout: 60_000, maxBuffer: 1_000_000,
  });
  if (child.status !== 0 || child.error) throw new Error(`Isolated run failed: ${item.id}`);
  const result = JSON.parse(child.stdout);
  if (result.fixtureManifestSha256 !== digest || result.cases.length !== 1 || result.cases[0].id !== item.id ||
      result.observations.length !== 1 || result.observations[0].id !== item.id ||
      result.scores.rows.length !== 1 || result.scores.rows[0].id !== item.id || result.observations[0].internalError) {
    throw new Error(`Invalid isolated result: ${item.id}`);
  }
  observations.push(result.observations[0]);
}
console.log(JSON.stringify({ schemaVersion: 'drobon.isolated-reproduction/v1',
  fixtureManifestSha256: digest, node: process.version, separateProcesses: observations.length,
  groundTruthReview: 'AUTHOR_DEFINED_NOT_INDEPENDENTLY_REVIEWED',
  scope: 'Existing engines, test-only rules, mock DAST transport and declaration-only SCA. No vendor comparison.',
  cases: fixtureManifest(), observations, scores: scoreCases(cases, observations) }, null, 2));
