#!/usr/bin/env node
/** Strictly score operator-reviewed, redacted v2 observations. No vendor is
 * invoked, and the operator's mapping/completion claims are not verified. */
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cases, manifestDigest } from './fixtures.mjs';
import { scoreExternal } from '../local/score-external.mjs';

export function scoreExpandedExternal(input) {
  return scoreExternal(input, { cases, fixtureManifestSha256: manifestDigest() });
}
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: node benchmarks/accuracy-v2/score-external.mjs /path/to/redacted-observations.json');
  const path = resolve(process.argv[2]);
  if (statSync(path).size > 100_000) throw new Error('Observation document exceeds its size limit');
  console.log(JSON.stringify(scoreExpandedExternal(JSON.parse(readFileSync(path, 'utf8'))), null, 2));
}
