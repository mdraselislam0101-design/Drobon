/** Score only an operator's redacted, case-mapped observations; never raw vendor reports. */
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cases, fixtureManifestDigest } from './fixtures.mjs';
import { scoreCases } from './scoring.mjs';

const PRODUCTS = new Set(['BURP_SUITE_PROFESSIONAL', 'INVICTI', 'SNYK', 'XBOW', 'HORIZON3_NODEZERO', 'PENTERA']);
const REASONS = new Set(['NOT_RUN', 'NOT_APPLICABLE', 'NO_LICENSE', 'NO_AUTHORIZATION', 'FAILED', 'TIMEOUT',
  'PARTIAL', 'UNMAPPED', 'EVIDENCE_NOT_REVIEWED', 'OTHER']);
const STATUSES = new Set(['DETECTED', 'NOT_DETECTED', 'UNASSESSED']);
const COVERAGE = new Set(['COMPLETE', 'PARTIAL', 'NONE']);
function exactKeys(object, keys) {
  return typeof object === 'object' && object !== null && !Array.isArray(object) &&
    Object.keys(object).every((key) => keys.includes(key));
}

export function scoreExternal(input, corpus = { cases, fixtureManifestSha256: fixtureManifestDigest() }) {
  if (!Array.isArray(corpus.cases) || typeof corpus.fixtureManifestSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(corpus.fixtureManifestSha256)) {
    throw new Error('Invalid trusted corpus');
  }
  if (!exactKeys(input, ['schemaVersion', 'product', 'version', 'executed', 'fixtureManifestSha256', 'unmappedAlertCount', 'observations']) ||
      input.schemaVersion !== 'drobon.vendor-observations/v1' || !PRODUCTS.has(input.product) ||
      (input.version !== null && (typeof input.version !== 'string' || !/^[A-Za-z0-9._+-]{1,60}$/.test(input.version))) ||
      typeof input.executed !== 'boolean' || (input.executed && input.version === null) || input.fixtureManifestSha256 !== corpus.fixtureManifestSha256 ||
      !(input.unmappedAlertCount === null || (Number.isSafeInteger(input.unmappedAlertCount) && input.unmappedAlertCount >= 0)) ||
      (!input.executed && input.unmappedAlertCount !== null) ||
      !Array.isArray(input.observations) || input.observations.length > corpus.cases.length) {
    throw new Error('Invalid redacted vendor observation document or fixture digest');
  }
  const observations = input.observations.map((entry) => {
    if (!exactKeys(entry, ['id', 'status', 'coverage', 'reasonCode', 'mappingReviewed', 'evidenceReviewed', 'matchingFindings']) ||
        typeof entry.id !== 'string' || !STATUSES.has(entry.status) || !COVERAGE.has(entry.coverage) ||
        typeof entry.mappingReviewed !== 'boolean' || typeof entry.evidenceReviewed !== 'boolean' ||
        !Number.isSafeInteger(entry.matchingFindings) || entry.matchingFindings < 0 ||
        (entry.status === 'UNASSESSED' ? !REASONS.has(entry.reasonCode) : entry.reasonCode !== null)) {
      throw new Error('Invalid case observation');
    }
    if (!input.executed && (entry.status !== 'UNASSESSED' || entry.coverage !== 'NONE' || entry.matchingFindings !== 0)) {
      throw new Error('An unrun product cannot have assessed cases, coverage or findings');
    }
    if (entry.status === 'NOT_DETECTED' && (entry.coverage !== 'COMPLETE' || entry.matchingFindings !== 0 ||
        !entry.mappingReviewed || !entry.evidenceReviewed)) {
      throw new Error('A negative requires reviewed scope and completion, complete coverage and zero mapped findings');
    }
    if (entry.status === 'DETECTED' && (entry.coverage === 'NONE' || !entry.mappingReviewed || !entry.evidenceReviewed || entry.matchingFindings < 1)) {
      throw new Error('A detection requires reviewed mapping and evidence');
    }
    return { id: entry.id, status: entry.status, reason: entry.reasonCode, matchingFindings: entry.matchingFindings };
  });
  return { schemaVersion: 'drobon.vendor-score/v1', product: input.product, version: input.version,
    executed: input.executed, fixtureManifestSha256: input.fixtureManifestSha256, unmappedAlertCount: input.unmappedAlertCount,
    groundTruthReview: 'AUTHOR_DEFINED_NOT_INDEPENDENTLY_REVIEWED',
    caveat: 'Case-level provisional scores only; no alert precision, autonomous parity, severity accuracy or product ranking is established.',
    scores: scoreCases(corpus.cases, observations) };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: node benchmarks/local/score-external.mjs /path/to/redacted-observations.json');
  const path = resolve(process.argv[2]);
  if (statSync(path).size > 100_000) throw new Error('Observation document exceeds its size limit');
  const result = scoreExternal(JSON.parse(readFileSync(path, 'utf8')));
  console.log(JSON.stringify(result, null, 2));
}
