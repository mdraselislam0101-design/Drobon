/**
 * Connect conformance-validated dataset packs to the scanner rule types.
 * Conversion errors must reach the scanner, so it can report partial coverage
 * instead of silently presenting an empty or incomplete rule set as success.
 */

import { SAST_RULES, type SastRule } from '../scans/sast/rules.js';
import { SECRETS_RULES, type SecretsRule } from '../scans/secrets/rules.js';
import type { DastRule } from '../scans/dast/packTypes.js';
import { convertSastPackToRule, convertSecretsPackToRule, convertDastPackToRule } from './packProvider.js';
import type { DatasetService } from './service.js';

function appendMapped<T extends { id: string }>(base: readonly T[], raw: readonly unknown[], convert: (entry: unknown) => T | undefined): T[] {
  const result = [...base];
  const ids = new Set(result.map((rule) => rule.id));
  for (const entry of raw) {
    const rule = convert(entry);
    if (rule === undefined || ids.has(rule.id)) {
      throw new Error('The configured dataset pack contains an unmappable or duplicate rule.');
    }
    ids.add(rule.id);
    result.push(rule);
  }
  return result;
}

export async function getMergedSastRules(dataset: DatasetService): Promise<readonly SastRule[]> {
  return appendMapped(SAST_RULES, await dataset.sastPacks(), convertSastPackToRule);
}

export async function getMergedSecretsRules(dataset: DatasetService): Promise<readonly SecretsRule[]> {
  return appendMapped(SECRETS_RULES, await dataset.secretsPacks(), convertSecretsPackToRule);
}

export async function getMergedDastRules(dataset: DatasetService): Promise<readonly DastRule[]> {
  return appendMapped([], await dataset.dastPacks(), convertDastPackToRule);
}

/** Rejected files make a configured scan partial even when other rules loaded. */
export async function hasRejectedPackRules(dataset: DatasetService, family: 'sast' | 'secrets' | 'dast' | 'sca'): Promise<boolean> {
  // Some callers inject a minimal dataset double; production services always
  // expose conformance(). A missing double method must not fabricate a report.
  if (typeof dataset.conformance !== 'function') return false;
  const report = (await dataset.conformance())[family];
  return report.accepted < report.filesSeen || report.enumerationFailures > 0 || report.manifestIssue !== undefined;
}
