/**
 * Pack integration helpers — merge embedded DG-* rules with dataset DPK-* packs.
 * Fail-closed: dataset packs are optional; invalid entries are already filtered by packProvider.
 */

import { SAST_RULES } from '../scans/sast/rules.js';
import { SECRETS_RULES } from '../scans/secrets/rules.js';
import { convertSastPackToRule, convertSecretsPackToRule, convertDastPackToRule } from './packProvider.js';
import type { SastRule } from '../scans/sast/rules.js';
import type { SecretsRule } from '../scans/secrets/rules.js';
import type { DastRule } from '../scans/dast/packTypes.js';
import type { DatasetService } from './service.js';

export async function getMergedSastRules(dataset: DatasetService): Promise<readonly SastRule[]> {
  const base = [...SAST_RULES];
  try {
    const raw = await dataset.sastPacks();
    for (const r of raw) {
      const rule = convertSastPackToRule(r);
      if (rule && !base.some(b => b.id === rule.id)) base.push(rule);
    }
  } catch {}
  return base;
}

export async function getMergedSecretsRules(dataset: DatasetService): Promise<readonly SecretsRule[]> {
  const base = [...SECRETS_RULES];
  try {
    const raw = await dataset.secretsPacks();
    for (const r of raw) {
      const rule = convertSecretsPackToRule(r as any);
      if (rule && !base.some(b => b.id === rule.id)) base.push(rule as any);
    }
  } catch {}
  return base as readonly SecretsRule[];
}

export async function getMergedDastRules(dataset: DatasetService): Promise<readonly DastRule[]> {
  try {
    const raw = await dataset.dastPacks();
    const out: DastRule[] = [];
    for (const r of raw) {
      const rule = convertDastPackToRule(r);
      if (rule) out.push(rule);
    }
    return out;
  } catch {
    return [];
  }
}
