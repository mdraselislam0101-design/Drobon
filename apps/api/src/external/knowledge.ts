/**
 * Knowledge loaders — remediation + CWE from dataset.
 * Exposes lookup for assistant, reports, findings.
 */

import type { DatasetService } from './service.js';

export interface RemediationEntry {
  ruleId: string;
  whyItMatters: string;
  actions: string[];
  verification: string;
  standardId?: string;
}

export interface CweEntry {
  id: string;
  name: string;
  summary: string;
  url: string;
}

export async function getRemediationMap(dataset: DatasetService): Promise<Map<string, RemediationEntry>> {
  const map = new Map<string, RemediationEntry>();
  try {
    const raw = await dataset.remediation();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    for (const r of raw as any[]) {
      if (typeof r.ruleId === 'string') map.set(r.ruleId, r as RemediationEntry);
    }
  } catch { /* fail closed: optional path */ }
  return map;
}

export async function getCweMap(dataset: DatasetService): Promise<Map<string, CweEntry>> {
  const map = new Map<string, CweEntry>();
  try {
    const raw = await dataset.cwe();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    for (const r of raw as any[]) {
      if (typeof r.id === 'string') map.set(r.id, r as CweEntry);
    }
  } catch { /* fail closed: optional path */ }
  return map;
}
