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
  /** Optional, untrusted dataset content; the resolver validates it separately. */
  example?: unknown;
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
    for (const entry of raw) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const item = entry as Record<string, unknown>;
      if (typeof item['ruleId'] === 'string') map.set(item['ruleId'], entry as RemediationEntry);
    }
  } catch { /* fail closed: optional path */ }
  return map;
}

export async function getCweMap(dataset: DatasetService): Promise<Map<string, CweEntry>> {
  const map = new Map<string, CweEntry>();
  try {
    const raw = await dataset.cwe();
    for (const entry of raw) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const item = entry as Record<string, unknown>;
      if (typeof item['id'] === 'string') map.set(item['id'], entry as CweEntry);
    }
  } catch { /* fail closed: optional path */ }
  return map;
}
