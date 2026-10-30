/**
 * Dataset guidance resolver — one cached lookup per process.
 *
 * The app never bundles remediation text. `getRemediationMap()` reads the
 * external checkout at runtime; the returned lookup is shared by the
 * assistant, finding-detail and report surfaces so they cannot disagree.
 */

import type { DatasetService } from './service.js';
import { getRemediationMap, type RemediationEntry } from './knowledge.js';

export type GuidanceLookup = (ruleId: string) => Promise<RemediationEntry | undefined>;

export function createGuidanceLookup(dataset: DatasetService): GuidanceLookup {
  let pending: Promise<Map<string, RemediationEntry>> | undefined;
  return async (ruleId: string) => {
    if (typeof ruleId !== 'string' || ruleId.length === 0 || ruleId.length > 64) return undefined;
    if (pending === undefined) pending = getRemediationMap(dataset).catch(() => new Map<string, RemediationEntry>());
    return (await pending).get(ruleId);
  };
}
