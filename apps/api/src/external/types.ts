/**
 * Dataset status types — honest reporting for every dataset-backed category.
 * Mirrors SCA's ScaDatasetStatus but generalized for packs/knowledge/audiences.
 */

import type { PackReport } from './conformance.js';

export type DatasetAvailability = 'AVAILABLE' | 'UNAVAILABLE' | 'NOT_CONFIGURED';

export interface DatasetCategoryStatus {
  status: DatasetAvailability;
  count: number;
  providerId: string;
  version?: string;
  packId?: string;
  lastLoadedAt?: string;
}

/** Canonical vuln-intel counters (GAP-043): raw files vs. deduplicated identity. */
export interface VulnIntelCounts {
  files: number;
  identityItems: number;
  advisoryIds: number;
}

export interface DatasetPackIdentity {
  packId: string;
  version: string;
}

export interface DatasetConformanceStatus {
  sast: PackReport;
  secrets: PackReport;
  dast: PackReport;
  sca: PackReport;
  /** Declared SCA tests are not evaluated by the app yet (no document evaluator). */
  scaDeclarationEvaluator: 'NOT_IMPLEMENTED';
}

export interface DatasetOverallStatus {
  configured: boolean;
  datasetPath?: string;
  providerId: string; // 'filesystem' | 'none'
  vulnIntel: DatasetCategoryStatus;
  vulnIntelCounts: VulnIntelCounts;
  sastPacks: DatasetCategoryStatus;
  secretsPacks: DatasetCategoryStatus;
  dastPacks: DatasetCategoryStatus;
  scaPacks: DatasetCategoryStatus;
  packs: Partial<Record<'sast' | 'secrets' | 'dast' | 'sca', DatasetPackIdentity>>;
  conformance: DatasetConformanceStatus;
  remediation: DatasetCategoryStatus;
  cwe: DatasetCategoryStatus;
  lessons: DatasetCategoryStatus & { byUserType?: Record<string, number> };
  assessmentTemplates: DatasetCategoryStatus;
  engagementTemplates: DatasetCategoryStatus;
  loadedAt?: string;
}
