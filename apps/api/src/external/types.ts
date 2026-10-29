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
  /**
   * The app owns a declaration-document evaluator: every declared SCA test
   * is executed at load time. `NOT_IMPLEMENTED` remains for older fixtures.
   */
  scaDeclarationEvaluator: 'AVAILABLE' | 'NOT_IMPLEMENTED';
  /** Parser kinds the SCAN-TIME declaration reader can turn into a document (v1: JSON). */
  scaDeclarationScanParsers?: readonly string[];
  /** Potentially eligible rules: supported reader + uploadable basename. Not full format coverage. */
  scaDeclarationScanReachableRules?: number;
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
