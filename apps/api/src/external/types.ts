/**
 * Dataset status types — honest reporting for every dataset-backed category.
 * Mirrors SCA's ScaDatasetStatus but generalized for packs/knowledge/audiences.
 */

import type { PackReport } from './conformance.js';

export type DatasetAvailability = 'AVAILABLE' | 'UNAVAILABLE' | 'NOT_CONFIGURED';

/** Aggregate loading gaps. An enumeration failure means the hidden count is unknown. */
export interface DatasetLoadIssues {
  /** Discovered JSON files; this is not the total when enumeration failed. */
  filesSeen: number;
  /** Discovered files that could not be read or parsed as JSON. */
  unreadableFiles: number;
  /** Records refused by the category's existing identity checks, if any. */
  invalidRecords: number;
  /** Failed directory/entry inspection or refused symbolic links. */
  enumerationFailures: number;
  /** Ambiguous duplicate identities; records remain available for compatibility. */
  duplicateRecords?: number;
  /** Files or subtrees refused because a resource limit was reached. */
  resourceLimitFailures?: number;
}

export interface DatasetCategoryStatus {
  status: DatasetAvailability;
  count: number;
  providerId: string;
  version?: string;
  packId?: string;
  lastLoadedAt?: string;
  /** Optional additive diagnostics; absence is not proof of semantic completeness. */
  incomplete?: true;
  loadIssues?: DatasetLoadIssues;
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
  /** Potentially eligible rules: supported reader + uploadable artifact path. Not full format coverage. */
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
