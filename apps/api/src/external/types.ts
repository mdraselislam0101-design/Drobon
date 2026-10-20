/**
 * Dataset status types — honest reporting for every dataset-backed category.
 * Mirrors SCA's ScaDatasetStatus but generalized for packs/knowledge/audiences.
 */

export type DatasetAvailability = 'AVAILABLE' | 'UNAVAILABLE' | 'NOT_CONFIGURED';

export interface DatasetCategoryStatus {
  status: DatasetAvailability;
  count: number;
  providerId: string;
  version?: string;
  lastLoadedAt?: string;
}

export interface DatasetOverallStatus {
  configured: boolean;
  datasetPath?: string;
  providerId: string; // 'filesystem' | 'none'
  vulnIntel: DatasetCategoryStatus;
  sastPacks: DatasetCategoryStatus;
  secretsPacks: DatasetCategoryStatus;
  dastPacks: DatasetCategoryStatus;
  remediation: DatasetCategoryStatus;
  cwe: DatasetCategoryStatus;
  lessons: DatasetCategoryStatus & { byUserType?: Record<string, number> };
  assessmentTemplates: DatasetCategoryStatus;
  engagementTemplates: DatasetCategoryStatus;
  loadedAt?: string;
}
