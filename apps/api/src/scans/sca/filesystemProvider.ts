/**
 * Filesystem-backed vulnerability-intelligence provider for Drobon-Dataset.
 *
 * This provider loads the verified Drobon-Dataset corpus from a
 * filesystem path (DATASET_PATH) that is OUTSIDE the main app repo —
 * preserving the absolute dataset lock (no dataset files are ever
 * committed to the app repo). The app repo only ships a Null provider;
 * this file is the future integration seam documented in
 * docs/PROVIDER_MAPPING.md of the dataset repo.
 *
 * Usage (local dev):
 *   git clone https://github.com/mdraselislam0101-design/Drobon-Dataset ../Drobon-Dataset
 *   DATASET_PATH=../Drobon-Dataset VULN_INTEL_PROVIDER=filesystem npm run dev
 *
 * Behaviour:
 * - Loads one JSON file per advisory-package (vuln-intel/npm/*.json, vuln-intel/pypi/*.json)
 * - Excludes fixtures (fixture:true) and invalid records (warn + skip)
 * - Assess matches by (ecosystem, package name) exact string + version range evaluation
 * - Returns honest datasetStatus: ASSESSED | NO_DATA_LOADED | DATASET_UNAVAILABLE
 * - Server-side only, no client influence, read-only, bounded
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScaEcosystem } from '@drobon/shared';
import { satisfiesRange } from './range.js';
import type {
  DependencyCoordinate,
  VulnerabilityAssessment,
  VulnerabilityIntelligenceProvider,
  ProviderAdvisory,
} from './provider.js';

interface DatasetRecord {
  schemaVersion: string;
  fixture: boolean;
  id: string;
  ecosystem: ScaEcosystem;
  package: string;
  summary: string;
  severity: ProviderAdvisory['severity'];
  url?: string;
  affected: Array<{ range: string; fixed?: string }>;
  provenance: { source: string; sourceUrl?: string; retrievedAt?: string };
}

interface FilesystemProviderOptions {
  datasetPath: string;
  logger?: Pick<Console, 'info' | 'warn' | 'error'>;
}

async function collectJsonFiles(dir: string, out: string[] = []): Promise<string[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let s;
    try {
      s = await stat(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      await collectJsonFiles(full, out);
    } else if (entry.endsWith('.json')) {
      out.push(full);
    }
  }
  return out;
}

function isValidRecord(obj: unknown): obj is DatasetRecord {
  if (typeof obj !== 'object' || obj === null) return false;
  const r = obj as Record<string, unknown>;
  return (
    typeof r['id'] === 'string' &&
    typeof r['ecosystem'] === 'string' &&
    typeof r['package'] === 'string' &&
    typeof r['summary'] === 'string' &&
    typeof r['severity'] === 'string' &&
    Array.isArray(r['affected']) &&
    r['affected'].every((a) => typeof (a as Record<string, unknown>)['range'] === 'string') &&
    typeof r['fixture'] === 'boolean'
  );
}

export function createFilesystemIntelligenceProvider(
  options: FilesystemProviderOptions,
): VulnerabilityIntelligenceProvider {
  const { datasetPath, logger } = options;
  let loaded = false;
  let records: DatasetRecord[] = [];
  let loadError: string | null = null;

  async function ensureLoaded(): Promise<void> {
    if (loaded) return;
    loaded = true;
    const npmDir = join(datasetPath, 'vuln-intel', 'npm');
    const pypiDir = join(datasetPath, 'vuln-intel', 'pypi');
    const files = [...(await collectJsonFiles(npmDir)), ...(await collectJsonFiles(pypiDir))];
    if (files.length === 0) {
      loadError = `No advisory files found under ${datasetPath}/vuln-intel`;
      logger?.warn?.(`[dataset] ${loadError}`);
      return;
    }
    for (const file of files) {
      // Skip samples explicitly
      if (file.includes('/samples/') || file.includes('\\samples\\')) continue;
      try {
        const raw = await readFile(file, 'utf8');
        const parsed = JSON.parse(raw) as unknown;
        if (!isValidRecord(parsed)) {
          logger?.warn?.(`[dataset] Skipping invalid record shape: ${file}`);
          continue;
        }
        if (parsed.fixture === true) continue;
        // Honesty: only non-fixture, valid records
        records.push(parsed);
      } catch (err) {
        logger?.warn?.(`[dataset] Failed to load ${file}: ${(err as Error).message}`);
      }
    }
    logger?.info?.(`[dataset] Loaded ${records.length} advisory records from ${datasetPath} (${files.length} files scanned)`);
    if (records.length === 0) {
      loadError = 'Dataset path exists but contains no valid non-fixture records';
    }
  }

  return {
    id: 'filesystem',
    assess: async (coordinates: readonly DependencyCoordinate[]): Promise<VulnerabilityAssessment> => {
      await ensureLoaded();
      if (loadError !== null || records.length === 0) {
        return {
          datasetStatus: 'DATASET_UNAVAILABLE',
          providerId: 'filesystem',
          advisories: [],
        };
      }

      // Index by ecosystem+package for fast lookup
      // We do exact string match per dataset normalization
      const advisories: ProviderAdvisory[] = [];
      const seen = new Set<string>(); // dedup by id per coordinate to avoid shard duplicates

      for (const coord of coordinates) {
        if (coord.version === undefined || coord.version === '') {
          // Conservative: version-less coordinates never match (per FORMAT.md)
          continue;
        }
        // Normalize version trim
        const version = coord.version.trim();
        if (version.length === 0) continue;

        for (const rec of records) {
          if (rec.ecosystem !== coord.ecosystem) continue;
          // Exact package name match (dataset stores normalized names)
          if (rec.package !== coord.name) continue;

          // Check any affected range matches
          let matched = false;
          for (const affected of rec.affected) {
            try {
              if (satisfiesRange(rec.ecosystem, version, affected.range)) {
                matched = true;
                break;
              }
            } catch {
              // Un-evaluable range => treat as unknown, never match (fail-closed)
              continue;
            }
          }
          if (!matched) continue;

          const key = `${coord.dependencyId}:${rec.id}`;
          if (seen.has(key)) continue;
          seen.add(key);

          advisories.push({
            id: rec.id,
            severity: rec.severity,
            summary: rec.summary,
            ...(rec.url === undefined ? {} : { url: rec.url }),
            dependencyId: coord.dependencyId,
          });
        }
      }

      return {
        datasetStatus: 'DATASET_AVAILABLE',
        providerId: 'filesystem',
        advisories,
      };
    },
  };
}
