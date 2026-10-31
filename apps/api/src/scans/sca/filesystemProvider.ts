/**
 * Filesystem-backed vulnerability-intelligence provider for Drobon-Dataset.
 *
 * This provider loads the verified Drobon-Dataset corpus from a
 * filesystem path (DATASET_PATH) that is OUTSIDE the main app repo —
 * without vendoring the dataset in the app repo. It is an optional,
 * operator-configured alternative to the default Null provider; it does
 * not fetch, refresh or establish completeness of external data.
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

import { lstat, opendir } from 'node:fs/promises';
import { join } from 'node:path';
import { FINDING_SEVERITIES, type ScaEcosystem } from '@drobon/shared';
import { satisfiesRange } from './range.js';
import { createJsonByteBudget, readBoundedJsonFile } from '../../external/boundedJson.js';
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

const DEFAULT_INTEL_LIMITS = {
  maxEntries: 20_000,
  maxFiles: 10_000,
  maxDepth: 12,
  maxFileBytes: 512 * 1024,
  maxTotalBytes: 32 * 1024 * 1024,
} as const;

type IntelLimits = { [K in keyof typeof DEFAULT_INTEL_LIMITS]: number };

interface FilesystemProviderOptions {
  datasetPath: string;
  logger?: Pick<Console, 'info' | 'warn' | 'error'>;
  /** Internal test seam can lower limits, never raise production ceilings. */
  limits?: Partial<IntelLimits>;
}

function limitsFor(overrides: Partial<IntelLimits> | undefined): IntelLimits {
  const limit = (key: keyof IntelLimits): number => {
    const value = overrides?.[key];
    return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
      ? Math.min(value, DEFAULT_INTEL_LIMITS[key])
      : DEFAULT_INTEL_LIMITS[key];
  };
  return { maxEntries: limit('maxEntries'), maxFiles: limit('maxFiles'), maxDepth: limit('maxDepth'),
    maxFileBytes: limit('maxFileBytes'), maxTotalBytes: limit('maxTotalBytes') };
}

interface EnumerationState {
  files: string[];
  entries: number;
  incomplete: boolean;
  halted: boolean;
}

async function collectJsonFiles(dir: string, limits: IntelLimits, state: EnumerationState, depth = 0): Promise<void> {
  if (state.halted) return;
  try {
    const info = await lstat(dir);
    if (info.isSymbolicLink() || !info.isDirectory()) { state.incomplete = true; return; }
  } catch (error) {
    // Missing optional ecosystem directories simply provide no records.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || depth > 0) state.incomplete = true;
    return;
  }
  try {
    const entries = await opendir(dir);
    for await (const entry of entries) {
      if (state.halted) break;
      state.entries += 1;
      if (state.entries > limits.maxEntries) { state.incomplete = true; state.halted = true; break; }
      if (entry.name === 'samples') continue;
      const full = join(dir, entry.name);
      let info;
      try { info = await lstat(full); } catch { state.incomplete = true; continue; }
      if (info.isSymbolicLink()) { state.incomplete = true; continue; }
      if (info.isDirectory()) {
        if (depth >= limits.maxDepth) state.incomplete = true;
        else await collectJsonFiles(full, limits, state, depth + 1);
      } else if (info.isFile() && entry.name.endsWith('.json')) {
        if (state.files.length >= limits.maxFiles) { state.incomplete = true; state.halted = true; break; }
        state.files.push(full);
      }
    }
  } catch {
    state.incomplete = true;
  }
}

function isValidRecord(obj: unknown): obj is DatasetRecord {
  if (typeof obj !== 'object' || obj === null) return false;
  const r = obj as Record<string, unknown>;
  return (
    typeof r['id'] === 'string' && r['id'].trim().length > 0 &&
    (r['ecosystem'] === 'npm' || r['ecosystem'] === 'pypi') &&
    typeof r['package'] === 'string' && r['package'].trim().length > 0 &&
    typeof r['summary'] === 'string' && r['summary'].trim().length > 0 &&
    typeof r['severity'] === 'string' && (FINDING_SEVERITIES as readonly string[]).includes(r['severity']) &&
    (r['url'] === undefined || typeof r['url'] === 'string') &&
    Array.isArray(r['affected']) && r['affected'].length > 0 &&
    r['affected'].every((a: unknown) => typeof a === 'object' && a !== null &&
      typeof (a as Record<string, unknown>)['range'] === 'string' &&
      ((a as Record<string, string>)['range'] ?? '').trim().length > 0) &&
    typeof r['fixture'] === 'boolean'
  );
}

export function createFilesystemIntelligenceProvider(
  options: FilesystemProviderOptions,
): VulnerabilityIntelligenceProvider {
  const { datasetPath, logger } = options;
  const limits = limitsFor(options.limits);
  let loadPromise: Promise<void> | undefined;
  const records: DatasetRecord[] = [];
  const recordsByPackage = new Map<string, DatasetRecord[]>();
  let loadError: string | null = null;
  let skippedRecord = false;

  async function loadRecords(): Promise<void> {
    const intelDir = join(datasetPath, 'vuln-intel');
    try {
      const info = await lstat(intelDir);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('advisory root is not a regular directory');
    } catch {
      loadError = 'Advisory root is missing, inaccessible or a symlink';
      logger?.warn?.(`[dataset] ${loadError}`);
      return;
    }
    const state: EnumerationState = { files: [], entries: 0, incomplete: false, halted: false };
    await collectJsonFiles(join(intelDir, 'npm'), limits, state);
    await collectJsonFiles(join(intelDir, 'pypi'), limits, state);
    skippedRecord = state.incomplete;
    const files = state.files.sort();
    if (files.length === 0) {
      loadError = 'No accessible advisory files found';
      logger?.warn?.(`[dataset] ${loadError}`);
      return;
    }
    const budget = createJsonByteBudget(limits.maxTotalBytes);
    for (const file of files) {
      try {
        const parsed = await readBoundedJsonFile(file, { maxFileBytes: limits.maxFileBytes, budget });
        if (!isValidRecord(parsed)) {
          skippedRecord = true;
          // A configured path or filename can contain arbitrary sensitive text.
          logger?.warn?.('[dataset] Skipping invalid record shape (details withheld)');
          continue;
        }
        if (parsed.fixture === true) continue;
        // Honesty: only non-fixture, valid records. Index once per loaded
        // dataset rather than scanning the entire corpus for each package.
        records.push(parsed);
        const key = `${parsed.ecosystem}\n${parsed.package}`;
        const bucket = recordsByPackage.get(key) ?? [];
        bucket.push(parsed);
        recordsByPackage.set(key, bucket);
      } catch {
        skippedRecord = true;
        // Parser and I/O errors may echo raw content, paths or credentials.
        logger?.warn?.('[dataset] Failed to load advisory record (details withheld)');
      }
    }
    logger?.info?.(`[dataset] Loaded ${records.length} advisory records (${files.length} files scanned)`);
    if (records.length === 0) {
      loadError = 'Dataset path exists but contains no valid non-fixture records';
    }
  }

  // Concurrent scans share one in-flight load. Marking the provider loaded
  // before asynchronous reads finish would transiently report no data.
  function ensureLoaded(): Promise<void> {
    loadPromise ??= loadRecords();
    return loadPromise;
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
      let incomplete = skippedRecord;

      for (const coord of coordinates) {
        if (coord.version === undefined || coord.version === '') {
          // A range or absent version is not a checked installed version.
          incomplete = true;
          continue;
        }
        // Normalize version trim
        const version = coord.version.trim();
        if (version.length === 0) { incomplete = true; continue; }
        // Exact package name match (dataset stores normalized names).
        const packageRecords = recordsByPackage.get(`${coord.ecosystem}\n${coord.name}`) ?? [];
        if (packageRecords.length === 0) incomplete = true;
        for (const rec of packageRecords) {
          // Check any affected range matches
          let matched = false;
          for (const affected of rec.affected) {
            try {
              if (satisfiesRange(rec.ecosystem, version, affected.range)) {
                matched = true;
                break;
              }
            } catch {
              // A non-evaluable version/range is unknown, never a clean result.
              incomplete = true;
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
        ...(incomplete ? { incomplete: true } : {}),
      };
    },
  };
}
