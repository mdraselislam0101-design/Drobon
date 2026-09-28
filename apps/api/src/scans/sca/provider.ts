/**
 * The vulnerability-intelligence provider boundary (Pump 9).
 *
 * This is the ONE seam where real external vulnerability data may
 * enter the product — as a SEPARATE, future, server-side dataset
 * integration. The core SCA engine (parsers, inventory, SBOM,
 * orchestration) is COMPLETELY USABLE without any provider data and
 * stays dataset-independent by construction.
 *
 * THE DATASET LOCK (absolute): Pump 9 ships NO dataset. The only
 * registered provider is the Null provider below, whose assessment is
 * always `NO_DATA_LOADED` with zero advisories — which the engine
 * translates to the honest `NOT_ASSESSED` state. The application
 * NEVER fabricates a CVE/GHSA/KEV/EPSS record, a "vulnerable" flag or
 * a risk score without an actual loaded intelligence source.
 *
 * Provider contract rules:
 * - server-side composition only (app.ts); nothing client-facing can
 *   select, register or influence a provider;
 * - `assess` receives dependency COORDINATES (never manifest content)
 *   and returns only VERIFIED records it actually matched;
 * - a provider that cannot answer (dataset missing/unreachable)
 *   reports a dataset status — the scan still completes with the
 *   inventory + SBOM, honestly NOT_ASSESSED.
 */

import type { ScaAdvisory, ScaDatasetStatus, ScaEcosystem } from '@drobon/shared';

/** The identity a provider matches against (no content, no paths). */
export interface DependencyCoordinate {
  ecosystem: ScaEcosystem;
  name: string;
  /** Exact version when a lockfile provided one; absent for ranges. */
  version?: string;
  /** The inventory record this coordinate came from (response wiring). */
  dependencyId: string;
}

/**
 * A verified advisory a provider matched against LOADED data. The
 * engine re-validates every field against the shared ScaAdvisory
 * contract before persisting — a provider cannot smuggle shapes.
 */
export interface ProviderAdvisory {
  id: string;
  severity: ScaAdvisory['severity'];
  summary: string;
  url?: string;
  /** The inventory dependency this advisory matched (dependencyId). */
  dependencyId: string;
}

export interface VulnerabilityAssessment {
  /**
   * Why the assessment came back empty (or didn't):
   * - `NO_DATA_LOADED` — the locked Null provider (no dataset exists);
   * - `DATASET_UNAVAILABLE` — a configured real provider whose data
   *   source was not loaded/reachable at scan time.
   */
  datasetStatus: ScaDatasetStatus;
  /** Which provider produced this assessment ('none' = Null). */
  providerId: string;
  /** Verified matches — EMPTY unless a real loaded dataset matched. */
  advisories: ProviderAdvisory[];
}

export interface VulnerabilityIntelligenceProvider {
  readonly id: string;
  /**
   * Look up dependency identities against the provider's loaded data.
   * Must be read-only, bounded and side-effect free; must NEVER
   * execute target code, fetch packages or install anything.
   */
  assess(coordinates: readonly DependencyCoordinate[]): Promise<VulnerabilityAssessment>;
}

/**
 * The locked default: no dataset exists in this repository, so the
 * answer is always the honest "no data loaded" — zero advisories.
 * This is INTENTIONAL and is NOT a failure state (see docs/SCA.md).
 */
export function createNullIntelligenceProvider(): VulnerabilityIntelligenceProvider {
  return {
    id: 'none',
    assess: async () => ({
      datasetStatus: 'NO_DATA_LOADED',
      providerId: 'none',
      advisories: [],
    }),
  };
}
