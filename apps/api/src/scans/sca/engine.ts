/**
 * THE REAL SCA ENGINE (Pump 9).
 *
 * Software-composition analysis of the project's source snapshot:
 *
 *   snapshot → manifest discovery (bounded) → defensive parsers →
 *   normalized inventory (direct/transitive, declared/resolved) →
 *   deterministic CycloneDX SBOM → optional intelligence provider →
 *   honest assessment
 *
 * SECURITY BOUNDARIES (all tested):
 * - READ-ONLY, NO EXECUTION: the engine reads manifest TEXT. It never
 *   runs npm/pip/setup.py/lifecycle scripts/shell, never downloads or
 *   installs packages, never executes target code — a manifest with
 *   `"postinstall": "touch /tmp/…"` is DATA and the marker file is
 *   never created (proven by tests).
 * - PATH CONTAINMENT: single shared path policy (see sources.ts) is
 *   re-validated inside the engine; a traversal-shaped stored path
 *   fails the scan closed (SCA_INPUT_INVALID). No filesystem access
 *   exists at all — the snapshot is a content tree.
 * - RESOURCE LIMITS: manifest count, per-manifest bytes, total
 *   manifest bytes, inventory size and a processing deadline are all
 *   hard-capped; breaches fail closed with closed-vocabulary codes.
 * - DATASET HONESTY: with no vulnerability intelligence loaded (the
 *   Pump 9 state, enforced by the dataset lock), the scan COMPLETES
 *   with the full inventory + SBOM and `NOT_ASSESSED` /
 *   `NO_DATA_LOADED` — zero fabricated advisories. The scan is NOT
 *   marked broken: the optional dataset being absent is designed.
 */

import {
  isValidSourcePath,
  SCA_MAX_DEPENDENCIES_PER_SCAN,
  SCA_MAX_MANIFESTS_PER_SCAN,
  type ScaAdvisory,
  type ScaManifestResult,
  type ScaResult,
  type ScaSummary,
  type ScanResultSummary,
} from '@drobon/shared';
import type { EngineOutcome, ScanEngine, ScanEngineContext } from '../engines.js';
import type { ScanRecord } from '../store.js';
import type { SourceSnapshotRecord } from '../sources.js';
import {
  buildInventory,
  buildSbom,
  parsePackageJson,
  parsePackageLock,
  parsePyprojectToml,
  parseRequirementsTxt,
  type DiscoveredManifest,
} from './inventory.js';
import {
  createNullIntelligenceProvider,
  type VulnerabilityIntelligenceProvider,
} from './provider.js';
import { evaluateScaDeclarations } from './declarationScan.js';
import type { DatasetService } from '../../external/service.js';

/** The engine's hard resource limits (defaults; injectable for tests). */
export interface ScaLimits {
  /** Maximum manifests analyzed per scan. */
  maxManifests: number;
  /** Maximum UTF-8 bytes of one manifest. */
  maxManifestBytes: number;
  /** Maximum total manifest bytes per scan. */
  maxTotalBytes: number;
  /** Maximum dependencies persisted per scan. */
  maxDependencies: number;
  /** Engine processing deadline in milliseconds. */
  deadlineMs: number;
}

export const DEFAULT_SCA_LIMITS: ScaLimits = {
  maxManifests: SCA_MAX_MANIFESTS_PER_SCAN,
  maxManifestBytes: 262_144, // 256 KiB per manifest
  maxTotalBytes: 786_432, // 768 KiB per scan (matches the upload cap)
  maxDependencies: SCA_MAX_DEPENDENCIES_PER_SCAN,
  deadlineMs: 10_000, // Well inside the processor's 30s engine timeout.
};

/** Manifest file names the engine looks for (exact, case-sensitive). */
export const SCA_MANIFEST_FILE_NAMES = [
  'package.json',
  'package-lock.json',
  'requirements.txt',
  'pyproject.toml',
] as const;

/**
 * Directory segments whose manifests are NOT project manifests: a
 * package.json inside node_modules describes an INSTALLED dependency,
 * not a declaration (and vendored/build trees are noise). The SAST
 * ignore list, reused for the same reason.
 */
export const SCA_IGNORED_DIR_SEGMENTS = [
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  'target',
  'cache',
] as const;

/** The minimal surface the engine needs from the source store. */
export interface SourceSnapshotProvider {
  findByProject(projectId: string): Promise<SourceSnapshotRecord | undefined>;
}

export interface ScaEngineOptions {
  sources: SourceSnapshotProvider;
  /** The intelligence provider (defaults to the locked Null provider). */
  provider?: VulnerabilityIntelligenceProvider;
  /**
   * Optional dataset service for SCA DECLARATION rules (Pump 14). Additive:
   * with no dataset configured the engine behaves exactly as before — zero
   * declaration findings, honest zero coverage counters.
   */
  dataset?: DatasetService;
  /** Override the default limits (tests). */
  limits?: Partial<ScaLimits>;
  /** Clock for the deadline (tests). */
  now?: () => number;
}

interface DiscoveredManifests {
  kind: 'ok';
  manifests: DiscoveredManifest[];
  skipped: number;
}

type DiscoveryFailure =
  | { kind: 'input-invalid' }
  | { kind: 'manifest-limit' }
  | { kind: 'too-large' };

function discover(snapshot: SourceSnapshotRecord, limits: ScaLimits): DiscoveredManifests | DiscoveryFailure {
  const manifests: DiscoveredManifest[] = [];
  let skipped = 0;
  let totalBytes = 0;
  const files = [...snapshot.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const file of files) {
    // PATH CONTAINMENT (defense in depth): re-validate every path
    // inside the engine — a failure here means corrupt state, and the
    // scan fails CLOSED.
    if (!isValidSourcePath(file.path)) {
      return { kind: 'input-invalid' };
    }
    const base = file.path.split('/').pop() ?? file.path;
    if (!(SCA_MANIFEST_FILE_NAMES as readonly string[]).includes(base)) {
      continue; // Not a manifest: not our file (SAST's territory).
    }
    const segments = file.path.split('/');
    segments.pop();
    if (
      segments.some((segment) =>
        (SCA_IGNORED_DIR_SEGMENTS as readonly string[]).includes(segment.toLowerCase()),
      )
    ) {
      skipped += 1;
      continue;
    }
    if (
      manifests.length >= limits.maxManifests ||
      Buffer.byteLength(file.content, 'utf8') > limits.maxManifestBytes
    ) {
      if (manifests.length >= limits.maxManifests) {
        return { kind: 'manifest-limit' };
      }
      skipped += 1; // Oversize manifest: skipped and counted, honest.
      continue;
    }
    // Binary-looking content is not a parseable manifest.
    if (file.content.includes('\u0000')) {
      skipped += 1;
      continue;
    }
    totalBytes += Buffer.byteLength(file.content, 'utf8');
    if (totalBytes > limits.maxTotalBytes) {
      return { kind: 'too-large' };
    }
    manifests.push({ path: file.path, content: file.content });
  }
  return { kind: 'ok', manifests, skipped };
}

/**
 * Re-validate a provider advisory against the shared contract and the
 * actual inventory: a provider can only surface records for
 * dependencies that exist in THIS scan, with bounded, well-formed
 * fields. Anything else is dropped (fail closed, never persisted).
 */
function sanitizeAdvisory(
  advisory: unknown,
  dependencyById: Map<string, { ecosystem: ScaAdvisory['ecosystem']; name: string; version?: string }>,
): ScaAdvisory | undefined {
  if (typeof advisory !== 'object' || advisory === null) {
    return undefined;
  }
  const record = advisory as Record<string, unknown>;
  const dependencyId = record['dependencyId'];
  if (typeof dependencyId !== 'string') {
    return undefined;
  }
  const dependency = dependencyById.get(dependencyId);
  if (dependency === undefined) {
    return undefined; // Advisory for a dependency not in this scan.
  }
  const id = record['id'];
  const severity = record['severity'];
  const summary = record['summary'];
  const url = record['url'];
  if (
    typeof id !== 'string' ||
    id.length === 0 ||
    id.length > 100 ||
    typeof summary !== 'string' ||
    summary.length === 0 ||
    summary.length > 400 ||
    typeof severity !== 'string' ||
    !['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)
  ) {
    return undefined;
  }
  if (url !== undefined && (typeof url !== 'string' || url.length > 400)) {
    return undefined;
  }
  return {
    id,
    severity: severity as ScaAdvisory['severity'],
    summary,
    ...(url === undefined ? {} : { url }),
    dependencyId,
    ecosystem: dependency.ecosystem,
    name: dependency.name,
    ...(dependency.version === undefined ? {} : { version: dependency.version }),
  };
}

/**
 * Build the real SCA engine and register it for the SCA scan type.
 * Side-effect bounded: reads the snapshot, parses manifests, consults
 * the (locked) provider — never mutates job state (the processor owns
 * transitions), never writes anywhere, never executes target code.
 */
export function createScaEngine(options: ScaEngineOptions): ScanEngine {
  const sources = options.sources;
  const provider = options.provider ?? createNullIntelligenceProvider();
  const limits: ScaLimits = { ...DEFAULT_SCA_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;

  return {
    scanType: 'SCA',
    execute: async (record: ScanRecord, ctx: ScanEngineContext): Promise<EngineOutcome> => {
      const snapshot = await sources.findByProject(record.projectId);
      if (snapshot === undefined) {
        return {
          kind: 'failed',
          failureCode: 'SCA_TARGET_NOT_FOUND',
          failureMessage:
            'No source snapshot is attached to this project. Upload source files before requesting an SCA scan.',
        };
      }
      if (snapshot.ownerId !== record.ownerId) {
        return {
          kind: 'failed',
          failureCode: 'SCA_INPUT_INVALID',
          failureMessage: 'The scan target is inconsistent with the scan owner.',
        };
      }

      const discovery = discover(snapshot, limits);
      if (discovery.kind === 'input-invalid') {
        return {
          kind: 'failed',
          failureCode: 'SCA_INPUT_INVALID',
          failureMessage: 'The scan target failed validation.',
        };
      }
      if (discovery.kind === 'manifest-limit') {
        return {
          kind: 'failed',
          failureCode: 'SCA_MANIFEST_LIMIT_EXCEEDED',
          failureMessage: `The snapshot has more manifests than the SCA limit (${limits.maxManifests}).`,
        };
      }
      if (discovery.kind === 'too-large') {
        return {
          kind: 'failed',
          failureCode: 'SCA_TARGET_TOO_LARGE',
          failureMessage: `The manifests exceed the SCA scan size limit (${limits.maxTotalBytes} bytes).`,
        };
      }

      const deadline = now() + limits.deadlineMs;
      // Parse + merge + SBOM are synchronous; the deadline is checked
      // at the boundaries (before/after the parse phase) — the parse
      // itself is linear in bounded input.
      if (now() > deadline || ctx.signal.aborted) {
        return deadlineFailure();
      }

      const inventory = buildInventory(discovery.manifests, limits.maxDependencies);
      const sbom = buildSbom(inventory);

      // Pump 14 (main-app only): evaluate the dataset's dependency-DECLARATION
      // rules against the same read-only snapshot. This is additive — no
      // dataset configured means no rules and therefore no declaration
      // findings; inventory/SBOM/advisory behaviour is unchanged.
      const declarationRules = options.dataset?.configured === true
        ? await options.dataset.scaPacks()
        : [];
      const declarations = evaluateScaDeclarations({
        rawRules: declarationRules,
        files: snapshot.files.map((file) => ({ path: file.path, content: file.content })),
        record,
        shouldStop: () => now() > deadline || ctx.signal.aborted,
      });

      // Manifest results for the response (paths + counts + bounded
      // notes — never manifest content).
      const manifestResults: ScaManifestResult[] = discovery.manifests.map((manifest) => {
        const base = manifest.path.split('/').pop() ?? manifest.path;
        const ecosystem = base === 'requirements.txt' || base === 'pyproject.toml' ? 'pypi' : 'npm';
        const parsed = parseForManifestResult(manifest);
        return parsed === undefined
          ? { path: manifest.path, ecosystem, status: 'ANALYZED' as const, dependencyCount: 0 }
          : { ...parsed, ecosystem };
      });

      // Consult the (optional) intelligence provider.
      // Version for matching: prefer the lockfile/resolved version when present;
      // fall back to a declared version that looks like a concrete version
      // (exact pins such as "6.2.4" or "5.2.16" — not range specs like
      // "^6.2.4" or ">=1.0"). This keeps package.json-only projects
      // honest without guessing ranges, and mirrors the SBOM version rule.
      const coordinates = inventory.dependencies.map((dependency) => {
        const versionForAssessment =
          dependency.resolvedVersion ??
          (dependency.declaredVersion !== undefined &&
          /^[0-9][A-Za-z0-9._+-]*$/.test(dependency.declaredVersion)
            ? dependency.declaredVersion
            : undefined);
        return {
          ecosystem: dependency.ecosystem,
          name: dependency.name,
          ...(versionForAssessment === undefined ? {} : { version: versionForAssessment }),
          dependencyId: dependency.dependencyId,
        };
      });
      const assessment = await provider.assess(coordinates);

      const dependencyById = new Map(
        inventory.dependencies.map((dependency) => {
          const versionForAdvisory =
            dependency.resolvedVersion ??
            (dependency.declaredVersion !== undefined &&
            /^[0-9][A-Za-z0-9._+-]*$/.test(dependency.declaredVersion)
              ? dependency.declaredVersion
              : undefined);
          return [
            dependency.dependencyId,
            {
              ecosystem: dependency.ecosystem,
              name: dependency.name,
              ...(versionForAdvisory === undefined ? {} : { version: versionForAdvisory }),
            },
          ];
        }),
      );
      const advisories: ScaAdvisory[] = [];
      for (const advisory of assessment.advisories) {
        const sanitized = sanitizeAdvisory(advisory, dependencyById);
        if (sanitized !== undefined) {
          advisories.push(sanitized);
        }
      }
      // Dedupe provider advisories deterministically (id+dependencyId).
      const seenAdvisory = new Set<string>();
      const uniqueAdvisories = advisories.filter((advisory) => {
        const key = `${advisory.id}\n${advisory.dependencyId}`;
        if (seenAdvisory.has(key)) {
          return false;
        }
        seenAdvisory.add(key);
        return true;
      });

      // ASSESSED requires the provider to have actually matched
      // verified records against loaded data; anything else (no data
      // loaded, dataset unavailable, zero matches) is NOT_ASSESSED.
      const assessmentState =
        uniqueAdvisories.length > 0 && assessment.datasetStatus !== 'NO_DATA_LOADED'
          ? 'ASSESSED'
          : 'NOT_ASSESSED';

      const summary: ScaSummary = {
        assessmentState,
        datasetStatus: assessment.datasetStatus,
        providerId: assessment.providerId,
        dependenciesTotal: inventory.totalUnique,
        directDependencies: inventory.directCount,
        transitiveDependencies: inventory.transitiveCount,
        unclassifiedDependencies: inventory.unclassifiedCount,
        advisoriesTotal: uniqueAdvisories.length,
        manifestsAnalyzed: manifestResults.filter((manifest) => manifest.status === 'ANALYZED')
          .length,
        manifestsPartial: manifestResults.filter((manifest) => manifest.status === 'PARTIAL')
          .length,
        manifestsUnsupported: manifestResults.filter((manifest) => manifest.status === 'UNSUPPORTED')
          .length,
        manifestsInvalid: manifestResults.filter((manifest) => manifest.status === 'INVALID_INPUT')
          .length,
        // A transitive closure is only claimable with lockfile
        // evidence. Requirements/pyproject-only projects list DIRECT
        // declarations — no graph exists there, even when every
        // dependency is classified.
        transitiveGraph:
          inventory.hasLockfileEvidence &&
          inventory.unclassifiedCount === 0 &&
          inventory.totalUnique > 0
            ? 'AVAILABLE'
            : 'UNAVAILABLE',
        truncated: inventory.truncated,
      };

      // Generic scan summary: advisories stay in the SCA payload (clearly
      // separated), while declaration-rule matches are REAL persisted
      // findings. Coverage counters state honestly how many declaration
      // rules were evaluated vs. left unevaluated in this scan.
      const resultSummary: ScanResultSummary = {
        findingsTotal: declarations.findings.length,
        findingsBySeverity: declarations.severityCounts,
        truncated: inventory.truncated || declarations.truncated,
        filesScanned: summary.manifestsAnalyzed + summary.manifestsPartial,
        filesSkipped:
          summary.manifestsUnsupported + summary.manifestsInvalid + discovery.skipped,
        dependenciesTotal: inventory.totalUnique,
        directDependencies: inventory.directCount,
        declarationRulesEvaluated: declarations.rulesEvaluated,
        declarationRulesNotEvaluated: declarations.rulesNotEvaluated,
      };

      const sca: ScaResult = {
        summary,
        dependencies: inventory.dependencies,
        manifests: manifestResults.slice(0, SCA_MAX_MANIFESTS_PER_SCAN),
        sbom,
        advisories: uniqueAdvisories,
      };

      if (now() > deadline || ctx.signal.aborted) {
        return deadlineFailure();
      }
      return {
        kind: 'completed',
        resultSummary,
        ...(declarations.findings.length === 0 ? {} : { findings: declarations.findings }),
        sca,
      };
    },
  };
}

function deadlineFailure(): EngineOutcome {
  return {
    kind: 'failed',
    failureCode: 'SCA_SCAN_TIMEOUT',
    failureMessage: 'The SCA engine exceeded its processing deadline.',
  };
}

/**
 * Derive the per-manifest result row by re-parsing the (bounded)
 * manifest text — cheap, self-contained and deterministic.
 */
function parseForManifestResult(
  manifest: DiscoveredManifest,
): Omit<ScaManifestResult, 'ecosystem'> | undefined {
  const base = manifest.path.split('/').pop() ?? manifest.path;
  if (base === 'package.json') {
    const parsed = parsePackageJson(manifest.content, manifest.path);
    return {
      path: manifest.path,
      status: parsed.status,
      dependencyCount: parsed.dependencies.length,
      ...(parsed.note === undefined ? {} : { note: parsed.note }),
    };
  }
  if (base === 'package-lock.json') {
    const parsed = parsePackageLock(manifest.content, manifest.path);
    return {
      path: manifest.path,
      status: parsed.status,
      dependencyCount: parsed.dependencies.length,
      ...(parsed.note === undefined ? {} : { note: parsed.note }),
    };
  }
  if (base === 'requirements.txt') {
    const parsed = parseRequirementsTxt(manifest.content, manifest.path);
    return {
      path: manifest.path,
      status: parsed.status,
      dependencyCount: parsed.dependencies.length,
      ...(parsed.note === undefined ? {} : { note: parsed.note }),
    };
  }
  if (base === 'pyproject.toml') {
    const parsed = parsePyprojectToml(manifest.content, manifest.path);
    return {
      path: manifest.path,
      status: parsed.status,
      dependencyCount: parsed.dependencies.length,
      ...(parsed.note === undefined ? {} : { note: parsed.note }),
    };
  }
  return undefined;
}
