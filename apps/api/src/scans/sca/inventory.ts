/**
 * SCA inventory + SBOM construction (Pump 9).
 *
 * Merge parsed manifest/lockfile evidence into the normalized,
 * deterministic dependency inventory, then derive the CycloneDX 1.5
 * JSON subset SBOM. Determinism contract: identical snapshot content
 * produces byte-identical inventories and SBOM serial numbers (no
 * random ids, no timestamps — the SBOM deliberately omits
 * metadata.timestamp so re-scans are stable and diffable).
 *
 * LOCKFILE PRIORITY (documented contract): a lockfile RESOLVED version
 * never overwrites the manifest's DECLARED range — both are kept and
 * clearly distinguished. A resolved version exists only when a
 * lockfile actually provided it.
 */

import { createHash } from 'node:crypto';
import {
  compareScaDependencies,
  SCA_MAX_DEPENDENCIES_PER_SCAN,
  type SbomComponent,
  type SbomDependencyEdge,
  type SbomDocument,
  type ScaDependency,
  type ScaEcosystem,
} from '@drobon/shared';
import { exactDeclaredVersion } from './exactVersion.js';
import {
  isPurlSafeVersion,
  parsePackageJson,
  parsePackageLock,
  parsePyprojectToml,
  parseRequirementsTxt,
  type ManifestParseResult,
  type RawDependency,
} from './parsers.js';

export { parsePackageJson, parsePackageLock, parsePyprojectToml, parseRequirementsTxt };

/** A manifest discovered in the snapshot (path + content, validated upstream). */
export interface DiscoveredManifest {
  path: string;
  content: string;
}

export interface InventoryResult {
  dependencies: ScaDependency[];
  /** Unique dependencies BEFORE the cap (the honest total). */
  totalUnique: number;
  truncated: boolean;
  /**
   * Counts are computed over the FULL unique set (not the capped
   * slice) so the summary stays honest when truncation kicks in.
   */
  directCount: number;
  transitiveCount: number;
  unclassifiedCount: number;
  /**
   * True when at least one dependency carries lockfile-resolved
   * evidence. Only then is a transitive closure claimable; a
   * requirements.txt/pyproject-only project has direct declarations
   * and NO graph, whatever the classification counts say.
   */
  hasLockfileEvidence: boolean;
  /** True only when every retained coordinate is backed by a lockfile. */
  allDependenciesResolved: boolean;
  /** Root project identity (single named package.json), when known. */
  rootName?: string;
  rootVersion?: string;
  /** The sole named package's path, used to avoid inventing SBOM root edges. */
  rootManifestPath?: string;
}

// ---------------------------------------------------------------------------
// Identity construction (deterministic — never random)
// ---------------------------------------------------------------------------

/** sha256 over the canonical coordinate + evidence path. */
function dependencyFingerprint(raw: RawDependency): string {
  const versionIdentity = raw.resolvedVersion ?? raw.declaredVersion ?? '';
  return createHash('sha256')
    .update(`${raw.ecosystem}\n${raw.name}\n${versionIdentity}\n${raw.manifestPath}`, 'utf8')
    .digest('hex');
}

/** package URL — constructed only from ecosystem + name (+ exact version). */
export function purlFor(ecosystem: ScaEcosystem, name: string, version?: string): string {
  if (ecosystem === 'npm') {
    // Scoped names URL-encode the '@' of the scope (purl spec).
    const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name;
    return version !== undefined && isPurlSafeVersion(version)
      ? `pkg:npm/${encoded}@${version}`
      : `pkg:npm/${encoded}`;
  }
  return version !== undefined && isPurlSafeVersion(version)
    ? `pkg:pypi/${name}@${version}`
    : `pkg:pypi/${name}`;
}

// ---------------------------------------------------------------------------
// Inventory merge
// ---------------------------------------------------------------------------

function rawSortKey(raw: RawDependency): string {
  return `${raw.ecosystem}\n${raw.name}\n${raw.resolvedVersion ?? raw.declaredVersion ?? ''}\n${raw.manifestPath}`;
}

/**
 * Build the normalized inventory from discovered manifests.
 *
 * Merge rules (deterministic):
 * - Entries dedupe on ecosystem, name, version evidence and manifest path;
 *   different versions and different manifest paths are retained.
 * - A package.json in a directory pairs with the package-lock.json in
 *   the SAME directory: manifest declarations supply declared ranges
 *   and the direct set; the lockfile supplies resolved versions,
 *   integrity and (for v1) the direct/transitive classification.
 * - Without a lockfile, npm entries keep class `direct` (manifest
 *   declarations) and the transitive graph is UNAVAILABLE.
 */
export function buildInventory(
  manifests: readonly DiscoveredManifest[],
  maxDependencies: number = SCA_MAX_DEPENDENCIES_PER_SCAN,
): InventoryResult {
  // Deterministic manifest order: path ASC.
  const sorted = [...manifests].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const parsedResults: Array<{ path: string; result: ManifestParseResult; kind: ManifestKind }> =
    [];
  for (const manifest of sorted) {
    parsedResults.push({ path: manifest.path, result: parseManifest(manifest), kind: kindOf(manifest.path) });
  }

  // Pair package.json ↔ package-lock.json per directory.
  const lockByDir = new Map<string, { path: string; result: ReturnType<typeof parsePackageLock> }>();
  for (const entry of parsedResults) {
    if (entry.kind === 'package-lock') {
      const lock = parsePackageLock(manifestContentOf(sorted, entry.path), entry.path);
      lockByDir.set(dirOf(entry.path), { path: entry.path, result: lock });
    }
  }

  interface MergedEntry {
    raw: RawDependency;
    fingerprint: string;
  }
  const byKey = new Map<string, MergedEntry>();
  let rootName: string | undefined;
  let rootVersion: string | undefined;
  let rootManifestPath: string | undefined;
  let namedRoots = 0;

  const consider = (raw: RawDependency): void => {
    // Different versions and manifest paths are distinct evidence. Name-only
    // deduplication silently lost vulnerable nested or monorepo versions.
    // Duplicate instances with the same coordinate and manifest still merge.
    const fingerprint = dependencyFingerprint(raw);
    const key = fingerprint;
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, { raw, fingerprint });
      return;
    }
    // Prefer resolved evidence; keep the first declared range.
    if (existing.raw.resolvedVersion === undefined && raw.resolvedVersion !== undefined) {
      const declaredVersion = raw.declaredVersion ?? existing.raw.declaredVersion;
      byKey.set(key, {
        raw: {
          ...raw,
          ...(declaredVersion === undefined ? {} : { declaredVersion }),
        },
        fingerprint,
      });
    } else if (existing.raw.dependencyClass !== 'direct' && raw.dependencyClass === 'direct') {
      // Identical resolved versions can occur both nested and at the root;
      // retain the evidenced direct copy and its manifest metadata.
      byKey.set(key, { raw, fingerprint });
    } else if (
      existing.raw.declaredVersion === undefined &&
      raw.declaredVersion !== undefined &&
      existing.raw.resolvedVersion !== undefined
    ) {
      // Enrich a resolved entry with the manifest's declared range.
      byKey.set(key, { raw: { ...existing.raw, declaredVersion: raw.declaredVersion }, fingerprint: existing.fingerprint });
    }
  };

  for (const entry of parsedResults) {
    const { result, kind } = entry;
    if (kind === 'package-json') {
      if (result.rootName !== undefined) {
        namedRoots += 1;
        if (namedRoots === 1) {
          rootName = result.rootName;
          rootVersion = result.rootVersion;
          rootManifestPath = entry.path;
        } else {
          // A multi-root monorepo is not one application component.
          rootName = undefined;
          rootVersion = undefined;
          rootManifestPath = undefined;
        }
      }
      const dir = dirOf(entry.path);
      const lock = lockByDir.get(dir);
      if (lock !== undefined && lock.result.status !== 'INVALID_INPUT') {
        // MERGE: lockfile resolution + manifest declaration + direct set.
        const directNames = new Set<string>([
          ...result.directNames,
          ...lock.result.directNames,
        ]);
        for (const lockDep of lock.result.dependencies) {
          // In v2/v3 the lock parser knows whether the installation is
          // root-level. Never attach a direct declaration to a nested copy.
          const isDirect = lock.result.lockfileVersion === 1
            ? lockDep.dependencyClass !== 'transitive' && directNames.has(lockDep.name)
            : lockDep.lockfileRoot === true && directNames.has(lockDep.name);
          const declared = isDirect ? result.dependencies.find(
            (manifestDep) => manifestDep.name === lockDep.name,
          ) : undefined;
          const declaredVersion = declared?.declaredVersion;
          consider({
            ...lockDep,
            manifestPath: entry.path,
            lockfilePath: lock.path,
            ...(declaredVersion === undefined ? {} : { declaredVersion }),
            dependencyType: declared?.dependencyType ?? lockDep.dependencyType,
            dependencyClass: isDirect ? 'direct' : 'transitive',
          });
        }
        for (const manifestDep of result.dependencies) {
          if (lock.result.dependencies.some((lockDep) => lockDep.name === manifestDep.name &&
              (lock.result.lockfileVersion === 1 ? lockDep.dependencyClass !== 'transitive' : lockDep.lockfileRoot === true))) {
            continue;
          }
          consider(manifestDep); // Declared but no direct resolution was evidenced.
        }
      } else {
        for (const manifestDep of result.dependencies) {
          consider(manifestDep);
        }
      }
    } else if (kind === 'package-lock') {
      const dir = dirOf(entry.path);
      const hasCompanionManifest = parsedResults.some(
        (candidate) => candidate.kind === 'package-json' && dirOf(candidate.path) === dir,
      );
      if (hasCompanionManifest) {
        continue; // Handled by the package.json branch above.
      }
      const lock = lockByDir.get(dir);
      if (lock === undefined) {
        continue;
      }
      for (const lockDep of lock.result.dependencies) {
        // No companion manifest: v2/v3 keep their root-entry
        // classification; v1 entries stay unknown (honest).
        consider(lockDep);
      }
    } else {
      for (const raw of result.dependencies) {
        consider(raw);
      }
    }
  }

  const merged = [...byKey.values()].sort((a, b) =>
    rawSortKey(a.raw) < rawSortKey(b.raw) ? -1 : rawSortKey(a.raw) > rawSortKey(b.raw) ? 1 : 0,
  );
  const totalUnique = merged.length;
  const truncated = totalUnique > maxDependencies;
  const capped = truncated ? merged.slice(0, maxDependencies) : merged;

  // Honest class counts over the FULL unique set, plus lockfile
  // evidence across everything seen (never just the capped slice).
  let directCount = 0;
  let transitiveCount = 0;
  let unclassifiedCount = 0;
  let hasLockfileEvidence = false;
  for (const { raw } of merged) {
    if (raw.dependencyClass === 'direct') {
      directCount += 1;
    } else if (raw.dependencyClass === 'transitive') {
      transitiveCount += 1;
    } else {
      unclassifiedCount += 1;
    }
    if (raw.versionSource === 'lockfile') {
      hasLockfileEvidence = true;
    }
  }

  const dependencies: ScaDependency[] = capped.map(({ raw, fingerprint }) => {
    const versionForPurl = raw.resolvedVersion;
    return {
      dependencyId: `dep_${fingerprint.slice(0, 24)}`,
      ecosystem: raw.ecosystem,
      name: raw.name,
      ...(raw.declaredVersion === undefined ? {} : { declaredVersion: raw.declaredVersion }),
      versionSource: raw.versionSource,
      ...(raw.resolvedVersion === undefined ? {} : { resolvedVersion: raw.resolvedVersion }),
      packageManager: raw.packageManager,
      manifestPath: raw.manifestPath,
      ...(raw.lockfilePath === undefined ? {} : { lockfilePath: raw.lockfilePath }),
      dependencyType: raw.dependencyType,
      dependencyClass: raw.dependencyClass,
      ...(raw.integrity === undefined ? {} : { integrity: raw.integrity }),
      ...(raw.resolvedVersion === undefined && raw.declaredVersion === undefined
        ? {}
        : { purl: purlFor(raw.ecosystem, raw.name, versionForPurl) }),
      fingerprint,
    };
  });

  dependencies.sort(compareScaDependencies);
  return {
    dependencies,
    totalUnique,
    truncated,
    directCount,
    transitiveCount,
    unclassifiedCount,
    hasLockfileEvidence,
    allDependenciesResolved: merged.length > 0 && merged.every(({ raw }) => raw.versionSource === 'lockfile'),
    ...(rootName === undefined ? {} : { rootName }),
    ...(rootName === undefined || rootVersion === undefined ? {} : { rootVersion }),
    ...(rootName === undefined || rootManifestPath === undefined ? {} : { rootManifestPath }),
  };
}

type ManifestKind = 'package-json' | 'package-lock' | 'requirements' | 'pyproject' | 'unknown';

function kindOf(path: string): ManifestKind {
  const base = path.split('/').pop() ?? path;
  if (base === 'package.json') {
    return 'package-json';
  }
  if (base === 'package-lock.json') {
    return 'package-lock';
  }
  if (base === 'requirements.txt') {
    return 'requirements';
  }
  if (base === 'pyproject.toml') {
    return 'pyproject';
  }
  return 'unknown';
}

function dirOf(path: string): string {
  const index = path.lastIndexOf('/');
  return index === -1 ? '' : path.slice(0, index);
}

function manifestContentOf(manifests: readonly DiscoveredManifest[], path: string): string {
  return manifests.find((manifest) => manifest.path === path)?.content ?? '';
}

function parseManifest(manifest: DiscoveredManifest): ManifestParseResult {
  const kind = kindOf(manifest.path);
  switch (kind) {
    case 'package-json':
      return parsePackageJson(manifest.content, manifest.path);
    case 'package-lock':
      return parsePackageLock(manifest.content, manifest.path);
    case 'requirements':
      return parseRequirementsTxt(manifest.content, manifest.path);
    case 'pyproject':
      return parsePyprojectToml(manifest.content, manifest.path);
    default:
      return {
        status: 'UNSUPPORTED',
        dependencies: [],
        directNames: [],
        note: 'Unsupported manifest type.',
      };
  }
}

// ---------------------------------------------------------------------------
// SBOM construction (CycloneDX 1.5 JSON subset)
// ---------------------------------------------------------------------------

const TOOL = { type: 'application' as const, name: 'drobon-aegis-sca', version: '1.0.0' };

function scopeFor(dependency: ScaDependency): 'required' | 'optional' | 'excluded' {
  if (dependency.dependencyType === 'optional') {
    return 'optional';
  }
  if (dependency.dependencyType === 'development' || dependency.dependencyType === 'peer') {
    return 'excluded';
  }
  return 'required';
}

function hashesFor(integrity: string | undefined): SbomHash[] | undefined {
  if (integrity === undefined) {
    return undefined;
  }
  if (integrity.startsWith('sha512-')) {
    return [{ alg: 'SHA-512', content: integrity.slice('sha512-'.length) }];
  }
  if (integrity.startsWith('sha256:')) {
    return [{ alg: 'SHA-256', content: integrity.slice('sha256:'.length) }];
  }
  return undefined;
}

interface SbomHash {
  alg: 'SHA-256' | 'SHA-512';
  content: string;
}

/** Deterministic UUID-shaped id from a sha256 digest (RFC 4122 v5 bits). */
function deterministicUuid(seed: string): string {
  const digest = createHash('sha256').update(seed, 'utf8').digest('hex');
  const hex = digest.slice(0, 32).split('');
  // Set version 5 (name-based sha) and the RFC 4122 variant bits.
  hex[12] = '5';
  const variant = parseInt(hex[16] ?? '0', 16);
  hex[16] = ((variant & 0x3) | 0x8).toString(16);
  const h = hex.join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * Build the SBOM. Emitted: bomFormat/specVersion/serialNumber/version,
 * tools + optional root component, one component per dependency, and
 * ONLY evidenced dependency edges (root → direct dependencies).
 * Deliberately omitted (documented limitations): metadata.timestamp
 * (determinism), per-component edges beyond the root (the flat
 * inventory cannot evidence nested resolution chains without guessing).
 */
export function buildSbom(inventory: InventoryResult): SbomDocument {
  const components: SbomComponent[] = inventory.dependencies.map((dependency) => {
    const version = dependency.resolvedVersion ?? exactDeclaredVersion(dependency.ecosystem, dependency.declaredVersion);
    const hashes = hashesFor(dependency.integrity);
    return {
      type: 'library' as const,
      'bom-ref': dependency.fingerprint,
      name: dependency.name,
      ...(version === undefined ? {} : { version }),
      ...(dependency.purl === undefined ? {} : { purl: dependency.purl }),
      scope: scopeFor(dependency),
      ...(hashes === undefined ? {} : { hashes }),
    };
  });

  const dependencies: SbomDependencyEdge[] = [];
  let rootBomRef: string | undefined;
  if (inventory.rootName !== undefined) {
    rootBomRef = `drobon:root:${deterministicUuid(`${inventory.rootName}@${inventory.rootVersion ?? ''}`)}`;
    const directRefs = inventory.dependencies
      .filter((dependency) => dependency.dependencyClass === 'direct' &&
        dependency.manifestPath === inventory.rootManifestPath)
      .map((dependency) => dependency.fingerprint);
    if (directRefs.length > 0) {
      dependencies.push({ ref: rootBomRef, dependsOn: directRefs });
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    // Identity = hash over the canonical component set: identical
    // inventory → identical serial (re-scans are diffable, never random).
    serialNumber: `urn:uuid:${deterministicUuid(
      components
        .map((component) => `${component['bom-ref']}|${component.name}|${component.version ?? ''}`)
        .join('\n'),
    )}`,
    version: 1,
    metadata: {
      tools: { components: [TOOL] },
      ...(inventory.rootName === undefined
        ? {}
        : {
            component: {
              type: 'application' as const,
              'bom-ref': rootBomRef ?? '',
              name: inventory.rootName,
              ...(inventory.rootVersion === undefined ? {} : { version: inventory.rootVersion }),
            },
          }),
    },
    components,
    dependencies,
  };
}
