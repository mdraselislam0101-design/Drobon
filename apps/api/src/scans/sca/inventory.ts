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
  parseCompiledRequirements,
  parsePipfile,
  parsePipfileLock,
  parsePoetryLock,
  parsePyprojectToml,
  parseRequirementsTxt,
  parseUvLock,
  type ManifestParseResult,
  type PoetryLockParseResult,
  type RawDependency,
} from './parsers.js';

export {
  parseCompiledRequirements,
  parsePackageJson,
  parsePackageLock,
  parsePipfile,
  parsePipfileLock,
  parsePoetryLock,
  parsePyprojectToml,
  parseRequirementsTxt,
  parseUvLock,
};

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
  /**
   * True when a lockfile that STATES dependency relationships was parsed (npm
   * `package-lock.json`, `poetry.lock`, `uv.lock`). A `Pipfile.lock` pins
   * versions but records no edges, so on its own it cannot evidence a graph.
   */
  edgeEvidence: boolean;
  /** Root project identity (single named package.json), when known. */
  rootName?: string;
  rootVersion?: string;
  /** The sole named package's path, used to avoid inventing SBOM root edges. */
  rootManifestPath?: string;
  /**
   * Evidenced dependency edges (P2-11), as fingerprint pairs. `from` is '' for
   * the project root. Only edges a lockfile actually stated are present; a
   * declared-but-unresolved range never becomes an edge.
   */
  edges: Array<{ from: string; to: string }>;
  /** Graph shape, derived from {@link edges} (never assumed). */
  graph: {
    nodes: number;
    edges: number;
    /** Longest evidenced chain from the root (0 when no edge exists). */
    maxDepth: number;
    /** Distinct components that at least one edge points at. */
    dependentNodes: number;
    /** True when the edge budget clipped the graph. */
    truncated: boolean;
  };
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

  /**
   * PyPI lock evidence (P2-11). Three formats, each with its own honesty level:
   * - `poetry.lock` / `uv.lock` state resolved packages AND which package needs
   *   which, so they can evidence a real graph;
   * - `Pipfile.lock` pins every resolved package but records NO inter-package
   *   edge, so it yields resolved versions and no graph.
   * A Python environment is flat (one installed version per name), so node keys
   * are `name@version`. The declaration file next to the lock supplies the
   * direct set and the declared ranges.
   */
  type PypiLockKind = 'poetry-lock' | 'uv-lock' | 'pipfile-lock' | 'requirements-graph';
  interface MergeableLock {
    path: string;
    kind: PypiLockKind;
    result: PoetryLockParseResult;
  }
  interface PypiLockInfo extends MergeableLock {
    companion: 'pyproject' | 'pipfile';
  }
  const pypiLockByDir = new Map<string, PypiLockInfo>();
  for (const entry of parsedResults) {
    if (entry.kind !== 'poetry-lock' && entry.kind !== 'uv-lock' && entry.kind !== 'pipfile-lock') {
      continue;
    }
    const dir = dirOf(entry.path);
    const companion: 'pyproject' | 'pipfile' =
      entry.kind === 'pipfile-lock' ? 'pipfile' : 'pyproject';
    const declaredNames = parsedResults
      .filter((candidate) => candidate.kind === companion && dirOf(candidate.path) === dir)
      .flatMap((candidate) => candidate.result.directNames);
    const content = manifestContentOf(sorted, entry.path);
    const result = entry.kind === 'poetry-lock'
      ? parsePoetryLock(content, entry.path, declaredNames)
      : entry.kind === 'uv-lock'
        ? parseUvLock(content, entry.path, declaredNames)
        : parsePipfileLock(content, entry.path, declaredNames);
    pypiLockByDir.set(dir, { path: entry.path, kind: entry.kind, companion, result });
  }

  /**
   * pip-compile provenance (P2-11): a `requirements.txt` that carries `# via`
   * lines is a compiled lock and can evidence a graph. A hand-written file has
   * no provenance, so it keeps the old declaration-only behaviour.
   */
  const requirementsGraphByPath = new Map<string, PoetryLockParseResult>();
  for (const entry of parsedResults) {
    if (entry.kind !== 'requirements') continue;
    const graph = parseCompiledRequirements(manifestContentOf(sorted, entry.path), entry.path);
    if (graph.graphEvidence) requirementsGraphByPath.set(entry.path, graph);
  }

  interface MergedEntry {
    raw: RawDependency;
    fingerprint: string;
  }
  const byKey = new Map<string, MergedEntry>();
  /**
   * path-key → fingerprint, per lockfile. The SAME package name installed at
   * two depths is two nodes, so edges must be resolved through the lock's own
   * model rather than by name.
   */
  const lockPathFingerprints = new Map<string, Map<string, string>>();
  const rawEdges: Array<{ lockPath: string; from: string; to: string }> = [];
  /** A parsed lock that can state edges (not a Pipfile lock). */
  let edgeEvidence = false;
  /** True when a lockfile's own edge budget clipped its graph. */
  let graphTruncatedByParser = false;
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

  /**
   * Merge a PyPI lock with its declaration file: the lock supplies resolved
   * versions (and edges, when the format states them), the declaration supplies
   * directness and declared ranges. Declarations the lock does not resolve are
   * still reported — from the manifest — so nothing disappears silently.
   */
  const mergePypiLock = (
    manifestPath: string,
    lock: MergeableLock,
    manifestDeps: readonly RawDependency[],
  ): void => {
    const directNames = new Set<string>(lock.result.directNames);
    const pathMap = new Map<string, string>();
    lockPathFingerprints.set(lock.path, pathMap);
    for (const lockDep of lock.result.dependencies) {
      const isDirect = directNames.has(lockDep.name);
      const declared = isDirect
        ? manifestDeps.find((manifestDep) => manifestDep.name === lockDep.name)
        : undefined;
      const raw: RawDependency = {
        ...lockDep,
        manifestPath,
        lockfilePath: lock.path,
        ...(declared?.declaredVersion === undefined
          ? {}
          : { declaredVersion: declared.declaredVersion }),
        dependencyType: declared?.dependencyType ?? lockDep.dependencyType,
        dependencyClass: isDirect ? 'direct' : 'transitive',
      };
      consider(raw);
      if (lockDep.pathKey !== undefined && lockDep.resolvedVersion !== undefined) {
        pathMap.set(lockDep.pathKey, dependencyFingerprint(raw));
      }
    }
    for (const edge of lock.result.edges) {
      rawEdges.push({ lockPath: lock.path, from: edge.from, to: edge.to });
    }
    // A Pipfile lock states versions only; poetry/uv locks state edges.
    if (lock.kind !== 'pipfile-lock') edgeEvidence = true;
    if (lock.result.edgesTruncated === true) graphTruncatedByParser = true;
    for (const manifestDep of manifestDeps) {
      if (lock.result.dependencies.some((lockDep) => lockDep.name === manifestDep.name)) continue;
      consider(manifestDep); // Declared but the lock does not resolve it.
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
        const pathMap = new Map<string, string>();
        lockPathFingerprints.set(lock.path, pathMap);
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
          const raw: RawDependency = {
            ...lockDep,
            manifestPath: entry.path,
            lockfilePath: lock.path,
            ...(declaredVersion === undefined ? {} : { declaredVersion }),
            dependencyType: declared?.dependencyType ?? lockDep.dependencyType,
            dependencyClass: isDirect ? 'direct' : 'transitive',
          };
          consider(raw);
          if (lockDep.pathKey !== undefined && lockDep.resolvedVersion !== undefined) {
            // Fingerprint is (ecosystem, name, version, manifestPath) — identical
            // to what `consider` computed, so edges join the same nodes.
            pathMap.set(lockDep.pathKey, dependencyFingerprint(raw));
          }
        }
        for (const edge of lock.result.edges) {
          rawEdges.push({ lockPath: lock.path, from: edge.from, to: edge.to });
        }
        edgeEvidence = true;
        if (lock.result.edgesTruncated === true) graphTruncatedByParser = true;
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
      const pathMap = new Map<string, string>();
      lockPathFingerprints.set(lock.path, pathMap);
      for (const lockDep of lock.result.dependencies) {
        // No companion manifest: v2/v3 keep their root-entry
        // classification; v1 entries stay unknown (honest).
        consider(lockDep);
        if (lockDep.pathKey !== undefined && lockDep.resolvedVersion !== undefined) {
          pathMap.set(lockDep.pathKey, dependencyFingerprint(lockDep));
        }
      }
      for (const edge of lock.result.edges) {
        rawEdges.push({ lockPath: lock.path, from: edge.from, to: edge.to });
      }
      edgeEvidence = true;
      if (lock.result.edgesTruncated === true) graphTruncatedByParser = true;
    } else if (kind === 'pyproject') {
      // Project identity for the SBOM root. A `package.json` root (the JS
      // application component) always wins; a Python-only project otherwise
      // has a real, declared identity of its own.
      if (rootName === undefined && result.rootName !== undefined) {
        rootName = result.rootName;
        rootVersion = result.rootVersion;
        rootManifestPath = entry.path;
      }
      const dir = dirOf(entry.path);
      const lock = pypiLockByDir.get(dir);
      if (lock === undefined || lock.companion !== 'pyproject' || lock.result.status === 'INVALID_INPUT') {
        for (const raw of result.dependencies) consider(raw);
      } else {
        mergePypiLock(entry.path, lock, result.dependencies);
      }
    } else if (kind === 'requirements') {
      const graph = requirementsGraphByPath.get(entry.path);
      if (graph === undefined) {
        for (const raw of result.dependencies) consider(raw);
      } else {
        mergePypiLock(entry.path, { path: entry.path, kind: 'requirements-graph', result: graph }, result.dependencies);
      }
    } else if (kind === 'pipfile') {
      const dir = dirOf(entry.path);
      const lock = pypiLockByDir.get(dir);
      if (lock === undefined || lock.companion !== 'pipfile' || lock.result.status === 'INVALID_INPUT') {
        for (const raw of result.dependencies) consider(raw);
      } else {
        mergePypiLock(entry.path, lock, result.dependencies);
      }
    } else if (kind === 'poetry-lock' || kind === 'uv-lock' || kind === 'pipfile-lock') {
      const dir = dirOf(entry.path);
      const companionKind = kind === 'pipfile-lock' ? 'pipfile' : 'pyproject';
      const hasCompanionManifest = parsedResults.some(
        (candidate) => candidate.kind === companionKind && dirOf(candidate.path) === dir,
      );
      if (hasCompanionManifest) continue; // Handled by the declaration branch above.
      const lock = pypiLockByDir.get(dir);
      if (lock === undefined) continue;
      // No declaration file: the locked installations are real, but which of
      // them the project declares directly is unknown (`unknown` class, never
      // `direct`). A uv lock still names the project package itself.
      if (kind === 'uv-lock' && rootName === undefined && lock.result.rootName !== undefined) {
        rootName = lock.result.rootName;
        rootVersion = lock.result.rootVersion;
        rootManifestPath = entry.path;
      }
      const pathMap = new Map<string, string>();
      lockPathFingerprints.set(lock.path, pathMap);
      for (const lockDep of lock.result.dependencies) {
        consider(lockDep);
        if (lockDep.pathKey !== undefined && lockDep.resolvedVersion !== undefined) {
          pathMap.set(lockDep.pathKey, dependencyFingerprint(lockDep));
        }
      }
      for (const edge of lock.result.edges) {
        rawEdges.push({ lockPath: lock.path, from: edge.from, to: edge.to });
      }
      if (kind !== 'pipfile-lock') edgeEvidence = true;
      if (lock.result.edgesTruncated === true) graphTruncatedByParser = true;
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

  // --- translate path keys to retained fingerprints -----------------------
  // An edge survives only when BOTH endpoints are real, retained nodes (or the
  // project root). A truncated inventory therefore never emits a dangling ref.
  const retained = new Set(dependencies.map((dependency) => dependency.fingerprint));
  const edgeKeys = new Set<string>();
  const edges: Array<{ from: string; to: string }> = [];
  let droppedEdges = 0;
  for (const raw of rawEdges) {
    const paths = lockPathFingerprints.get(raw.lockPath);
    if (paths === undefined) continue;
    const from = raw.from === '' ? '' : paths.get(raw.from);
    const to = raw.to === '' ? '' : paths.get(raw.to);
    // An endpoint that is not a retained node means the edge cannot be shown;
    // the graph is then reported as incomplete rather than quietly thinned.
    if (to === undefined || to === '' || !retained.has(to) || from === undefined ||
      (from !== '' && !retained.has(from))) {
      droppedEdges += 1;
      continue;
    }
    const key = `${from}\n${to}`;
    if (edgeKeys.has(key)) continue;
    edgeKeys.add(key);
    edges.push({ from, to });
  }
  edges.sort((a, b) => (a.from === b.from ? (a.to < b.to ? -1 : a.to > b.to ? 1 : 0) : a.from < b.from ? -1 : 1));

  return {
    dependencies,
    totalUnique,
    truncated,
    directCount,
    transitiveCount,
    unclassifiedCount,
    hasLockfileEvidence,
    allDependenciesResolved: merged.length > 0 && merged.every(({ raw }) => raw.versionSource === 'lockfile'),
    edgeEvidence,
    ...(rootName === undefined ? {} : { rootName }),
    ...(rootName === undefined || rootVersion === undefined ? {} : { rootVersion }),
    ...(rootName === undefined || rootManifestPath === undefined ? {} : { rootManifestPath }),
    edges,
    graph: summarizeGraph(edges, graphTruncatedByParser || droppedEdges > 0),
  };
}

/**
 * Graph shape from the evidenced edge list. Depth is a BFS from the root over
 * the actual edges (cycle-safe), never a guess from the node count.
 */
function summarizeGraph(
  edges: ReadonlyArray<{ from: string; to: string }>,
  truncated = false,
): InventoryResult['graph'] {
  const children = new Map<string, string[]>();
  for (const edge of edges) {
    const list = children.get(edge.from);
    if (list === undefined) children.set(edge.from, [edge.to]);
    else if (!list.includes(edge.to)) list.push(edge.to);
  }
  const depth = new Map<string, number>([['', 0]]);
  const queue = [''];
  let maxDepth = 0;
  for (let index = 0; index < queue.length && index < 10_000; index += 1) {
    const node = queue[index];
    if (node === undefined) break;
    const current = depth.get(node) ?? 0;
    for (const child of children.get(node) ?? []) {
      if (depth.has(child)) continue; // cycle or already reached
      depth.set(child, current + 1);
      maxDepth = Math.max(maxDepth, current + 1);
      queue.push(child);
    }
  }
  const involved = new Set<string>();
  const dependent = new Set<string>();
  for (const edge of edges) {
    involved.add(edge.from);
    involved.add(edge.to);
    if (edge.from !== '') dependent.add(edge.from);
  }
  return {
    nodes: involved.size,
    edges: edges.length,
    maxDepth,
    dependentNodes: dependent.size,
    truncated,
  };
}

type ManifestKind =
  | 'package-json'
  | 'package-lock'
  | 'requirements'
  | 'pyproject'
  | 'poetry-lock'
  | 'uv-lock'
  | 'pipfile'
  | 'pipfile-lock'
  | 'unknown';

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
  if (base === 'poetry.lock') {
    return 'poetry-lock';
  }
  if (base === 'uv.lock') {
    return 'uv-lock';
  }
  if (base === 'Pipfile') {
    return 'pipfile';
  }
  if (base === 'Pipfile.lock') {
    return 'pipfile-lock';
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
    case 'poetry-lock':
    case 'uv-lock':
      // Parsed again with its companion declaration below (directness needs
      // it); this bare pass only feeds the manifest result summary.
      return kind === 'poetry-lock'
        ? parsePoetryLock(manifest.content, manifest.path)
        : parseUvLock(manifest.content, manifest.path);
    case 'pipfile':
      return parsePipfile(manifest.content, manifest.path);
    case 'pipfile-lock':
      return parsePipfileLock(manifest.content, manifest.path);
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
 * ONLY evidenced dependency edges: the root → its resolved direct set, plus
 * one edge per component whose own resolved children the lockfile states.
 * Edges are emitted ONLY when a lockfile evidences them; a declared-but-
 * unresolved range never becomes an edge (it stays a direct declaration).
 * Deliberately omitted: metadata.timestamp (determinism).
 */
/**
 * SBOM identity: the component set AND the evidenced edges. Same components
 * with a different graph must not share a serial number, otherwise two
 * structurally different SBOMs would look like the same document.
 */
function sbomIdentity(
  components: readonly SbomComponent[],
  edges: readonly SbomDependencyEdge[],
): string {
  return [
    ...components.map((component) => `${component['bom-ref']}|${component.name}|${component.version ?? ''}`),
    ...edges.map((edge) => `->${edge.ref}|${edge.dependsOn.join(',')}`),
  ].join(String.fromCharCode(10));
}

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
    // Root children come from the EVIDENCED graph when the lockfile stated
    // them; otherwise fall back to the manifest's direct declarations (which
    // is still evidence — just of declaration, not of installation).
    const evidencedRoots = inventory.edges
      .filter((edge) => edge.from === '')
      .map((edge) => edge.to)
      .sort();
    const directRefs = evidencedRoots.length > 0
      ? evidencedRoots
      : inventory.dependencies
        .filter((dependency) => dependency.dependencyClass === 'direct' &&
          dependency.manifestPath === inventory.rootManifestPath)
        .map((dependency) => dependency.fingerprint);
    if (directRefs.length > 0) {
      dependencies.push({ ref: rootBomRef, dependsOn: directRefs });
    }
  }

  // Transitive edges (P2-11): one edge per component that actually depends on
  // something, in fingerprint order for determinism. The CycloneDX guard caps
  // the array at components+1, so the root edge + one edge per component fits
  // exactly; anything beyond is dropped rather than emitted as a guess.
  const childrenByNode = new Map<string, string[]>();
  for (const edge of inventory.edges) {
    if (edge.from === '') continue;
    const list = childrenByNode.get(edge.from);
    if (list === undefined) childrenByNode.set(edge.from, [edge.to]);
    else if (!list.includes(edge.to)) list.push(edge.to);
  }
  const componentRefs = new Set(components.map((component) => component['bom-ref']));
  for (const ref of [...childrenByNode.keys()].sort()) {
    if (!componentRefs.has(ref)) continue;
    const dependsOn = (childrenByNode.get(ref) ?? []).filter((child) => componentRefs.has(child)).sort();
    if (dependsOn.length === 0) continue;
    if (dependencies.length >= inventory.dependencies.length) break;
    dependencies.push({ ref, dependsOn });
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    // Identity = hash over the canonical component set: identical
    // inventory → identical serial (re-scans are diffable, never random).
    serialNumber: `urn:uuid:${deterministicUuid(sbomIdentity(components, dependencies))}`,
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
