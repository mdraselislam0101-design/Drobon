import { describe, expect, test } from 'vitest';
import { isScaResult } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';

/**
 * PyPI transitive-graph tests (P2-11, PyPI half).
 *
 * A `poetry.lock` is installation-level evidence: it names the resolved
 * package set AND each package's dependency table. These tests prove the
 * engine turns that into a real graph, and — just as importantly — that it
 * refuses to claim a graph it could not evidence.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000021';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000022';

function scanRecord(): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000023',
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SCA',
    status: 'RUNNING',
    createdAt: '2026-11-02T10:00:00.000Z',
    updatedAt: '2026-11-02T10:00:00.000Z',
    startedAt: '2026-11-02T10:00:00.000Z',
  };
}

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    projectId: PROJECT,
    ownerId: OWNER,
    files: files.map((file) => ({
      path: file.path,
      bytes: Buffer.byteLength(file.content, 'utf8'),
      content: file.content,
    })),
    createdAt: '2026-11-02T09:00:00.000Z',
    updatedAt: '2026-11-02T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

const ctx = { signal: new AbortController().signal };

const PYPROJECT = [
  '[project]',
  'name = "demo"',
  'version = "1.0.0"',
  'dependencies = [',
  '  "requests>=2.0",',
  ']',
].join('\n');

const POETRY_LOCK = [
  '[[package]]',
  'name = "requests"',
  'version = "2.31.0"',
  '[package.dependencies]',
  'certifi = ">=2017.4.17"',
  'urllib3 = ">=1.21.1,<3"',
  '',
  '[[package]]',
  'name = "certifi"',
  'version = "2023.7.22"',
  '',
  '[[package]]',
  'name = "urllib3"',
  'version = "2.0.4"',
  '',
  '[metadata]',
  'lock-version = "2.0"',
  'python-versions = "^3.9"',
].join('\n');

describe('SCA: PyPI transitive graph from poetry.lock (P2-11)', () => {
  test('a locked Poetry project produces evidenced nodes, edges and a graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'pyproject.toml', content: PYPROJECT },
          { path: 'poetry.lock', content: POETRY_LOCK },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(isScaResult(outcome.sca)).toBe(true);
    const sca = outcome.sca;
    if (sca === undefined) return;
    const byName = new Map(sca.dependencies.map((dependency) => [dependency.name, dependency]));
    expect([...byName.keys()].sort()).toEqual(['certifi', 'requests', 'urllib3']);

    // Resolution comes from the lock, directness from the pyproject.
    expect(byName.get('requests')).toMatchObject({
      ecosystem: 'pypi',
      dependencyClass: 'direct',
      versionSource: 'lockfile',
      resolvedVersion: '2.31.0',
      packageManager: 'pip',
      lockfilePath: 'poetry.lock',
      purl: 'pkg:pypi/requests@2.31.0',
    });
    expect(byName.get('certifi')).toMatchObject({
      dependencyClass: 'transitive',
      resolvedVersion: '2023.7.22',
    });
    expect(byName.get('urllib3')).toMatchObject({
      dependencyClass: 'transitive',
      resolvedVersion: '2.0.4',
    });

    expect(sca.summary).toMatchObject({
      dependenciesTotal: 3,
      directDependencies: 1,
      transitiveDependencies: 2,
      unclassifiedDependencies: 0,
      transitiveGraph: 'AVAILABLE',
    });

    // The graph is in the SBOM: root → requests, requests → its two children.
    const rootComponent = sca.sbom.metadata.component;
    if (rootComponent === undefined) return;
    const rootRef = rootComponent['bom-ref'];
    const refs = new Set(sca.sbom.components.map((component) => component['bom-ref']));
    expect(sca.sbom.dependencies).toHaveLength(2);
    expect(sca.sbom.dependencies.flatMap((edge) => edge.dependsOn)).toHaveLength(3);
    for (const edge of sca.sbom.dependencies) {
      expect(edge.ref === rootRef || refs.has(edge.ref)).toBe(true);
      for (const target of edge.dependsOn) {
        expect(targetsAreKnown(refs, rootRef, target)).toBe(true);
      }
    }
    const requestsRef = byName.get('requests')?.fingerprint;
    const rootEdge = sca.sbom.dependencies.find((edge) => edge.ref === rootRef);
    expect(rootEdge?.dependsOn).toEqual([requestsRef]);
    const requestsEdge = sca.sbom.dependencies.find((edge) => edge.ref === requestsRef);
    expect([...(requestsEdge?.dependsOn ?? [])].sort()).toEqual([
      byName.get('certifi')?.fingerprint,
      byName.get('urllib3')?.fingerprint,
    ]);
    // The root component is the project's own declared identity.
    expect(rootComponent).toMatchObject({ name: 'demo', version: '1.0.0' });
  });

  test('a lock without its pyproject never claims directness or a graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'poetry.lock', content: POETRY_LOCK }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    // Locked installations are real, so they are reported…
    expect(sca.dependencies.map((dependency) => dependency.name).sort()).toEqual([
      'certifi', 'requests', 'urllib3',
    ]);
    // …but with no declaration there is no honest "direct" set.
    expect(sca.dependencies.every((dependency) => dependency.dependencyClass === 'unknown')).toBe(true);
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
  });

  test('a declared dependency the lock does not resolve keeps the graph UNAVAILABLE', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          {
            path: 'pyproject.toml',
            content: [
              '[project]',
              'name = "demo"',
              'dependencies = [',
              '  "requests>=2.0",',
              '  "flask>=3.0",',
              ']',
            ].join('\n'),
          },
          { path: 'poetry.lock', content: POETRY_LOCK },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    // The unresolvable declaration is still reported, from the manifest.
    const flask = sca.dependencies.find((dependency) => dependency.name === 'flask');
    expect(flask).toMatchObject({ dependencyClass: 'direct', versionSource: 'manifest' });
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(sca.summary.truncated).toBe(false);
  });

  test('a hostile lock cannot inject nodes, paths or dependency classes', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'pyproject.toml', content: PYPROJECT },
          {
            path: 'poetry.lock',
            content: [
              '[[package]]',
              'name = "requests"',
              'version = "2.31.0"',
              '[package.dependencies]',
              '__proto__ = "1.0"',
              'constructor = "1.0"',
              'name = "1.0"',
              '[[package]]',
              'name = "../escape"',
              'version = "1.0.0"',
              '[[package]]',
              'name = "requests"',
              'version = "2.31.0"',
            ].join('\n'),
          },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    expect(sca.dependencies.map((dependency) => dependency.name)).toEqual(['requests']);
    expect(sca.dependencies[0]?.manifestPath).toBe('pyproject.toml');
    expect(sca.dependencies[0]?.lockfilePath).toBe('poetry.lock');
    // `name = "1.0"` is a dependency entry pointing at a package the lock does
    // not list, so the graph is honestly reported as incomplete.
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
  });

  test('the same Poetry snapshot always yields the same inventory (deterministic)', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'pyproject.toml', content: PYPROJECT },
          { path: 'poetry.lock', content: POETRY_LOCK },
        ]),
      ),
    });
    const first = await engine.execute(scanRecord(), ctx);
    const second = await engine.execute(scanRecord(), ctx);
    expect(first.kind).toBe('completed');
    expect(second.kind).toBe('completed');
    if (first.kind !== 'completed' || second.kind !== 'completed') return;
    const firstSca = first.sca;
    const secondSca = second.sca;
    if (firstSca === undefined || secondSca === undefined) return;
    expect(secondSca.dependencies).toEqual(firstSca.dependencies);
    expect(secondSca.sbom).toEqual(firstSca.sbom);
    expect(secondSca.summary).toEqual(firstSca.summary);
  });
});

/** `dependsOn` entries are either component purls or the root bom-ref. */
function targetsAreKnown(refs: Set<string>, rootRef: unknown, target: string): boolean {
  return refs.has(target) || target === rootRef;
}
