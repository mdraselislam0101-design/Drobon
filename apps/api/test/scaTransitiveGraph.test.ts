import { describe, expect, test } from 'vitest';
import { isScaResult, SCA_MAX_DEPENDENCIES_PER_SCAN, type ScaResult } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';
import { createNullIntelligenceProvider } from '../src/scans/sca/provider.js';
import { LOCK_MAX_EDGES, parsePackageLock } from '../src/scans/sca/parsers.js';

/**
 * P2-11 — transitive dependency graph.
 *
 * The contract under test: an SBOM edge exists ONLY where a lockfile states a
 * dependency AND that dependency resolves to an installation the lockfile
 * actually lists. No lockfile, no edge. No resolution, no edge. Every edge is
 * bounded, deterministic and points at a real component of the same document.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';

function scanRecord(): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000003',
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SCA',
    status: 'RUNNING',
    createdAt: '2026-09-28T10:00:00.000Z',
    updatedAt: '2026-09-28T10:00:00.000Z',
    startedAt: '2026-09-28T10:00:00.000Z',
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
    createdAt: '2026-09-28T09:00:00.000Z',
    updatedAt: '2026-09-28T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

const ctx = { signal: new AbortController().signal };

async function runSca(record: SourceSnapshotRecord): Promise<ScaResult> {
  const engine = createScaEngine({
    sources: providerFor(record),
    provider: createNullIntelligenceProvider(),
  });
  const outcome = await engine.execute(scanRecord(), ctx);
  expect(outcome.kind).toBe('completed');
  if (outcome.kind !== 'completed' || outcome.sca === undefined) {
    throw new Error('SCA engine did not produce a result');
  }
  // Every graph-related assertion below is made against a contract-valid
  // payload, so the shared validator sees the new edges too.
  expect(isScaResult(outcome.sca)).toBe(true);
  return outcome.sca;
}

/** npm components → name map (the fixture uses unique names). */
function namesByRef(sca: ScaResult): Map<string, string> {
  return new Map(sca.sbom.components.map((component) => [component['bom-ref'], component.name]));
}

describe('SCA transitive graph (P2-11): parser resolution', () => {
  test('v3: edges follow Node resolution, including nested copies', () => {
    const lock = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { a: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { b: '^2.0.0' } },
          'node_modules/b': { version: '2.0.0' },
          'node_modules/a/node_modules/b': { version: '2.5.0', dependencies: { c: '^3.0.0' } },
          'node_modules/c': { version: '3.0.0' },
        },
      }),
      'package-lock.json',
    );
    expect(lock.status).toBe('ANALYZED');
    const paths = new Map(lock.entries.map((entry) => [entry.name + '@' + entry.version, entry.pathKey]));
    expect(paths.get('a@1.0.0')).toBe('node_modules/a');
    expect(paths.get('b@2.5.0')).toBe('node_modules/a/node_modules/b');
    // Real resolution: `a` sees the nested b@2.5.0, not the hoisted b@2.0.0.
    expect(lock.edges).toEqual([
      { from: '', to: 'node_modules/a' },
      { from: 'node_modules/a', to: 'node_modules/a/node_modules/b' },
      { from: 'node_modules/a/node_modules/b', to: 'node_modules/c' },
    ]);
  });

  test('declared-but-absent dependencies never become edges', () => {
    const lock = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { ghost: '^9.0.0', real: '^1.0.0' } },
          // `ghost` is declared but not installed.
          'node_modules/real': { version: '1.0.0' },
        },
      }),
      'package-lock.json',
    );
    expect(lock.edges).toEqual([{ from: '', to: 'node_modules/real' }]);
  });

  test('v1: nesting is structural evidence (parent → child), bounded', () => {
    const lock = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
          c: { version: '1.0.0' },
        },
      }),
      'package-lock.json',
    );
    expect(lock.status).toBe('ANALYZED');
    expect(lock.edges).toEqual([
      { from: '', to: 'node_modules/a' },
      { from: '', to: 'node_modules/c' },
      { from: 'node_modules/a', to: 'node_modules/a/node_modules/b' },
    ]);
  });

  /** A complete dependency mesh over `count` packages (every node → every other). */
  function meshLock(count: number): string {
    const names = Array.from({ length: count }, (_, index) => `pkg-${index}`);
    const packages: Record<string, unknown> = {
      '': { name: 'app', dependencies: Object.fromEntries(names.map((name) => [name, '^1.0.0'])) },
    };
    for (const [index, name] of names.entries()) {
      packages[`node_modules/${name}`] = {
        version: '1.0.0',
        dependencies: Object.fromEntries(
          names.filter((_, other) => other !== index).map((other) => [other, '^1.0.0']),
        ),
      };
    }
    return JSON.stringify({ lockfileVersion: 3, packages });
  }

  test('a graph below the budget is complete and unflagged', () => {
    const lock = parsePackageLock(meshLock(60), 'package-lock.json');
    expect(lock.edgesTruncated).toBeUndefined();
    // 60 root edges + 60 × 59 mesh edges.
    expect(lock.edges).toHaveLength(60 + 60 * 59);
    expect(new Set(lock.edges.map((edge) => `${edge.from}\n${edge.to}`)).size).toBe(lock.edges.length);
  });

  test('a graph above the budget is clipped at the cap AND flagged', () => {
    const lock = parsePackageLock(meshLock(80), 'package-lock.json');
    expect(lock.edgesTruncated).toBe(true);
    expect(lock.edges).toHaveLength(LOCK_MAX_EDGES);
  });

  test('malformed lockfiles carry no edges at all', () => {
    for (const text of ['{not json', '[]', '{"lockfileVersion":3}', '{"dependencies":"x"}']) {
      const lock = parsePackageLock(text, 'package-lock.json');
      expect(lock.edges).toEqual([]);
    }
  });
});

describe('SCA transitive graph (P2-11): SBOM edges', () => {
  const LOCKED = snapshot([
    {
      path: 'package.json',
      content: JSON.stringify({
        name: 'graph-app',
        version: '1.0.0',
        dependencies: { a: '^1.0.0' },
      }),
    },
    {
      path: 'package-lock.json',
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'graph-app', version: '1.0.0', dependencies: { a: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { b: '^2.0.0' } },
          'node_modules/b': { version: '2.0.0', dependencies: { c: '^3.0.0' } },
          'node_modules/c': { version: '3.0.0' },
        },
      }),
    },
  ]);

  test('every edge points at a real component and the graph reports AVAILABLE', async () => {
    const sca = await runSca(LOCKED);
    expect(sca.summary.transitiveGraph).toBe('AVAILABLE');
    expect(sca.summary.transitiveDependencies).toBe(2);

    const names = namesByRef(sca);
    const rootRef = sca.sbom.metadata.component?.['bom-ref'];
    expect(typeof rootRef).toBe('string');
    const componentRefs = new Set(names.keys());

    // Root → direct, then one edge per component that has children.
    expect(sca.sbom.dependencies).toHaveLength(3);
    expect(sca.sbom.dependencies[0]?.ref).toBe(rootRef);
    expect(sca.sbom.dependencies[0]?.dependsOn.map((ref) => names.get(ref))).toEqual(['a']);

    const byName = new Map([...names].map(([ref, name]) => [name, ref]));
    const edgesByName = new Map<string | undefined, string[]>();
    for (const edge of sca.sbom.dependencies) {
      edgesByName.set(names.get(edge.ref) ?? '<root>', edge.dependsOn.map((ref) => names.get(ref) ?? '?'));
      // No dangling references: a CycloneDX consumer must resolve every ref.
      expect(componentRefs.has(edge.ref) || edge.ref === rootRef).toBe(true);
      for (const ref of edge.dependsOn) {
        expect(componentRefs.has(ref)).toBe(true);
      }
    }
    expect(edgesByName.get('<root>')).toEqual(['a']);
    expect(edgesByName.get('a')).toEqual(['b']);
    expect(edgesByName.get('b')).toEqual(['c']);
    // A leaf has no edge of its own — the graph adds nothing it cannot prove.
    expect(edgesByName.has('c')).toBe(false);
    expect(byName.get('c')).toBeDefined();
  });

  test('identical snapshots → identical edges and identical SBOM serial', async () => {
    const first = await runSca(LOCKED);
    const second = await runSca(LOCKED);
    expect(second.sbom.dependencies).toEqual(first.sbom.dependencies);
    expect(second.sbom.serialNumber).toBe(first.sbom.serialNumber);
  });

  test('the serial number covers the graph, not only the component set', async () => {
    // Same components, different evidence: `c` stops depending on anything.
    const withoutEdge = await runSca(
      snapshot([
        {
          path: 'package.json',
          content: JSON.stringify({ name: 'graph-app', version: '1.0.0', dependencies: { a: '^1.0.0' } }),
        },
        {
          path: 'package-lock.json',
          content: JSON.stringify({
            lockfileVersion: 3,
            packages: {
              '': { name: 'graph-app', version: '1.0.0', dependencies: { a: '^1.0.0' } },
              'node_modules/a': { version: '1.0.0', dependencies: { b: '^2.0.0' } },
              'node_modules/b': { version: '2.0.0' },
              'node_modules/c': { version: '3.0.0' },
            },
          }),
        },
      ]),
    );
    const withEdge = await runSca(LOCKED);
    expect(withoutEdge.sbom.components.map((c) => c['bom-ref'])).toEqual(
      withEdge.sbom.components.map((c) => c['bom-ref']),
    );
    expect(withoutEdge.sbom.dependencies).not.toEqual(withEdge.sbom.dependencies);
    expect(withoutEdge.sbom.serialNumber).not.toBe(withEdge.sbom.serialNumber);
  });

  test('declarations without a lockfile stay a flat list (no invented edges)', async () => {
    const sca = await runSca(
      snapshot([
        {
          path: 'package.json',
          content: JSON.stringify({ name: 'decl-app', version: '1.0.0', dependencies: { a: '^1.0.0', b: '^2.0.0' } }),
        },
      ]),
    );
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    // Direct declarations are still shown as the root's children — evidence
    // of declaration, exactly as before — but there is no deeper graph.
    expect(sca.sbom.dependencies).toHaveLength(1);
    expect(sca.sbom.dependencies[0]?.dependsOn).toHaveLength(2);
    expect(sca.summary.transitiveDependencies).toBe(0);
  });

  test('a clipped graph is UNAVAILABLE and states why (never overclaimed)', async () => {
    // 80 direct packages, each depending on the other 79: the dependency list
    // is well inside the 200-component cap, but the edge set exceeds the
    // parser budget — so the graph must be reported as incomplete.
    const count = 80;
    const names = Array.from({ length: count }, (_, index) => `pkg-${index}`);
    const packages: Record<string, unknown> = {
      '': {
        name: 'mesh-app',
        version: '1.0.0',
        dependencies: Object.fromEntries(names.map((name) => [name, '^1.0.0'])),
      },
    };
    for (const [index, name] of names.entries()) {
      packages[`node_modules/${name}`] = {
        version: '1.0.0',
        dependencies: Object.fromEntries(
          names.filter((_, other) => other !== index).map((other) => [other, '^1.0.0']),
        ),
      };
    }
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          {
            path: 'package.json',
            content: JSON.stringify({
              name: 'mesh-app',
              version: '1.0.0',
              dependencies: Object.fromEntries(names.map((name) => [name, '^1.0.0'])),
            }),
          },
          { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages }) },
        ]),
      ),
      provider: createNullIntelligenceProvider(),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      throw new Error('SCA engine did not produce a result');
    }
    expect(isScaResult(outcome.sca)).toBe(true);
    expect(outcome.sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(outcome.sca.summary.transitiveDependencies).toBe(0);
    expect(outcome.resultSummary.partialReason).toContain('dependency graph exceeded its edge budget');
    // The SBOM stays contract-valid and bounded even though the graph clipped.
    expect(outcome.sca.sbom.dependencies.length).toBeLessThanOrEqual(SCA_MAX_DEPENDENCIES_PER_SCAN + 1);
  });

  test('python-only projects emit no graph edges', async () => {
    const sca = await runSca(
      snapshot([{ path: 'requirements.txt', content: 'flask==2.3.2\nrequests==2.31.0\n' }]),
    );
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(sca.sbom.dependencies).toEqual([]);
  });

  test('edge count stays inside the shared CycloneDX bound for a large graph', async () => {
    const packages: Record<string, unknown> = {
      '': {
        name: 'big-app',
        version: '1.0.0',
        dependencies: Object.fromEntries(
          Array.from({ length: 40 }, (_, index) => [`pkg-${index}`, '^1.0.0']),
        ),
      },
    };
    for (let index = 0; index < 40; index += 1) {
      packages[`node_modules/pkg-${index}`] = {
        version: '1.0.0',
        // Each package depends on the next one: a chain, so every node has a child.
        ...(index === 39 ? {} : { dependencies: { [`pkg-${index + 1}`]: '^1.0.0' } }),
      };
    }
    const sca = await runSca(
      snapshot([
        {
          path: 'package.json',
          content: JSON.stringify({
            name: 'big-app',
            version: '1.0.0',
            dependencies: Object.fromEntries(
              Array.from({ length: 40 }, (_, index) => [`pkg-${index}`, '^1.0.0']),
            ),
          }),
        },
        { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages }) },
      ]),
    );
    expect(sca.summary.transitiveGraph).toBe('AVAILABLE');
    expect(sca.sbom.dependencies.length).toBeLessThanOrEqual(SCA_MAX_DEPENDENCIES_PER_SCAN + 1);
    // One root edge (40 direct children) + 39 chain edges (the last package is
    // a leaf): 40 edges for 40 components — inside the 200-component budget.
    expect(sca.sbom.dependencies.length).toBe(40);
    for (const edge of sca.sbom.dependencies) {
      for (const ref of edge.dependsOn) {
        expect(sca.sbom.components.some((component) => component['bom-ref'] === ref)).toBe(true);
      }
    }
    // isScaResult above already re-validated the whole payload against the bound.
  });
});
