import { describe, expect, test } from 'vitest';
import { isScaResult } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';
import { parseCompiledRequirements, parsePipfile, parsePipfileLock, parseUvLock } from '../src/scans/sca/parsers.js';

/**
 * PyPI lock formats beyond Poetry (P2-11).
 *
 * Two very different honesty levels are pinned here:
 * - `uv.lock` states resolved packages AND inter-package dependencies, so it
 *   can evidence a real graph;
 * - `Pipfile.lock` pins every resolved package but records NO relationship, so
 *   it upgrades version evidence and must never claim a graph.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000041';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000042';

function scanRecord(): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000043',
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

const UV_PYPROJECT = [
  '[project]',
  'name = "demo-uv"',
  'version = "0.1.0"',
  'dependencies = [',
  '  "requests>=2.0",',
  ']',
].join('\n');

const UV_LOCK = [
  'version = 1',
  'requires-python = ">=3.9"',
  '',
  '[[package]]',
  'name = "demo-uv"',
  'version = "0.1.0"',
  'source = { editable = "." }',
  'dependencies = [',
  '    { name = "requests" },',
  ']',
  '',
  '[package.metadata]',
  'requires-dist = [{ name = "requests", specifier = ">=2.0" }]',
  '',
  '[[package]]',
  'name = "requests"',
  'version = "2.31.0"',
  'source = { registry = "https://pypi.org/simple" }',
  'dependencies = [',
  '    { name = "certifi" },',
  '    { name = "urllib3" },',
  ']',
  'sdist = { url = "https://files.example/requests.tar.gz", hash = "sha256:aaa" }',
  '',
  '[[package]]',
  'name = "certifi"',
  'version = "2023.7.22"',
  'source = { registry = "https://pypi.org/simple" }',
  '',
  '[[package]]',
  'name = "urllib3"',
  'version = "2.0.4"',
  'source = { registry = "https://pypi.org/simple" }',
].join('\n');

const PIPFILE = [
  '[[source]]',
  'url = "https://pypi.org/simple"',
  'verify_ssl = true',
  'name = "pypi"',
  '',
  '[packages]',
  'requests = "*"',
  'flask = { version = "==2.3.2", extras = ["async"] }',
  '',
  '[dev-packages]',
  'pytest = "*"',
].join('\n');

const PIPFILE_LOCK = JSON.stringify({
  _meta: { hash: { sha256: 'aaa' }, 'pipfile-spec': 6 },
  default: {
    requests: { version: '==2.31.0', hashes: [] },
    certifi: { version: '==2023.7.22' },
    urllib3: { version: '==2.0.4' },
    flask: { version: '==2.3.2' },
    'vcs-dep': { git: 'https://example.invalid/repo.git' },
  },
  develop: { pytest: { version: '==7.4.0' } },
});

describe('uv.lock parsing (P2-11)', () => {
  test('the project package is the root, never a dependency', () => {
    const parsed = parseUvLock(UV_LOCK, 'uv.lock', ['requests']);
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dependency) => dependency.name).sort()).toEqual([
      'certifi', 'requests', 'urllib3',
    ]);
    expect(parsed.rootName).toBe('demo-uv');
    expect(parsed.rootVersion).toBe('0.1.0');
    expect(parsed.edges.map((edge) => `${edge.from}->${edge.to}`).sort()).toEqual([
      '->requests@2.31.0',
      'requests@2.31.0->certifi@2023.7.22',
      'requests@2.31.0->urllib3@2.0.4',
    ]);
    expect(parsed.unresolvedEdges).toBe(0);
    expect(parsed.directNames).toEqual(['requests']);
  });

  test('a dependency naming a package the lock does not list stays unresolved', () => {
    const parsed = parseUvLock(
      [
        '[[package]]',
        'name = "demo"',
        'version = "1.0.0"',
        'source = { editable = "." }',
        'dependencies = [',
        '    { name = "missing-pkg" },',
        ']',
      ].join('\n'),
      'uv.lock',
    );
    expect(parsed.edges).toEqual([]);
    expect(parsed.unresolvedEdges).toBe(1);
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.note).toContain('could not be resolved');
  });

  test('an ambiguous name (several locked versions) produces no invented edge', () => {
    const parsed = parseUvLock(
      [
        '[[package]]',
        'name = "demo"',
        'version = "1.0.0"',
        'source = { editable = "." }',
        'dependencies = [',
        '    { name = "idna" },',
        ']',
        '[[package]]',
        'name = "idna"',
        'version = "3.4"',
        '[[package]]',
        'name = "idna"',
        'version = "3.6"',
      ].join('\n'),
      'uv.lock',
    );
    expect(parsed.edges).toEqual([]);
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.note).toContain('matched several locked versions');
    // An explicitly pinned reference still resolves.
    const pinned = parseUvLock(
      [
        '[[package]]',
        'name = "idna"',
        'version = "3.4"',
        '[[package]]',
        'name = "idna"',
        'version = "3.6"',
        '[[package]]',
        'name = "demo"',
        'version = "1.0.0"',
        'source = { editable = "." }',
        'dependencies = [',
        '    { name = "idna", version = "3.6" },',
        ']',
      ].join('\n'),
      'uv.lock',
    );
    expect(pinned.edges).toEqual([{ from: '', to: 'idna@3.6' }]);
  });

  test('hostile names/versions and a table-less file are refused honestly', () => {
    const hostile = parseUvLock(
      [
        '[[package]]',
        'name = "../../etc/passwd"',
        'version = "1.0.0"',
        '[[package]]',
        'name = "ok"',
        `version = "1.0${String.fromCharCode(1)}0"`,
        '[[package]]',
        'name = "good"',
        'version = "1.2.3"',
      ].join('\n'),
      'uv.lock',
    );
    expect(hostile.dependencies.map((dependency) => dependency.name)).toEqual(['good']);
    expect(hostile.note).toContain('2 [[package]] entries had no usable name/version.');

    const empty = parseUvLock('version = 1\nrequires-python = ">=3.9"', 'uv.lock');
    expect(empty.status).toBe('INVALID_INPUT');
    expect(empty.dependencies).toEqual([]);
  });
});

describe('Pipfile / Pipfile.lock parsing (P2-11)', () => {
  test('a Pipfile declares direct requirements only', () => {
    const parsed = parsePipfile(PIPFILE, 'Pipfile');
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dependency) => dependency.name).sort()).toEqual([
      'flask', 'pytest', 'requests',
    ]);
    expect(parsed.dependencies.find((dependency) => dependency.name === 'flask')).toMatchObject({
      declaredVersion: '==2.3.2',
      dependencyType: 'runtime',
      versionSource: 'manifest',
    });
    expect(parsed.dependencies.find((dependency) => dependency.name === 'pytest')?.dependencyType)
      .toBe('development');
    expect(parsePipfile('[foo]\nbar = "1"', 'Pipfile').status).toBe('UNSUPPORTED');
  });

  test('a Pipfile.lock pins versions and states no edges at all', () => {
    const parsed = parsePipfileLock(PIPFILE_LOCK, 'Pipfile.lock', ['requests', 'flask', 'pytest']);
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.edges).toEqual([]);
    expect(parsed.note).toContain('records no inter-package edges');
    const byName = new Map(parsed.dependencies.map((dependency) => [dependency.name, dependency]));
    expect(byName.get('requests')).toMatchObject({
      ecosystem: 'pypi',
      resolvedVersion: '2.31.0',
      versionSource: 'lockfile',
      dependencyClass: 'direct',
      packageManager: 'pipenv',
    });
    expect(byName.get('certifi')?.dependencyClass).toBe('transitive');
    expect(byName.get('pytest')).toMatchObject({
      dependencyClass: 'direct',
      dependencyType: 'development',
    });
    // A VCS requirement has no version: it is counted, never invented.
    expect(byName.has('vcs-dep')).toBe(false);
    expect(parsed.note).toContain('1 locked entry had no usable version.');
  });

  test('a Pipfile.lock without a Pipfile leaves every class unknown', () => {
    const parsed = parsePipfileLock(PIPFILE_LOCK, 'Pipfile.lock');
    expect(parsed.dependencies.every((dependency) => dependency.dependencyClass === 'unknown')).toBe(true);
    expect(parsePipfileLock('{not json', 'Pipfile.lock').status).toBe('INVALID_INPUT');
    expect(parsePipfileLock(JSON.stringify({ _meta: {} }), 'Pipfile.lock').status).toBe('INVALID_INPUT');
    expect(parsePipfileLock(JSON.stringify({ default: { __proto__: { version: '==1.0.0' } } }), 'Pipfile.lock').dependencies)
      .toEqual([]);
  });
});

describe('SCA engine: uv.lock and Pipfile.lock end-to-end', () => {
  test('a uv project reports an evidenced PyPI graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'pyproject.toml', content: UV_PYPROJECT },
          { path: 'uv.lock', content: UV_LOCK },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    expect(isScaResult(sca)).toBe(true);

    const byName = new Map(sca.dependencies.map((dependency) => [dependency.name, dependency]));
    expect([...byName.keys()].sort()).toEqual(['certifi', 'requests', 'urllib3']);
    expect(byName.get('requests')).toMatchObject({
      dependencyClass: 'direct',
      resolvedVersion: '2.31.0',
      versionSource: 'lockfile',
      lockfilePath: 'uv.lock',
      packageManager: 'pip',
    });
    expect(byName.get('certifi')?.dependencyClass).toBe('transitive');
    expect(sca.summary).toMatchObject({
      dependenciesTotal: 3,
      directDependencies: 1,
      transitiveDependencies: 2,
      unclassifiedDependencies: 0,
      transitiveGraph: 'AVAILABLE',
    });
    // The SBOM root is the declared project, and the graph is really there.
    const rootComponent = sca.sbom.metadata.component;
    if (rootComponent === undefined) return;
    expect(rootComponent).toMatchObject({ name: 'demo-uv', version: '0.1.0' });
    const rootEdge = sca.sbom.dependencies.find((edge) => edge.ref === rootComponent['bom-ref']);
    expect(rootEdge?.dependsOn).toEqual([byName.get('requests')?.fingerprint]);
    expect(sca.sbom.dependencies.flatMap((edge) => edge.dependsOn)).toHaveLength(3);
  });

  test('a Pipenv project reports resolved versions but never a graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'Pipfile', content: PIPFILE },
          { path: 'Pipfile.lock', content: PIPFILE_LOCK },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;

    const byName = new Map(sca.dependencies.map((dependency) => [dependency.name, dependency]));
    // `flask` is declared but VCS-pinned in the fixture: the declaration stays.
    expect(byName.get('flask')).toMatchObject({ versionSource: 'lockfile', resolvedVersion: '2.3.2' });
    expect(byName.get('requests')?.resolvedVersion).toBe('2.31.0');
    expect(byName.get('certifi')?.dependencyClass).toBe('transitive');
    // No lock format here states edges, so the graph claim must stay false.
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    // requests/flask/pytest are declared directly; only certifi+urllib3 remain.
    expect(sca.summary.directDependencies).toBe(3);
    expect(sca.summary.transitiveDependencies).toBe(2);
    // Declared ranges survive as evidence next to the resolved version.
    expect(byName.get('flask')?.declaredVersion).toBe('==2.3.2');
  });

  test('the same uv snapshot always yields the same inventory (deterministic)', async () => {
    const engine = createScaEngine({
      sources: providerFor(
        snapshot([
          { path: 'pyproject.toml', content: UV_PYPROJECT },
          { path: 'uv.lock', content: UV_LOCK },
        ]),
      ),
    });
    const first = await engine.execute(scanRecord(), ctx);
    const second = await engine.execute(scanRecord(), ctx);
    expect(first.kind).toBe('completed');
    expect(second.kind).toBe('completed');
    if (first.kind !== 'completed' || second.kind !== 'completed') return;
    expect(second.sca?.dependencies).toEqual(first.sca?.dependencies);
    expect(second.sca?.sbom).toEqual(first.sca?.sbom);
    expect(second.sca?.summary).toEqual(first.sca?.summary);
  });
});

const COMPILED_REQUIREMENTS = [
  '# This file is autogenerated by pip-compile.',
  'certifi==2023.7.22',
  '    # via requests',
  'charset-normalizer==3.2.0',
  '    # via requests',
  'requests==2.31.0',
  '    # via -r requirements.in',
  'urllib3==2.0.4',
  '    # via requests',
].join('\n');

describe('pip-compile provenance (P2-11)', () => {
  test('`# via` lines become real edges, `-r` marks the direct set', () => {
    const parsed = parseCompiledRequirements(COMPILED_REQUIREMENTS, 'requirements.txt');
    expect(parsed.graphEvidence).toBe(true);
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dependency) => dependency.name).sort()).toEqual([
      'certifi', 'charset-normalizer', 'requests', 'urllib3',
    ]);
    expect(parsed.dependencies.every((dependency) => dependency.versionSource === 'lockfile')).toBe(true);
    expect(parsed.directNames).toEqual(['requests']);
    expect(parsed.edges.map((edge) => `${edge.from}->${edge.to}`).sort()).toEqual([
      '->requests@2.31.0',
      'requests@2.31.0->certifi@2023.7.22',
      'requests@2.31.0->charset-normalizer@3.2.0',
      'requests@2.31.0->urllib3@2.0.4',
    ]);
  });

  test('hash-pinned pip-compile output keeps its provenance', () => {
    // `pip-compile --generate-hashes` joins the requirement, its hashes and the
    // `# via` marker into one backslash-continued logical line.
    const compiled = [
      'requests==2.31.0 \\',
      '    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\',
      '    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \\',
      '    # via -r requirements.in',
      'certifi==2023.7.22 \\',
      '    --hash=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \\',
      '    # via requests',
    ].join('\n');
    const parsed = parseCompiledRequirements(compiled, 'requirements.txt');
    expect(parsed.graphEvidence).toBe(true);
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.directNames).toEqual(['requests']);
    expect(parsed.edges.map((edge) => `${edge.from}->${edge.to}`).sort()).toEqual([
      '->requests@2.31.0',
      'requests@2.31.0->certifi@2023.7.22',
    ]);
    // The recorded hash is real integrity evidence, kept with the node.
    expect(parsed.dependencies.find((dependency) => dependency.name === 'requests')?.integrity)
      .toBe('sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  });

  test('a hand-written file has no provenance and therefore no graph', () => {
    const parsed = parseCompiledRequirements('flask==2.3.2\nrequests==2.31.0\n', 'requirements.txt');
    expect(parsed.graphEvidence).toBe(false);
    expect(parsed.edges).toEqual([]);
    expect(parsed.dependencies).toEqual([]);
  });

  test('a multi-parent block and an unpinned parent are handled honestly', () => {
    const multi = parseCompiledRequirements(
      [
        'idna==3.4',
        '    # via',
        '    #   requests',
        '    #   httpx',
        'requests==2.31.0',
        '    # via -r requirements.in',
        'httpx==0.24.0',
        '    # via -r requirements.in',
      ].join('\n'),
      'requirements.txt',
    );
    expect(multi.edges.map((edge) => `${edge.from}->${edge.to}`).sort()).toEqual([
      '->httpx@0.24.0',
      '->requests@2.31.0',
      'httpx@0.24.0->idna@3.4',
      'requests@2.31.0->idna@3.4',
    ]);
    expect(multi.status).toBe('ANALYZED');

    const dangling = parseCompiledRequirements(
      ['idna==3.4', '    # via not-pinned-anywhere', 'requests==2.31.0', '    # via -r requirements.in'].join('\n'),
      'requirements.txt',
    );
    expect(dangling.status).toBe('PARTIAL');
    expect(dangling.unresolvedEdges).toBe(1);
    expect(dangling.edges).toEqual([{ from: '', to: 'requests@2.31.0' }]);
  });

  test('a pin without provenance is counted, not guessed', () => {
    const parsed = parseCompiledRequirements(
      ['requests==2.31.0', '    # via -r requirements.in', 'mystery==1.0.0'].join('\n'),
      'requirements.txt',
    );
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.note).toContain('1 pinned requirement(s) carry no \'# via\' provenance');
    // It still becomes a node (a real pinned installation) — just no edge.
    expect(parsed.dependencies.map((dependency) => dependency.name).sort()).toEqual(['mystery', 'requests']);
    expect(parsed.edges).toEqual([{ from: '', to: 'requests@2.31.0' }]);
  });
});

describe('SCA engine: pip-compile requirements end-to-end', () => {
  test('a compiled requirements file yields an evidenced PyPI graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'requirements.txt', content: COMPILED_REQUIREMENTS }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    const byName = new Map(sca.dependencies.map((dependency) => [dependency.name, dependency]));
    expect(byName.get('requests')).toMatchObject({
      dependencyClass: 'direct',
      resolvedVersion: '2.31.0',
      versionSource: 'lockfile',
      lockfilePath: 'requirements.txt',
    });
    expect(byName.get('certifi')?.dependencyClass).toBe('transitive');
    expect(sca.summary).toMatchObject({
      dependenciesTotal: 4,
      directDependencies: 1,
      transitiveDependencies: 3,
      transitiveGraph: 'AVAILABLE',
    });
    // A requirements file declares no project identity, so there is no root
    // component to hang root edges on; the package→package edges are present.
    expect(sca.sbom.metadata.component).toBeUndefined();
    expect(sca.sbom.dependencies.flatMap((edge) => edge.dependsOn)).toHaveLength(3);
  });

  test('a hand-written requirements file still claims no graph', async () => {
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'requirements.txt', content: 'flask==2.3.2\nrequests==2.31.0\n' }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const sca = outcome.sca;
    if (sca === undefined) return;
    expect(sca.summary.transitiveGraph).toBe('UNAVAILABLE');
    expect(sca.sbom.dependencies).toEqual([]);
    expect(sca.summary.directDependencies).toBe(2);
  });
});
