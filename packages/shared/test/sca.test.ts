import { describe, expect, test } from 'vitest';
import {
  compareScaDependencies,
  isScaAdvisory,
  isScaDependency,
  isScaManifestResult,
  isScaResult,
  isSbomComponent,
  isSbomDocument,
  isSbomHash,
  SCA_DEPENDENCY_ID_PATTERN,
  SCA_FINGERPRINT_PATTERN,
  SCA_MAX_DEPENDENCIES_PER_SCAN,
  SCA_MAX_MANIFESTS_PER_SCAN,
  type ScaDependency,
  type ScaManifestResult,
  type ScaResult,
  type ScaSummary,
  type SbomDocument,
} from '../src/sca.js';
import { SCAN_FAILURE_CODES, isScanType } from '../src/scans.js';

/**
 * SCA contract guards (Pump 9) — the wire-shape security invariants.
 * These run in `packages/shared` so EVERY consumer (API, web, future
 * CLI) is bound by the same closed contracts.
 */

// The fingerprint MUST be the id source: dep_ + fingerprint[:24].
const FINGERPRINT = `0123456789abcdef01234567${'a'.repeat(40)}`;
const DEPENDENCY_BASE: ScaDependency = {
  dependencyId: 'dep_0123456789abcdef01234567',
  ecosystem: 'npm',
  name: 'express',
  declaredVersion: '^4.18.0',
  versionSource: 'lockfile',
  resolvedVersion: '4.18.2',
  packageManager: 'npm',
  manifestPath: 'package.json',
  lockfilePath: 'package-lock.json',
  dependencyType: 'runtime',
  dependencyClass: 'direct',
  purl: 'pkg:npm/express@4.18.2',
  fingerprint: FINGERPRINT,
};

const SBOM_BASE: SbomDocument = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: 'urn:uuid:01234567-89ab-cdef-0123-456789abcdef',
  version: 1,
  metadata: {
    tools: {
      components: [{ type: 'application', name: 'drobon-sca', version: '1.0.0' }],
    },
    component: {
      type: 'application',
      'bom-ref': 'root',
      name: 'demo-app',
      version: '1.0.0',
    },
  },
  components: [
    {
      type: 'library',
      'bom-ref': 'dep_0123456789abcdef01234567',
      name: 'express',
      version: '4.18.2',
      scope: 'required',
      purl: 'pkg:npm/express@4.18.2',
    },
  ],
  dependencies: [{ ref: 'root', dependsOn: ['dep_0123456789abcdef01234567'] }],
};

const SUMMARY_BASE: ScaSummary = {
  assessmentState: 'NOT_ASSESSED',
  datasetStatus: 'NO_DATA_LOADED',
  providerId: 'none',
  dependenciesTotal: 1,
  directDependencies: 1,
  transitiveDependencies: 0,
  unclassifiedDependencies: 0,
  advisoriesTotal: 0,
  manifestsAnalyzed: 2,
  manifestsPartial: 0,
  manifestsUnsupported: 0,
  manifestsInvalid: 0,
  transitiveGraph: 'AVAILABLE',
  truncated: false,
};

const MANIFEST_BASE: ScaManifestResult = {
  path: 'package.json',
  ecosystem: 'npm',
  status: 'ANALYZED',
  dependencyCount: 1,
};

function fullScaResult(): ScaResult {
  return {
    summary: SUMMARY_BASE,
    dependencies: [DEPENDENCY_BASE],
    advisories: [],
    manifests: [MANIFEST_BASE],
    sbom: SBOM_BASE,
  };
}

describe('SCA contracts: vocabularies and identities', () => {
  test('the dataset lock is structural: NO_DATA_LOADED is the only honest default', () => {
    // With the locked Null provider this is the shape every SCA scan
    // must produce — asserted end-to-end in the API suites too.
    expect(SUMMARY_BASE.assessmentState).toBe('NOT_ASSESSED');
    expect(SUMMARY_BASE.datasetStatus).toBe('NO_DATA_LOADED');
    expect(SUMMARY_BASE.advisoriesTotal).toBe(0);
  });

  test('dependency ids and fingerprints are deterministic shapes (never random UUIDs)', () => {
    expect('dep_0123456789abcdef01234567').toMatch(SCA_DEPENDENCY_ID_PATTERN);
    expect('dep_NOTHEX').not.toMatch(SCA_DEPENDENCY_ID_PATTERN);
    expect('fnd_0123456789abcdef01234567').not.toMatch(SCA_DEPENDENCY_ID_PATTERN);
    expect('a'.repeat(64)).toMatch(SCA_FINGERPRINT_PATTERN);
    expect('a'.repeat(63)).not.toMatch(SCA_FINGERPRINT_PATTERN);
  });

  test('inventory caps are the documented bounded values', () => {
    expect(SCA_MAX_DEPENDENCIES_PER_SCAN).toBe(200);
    expect(SCA_MAX_MANIFESTS_PER_SCAN).toBe(50);
  });

  test('the SCA scan failure codes are part of the shared scan vocabulary', () => {
    for (const code of [
      'SCA_TARGET_NOT_FOUND',
      'SCA_TARGET_TOO_LARGE',
      'SCA_INPUT_INVALID',
      'SCA_MANIFEST_LIMIT_EXCEEDED',
      'SCA_SCAN_TIMEOUT',
    ]) {
      expect(SCAN_FAILURE_CODES).toContain(code);
    }
    expect(isScanType('SCA')).toBe(true);
  });
});

describe('SCA contracts: closed guards reject hostile shapes', () => {
  test('isScaDependency accepts the full honest shape', () => {
    expect(isScaDependency(DEPENDENCY_BASE)).toBe(true);
  });

  test('isScaDependency rejects unknown properties (no smuggling)', () => {
    expect(isScaDependency({ ...DEPENDENCY_BASE, cve: 'CVE-FAKE' })).toBe(false);
    // A hostile own property the parser might forward verbatim.
    expect(isScaDependency({ ...DEPENDENCY_BASE, constructor: { pollute: true } })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, scripts: { postinstall: 'rm -rf /' } })).toBe(false);
  });

  test('isScaDependency rejects out-of-vocabulary and malformed fields', () => {
    expect(isScaDependency({ ...DEPENDENCY_BASE, ecosystem: 'java' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, dependencyType: 'bundled' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, dependencyClass: 'indirect' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, versionSource: 'registry' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, dependencyId: 'dep_XXX' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, fingerprint: 'zzz' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, name: '' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, name: 'x'.repeat(300) })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, manifestPath: '../../etc/passwd' })).toBe(false);
    expect(isScaDependency({ ...DEPENDENCY_BASE, manifestPath: 'C:\\secret\\package.json' })).toBe(false);
    // A lockfilePath without a resolvedVersion is a contradiction.
    expect(
      isScaDependency({
        ...DEPENDENCY_BASE,
        resolvedVersion: undefined,
        lockfilePath: 'package-lock.json',
      }),
    ).toBe(false);
    // resolvedVersion requires lockfile provenance (manifests carry
    // ranges — a "resolved" manifest version is a fabricated pin).
    expect(isScaDependency({ ...DEPENDENCY_BASE, versionSource: 'manifest' })).toBe(false);
  });

  test('isScaAdvisory: closed shape, bounded text, real severity only', () => {
    const advisory = {
      id: 'GHSA-xxxx-yyyy-zzzz',
      severity: 'HIGH',
      dependencyId: 'dep_0123456789abcdef01234567',
      ecosystem: 'npm',
      name: 'express',
      version: '4.18.2',
      summary: 'Verified advisory from a loaded dataset.',
      url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
    };
    expect(isScaAdvisory(advisory)).toBe(true);
    expect(isScaAdvisory({ ...advisory, extra: 1 })).toBe(false);
    expect(isScaAdvisory({ ...advisory, severity: 'EXTREME' })).toBe(false);
    expect(isScaAdvisory({ ...advisory, id: '' })).toBe(false);
    expect(isScaAdvisory({ ...advisory, summary: 'x'.repeat(500) })).toBe(false);
    // The matched dependency must be a real dependency id shape.
    expect(isScaAdvisory({ ...advisory, dependencyId: 'CVE-FAKE' })).toBe(false);
  });

  test('isScaManifestResult: statuses and ecosystems stay closed', () => {
    expect(isScaManifestResult(MANIFEST_BASE)).toBe(true);
    expect(
      isScaManifestResult({
        ...MANIFEST_BASE,
        status: 'PARTIAL',
        dependencyCount: 500,
        note: 'parser limit reached',
      }),
    ).toBe(true);
    expect(isScaManifestResult({ ...MANIFEST_BASE, status: 'EXPLODED' })).toBe(false);
    expect(isScaManifestResult({ ...MANIFEST_BASE, ecosystem: 'gem' })).toBe(false);
    expect(isScaManifestResult({ ...MANIFEST_BASE, dependencyCount: -1 })).toBe(false);
    expect(isScaManifestResult({ ...MANIFEST_BASE, dependencyCount: 1.5 })).toBe(false);
    expect(isScaManifestResult({ ...MANIFEST_BASE, note: 'x'.repeat(300) })).toBe(false);
    // Paths stay bounded and traversal-free by length rules.
    expect(isScaManifestResult({ ...MANIFEST_BASE, path: `${'x'.repeat(200)}/package.json` })).toBe(false);
  });

  test('SBOM guards: CycloneDX subset only, deterministic serial, no invented hashes', () => {
    expect(isSbomDocument(SBOM_BASE)).toBe(true);
    expect(isSbomDocument({ ...SBOM_BASE, bomFormat: 'SPDX' })).toBe(false);
    expect(isSbomDocument({ ...SBOM_BASE, specVersion: '1.6' })).toBe(false);
    expect(isSbomDocument({ ...SBOM_BASE, serialNumber: 'not-a-urn' })).toBe(false);
    // Hashes are integrity strings, never file paths or URLs.
    const DIGEST = 'QWJjZGVmZ2hpamtsbW5vcFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg==';
    expect(isSbomHash({ alg: 'SHA-512', content: DIGEST })).toBe(true);
    expect(isSbomHash({ alg: 'MD5', content: DIGEST })).toBe(false);
    expect(isSbomHash({ alg: 'SHA-512', content: 'aaaa' })).toBe(false); // too short
    expect(isSbomHash({ alg: 'SHA-512', content: 'https://evil.test/x' })).toBe(false);
    expect(isSbomHash({ alg: 'SHA-512', content: '/etc/passwd' })).toBe(false);
    expect(isSbomHash({ alg: 'SHA-512', content: 'a'.repeat(11) })).toBe(false); // not %4
    expect(
      isSbomComponent({
        ...SBOM_BASE.components[0]!,
        hashes: [{ alg: 'SHA-256', content: '/etc/passwd' }],
      }),
    ).toBe(false);
  });

  test('isScaResult: the whole payload is guarded, top to bottom', () => {
    expect(isScaResult(fullScaResult())).toBe(true);
    expect(isScaResult({ ...fullScaResult(), extra: true })).toBe(false);
    expect(isScaResult({ ...fullScaResult(), dependencies: [{ junk: true }] })).toBe(false);
    expect(isScaResult({ ...fullScaResult(), advisories: [{ junk: true }] })).toBe(false);
    expect(isScaResult({ ...fullScaResult(), manifests: [{ junk: true }] })).toBe(false);
    expect(isScaResult({ ...fullScaResult(), sbom: { junk: true } })).toBe(false);
    // Cross-field honesty: ASSESSED with a null provider is a lie.
    expect(
      isScaResult({
        ...fullScaResult(),
        summary: { ...SUMMARY_BASE, assessmentState: 'ASSESSED', providerId: 'none' },
      }),
    ).toBe(false);
    // Cross-field honesty: advisoriesTotal must match the array.
    expect(
      isScaResult({
        ...fullScaResult(),
        summary: { ...SUMMARY_BASE, advisoriesTotal: 3 },
        advisories: [],
      }),
    ).toBe(false);
    // Cross-field honesty: a manifest cannot exceed the manifest cap.
    expect(
      isScaResult({
        ...fullScaResult(),
        manifests: Array.from({ length: SCA_MAX_MANIFESTS_PER_SCAN + 1 }, (_, i) => ({
          ...MANIFEST_BASE,
          path: `p${i}/package.json`,
        })),
      }),
    ).toBe(false);
  });
});

describe('SCA contracts: deterministic ordering', () => {
  test('compareScaDependencies yields a stable total order across shuffles', () => {
    const a: ScaDependency = { ...DEPENDENCY_BASE, name: 'aaa', ecosystem: 'npm' };
    const b: ScaDependency = { ...DEPENDENCY_BASE, name: 'aaa', ecosystem: 'pypi' };
    const c: ScaDependency = { ...DEPENDENCY_BASE, name: 'bbb', ecosystem: 'npm' };
    // Ecosystem first (npm < pypi), then name — so [a, c, b].
    const ordered = [a, c, b];
    for (const shuffled of [
      [c, b, a],
      [b, c, a],
      [c, a, b],
    ]) {
      expect([...shuffled].sort(compareScaDependencies)).toEqual(ordered);
    }
  });
});
