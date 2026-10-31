import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { satisfiesRange, validateRange } from '../src/scans/sca/range.js';
import { createFilesystemIntelligenceProvider } from '../src/scans/sca/filesystemProvider.js';

/** Expected npm/PEP 440 cases were checked offline against node-semver and pip's vendored packaging. */
describe('conservative npm advisory range evaluation', () => {
  test('prereleases require an explicit same-version prerelease comparator', () => {
    expect(() => satisfiesRange('npm', '1.5.0-beta.1', '>=1.0.0 <2.0.0')).toThrow(/prerelease/);
    expect(() => satisfiesRange('npm', '1.6.0-beta.1', '>=1.5.0-beta.1 <2.0.0')).toThrow(/prerelease/);
    expect(satisfiesRange('npm', '1.5.0-beta.2', '>=1.5.0-beta.1 <2.0.0')).toBe(true);
    expect(satisfiesRange('npm', '1.5.0-beta.1', '=1.5.0-beta.1')).toBe(true);
    expect(satisfiesRange('npm', '1.5.0', '>=1.0.0 <2.0.0')).toBe(true);
    expect(satisfiesRange('npm', '2.0.0', '>=1.0.0 <2.0.0')).toBe(false);
  });

  test('a definite OR match is not masked by an ambiguous prerelease branch', () => {
    expect(satisfiesRange('npm', '1.5.0-beta.2', '>=1.0.0 <2.0.0 || >=1.5.0-beta.1 <2.0.0')).toBe(true);
    expect(satisfiesRange('npm', '1.5.0-beta.2', '>=1.5.0-beta.1 <2.0.0 || >=1.0.0 <2.0.0')).toBe(true);
    expect(() => satisfiesRange('npm', '1.5.0-beta.2', '>=1.0.0 <2.0.0 || >=3.0.0')).toThrow(/prerelease/);
  });

  test('invalid or imprecise versions never silently become a non-match', () => {
    for (const version of ['01.2.3', '1.2.3-alpha.01', '1.2.3-alpha..1', '1.2.3+foo..bar', '9007199254740993.0.0']) {
      expect(() => satisfiesRange('npm', version, '<2.0.0'), version).toThrow();
    }
    for (const range of ['>=2.0.0 <01.0.0', '1.x.3', '>=9007199254740993.0.0']) {
      expect(validateRange('npm', range), range).not.toBeNull();
      expect(() => satisfiesRange('npm', '1.0.0', range), range).toThrow();
    }
    expect(() => satisfiesRange('npm', '1.0.0', '<1.0.0 >=1.2')).toThrow(/wildcard/);
  });
});

describe('conservative PEP 440 advisory range evaluation', () => {
  test('development releases sort before alpha and are not misreported as later', () => {
    expect(satisfiesRange('pypi', '1.0.dev1', '<=1.0a1')).toBe(true);
    expect(satisfiesRange('pypi', '1.0.dev1', '>=1.0a1')).toBe(false);
    expect(satisfiesRange('pypi', '1.0a1.dev1', '<=1.0a1')).toBe(true);
    expect(satisfiesRange('pypi', '1.0.post1.dev1', '>=1.0,<=1.0.post1.dev2')).toBe(true);
  });

  test('explicit exclusive prerelease bounds include earlier/later prereleases for advisory coverage', () => {
    expect(satisfiesRange('pypi', '0.5.0b3.dev100', '<0.5.0b3.dev101')).toBe(true);
    expect(satisfiesRange('pypi', '0.5.0b3.dev101', '<0.5.0b3.dev101')).toBe(false);
    expect(satisfiesRange('pypi', '0.5.0b3.dev102', '>0.5.0b3.dev101')).toBe(true);
    expect(satisfiesRange('pypi', '1.0rc1', '<1.0rc2')).toBe(true);
  });

  test('epoch-aware wildcard and compatible ranges do not cross version epochs', () => {
    expect(satisfiesRange('pypi', '1!1.0', '==1.*')).toBe(false);
    expect(satisfiesRange('pypi', '1!1.0', '!=1.*')).toBe(true);
    expect(satisfiesRange('pypi', '1!1.0', '~=1.0')).toBe(false);
    expect(satisfiesRange('pypi', '1!1.0', '~=1!1.0')).toBe(true);
    expect(satisfiesRange('pypi', '1!1.1', '~=1!1.0')).toBe(true);
    expect(satisfiesRange('pypi', '2!1.0', '~=1!1.0')).toBe(false);
  });

  test('exclusive ordered bounds respect same-base post, pre and local exclusions', () => {
    expect(satisfiesRange('pypi', '1.0+local', '>1.0rc1')).toBe(false);
    expect(satisfiesRange('pypi', '1.0.post1', '>1.0rc1')).toBe(false);
    expect(satisfiesRange('pypi', '1.0rc1', '>=1.0rc1,<1.0.post1')).toBe(false);
    expect(satisfiesRange('pypi', '1.0.post1.dev1', '>=1.0rc1,<1.0.post1')).toBe(false);
    expect(satisfiesRange('pypi', '1.0.post2', '>1.0.post1')).toBe(true);
    expect(satisfiesRange('pypi', '1.0.1+local', '>1.0')).toBe(true);
  });

  test('ambiguous prereleases and unsupported wildcard prefixes are unknown', () => {
    expect(() => satisfiesRange('pypi', '1.2rc1', '>=1.0,<2.0')).toThrow(/prerelease/);
    expect(satisfiesRange('pypi', '1.2rc1', '>=1.0rc1,<2.0')).toBe(true);
    expect(() => satisfiesRange('pypi', '1.0rc1', '==1.0rc1.*')).toThrow(/wildcard prefix/);
    expect(() => satisfiesRange('pypi', '1.0', '<1.0,==1.0rc1.*')).toThrow(/wildcard prefix/);
    expect(() => satisfiesRange('pypi', '9007199254740993.0', '<2.0')).toThrow(/precision/);
  });
});

describe('filesystem intelligence propagation', () => {
  test('ambiguous prerelease is partial rather than a match or a clean assessment', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-range-fixture-'));
    try {
      const dir = join(root, 'vuln-intel', 'npm');
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'synthetic.json'), JSON.stringify({
        fixture: false, id: 'GHSA-aaaa-bbbb-cccc', ecosystem: 'npm', package: 'fixture-package',
        summary: 'Synthetic advisory.', severity: 'HIGH', affected: [{ range: '>=1.0.0 <2.0.0' }],
      }));
      const result = await createFilesystemIntelligenceProvider({ datasetPath: root }).assess([
        { dependencyId: 'dep_synthetic', ecosystem: 'npm', name: 'fixture-package', version: '1.5.0-beta.1' },
      ]);
      expect(result.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(result.incomplete).toBe(true);
      expect(result.advisories).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
