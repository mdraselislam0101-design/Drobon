import { describe, expect, test } from 'vitest';
import {
  normalizeNpmName,
  normalizePypiName,
  parsePackageJson,
  parsePackageLock,
  parsePyprojectToml,
  parseRequirementLine,
  parseRequirementsTxt,
  SCA_PARSER_MAX_ENTRIES,
} from '../src/scans/sca/parsers.js';

/**
 * SCA parser tests (Pump 9) — the defensive core. Every hostile shape
 * from the pump spec is exercised here: malformed JSON, prototype
 * pollution, deeply nested payloads, huge dependency maps, invalid
 * names/versions, duplicate declarations and unsupported constructs.
 * The engine/HTTP layers are covered by scaEngine/scaApi.
 */

describe('ecosystem name normalization', () => {
  test('npm: plain, scoped, and defensive lowercase', () => {
    expect(normalizeNpmName('lodash')).toBe('lodash');
    expect(normalizeNpmName('@scope/pkg')).toBe('@scope/pkg');
    expect(normalizeNpmName('Left-Pad')).toBe('left-pad');
  });

  test('npm: rejects traversal-shaped, empty, unicode and malformed names', () => {
    expect(normalizeNpmName('')).toBeUndefined();
    expect(normalizeNpmName('@broken')).toBeUndefined();
    expect(normalizeNpmName('../evil')).toBeUndefined();
    expect(normalizeNpmName('a/b/c')).toBeUndefined();
    expect(normalizeNpmName('.hidden')).toBeUndefined();
    expect(normalizeNpmName('pkg\x00null')).toBeUndefined();
    expect(normalizeNpmName(`${'x'.repeat(300)}`)).toBeUndefined();
  });

  test('pypi: PEP 503 normalization (case + separator runs)', () => {
    expect(normalizePypiName('Flask')).toBe('flask');
    expect(normalizePypiName('zope.interface')).toBe('zope-interface');
    expect(normalizePypiName('python_json_logger')).toBe('python-json-logger');
    expect(normalizePypiName('A..B__C')).toBe('a-b-c');
  });

  test('pypi: rejects junk', () => {
    expect(normalizePypiName('')).toBeUndefined();
    expect(normalizePypiName('-leading')).toBeUndefined();
    expect(normalizePypiName('has space')).toBeUndefined();
  });
});

describe('package.json parsing', () => {
  test('extracts all four sections with types, ranges, and the root identity', () => {
    const parsed = parsePackageJson(
      JSON.stringify({
        name: 'Demo-App',
        version: '2.1.0',
        dependencies: { lodash: '^4.17.21', '@scope/tool': '~2.0.0' },
        devDependencies: { vitest: '^1.0.0' },
        optionalDependencies: { 'fsevents': '^2.3.2' },
        peerDependencies: { react: '^18.0.0' },
      }),
      'package.json',
    );
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.rootName).toBe('demo-app');
    expect(parsed.rootVersion).toBe('2.1.0');
    expect(parsed.dependencies).toHaveLength(5);
    const byName = new Map(parsed.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('lodash')).toMatchObject({
      declaredVersion: '^4.17.21',
      dependencyType: 'runtime',
      dependencyClass: 'direct',
      versionSource: 'manifest',
      ecosystem: 'npm',
    });
    expect(byName.get('@scope/tool')?.declaredVersion).toBe('~2.0.0');
    expect(byName.get('vitest')?.dependencyType).toBe('development');
    expect(byName.get('fsevents')?.dependencyType).toBe('optional');
    expect(byName.get('react')?.dependencyType).toBe('peer');
    expect(parsed.directNames).toContain('lodash');
  });

  test('duplicate names across sections: fixed precedence (runtime wins)', () => {
    const parsed = parsePackageJson(
      '{"dependencies":{"x":"1.0.0"},"devDependencies":{"x":"2.0.0"},"peerDependencies":{"x":"3.0.0"}}',
      'package.json',
    );
    expect(parsed.dependencies).toHaveLength(1);
    expect(parsed.dependencies[0]).toMatchObject({
      name: 'x',
      declaredVersion: '1.0.0',
      dependencyType: 'runtime',
    });
  });

  test('prototype pollution keys are skipped, never treated as data', () => {
    const parsed = parsePackageJson(
      '{"dependencies":{"lodash":"1.0.0","__proto__":{"admin":true},"constructor":{"x":1},"prototype":"1"}}',
      'package.json',
    );
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(['lodash']);
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
  });

  test('deeply nested malicious JSON is ignored by construction (no recursion)', () => {
    let deep = '{"a":1}';
    for (let depth = 0; depth < 200; depth += 1) {
      deep = `{"x":${deep}}`;
    }
    const parsed = parsePackageJson(
      `{"dependencies":{"lodash":"1.0.0","evil":${deep}}}`,
      'package.json',
    );
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(['lodash']);
  });

  test('huge dependency maps are capped → PARTIAL with an honest note', () => {
    const map: Record<string, string> = {};
    for (let index = 0; index < SCA_PARSER_MAX_ENTRIES + 50; index += 1) {
      map[`pkg-${index}`] = '^1.0.0';
    }
    const parsed = parsePackageJson(
      JSON.stringify({ dependencies: map }),
      'package.json',
    );
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.dependencies).toHaveLength(SCA_PARSER_MAX_ENTRIES);
    expect(parsed.note).toContain('parser limit');
  });

  test('invalid names and non-string versions are dropped, not coerced', () => {
    const parsed = parsePackageJson(
      JSON.stringify({
        dependencies: {
          '../evil': '1.0.0',
          ok: 123,
          also_ok: { version: '1.0.0' },
          valid: '^1.2.3',
        },
      }),
      'package.json',
    );
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(['valid']);
  });

  test('malformed JSON → INVALID_INPUT with a bounded note (no content leak)', () => {
    const parsed = parsePackageJson('{ not json', 'package.json');
    expect(parsed.status).toBe('INVALID_INPUT');
    expect(parsed.note).toBe('Manifest is not valid JSON.');
    expect(parsed.dependencies).toEqual([]);
  });

  test('non-object root → INVALID_INPUT', () => {
    expect(parsePackageJson('[]', 'package.json').status).toBe('INVALID_INPUT');
    expect(parsePackageJson('"string"', 'package.json').status).toBe('INVALID_INPUT');
    expect(parsePackageJson('null', 'package.json').status).toBe('INVALID_INPUT');
  });
});

describe('package-lock.json parsing', () => {
  const LOCK_V3 = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'app',
        version: '1.0.0',
        dependencies: { express: '^4.18.0' },
        devDependencies: { vitest: '^1.0.0' },
      },
      'node_modules/express': {
        version: '4.18.2',
        resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
        integrity: 'sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=',
        dependencies: { accepts: '~1.3.8' },
      },
      'node_modules/accepts': { version: '1.3.8', integrity: 'sha512-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=' },
      'node_modules/@scope/tool': { version: '2.0.1' },
      'node_modules/vitest': { version: '1.2.3', dev: true },
      'node_modules/optional-thing': { version: '0.1.0', optional: true },
      'node_modules/peer-thing': { version: '5.0.0', peer: true },
      'packages/workspace-app': { link: true },
      'node_modules/no-version': { resolved: 'https://example.test/x.tgz' },
    },
  });

  test('v3: direct set from the root entry; nested/scoped/dev/optional/peer entries', () => {
    const parsed = parsePackageLock(LOCK_V3, 'package-lock.json');
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.lockfileVersion).toBe(3);
    expect(parsed.directNames).toEqual(['express', 'vitest']);
    const byName = new Map(parsed.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('express')).toMatchObject({
      resolvedVersion: '4.18.2',
      integrity: 'sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=',
      dependencyClass: 'direct',
      dependencyType: 'runtime',
      versionSource: 'lockfile',
    });
    expect(byName.get('accepts')?.dependencyClass).toBe('transitive');
    expect(byName.get('@scope/tool')?.resolvedVersion).toBe('2.0.1');
    expect(byName.get('vitest')?.dependencyType).toBe('development');
    expect(byName.get('optional-thing')?.dependencyType).toBe('optional');
    expect(byName.get('peer-thing')?.dependencyType).toBe('peer');
    // Workspace links and version-less entries are skipped entirely.
    expect(byName.has('workspace-app')).toBe(false);
    expect(byName.has('no-version')).toBe(false);
  });

  test('nested node_modules paths resolve to the innermost package name', () => {
    const parsed = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { a: '1.0.0' } },
          'node_modules/a': { version: '1.0.0' },
          'node_modules/b': { version: '2.0.0' },
          'node_modules/a/node_modules/c': { version: '3.0.0' },
        },
      }),
      'package-lock.json',
    );
    const names = parsed.dependencies.map((dep) => dep.name).sort();
    expect(names).toEqual(['a', 'b', 'c']);
  });

  test('v1: flat map; class unknown at parse time (companion manifest merges later)', () => {
    const parsed = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          lodash: { version: '4.17.21', integrity: 'sha512-ccccccccccccccccccccccccccccccccccccccccccc=' },
          leftpad: { version: '1.3.0', dev: true },
        },
      }),
      'package-lock.json',
    );
    expect(parsed.lockfileVersion).toBe(1);
    expect(parsed.dependencies).toHaveLength(2);
    expect(parsed.dependencies.every((dep) => dep.dependencyClass === 'unknown')).toBe(true);
    const byName = new Map(parsed.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('lodash')).toMatchObject({
      resolvedVersion: '4.17.21',
      dependencyType: 'runtime',
    });
    expect(byName.get('leftpad')?.dependencyType).toBe('development');
  });

  test('malformed locks → INVALID_INPUT (bad JSON, bad version, empty shape)', () => {
    expect(parsePackageLock('nope{', 'package-lock.json').status).toBe('INVALID_INPUT');
    expect(
      parsePackageLock('{"dependencies":{"x":"not-an-object"}}', 'package-lock.json').status,
    ).toBe('INVALID_INPUT');
    expect(parsePackageLock('{"lockfileVersion":9}', 'package-lock.json').status).toBe(
      'INVALID_INPUT',
    );
    expect(parsePackageLock('{"lockfileVersion":3,"packages":{}}', 'package-lock.json').status).toBe(
      'INVALID_INPUT',
    );
  });

  test('prototype keys in lock maps are skipped', () => {
    const parsed = parsePackageLock(
      '{"lockfileVersion":1,"dependencies":{"lodash":{"version":"1.0.0"},"__proto__":{"version":"9.9.9"}}}',
      'package-lock.json',
    );
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(['lodash']);
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
  });

  test('pathological lockfiles are bounded (entry cap → PARTIAL)', () => {
    const packages: Record<string, unknown> = { '': { dependencies: {} } };
    for (let index = 0; index < SCA_PARSER_MAX_ENTRIES + 10; index += 1) {
      packages[`node_modules/pkg-${index}`] = { version: '1.0.0' };
    }
    const parsed = parsePackageLock(
      JSON.stringify({ lockfileVersion: 3, packages }),
      'package-lock.json',
    );
    expect(parsed.status).toBe('PARTIAL');
    expect(parsed.dependencies).toHaveLength(SCA_PARSER_MAX_ENTRIES);
  });
});

describe('requirements.txt parsing', () => {
  test('pins, ranges, extras, markers, hashes, comments and continuations', () => {
    const parsed = parseRequirementsTxt(
      [
        '# core deps',
        'flask==2.3.2',
        'requests >= 2.28, < 3.0',
        'gunicorn[gevent]==20.1.0 ; python_version >= "3.8"',
        'python_json_logger==2.0.7 --hash=sha256:abc123def456',
        '',
        'scrypt\\',
        '==0.8.20',
        '-r other-requirements.txt',
        '--index-url https://pypi.example.test/simple',
        'https://example.test/pkg.whl',
      ].join('\n'),
      'requirements.txt',
    );
    expect(parsed.status).toBe('ANALYZED');
    const byName = new Map(parsed.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('flask')).toMatchObject({
      declaredVersion: '==2.3.2',
      dependencyType: 'runtime',
      dependencyClass: 'direct',
      versionSource: 'manifest',
      ecosystem: 'pypi',
    });
    expect(byName.get('requests')?.declaredVersion).toBe('>=2.28,<3.0');
    // Extras are stripped; markers stripped; names PEP 503 normalized.
    expect(byName.get('gunicorn')?.declaredVersion).toBe('==20.1.0');
    expect(byName.get('python-json-logger')?.integrity).toBe('sha256:abc123def456');
    // Continuation line joins scrypt + ==0.8.20.
    expect(byName.get('scrypt')?.declaredVersion).toBe('==0.8.20');
    // Options and URLs are skipped (counted, noted, never parsed).
    expect(parsed.note).toContain('option/directive line(s) skipped');
    expect(parsed.dependencies).toHaveLength(5);
  });

  test('invalid requirement lines are dropped, never guessed', () => {
    const names = parseRequirementsTxt(
      ['$$$junk===', 'ok-pkg==1.0', 'has space==1.0', 'pkg==controlled\x01'].join('\n'),
      'requirements.txt',
    ).dependencies.map((dep) => dep.name);
    expect(names).toEqual(['ok-pkg']);
    // A bare name with no specifier IS valid evidence.
    const bare = parseRequirementsTxt('flask\n', 'requirements.txt');
    expect(bare.dependencies).toHaveLength(1);
    expect(bare.dependencies[0]).toMatchObject({ name: 'flask' });
    expect(bare.dependencies[0]?.declaredVersion).toBeUndefined();
  });

  test('preserves distinct declarations for a name and deduplicates identical constraints', () => {
    const parsed = parseRequirementsTxt('flask==1.0\nFlask==2.0\nFLASK==1.0\n', 'requirements.txt');
    expect(parsed.dependencies).toHaveLength(2);
    expect(parsed.dependencies.map((item) => item.declaredVersion)).toEqual(['==1.0', '==2.0']);
  });

  test('line cap → INVALID_INPUT', () => {
    const many = `${'flask==1.0\n'.repeat(10_001)}`;
    expect(parseRequirementsTxt(many, 'requirements.txt').status).toBe('INVALID_INPUT');
  });

  test('parseRequirementLine: URL requirements keep the name, drop the version', () => {
    expect(parseRequirementLine('mypkg @ https://example.test/x.tar.gz')).toEqual({
      name: 'mypkg',
    });
    expect(parseRequirementLine('pkg>=1.0 --hash=sha256:deadbeef')).toEqual({
      name: 'pkg',
      declaredVersion: '>=1.0',
      integrity: 'sha256:deadbeef',
    });
  });
});

describe('pyproject.toml parsing (defensive subset)', () => {
  test('PEP 621 dependencies + optional groups + poetry table', () => {
    const parsed = parsePyprojectToml(
      [
        '[build-system]',
        'requires = ["setuptools>=61"]',
        '',
        '[project]',
        'name = "demo"',
        'version = "1.0.0"',
        'dependencies = [',
        '  "flask>=2.0",',
        '  "requests==2.31.0",',
        ']',
        '',
        '[project.optional-dependencies]',
        'test = ["pytest>=7.0", "pytest-cov[toml]==4.0"]',
        '',
        '[tool.poetry.dependencies]',
        'python = "^3.11"',
        'django = "^4.2"',
        'celery = { version = "==5.3.1", extras = ["redis"] }',
      ].join('\n'),
      'pyproject.toml',
    );
    expect(parsed.status).toBe('ANALYZED');
    const byName = new Map(parsed.dependencies.map((dep) => [dep.name, dep]));
    expect(byName.get('flask')).toMatchObject({
      declaredVersion: '>=2.0',
      dependencyType: 'runtime',
      dependencyClass: 'direct',
    });
    expect(byName.get('requests')?.declaredVersion).toBe('==2.31.0');
    expect(byName.get('pytest')?.dependencyType).toBe('optional');
    expect(byName.get('pytest-cov')?.declaredVersion).toBe('==4.0');
    // poetry: python constraint excluded; string + table constraints read.
    expect(byName.has('python')).toBe(false);
    expect(byName.get('django')?.declaredVersion).toBe('^4.2');
    expect(byName.get('celery')?.declaredVersion).toBe('==5.3.1');
  });

  test('unsupported constructs → UNSUPPORTED with an honest note', () => {
    const parsed = parsePyprojectToml(
      ['[build-system]', 'requires = ["hatchling"]', '[tool.ruff]', 'line-length = 100'].join('\n'),
      'pyproject.toml',
    );
    expect(parsed.status).toBe('UNSUPPORTED');
    expect(parsed.note).toContain('No supported dependency declaration found');
  });

  test('shell-looking strings inside manifests are DATA (never executed)', () => {
    // The hostile manifest: a postinstall hook that would create a
    // marker file if anything ever executed it. Parsers must treat it
    // as inert text (execution-safety is proven at the engine level
    // by the absence of the marker file after a scan).
    const hostile = JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'touch /tmp/pump9-sca-marker' },
      dependencies: { lodash: '^4.0.0' },
    });
    const parsed = parsePackageJson(hostile, 'package.json');
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(['lodash']);
    expect(parsed.rootName).toBe('evil-pkg');
  });

  test('control characters in TOML values drop the malformed element', () => {
    const parsed = parsePyprojectToml(
      '[project]\ndependencies = ["pkg\x11>=1.0", "flask>=2.0"]',
      'pyproject.toml',
    );
    // The malformed element is dropped; the well-formed one survives.
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.dependencies).toHaveLength(1);
    expect(parsed.dependencies[0]).toMatchObject({ name: 'flask', declaredVersion: '>=2.0' });
  });
});
