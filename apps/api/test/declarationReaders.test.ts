import { describe, expect, test } from 'vitest';
import { isFinding } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import type { DatasetService } from '../src/external/service.js';
import { createScaEngine, type SourceSnapshotProvider } from '../src/scans/sca/engine.js';
import { SCA_READABLE_PARSERS } from '../src/external/scaDeclaration.js';
import {
  DECLARATION_READER_PARSERS,
  parseDeclarationDocument,
  readToml,
  readYaml,
  readXml,
  readIni,
  readProperties,
  readRequirements,
  readGradle,
} from '../src/scans/sca/declarationReaders.js';
import { evaluateScaDeclarations } from '../src/scans/sca/declarationScan.js';

/**
 * Pump 18 — BOUNDED DECLARATION DOCUMENT READERS (MAIN-APP ONLY).
 * Proves all nine parser kinds turn REAL manifest text into the normalized
 * documents the dataset rules consume, and that non-JSON rules now produce
 * real persisted SCA findings in a scan.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const ctx = { signal: new AbortController().signal };

function record(): ScanRecord {
  return {
    id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: 'SCA', status: 'RUNNING',
    createdAt: '2026-10-26T10:00:00.000Z', updatedAt: '2026-10-26T10:00:00.000Z',
    startedAt: '2026-10-26T10:00:00.000Z',
  };
}

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    projectId: PROJECT, ownerId: OWNER,
    files: files.map((file) => ({ path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), content: file.content })),
    createdAt: '2026-10-26T09:00:00.000Z', updatedAt: '2026-10-26T09:00:00.000Z',
  };
}

function providerFor(value: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => value };
}

function rawRule(parser: string, artifact: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 'drobon.pack.sca/v1', id: 'DPK-SCA-9001',
    title: 'Dependency declared with a bare wildcard range',
    description: 'A wildcard range accepts every published version.',
    severity: 'MEDIUM', category: 'dependency-hygiene', cwe: 'CWE-1104',
    remediation: 'Pin the dependency to an exact version.',
    limitation: 'Fixture rule; declaration only.',
    ecosystems: ['npm'], artifact, parser, patternRefs: ['DPK-PAT-9001'],
    check: { type: 'sca-field-matches', path: 'packages.*', valuePattern: '^\\*$' },
    tests: [
      { file: artifact, document: { packages: { x: '*' } }, match: true },
      { file: artifact, document: { packages: { x: '1.0.0' } }, match: false },
    ],
    ...overrides,
  };
}

describe('reader registry', () => {
  test('all nine dataset parser kinds have a reader', () => {
    expect(DECLARATION_READER_PARSERS).toHaveLength(9);
    expect([...SCA_READABLE_PARSERS].sort()).toEqual([...DECLARATION_READER_PARSERS].sort());
    for (const parser of DECLARATION_READER_PARSERS) expect(SCA_READABLE_PARSERS).toContain(parser);
  });

  test('malformed or empty input is never turned into a fabricated document', () => {
    expect(parseDeclarationDocument('json', 'package.json', '{not json')).toBeUndefined();
    expect(parseDeclarationDocument('json', 'package.json', '')).toBeUndefined();
    expect(parseDeclarationDocument('toml', 'Pipfile', '')).toBeUndefined();
    expect(parseDeclarationDocument('yaml', 'pubspec.yaml', '')).toBeUndefined();
  });
});

describe('real raw manifest → normalized document', () => {
  test('TOML: Pipfile, Cargo.toml, pyproject.toml, arrays of tables', () => {
    expect(readToml('[[source]]\nurl = "https://pypi.org/simple"\n[packages]\nrequests = "*"\n'))
      .toMatchObject({ packages: { requests: '*' } });
    expect(readToml('[package]\nname = "demo"\n[dependencies]\nserde = { version = "*" }\n'))
      .toMatchObject({ dependencies: { serde: { version: '*' } } });
    expect(readToml('[project]\nname = "demo"\ndependencies = ["requests"]\n'))
      .toMatchObject({ project: { dependencies: ['requests'] } });
    expect(readToml('[[package]]\nname = "requests"\nversion = "2.32.3"\n'))
      .toMatchObject({ package: [{ name: 'requests', version: '2.32.3' }] });
  });

  test('YAML: nested maps and sequences', () => {
    expect(readYaml('name: demo-service\nconfig:\n  npmRegistryServer: "http://npm.acme.example/"\n'))
      .toMatchObject({ name: 'demo-service', config: { npmRegistryServer: 'http://npm.acme.example/' } });
    expect(readYaml('dependencies:\n  http: any\n')).toMatchObject({ dependencies: { http: 'any' } });
    expect(readYaml('name: demo\ndependencies:\n  - numpy\n  - pandas\n'))
      .toMatchObject({ dependencies: ['numpy', 'pandas'] });
  });

  test('XML: repeated children collapse into arrays; versions stay strings', () => {
    expect(readXml('<project><dependencies><dependency><groupId>a</groupId></dependency><dependency><groupId>b</groupId></dependency></dependencies></project>'))
      .toMatchObject({ project: { dependencies: [{ groupId: 'a' }, { groupId: 'b' }] } });
    expect(readXml('<packages><package id="Newtonsoft.Json" version="2.0.13" /></packages>'))
      .toMatchObject({ packages: [{ id: 'Newtonsoft.Json', version: '2.0.13' }] });
  });

  test('INI / properties: sections, arrays and dual config shapes', () => {
    const npmrc = readIni('name=demo-service\nregistry=http://registry.acme.example/\n', '.npmrc');
    expect(npmrc).toMatchObject({ name: 'demo-service', config: { registry: 'http://registry.acme.example/' }, registry: 'http://registry.acme.example/' });
    expect(readIni('[metadata]\nname = demo\n[options]\ninstall_requires[] = requests==2.32.3\n', 'setup.cfg'))
      .toMatchObject({ metadata: { name: 'demo' }, options: { install_requires: ['requests==2.32.3'] } });
    expect(readProperties('repoUrl=http://repo.acme.example/maven2\n', 'gradle.properties'))
      .toMatchObject({ properties: { repoUrl: 'http://repo.acme.example/maven2' } });
    expect(readProperties('Package: demo\nDepends[]: methods, R (>= 4.1)\n', 'DESCRIPTION'))
      .toMatchObject({ Package: 'demo', Depends: ['methods', 'R (>= 4.1)'] });
  });

  test('requirements: names, specifiers, direct sources and hashes', () => {
    expect(readRequirements('requests\nflask==2.3.2\n'))
      .toMatchObject({ requirements: [{ name: 'requests', specifier: '' }, { name: 'flask', specifier: '==2.3.2' }] });
    expect(readRequirements('acme-sdk[dev] @ git+https://github.com/acme/sdk.git@abc\n'))
      .toMatchObject({ requirements: [{ name: 'acme-sdk', extras: ['dev'], source: 'git+https://github.com/acme/sdk.git@abc' }] });
  });

  test('gradle / go.mod / lockfile-text readers', () => {
    expect(readGradle('repositories { maven { name "acme"; url "http://repo.acme.example/maven2" } }\n', 'build.gradle'))
      .toMatchObject({ repositories: [{ name: 'acme', url: 'http://repo.acme.example/maven2' }] });
    expect(parseDeclarationDocument('lockfile-text', 'go.mod', 'module example.com/demo\ngo 1.22\nrequire github.com/acme/sdk v4.2.0\n'))
      .toMatchObject({ module: 'example.com/demo', require: [{ module: 'github.com/acme/sdk', version: 'v4.2.0' }] });
    expect(parseDeclarationDocument('lockfile-text', 'yarn.lock', 'left-pad@^1.3.0:\n  version "1.3.0"\n  integrity "sha1-AAAA"\n'))
      .toMatchObject({ entries: [{ name: 'left-pad', version: '1.3.0', integrity: 'sha1-AAAA' }] });
    expect(parseDeclarationDocument('lockfile-text', 'Gemfile', 'source "https://rubygems.org"\ngem "rails", "7.1"\n'))
      .toMatchObject({ source: 'https://rubygems.org', gems: [{ name: 'rails', requirement: '7.1' }] });
  });

  test('json parser is unchanged', () => {
    expect(parseDeclarationDocument('json', 'package.json', '{"dependencies":{"x":"*"}}'))
      .toEqual({ dependencies: { x: '*' } });
  });
});

describe('declaration scan layer: non-JSON rules now produce real findings', () => {
  test('evaluateScaDeclarations evaluates a TOML rule against a Pipfile', () => {
    const result = evaluateScaDeclarations({
      rawRules: [rawRule('toml', 'Pipfile')],
      files: [{ path: 'Pipfile', content: '[[source]]\nurl = "https://pypi.org/simple"\n[packages]\nrequests = "*"\n' }],
      record: record(),
    });
    expect(result.rulesEvaluated).toBe(1);
    expect(result.rulesNotEvaluated).toBe(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.scanner).toBe('SCA');
    expect(result.findings[0]?.evidence).toContain('values withheld');
    expect(isFinding(result.findings[0] as never)).toBe(true);
  });

  test('a malformed artifact is counted as NOT evaluated, never as a clean result', () => {
    const result = evaluateScaDeclarations({
      rawRules: [rawRule('toml', 'Pipfile')],
      files: [{ path: 'Pipfile', content: '' }],
      record: record(),
    });
    expect(result.findings).toHaveLength(0);
    expect(result.rulesEvaluated).toBe(0);
    expect(result.rulesNotEvaluated).toBe(1);
  });

  test('the SCA ENGINE persists a non-JSON declaration finding end to end', async () => {
    // Dotfile artifacts (.npmrc, .yarnrc.yml …) are blocked by the shared
    // source-path policy, so a real scan uses an uploadable manifest.
    const dataset = {
      configured: true,
      scaPacks: async () => [rawRule('toml', 'Pipfile')],
    } as unknown as DatasetService;
    const engine = createScaEngine({
      sources: providerFor(snapshot([{ path: 'Pipfile', content: '[packages]\nrequests = "*"\n' }])),
      dataset,
    });
    const outcome = await engine.execute(record(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const declaration = (outcome.findings ?? []).filter((finding) => finding.ruleId.startsWith('DPK-SCA-'));
    expect(declaration).toHaveLength(1);
    expect(outcome.resultSummary.findingsTotal).toBe((outcome.findings ?? []).length);
    expect(isFinding(declaration[0] as never)).toBe(true);
  });
});
