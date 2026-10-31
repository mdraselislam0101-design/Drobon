import { describe, expect, test } from 'vitest';
import { diagnoseReaderFixture, renderDeclarationDocument } from '../../../scripts/sca-reader-fixtures.mjs';
import { isValidSourcePath } from '@drobon/shared';
import { parseDeclarationDocument } from '../src/scans/sca/declarationReaders.js';

function textOf(value: string | { text: string; wrapped: boolean } | undefined): string | undefined {
  return typeof value === 'string' ? value : value?.text;
}

describe('SCA raw-fixture rendering', () => {
  test('does not invent a NuGet source list when the normalized aliases conflict', () => {
    const contradictory = {
      sources: [{ key: 'fixture', value: 'https://example.org/v3' }],
      packageSources: {},
    };
    expect(renderDeclarationDocument('xml', 'nuget.config', contradictory)).toBeUndefined();
    expect(renderDeclarationDocument('xml', 'nuget.config', { ...contradictory, packageSources: { clear: true } })).toBeUndefined();
    const mismatchedAliases = { ...contradictory, packageSources: { add: [{ key: 'different', value: 'https://example.org/other' }] } };
    expect(renderDeclarationDocument('xml', 'nuget.config', mismatchedAliases)).toBeUndefined();
    const realistic = { ...contradictory, packageSources: { add: contradictory.sources, clear: 'false' } };
    const text = textOf(renderDeclarationDocument('xml', 'nuget.config', realistic));
    expect(text).toBeDefined();
    expect(text).not.toContain('<clear');
    expect(parseDeclarationDocument('xml', 'nuget.config', text ?? '')).toMatchObject({
      packageSources: { clear: false, add: [{ key: 'fixture', value: 'https://example.org/v3' }] },
    });
  });

  test('explicit empty pip options round-trip, but a missing option argument remains unparsed', () => {
    for (const key of ['trusted-host', 'no-binary']) {
      const text = textOf(renderDeclarationDocument('requirements', 'requirements.txt', { requirements: [], [key]: '' }));
      expect(text).toBe(`--${key}=\n`);
      expect(parseDeclarationDocument('requirements', 'requirements.txt', text ?? '')).toMatchObject({ [key]: '' });
      expect(parseDeclarationDocument('requirements', 'requirements.txt', `--${key}\n`)).toBeUndefined();
      const valid = textOf(renderDeclarationDocument('requirements', 'requirements.txt', { requirements: [], [key]: 'fixture' }));
      expect(parseDeclarationDocument('requirements', 'requirements.txt', valid ?? '')).toMatchObject({ [key]: 'fixture' });
    }
  });

  test.each(['index-url', 'extra-index-url', 'trusted-host', 'no-binary'])('accepts an explicitly empty pip %s value while rejecting a missing argument', (key) => {
    const explicit = parseDeclarationDocument('requirements', 'requirements.txt', `--${key}=\n`);
    expect(explicit).toMatchObject({ [key]: '' });
    expect(parseDeclarationDocument('requirements', 'requirements.txt', `--${key}\n`)).toBeUndefined();
  });

  test('blocked-path reader diagnostics never imply that the production upload accepts a dotfile', () => {
    const rule = { parser: 'ini', artifact: '.npmrc' };
    const fixture = { document: { config: { audit: false } }, match: true };
    const evaluate = (_compiled: unknown, parsed: unknown): boolean => {
      const doc = parsed as { config?: { audit?: boolean } };
      return doc.config?.audit === false;
    };
    expect(isValidSourcePath(rule.artifact)).toBe(false);
    expect(diagnoseReaderFixture(rule, fixture, {}, parseDeclarationDocument, evaluate)).toBe('matches');
    expect(diagnoseReaderFixture(rule, { ...fixture, match: false }, {}, parseDeclarationDocument, evaluate)).toBe('false-positive');
    expect(diagnoseReaderFixture(rule, fixture, {}, () => undefined, evaluate)).toBe('parse-failure');
    expect(diagnoseReaderFixture({ parser: 'unsupported', artifact: '.unknown' }, fixture, {}, parseDeclarationDocument, evaluate)).toBe('unrenderable');
    expect(diagnoseReaderFixture(rule, fixture, undefined, parseDeclarationDocument, evaluate)).toBe('compile-failure');
  });

  test('renders a Gradle boolean string without treating false as truthy', () => {
    const rendered = renderDeclarationDocument('gradle', 'build.gradle', {
      repositories: [], dependencies: [], dependencyLocking: { lockAllConfigurations: 'false' },
    });
    const text = textOf(rendered);
    expect(text).not.toContain('lockAllConfigurations()');
    expect(parseDeclarationDocument('gradle', 'build.gradle', text ?? '')).toMatchObject({
      dependencyLocking: { lockAllConfigurations: false },
    });
  });
});
