import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createFilesystemIntelligenceProvider } from '../src/scans/sca/filesystemProvider.js';

function advisory(name: string, id: string): string {
  return JSON.stringify({
    fixture: false, id, ecosystem: 'npm', package: name, summary: 'Synthetic advisory only.',
    severity: 'HIGH', affected: [{ range: '<2.0.0' }],
  });
}

function coordinate(name: string) {
  return { dependencyId: `dep_${name}`, ecosystem: 'npm' as const, name, version: '1.0.0' };
}

describe('bounded, read-only filesystem intelligence loading', () => {
  test('refuses symlinked files, external directories and cycles while retaining valid results', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-intel-root-'));
    const outside = mkdtempSync(join(tmpdir(), 'drobon-intel-outside-'));
    try {
      const npm = join(root, 'vuln-intel', 'npm');
      mkdirSync(npm, { recursive: true });
      writeFileSync(join(npm, 'valid.json'), advisory('trusted', 'GHSA-aaaa-bbbb-cccc'));
      writeFileSync(join(outside, 'external.json'), advisory('external', 'GHSA-dddd-eeee-ffff'));
      symlinkSync(join(outside, 'external.json'), join(npm, 'file-link.json'));
      symlinkSync(outside, join(npm, 'external-link'));
      symlinkSync(npm, join(npm, 'loop'));
      const result = await createFilesystemIntelligenceProvider({ datasetPath: root }).assess([coordinate('trusted'), coordinate('external')]);
      expect(result.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(result.incomplete).toBe(true);
      expect(result.advisories.map((entry) => entry.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test('a symlinked intelligence root is unavailable, not followed', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-intel-root-link-'));
    const outside = mkdtempSync(join(tmpdir(), 'drobon-intel-root-target-'));
    try {
      mkdirSync(join(outside, 'npm'), { recursive: true });
      writeFileSync(join(outside, 'npm', 'external.json'), advisory('external', 'GHSA-dddd-eeee-ffff'));
      symlinkSync(outside, join(root, 'vuln-intel'));
      const result = await createFilesystemIntelligenceProvider({ datasetPath: root }).assess([coordinate('external')]);
      expect(result.datasetStatus).toBe('DATASET_UNAVAILABLE');
      expect(result.advisories).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test('oversized files and depth caps are disclosed as incomplete', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-intel-bounds-'));
    try {
      const npm = join(root, 'vuln-intel', 'npm');
      mkdirSync(join(npm, 'nested', 'too-deep'), { recursive: true });
      writeFileSync(join(npm, 'valid.json'), advisory('trusted', 'GHSA-aaaa-bbbb-cccc'));
      writeFileSync(join(npm, 'oversized.json'), ' '.repeat(1_000));
      writeFileSync(join(npm, 'nested', 'too-deep', 'external.json'), advisory('deep', 'GHSA-dddd-eeee-ffff'));
      const result = await createFilesystemIntelligenceProvider({ datasetPath: root, limits: { maxFileBytes: 300, maxDepth: 1 } }).assess([coordinate('trusted'), coordinate('deep')]);
      expect(result.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(result.incomplete).toBe(true);
      expect(result.advisories.map((entry) => entry.id)).toEqual(['GHSA-aaaa-bbbb-cccc']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('entry and cumulative byte caps retain only bounded results and mark coverage incomplete', async () => {
    const root = mkdtempSync(join(tmpdir(), 'drobon-intel-entry-cap-'));
    try {
      const npm = join(root, 'vuln-intel', 'npm');
      mkdirSync(npm, { recursive: true });
      for (let i = 0; i < 4; i += 1) writeFileSync(join(npm, `${i}.json`), advisory('trusted', `GHSA-aaaa-bbbb-${i}ccc`));
      const entryLimited = await createFilesystemIntelligenceProvider({ datasetPath: root, limits: { maxEntries: 2 } }).assess([coordinate('trusted')]);
      expect(entryLimited.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(entryLimited.incomplete).toBe(true);
      expect(entryLimited.advisories.length).toBeLessThanOrEqual(2);
      const byteLimited = await createFilesystemIntelligenceProvider({ datasetPath: root, limits: { maxTotalBytes: 300 } }).assess([coordinate('trusted')]);
      expect(byteLimited.datasetStatus).toBe('DATASET_AVAILABLE');
      expect(byteLimited.incomplete).toBe(true);
      expect(byteLimited.advisories.length).toBeLessThan(4);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
