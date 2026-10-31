import { describe, expect, test } from 'vitest';
import { inventory } from '../src/agent/recon.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';

const snapshot = (files: Array<{ path: string; content: string }>): SourceSnapshotRecord => ({
  ownerId: 'owner', projectId: 'project', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  files: files.map((file) => ({ ...file, bytes: Buffer.byteLength(file.content) })),
});

describe('bounded local agent inventory', () => {
  test('counts only syntax-shaped JS/TS literals and supported manifest basenames without returning source', () => {
    const marker = 'UNTRUSTED_INVENTORY_CONTENT';
    const result = inventory(snapshot([{ path: 'src/index.js', content: `app.get('/one', handler); router.post(dynamic, handler); // ${marker}` },
      { path: 'package.json', content: '{}' }, { path: 'src/other.py', content: 'some_route()' }]), true);
    expect(result).toMatchObject({ sourceFiles: 3, targetConfigured: true, manifestFiles: 1, routeCandidates: 1, routeAnalysis: 'COMPLETE' });
    expect(JSON.stringify(result)).not.toContain(marker);
    expect(JSON.stringify(result)).not.toContain('/one');
  });
  test('marks malformed source as partial rather than complete', () => {
    const result = inventory(snapshot([{ path: 'bad.js', content: "app.get('/unfinished', () => {" }]), false);
    expect(result.routeAnalysis).toBe('PARTIAL');
  });
  test('reports no applicable route analysis for unsupported languages', () => {
    expect(inventory(snapshot([{ path: 'main.py', content: 'pass' }]), false).routeAnalysis).toBe('NOT_APPLICABLE');
  });
});
