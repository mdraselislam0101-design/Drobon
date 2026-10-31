import { afterEach, describe, expect, test } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digestDataset, digestSource } from '../src/agent/snapshot.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';

const temporary: string[] = [];
function catalog(): string {
  const path = mkdtempSync(join(tmpdir(), 'drobon-agent-synthetic-catalog-'));
  temporary.push(path);
  mkdirSync(join(path, 'packs', 'sast', 'v1', 'rules'), { recursive: true });
  writeFileSync(join(path, 'packs', 'sast', 'v1', 'rules', 'sample.json'), '{"fixture":1}');
  return path;
}
afterEach(() => { for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe('agent bounded Dataset and source snapshots (synthetic only)', () => {
  test('detects content changes, additions, removals and optional intelligence changes', async () => {
    const root = catalog();
    const first = await digestDataset(root);
    expect(await digestDataset(root)).toBe(first);
    const file = join(root, 'packs', 'sast', 'v1', 'rules', 'sample.json');
    writeFileSync(file, '{"fixture":2}');
    utimesSync(file, new Date(0), new Date(0)); // timestamps alone are not the check
    const changed = await digestDataset(root);
    expect(changed).not.toBe(first);
    mkdirSync(join(root, 'vuln-intel', 'npm'), { recursive: true });
    writeFileSync(join(root, 'vuln-intel', 'npm', 'synthetic.json'), '{"fixture":true}');
    const withIntel = await digestDataset(root);
    expect(withIntel).not.toBe(changed);
    rmSync(join(root, 'vuln-intel'), { recursive: true });
    expect(await digestDataset(root)).toBe(changed);
  });

  test('fails closed for missing roots, links, oversized files and cancellation', async () => {
    const root = catalog();
    await expect(digestDataset(undefined)).rejects.toThrow();
    await expect(digestDataset(join(root, 'missing'))).rejects.toThrow();
    symlinkSync('/nonexistent', join(root, 'packs', 'bad-link'));
    await expect(digestDataset(root)).rejects.toThrow();
    rmSync(join(root, 'packs', 'bad-link'));
    writeFileSync(join(root, 'packs', 'too-big.json'), Buffer.alloc(2 * 1024 * 1024 + 1));
    await expect(digestDataset(root)).rejects.toThrow();
    const controller = new AbortController();
    controller.abort();
    await expect(digestDataset(root, controller.signal)).rejects.toThrow();
  });

  test('source digest is order-independent, sensitive to content and never returns content', () => {
    const snapshot: SourceSnapshotRecord = {
      ownerId: 'owner', projectId: 'project', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
      files: [{ path: 'b.js', content: 'second', bytes: 6 }, { path: 'a.js', content: 'first', bytes: 5 }],
    };
    const digest = digestSource(snapshot);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(digestSource({ ...snapshot, files: [...snapshot.files].reverse() })).toBe(digest);
    expect(digestSource({ ...snapshot, files: [{ path: 'a.js', content: 'other', bytes: 5 }] })).not.toBe(digest);
  });
});
