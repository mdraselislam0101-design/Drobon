import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, linkSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { createJsonFileSourceStore } from '../src/scans/sources.js';
import { createJsonFileScanStore } from '../src/scans/store.js';
import { buildSecurityReport, verifySecurityReportIntegrity } from '../src/reports/build.js';

const script = resolve('../../scripts/restrict-json-file.mjs');
const cli = (...args: string[]) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
const digest = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
const mode = (path: string) => statSync(path).mode & 0o777;
const confirm = '--confirm-owner-only';
const enabled = process.platform !== 'win32';

async function withDir(run: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-permissions-'));
  try { await run(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe.skipIf(!enabled)('opt-in offline historical file permissions', () => {
  test('dry-run plan, protected backup, restored copy, apply and rollback preserve source bytes and report identity', () => withDir(async (dir) => {
    const project = await createMemoryProjectStore().create({ ownerId: 'usr_fixture', name: 'Synthetic', description: '' });
    const sourcesPath = join(dir, 'sources.json');
    const sources = createJsonFileSourceStore(sourcesPath);
    const content = 'const fixtureOnly = "private synthetic content";';
    await sources.replace({ ownerId: project.ownerId, projectId: project.id, files: [{ path: 'src/fixture.js', content }] });
    const scansPath = join(dir, 'scans.json');
    const scans = createJsonFileScanStore(scansPath);
    await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('missing fixture scan');
    const completed = await scans.completeScan(running.id, { findingsTotal: 0 }, []);
    if (completed === undefined) throw new Error('missing fixture completion');
    const report = buildSecurityReport(project, completed, '2026-10-31T00:00:00.000Z');
    expect((await scans.createReport(report)).outcome).toBe('created');
    for (const path of [sourcesPath, scansPath]) {
      chmodSync(path, 0o644); // synthetic old deployment permissions
      const backup = `${path}.backup`;
      copyFileSync(path, backup);
      chmodSync(backup, 0o600);
      const originalDigest = digest(path);
      const plan = `${path}.plan`;
      const preview = cli('plan', path, plan);
      expect(preview.status).toBe(0);
      expect(JSON.parse(preview.stdout)).toMatchObject({ operation: 'plan', beforeMode: '0644', afterMode: '0600', changeRequired: true });
      expect(mode(path)).toBe(0o644); // plan alone is read-only for the store
      expect(mode(plan)).toBe(0o600);
      expect(digest(path)).toBe(originalDigest);
      expect(cli('apply', path, plan).status).not.toBe(0); // explicit opt-in required
      const applied = cli('apply', path, plan, confirm);
      expect(applied.status).toBe(0);
      expect(applied.stdout + applied.stderr).not.toContain(content);
      expect(mode(path)).toBe(0o600);
      expect(digest(path)).toBe(originalDigest);
      expect(digest(backup)).toBe(originalDigest);
      const restored = `${path}.restored`;
      copyFileSync(backup, restored); // rehearse restoration to a separate synthetic path
      chmodSync(restored, 0o600);
      expect(digest(restored)).toBe(originalDigest);
      if (path === sourcesPath) expect((await createJsonFileSourceStore(restored).findByProject(project.id))?.files[0]?.content).toBe(content);
      else {
        const restoredReport = await createJsonFileScanStore(restored).findReportByProjectAndScan(project.id, completed.id);
        expect(restoredReport?.reportId).toBe(report.reportId);
        expect(verifySecurityReportIntegrity(restoredReport)).toBe(true);
      }
      expect(cli('apply', path, plan, confirm).status).toBe(0); // idempotent
      if (path === sourcesPath) expect((await createJsonFileSourceStore(path).findByProject(project.id))?.files[0]?.content).toBe(content);
      else {
        const reopened = await createJsonFileScanStore(path).findReportByProjectAndScan(project.id, completed.id);
        expect(reopened?.reportId).toBe(report.reportId);
        expect(verifySecurityReportIntegrity(reopened)).toBe(true);
      }
      expect(cli('rollback', path, plan, confirm).status).toBe(0);
      expect(cli('rollback', path, plan, confirm).status).toBe(0);
      expect(mode(path)).toBe(0o644);
      expect(digest(path)).toBe(originalDigest);
      expect(digest(backup)).toBe(originalDigest);
    }
  }));

  test('rejects stale plans and does not touch a replacement file', () => withDir(async (dir) => {
    const path = join(dir, 'legacy.json'); const plan = join(dir, 'plan.json');
    writeFileSync(path, '{"version":1}'); chmodSync(path, 0o644);
    expect(cli('plan', path, plan).status).toBe(0);
    renameSync(path, join(dir, 'original.json'));
    writeFileSync(path, '{"replacement":true}'); chmodSync(path, 0o644);
    const before = digest(path);
    const applied = cli('apply', path, plan, confirm);
    expect(applied.status).not.toBe(0);
    expect(mode(path)).toBe(0o644);
    expect(digest(path)).toBe(before);
  }));

  test('rejects symlinks, hard links, special mode bits, preexisting plans and changed permissions', () => withDir(async (dir) => {
    const path = join(dir, 'legacy.json'); const plan = join(dir, 'plan.json');
    writeFileSync(path, '{}'); chmodSync(path, 0o644);
    symlinkSync(path, join(dir, 'alias.json'));
    expect(cli('plan', join(dir, 'alias.json'), plan).status).not.toBe(0);
    linkSync(path, join(dir, 'hard.json'));
    expect(cli('plan', path, plan).status).not.toBe(0);
    rmSync(join(dir, 'hard.json'));
    chmodSync(path, 0o4644);
    expect(statSync(path).mode & 0o7777).toBe(0o4644);
    expect(cli('plan', path, plan).status).not.toBe(0);
    expect(statSync(path).mode & 0o7777).toBe(0o4644);
    chmodSync(path, 0o644);
    expect(cli('plan', path, plan).status).toBe(0);
    const planBytes = readFileSync(plan, 'utf8');
    expect(cli('plan', path, plan).status).not.toBe(0);
    expect(readFileSync(plan, 'utf8')).toBe(planBytes);
    chmodSync(path, 0o640);
    expect(cli('apply', path, plan, confirm).status).not.toBe(0);
    expect(mode(path)).toBe(0o640);
  }));
});
