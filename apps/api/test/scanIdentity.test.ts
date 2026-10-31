import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createJsonFileScanStore } from '../src/scans/store.js';

describe('DAST idempotency across scan store restarts', () => {
  test('legacy passive scan replays as passive but conflicts with active or changed consent', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-scan-identity-'));
    const path = join(dir, 'scans.json');
    let consumed = 0;
    const input = {
      ownerId: 'usr_test',
      projectId: 'prj_00000000-0000-4000-8000-000000000001',
      scanType: 'DAST' as const,
      targetUrl: 'https://example.test/',
      idempotencyKey: 'legacy-passive-key',
      consume: async () => { consumed += 1; return { ok: true as const }; },
    };
    try {
      const first = await createJsonFileScanStore(path).createScanWithQuota(input);
      expect(first.outcome).toBe('created');
      const reloaded = createJsonFileScanStore(path);
      const replay = await reloaded.createScanWithQuota({ ...input, dastMode: 'PASSIVE' });
      expect(replay.outcome).toBe('replayed');
      if (first.outcome === 'created' && replay.outcome === 'replayed') expect(replay.scan.id).toBe(first.scan.id);
      expect((await reloaded.createScanWithQuota({ ...input, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true })).outcome).toBe('conflict');
      expect((await reloaded.createScanWithQuota({ ...input, dastActiveConsent: true })).outcome).toBe('conflict');
      expect(consumed).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
