import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { Finding } from '@drobon/shared';
import { createJsonFileScanStore, type ScanStore } from '../src/scans/store.js';
import { findingFingerprint } from '../src/scans/findingIdentity.js';
import { readJson, sessionCookieFrom, startTestServer } from './helpers.js';

const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const ownerId = 'usr_identity';
function fingerprint(overrides: Partial<Parameters<typeof findingFingerprint>[0]> = {}): string {
  return findingFingerprint({ scanner: 'SAST', projectId, ruleId: 'DG-SAST-001', location: 'src/app.js', line: 4, evidence: 'first text', ...overrides });
}
function fixture(scanId: string, project: string, fp: string, line = 4, evidence = 'legacy text'): Finding {
  return { id: `fnd_${fp.slice(0, 24)}`, scanId, scanner: 'SAST', projectId: project, ruleId: 'DG-SAST-001', severity: 'HIGH', title: 'Synthetic command finding', description: 'Synthetic evidence.', remediation: 'Review manually.', file: 'src/app.js', line, column: 1, evidence, fingerprint: fp };
}
async function finish(scans: ScanStore, project: string, owner: string, fingerprints: string[], lines = fingerprints.map(() => 4)) {
  const created = await scans.createScanWithQuota({ ownerId: owner, projectId: project, scanType: 'SAST', consume: async () => ({ ok: true }) });
  if (created.outcome !== 'created') throw new Error('scan creation failed');
  const running = await scans.claimNextQueued();
  if (running === undefined) throw new Error('scan claim failed');
  const findings = fingerprints.map((fp, index) => fixture(running.id, project, fp, lines[index], `evidence version ${index}`));
  const completed = await scans.completeScan(running.id, { findingsTotal: findings.length }, findings);
  if (completed === undefined) throw new Error('scan completion failed');
  return completed;
}

describe('stable source finding identity', () => {
  test('evidence changes do not change identity; scanner, project, rule, path and line do', () => {
    const base = fingerprint();
    expect(fingerprint({ evidence: 'completely different redaction text' })).toBe(base);
    expect(fingerprint({ location: 'src\\app.js' })).toBe(base);
    for (const change of [
      { scanner: 'SECRETS' as const }, { projectId: 'prj_00000000-0000-4000-8000-000000000002' },
      { ruleId: 'DG-SAST-002' }, { location: 'src/other.js' }, { line: 5 },
    ]) expect(fingerprint(change)).not.toBe(base);
  });

  test('unambiguous legacy finding keeps workflow and reopens after a v2 rescan and restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-identity-v2-'));
    try {
      const path = join(dir, 'scans.json'); let scans = createJsonFileScanStore(path);
      const legacy = 'a'.repeat(64);
      const old = await finish(scans, projectId, ownerId, [legacy]);
      expect((await scans.transitionFindingLifecycle(projectId, legacy, 'RESOLVED', ownerId, '2026-10-31T00:00:00.000Z')).outcome).toBe('updated');
      const v2 = fingerprint();
      expect(v2).not.toBe(legacy);
      const current = await finish(scans, projectId, ownerId, [v2]);
      expect(current.findings?.[0]?.fingerprint).toBe(legacy);
      expect(current.findings?.[0]?.id).toBe(old.findings?.[0]?.id);
      expect((await scans.getFindingWorkflow(projectId, legacy))?.state).toBe('REOPENED');
      // Different location remains a different vulnerability.
      const separate = await finish(scans, projectId, ownerId, [fingerprint({ line: 5 })], [5]);
      expect(separate.findings?.[0]?.fingerprint).not.toBe(legacy);
      scans = createJsonFileScanStore(path);
      expect((await scans.findByProjectAndId(projectId, current.id))?.findings?.[0]?.fingerprint).toBe(legacy);
      expect((await scans.getFindingWorkflow(projectId, legacy))?.state).toBe('REOPENED');
      expect((await scans.findByProjectAndId(projectId, old.id))?.findings?.[0]?.fingerprint).toBe(legacy);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('HTTP comparison pairs unambiguous old evidence variants and refuses ambiguous matches', async () => {
    const server = await startTestServer();
    try {
      const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'identity-v2@example.test', password: 'synthetic identity fixture passphrase' }) });
      expect(registered.status).toBe(201);
      const registeredBody = await readJson(registered) as { data: { user: { id: string } } };
      const owner = registeredBody.data.user.id;
      const login = await fetch(`${server.baseUrl}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'identity-v2@example.test', password: 'synthetic identity fixture passphrase' }) });
      const cookie = sessionCookieFrom(login);
      const projectResponse = await fetch(`${server.baseUrl}/api/v1/projects`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ name: 'Legacy comparison' }) });
      const project = (await readJson(projectResponse) as { data: { project: { id: string } } }).data.project.id;
      const first = await finish(server.scans, project, owner, ['1'.repeat(64)]);
      const second = await finish(server.scans, project, owner, ['2'.repeat(64)]);
      const compare = await fetch(`${server.baseUrl}/api/v1/projects/${project}/scans/${second.id}/compare/${first.id}`, { headers: { cookie } });
      expect(compare.status).toBe(200);
      expect((await readJson(compare) as { data: { counts: unknown } }).data.counts).toMatchObject({ new: 0, resolved: 0, unchanged: 1 });
      const ambiguous = await finish(server.scans, project, owner, ['3'.repeat(64), '4'.repeat(64)]);
      const denied = await fetch(`${server.baseUrl}/api/v1/projects/${project}/scans/${second.id}/compare/${ambiguous.id}`, { headers: { cookie } });
      expect(denied.status).toBe(409);
    } finally { await server.stop(); }
  });
});
