import { describe, expect, test } from 'vitest';
import { createMemoryAssessmentStore } from '../src/assessments/store.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createActiveDastEngine } from '../src/scans/dast/activeEngine.js';
import { isDastResult } from '@drobon/shared';
import { createAssessmentDastAuthorizer } from '../src/scans/dast/authorization.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import type { ScanRecord } from '../src/scans/store.js';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const TARGET = 'https://app.example.org/api/';
const NOW = '2026-10-28T12:00:00.000Z';

async function fixture() {
  const store = createMemoryAssessmentStore();
  const created = await store.create({
    ownerId: OWNER, projectId: PROJECT, title: 'Scoped review', objectives: ['Review the API'],
    scope: { inScopeHosts: ['app.example.org'], outOfScopeHosts: [] }, now: NOW,
  });
  if ('outcome' in created) throw new Error('fixture could not be created');
  await store.transition({ ownerId: OWNER, projectId: PROJECT, assessmentId: created.id, status: 'ACTIVE', now: NOW });
  const declared = await store.recordEngagement({
    ownerId: OWNER, projectId: PROJECT, assessmentId: created.id, action: 'DECLARE', now: NOW,
    engagement: {
      clientName: 'Fixture client', targetUrl: TARGET, inScopeHosts: ['app.example.org'], scopePaths: ['/api'],
      allowedScanTypes: ['DAST'], validFrom: '2026-10-01T00:00:00.000Z', validUntil: '2026-12-01T00:00:00.000Z',
      statement: 'Owner declares permission for the test scope.',
    },
  });
  const engagementId = declared.assessment?.engagements?.[0]?.id;
  if (engagementId === undefined) throw new Error('fixture engagement missing');
  const scan: ScanRecord = {
    id: 'scan_00000000-0000-4000-8000-000000000003', ownerId: OWNER, projectId: PROJECT,
    scanType: 'DAST', status: 'RUNNING', assessmentId: created.id, dastTargetUrl: TARGET,
    createdAt: NOW, updatedAt: NOW, startedAt: NOW,
  };
  return { store, scan, engagementId, authorizer: createAssessmentDastAuthorizer(store, () => Date.parse(NOW)) };
}

const policy = () => createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
const signal = { signal: new AbortController().signal };

describe('assessment-scoped DAST request authorization', () => {
  test('refuses a linked request when the authorizer is unavailable, before transport', async () => {
    const { scan } = await fixture();
    let requests = 0;
    const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected request'); } };
    const result = await createDastEngine({ targetPolicy: policy(), transport }).execute(scan, signal);
    expect(result.kind).toBe('failed');
    if (result.kind === 'failed') expect(result.failureCode).toBe('DAST_TARGET_BLOCKED');
    expect(requests).toBe(0);
  });

  test('does not follow a same-host redirect outside the declared path scope', async () => {
    const { scan, authorizer } = await fixture();
    const calls: string[] = [];
    const transport: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return { status: 302, headers: { location: '/outside' }, body: '', bodyTruncated: false, elapsedMs: 3 } satisfies DastProbeResponse;
    } };
    const result = await createDastEngine({ targetPolicy: policy(), transport, authorize: authorizer }).execute(scan, signal);
    expect(calls).toEqual([TARGET]);
    expect(result.kind).toBe('completed');
    if (result.kind === 'completed') {
      expect(result.dast?.partial).toBe(true);
      expect(result.dast?.partialReason).toContain('scope');
      expect(result.dast?.requestCount).toBe(1);
    }
  });

  test('a withdrawn engagement stops a queued linked scan before its first request', async () => {
    const { scan, store, engagementId, authorizer } = await fixture();
    const withdrawn = await store.recordEngagement({
      ownerId: OWNER, projectId: PROJECT, assessmentId: scan.assessmentId!, action: 'WITHDRAW', engagementId,
      now: '2026-10-28T12:01:00.000Z',
    });
    expect(withdrawn.outcome).toBe('updated');
    let requests = 0;
    const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected request'); } };
    const result = await createDastEngine({ targetPolicy: policy(), transport, authorize: authorizer }).execute(scan, signal);
    expect(result.kind).toBe('failed');
    expect(requests).toBe(0);
  });

  test('the existing active delegate also rechecks scope before following a link', async () => {
    const { scan, authorizer } = await fixture();
    const calls: string[] = [];
    const transport: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return { status: 200, headers: {}, body: '<a href="/outside">link</a>', bodyTruncated: false, elapsedMs: 3 } satisfies DastProbeResponse;
    } };
    const engine = createActiveDastEngine({ targetPolicy: policy(), transport, authorize: authorizer, throttleMs: 0 });
    const result = await engine.execute({ ...scan, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, signal);
    expect(calls[0]).toBe(TARGET);
    expect(calls.every((url) => new URL(url).pathname.startsWith('/api/'))).toBe(true);
    expect(calls).not.toContain('https://app.example.org/outside');
    expect(result.kind).toBe('completed');
    if (result.kind === 'completed') {
      expect(result.dast?.mode).toBe('ACTIVE_SAFE');
      expect(result.dast?.partial).toBe(true);
      expect(isDastResult(result.dast)).toBe(true);
    }
  });

  test('withdrawal during preflight is rechecked before opening transport', async () => {
    const { scan } = await fixture();
    let checks = 0;
    let requests = 0;
    const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected request'); } };
    const result = await createDastEngine({
      targetPolicy: policy(), transport, authorize: async () => { checks += 1; return checks === 1; },
    }).execute(scan, signal);
    expect(result.kind).toBe('failed');
    expect(checks).toBe(2);
    expect(requests).toBe(0);
  });

  test('an authorizer error is treated as a refusal', async () => {
    const { scan } = await fixture();
    let requests = 0;
    const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected request'); } };
    const result = await createDastEngine({ targetPolicy: policy(), transport, authorize: async () => { throw new Error('failed'); } }).execute(scan, signal);
    expect(result.kind).toBe('failed');
    expect(requests).toBe(0);
  });
});
