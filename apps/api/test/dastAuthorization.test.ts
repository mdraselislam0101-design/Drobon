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
  test('strict mode blocks old unlinked and undeclared queued scans before DNS or transport', async () => {
    const { scan, store } = await fixture();
    const noEngagement = createMemoryAssessmentStore();
    const created = await noEngagement.create({ ownerId: OWNER, projectId: PROJECT, title: 'Legacy assessment',
      objectives: ['Review'], scope: { inScopeHosts: ['app.example.org'], outOfScopeHosts: [] }, now: NOW });
    if ('outcome' in created) throw new Error('fixture could not be created');
    await noEngagement.transition({ ownerId: OWNER, projectId: PROJECT, assessmentId: created.id, status: 'ACTIVE', now: NOW });
    const unlinked = { ...scan }; delete unlinked.assessmentId;
    const linkedUndeclared = { ...scan, assessmentId: created.id };
    for (const record of [unlinked, linkedUndeclared]) for (const active of [false, true]) {
      let resolutions = 0; let requests = 0;
      const targetPolicy = createDastTargetPolicy({ resolve: async () => { resolutions += 1; return ['93.184.216.34']; } });
      const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected'); } };
      const authorize = createAssessmentDastAuthorizer(noEngagement, () => Date.parse(NOW), { requireEngagement: true });
      const options = { targetPolicy, transport, authorize };
      const engine = active ? createActiveDastEngine({ ...options, throttleMs: 0 }) : createDastEngine(options);
      const result = await engine.execute(active ? { ...record, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true } : record, signal);
      expect(result.kind).toBe('failed');
      expect(resolutions).toBe(0);
      expect(requests).toBe(0);
    }
    const strict = createAssessmentDastAuthorizer(store, () => Date.parse(NOW), { requireEngagement: true });
    expect(await strict(scan, TARGET)).toBe(true);
    expect(await strict(scan, 'https://app.example.org/outside')).toBe(false);
    const compatibility = createAssessmentDastAuthorizer(noEngagement, () => Date.parse(NOW));
    expect(await compatibility(unlinked, TARGET)).toBe(true);
    expect(await compatibility(linkedUndeclared, TARGET)).toBe(true);
  });

  test('a denied initial scope causes neither DNS resolution nor transport', async () => {
    const { scan } = await fixture();
    for (const active of [false, true]) {
      let resolutions = 0;
      let requests = 0;
      const targetPolicy = createDastTargetPolicy({ resolve: async () => { resolutions += 1; return ['93.184.216.34']; } });
      const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected'); } };
      const options = { targetPolicy, transport, authorize: async () => false };
      const engine = active ? createActiveDastEngine({ ...options, throttleMs: 0 }) : createDastEngine(options);
      const result = await engine.execute(active ? { ...scan, dastMode: 'ACTIVE_SAFE', dastActiveConsent: true } : scan, signal);
      expect(result.kind).toBe('failed');
      expect(resolutions).toBe(0);
      expect(requests).toBe(0);
    }
  });

  test('nested-encoded separators are refused before DNS and transport for linked and legacy-unlinked scans', async () => {
    const { scan, authorizer } = await fixture();
    for (const linked of [true, false]) for (const active of [false, true]) {
      let resolutions = 0;
      let requests = 0;
      const unsafe = { ...scan, dastTargetUrl: 'https://app.example.org/api/%252e%252e%252foutside',
        ...(active ? { dastMode: 'ACTIVE_SAFE' as const, dastActiveConsent: true } : {}) };
      if (!linked) delete unsafe.assessmentId;
      const targetPolicy = createDastTargetPolicy({ resolve: async () => { resolutions += 1; return ['93.184.216.34']; } });
      const transport: DastTransport = { probe: async () => {
        requests += 1;
        return { status: 200, headers: {}, body: '', bodyTruncated: false, elapsedMs: 1 };
      } };
      const options = { targetPolicy, transport, ...(linked ? { authorize: authorizer } : {}) };
      const engine = active ? createActiveDastEngine({ ...options, throttleMs: 0 }) : createDastEngine(options);
      const result = await engine.execute(unsafe, signal);
      expect(result.kind).toBe('failed');
      expect(resolutions).toBe(0);
      expect(requests).toBe(0);
    }
  });

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

  test('an unlinked legacy scan does not follow an encoded traversal normalized by URL parsing', async () => {
    const { scan } = await fixture();
    const unlinked = { ...scan }; delete unlinked.assessmentId;
    const requests: string[] = [];
    const transport: DastTransport = { probe: async (target) => {
      requests.push(target.url);
      return { status: 302, headers: { location: '/api/%2e%2e/admin' }, body: '', bodyTruncated: false, elapsedMs: 1 };
    } };
    const result = await createDastEngine({ targetPolicy: policy(), transport }).execute(unlinked, signal);
    expect(result.kind).toBe('completed');
    expect(requests).toEqual([TARGET]);
    if (result.kind === 'completed') expect(result.dast?.partial).toBe(true);
  });

  test('an active legacy crawl does not normalize encoded traversal into a new request', async () => {
    const { scan } = await fixture();
    const unlinked = { ...scan, dastMode: 'ACTIVE_SAFE' as const, dastActiveConsent: true }; delete unlinked.assessmentId;
    const requests: string[] = [];
    const transport: DastTransport = { probe: async (target) => {
      requests.push(target.url);
      return { status: 200, headers: {}, body: '<a href="/api/%2e%2e/admin">unsafe</a>', bodyTruncated: false, elapsedMs: 1 };
    } };
    await createActiveDastEngine({ targetPolicy: policy(), transport, throttleMs: 0 }).execute(unlinked, signal);
    expect(requests[0]).toBe(TARGET);
    expect(requests).not.toContain('https://app.example.org/admin');
  });

  test('an unlinked legacy scan never resolves or contacts a cross-host redirect', async () => {
    const { scan } = await fixture();
    const unlinked = { ...scan };
    delete unlinked.assessmentId;
    const hosts: string[] = [];
    const requests: string[] = [];
    const targetPolicy = createDastTargetPolicy({ resolve: async (host) => { hosts.push(host); return ['93.184.216.34']; } });
    const transport: DastTransport = { probe: async (target) => {
      requests.push(target.url);
      return { status: 302, headers: { location: 'https://elsewhere.example.org/outside' }, body: '', bodyTruncated: false, elapsedMs: 3 };
    } };
    const result = await createDastEngine({ targetPolicy, transport }).execute(unlinked, signal);
    expect(result.kind).toBe('completed');
    expect(requests).toEqual([TARGET]);
    expect(hosts.length).toBeGreaterThan(0);
    expect(hosts.every((host) => host === 'app.example.org')).toBe(true);
    if (result.kind === 'completed') expect(result.dast?.partial).toBe(true);
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

  test('withdrawal while DNS is resolving blocks passive and active transport', async () => {
    const { scan } = await fixture();
    for (const active of [false, true]) {
      let allowed = true;
      let requests = 0;
      const targetPolicy = createDastTargetPolicy({ resolve: async () => { allowed = false; return ['93.184.216.34']; } });
      const transport: DastTransport = { probe: async () => { requests += 1; throw new Error('unexpected transport'); } };
      const options = { targetPolicy, transport, authorize: async () => allowed };
      const engine = active ? createActiveDastEngine({ ...options, throttleMs: 0 }) : createDastEngine(options);
      const record = active ? { ...scan, dastMode: 'ACTIVE_SAFE' as const, dastActiveConsent: true } : scan;
      expect((await engine.execute(record, signal)).kind).toBe('failed');
      expect(requests).toBe(0);
    }
  });

  test('active and passive redirects never resolve or request a cross-host destination', async () => {
    const { scan, authorizer } = await fixture();
    for (const linked of [true, false]) for (const active of [false, true]) {
      const hosts: string[] = [];
      const requests: string[] = [];
      const targetPolicy = createDastTargetPolicy({ resolve: async (host) => { hosts.push(host); return ['93.184.216.34']; } });
      const transport: DastTransport = { probe: async (target) => {
        requests.push(target.url);
        return { status: 302, headers: { location: 'https://elsewhere.example.org/outside' }, body: '', bodyTruncated: false, elapsedMs: 1 };
      } };
      const record = { ...scan, ...(active ? { dastMode: 'ACTIVE_SAFE' as const, dastActiveConsent: true } : {}) };
      if (!linked) delete record.assessmentId;
      const options = { targetPolicy, transport, maxRequests: 1, ...(linked ? { authorize: authorizer } : {}) };
      const engine = active ? createActiveDastEngine({ ...options, throttleMs: 0 }) : createDastEngine(options);
      expect((await engine.execute(record, signal)).kind).toBe('completed');
      expect(requests).toEqual([TARGET]);
      expect(hosts.length).toBeGreaterThan(0);
      expect(hosts.every((host) => host === 'app.example.org')).toBe(true);
    }
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
