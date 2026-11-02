import { describe, expect, test } from 'vitest';
import { isDastResult } from '@drobon/shared';
import {
  DAST_FORBIDDEN_AUTH_HEADERS,
  dastAuthMode,
  isDastAuthHeaderValue,
  normalizeDastAuthHeaderName,
  resolveDastAuth,
} from '../src/scans/dast/auth.js';
import { createActiveDastEngine } from '../src/scans/dast/activeEngine.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastProbeOptions, DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import type { ScanRecord } from '../src/scans/store.js';

/**
 * P2-12 — operator-configured authenticated probing.
 *
 * The contract under test: the credential is opt-in, server-side, attached per
 * request, and NEVER observable from a result. Drobon still cannot log in, keep
 * a cookie jar or store a user secret — and these tests pin that.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000031';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000032';
const TARGET = 'https://app.example.org/';
const NOW = '2026-11-02T10:00:00.000Z';
const TOKEN = 'synthetic-token-do-not-log-9f2c1a';

function record(extra: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000033',
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'DAST',
    status: 'RUNNING',
    dastTargetUrl: TARGET,
    dastMode: 'ACTIVE_SAFE',
    // Consent is required for the active engine to leave the gate.
    dastActiveConsent: true,
    createdAt: NOW,
    updatedAt: NOW,
    startedAt: NOW,
    ...extra,
  } as ScanRecord;
}

const policy = () => createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });

function response(body: string, status = 200, contentType = 'text/html'): DastProbeResponse {
  return { status, headers: { 'content-type': contentType }, body, bodyTruncated: false, elapsedMs: 2 };
}

interface SeenRequest {
  url: string;
  headers: Readonly<Record<string, string>> | undefined;
}

function recordingTransport(): { transport: DastTransport; seen: SeenRequest[] } {
  const seen: SeenRequest[] = [];
  return {
    seen,
    transport: {
      probe: async (target, options: DastProbeOptions) => {
        seen.push({ url: target.url, headers: options.extraHeaders });
        return response('<html><body>ok</body></html>');
      },
    },
  };
}

describe('DAST auth: configuration boundary', () => {
  test('a header name is a plain token and never one the client owns', () => {
    expect(normalizeDastAuthHeaderName('Authorization')).toBe('authorization');
    expect(normalizeDastAuthHeaderName('x-api-key')).toBe('x-api-key');
    expect(normalizeDastAuthHeaderName('Cookie')).toBe('cookie');
    for (const forbidden of DAST_FORBIDDEN_AUTH_HEADERS) {
      expect(normalizeDastAuthHeaderName(forbidden)).toBeUndefined();
      expect(normalizeDastAuthHeaderName(forbidden.toUpperCase())).toBeUndefined();
    }
    // Injection attempts and non-headers are refused outright.
    expect(normalizeDastAuthHeaderName('x-token\r\nhost: evil')).toBeUndefined();
    expect(normalizeDastAuthHeaderName('x token')).toBeUndefined();
    expect(normalizeDastAuthHeaderName('')).toBeUndefined();
    expect(normalizeDastAuthHeaderName('x'.repeat(49))).toBeUndefined();
    expect(normalizeDastAuthHeaderName(42)).toBeUndefined();
  });

  test('a value is one bounded, printable line', () => {
    expect(isDastAuthHeaderValue('Bearer abc.def')).toBe(true);
    expect(isDastAuthHeaderValue('')).toBe(false);
    expect(isDastAuthHeaderValue('   ')).toBe(false);
    expect(isDastAuthHeaderValue('a\r\nb')).toBe(false);
    expect(isDastAuthHeaderValue(`a${String.fromCharCode(0)}b`)).toBe(false);
    expect(isDastAuthHeaderValue(`a${String.fromCharCode(127)}b`)).toBe(false);
    expect(isDastAuthHeaderValue('x'.repeat(4097))).toBe(false);
    expect(isDastAuthHeaderValue(undefined)).toBe(false);
  });

  test('both halves are required — a misconfiguration is never half-applied', () => {
    expect(resolveDastAuth('authorization', `Bearer ${TOKEN}`)).toEqual({
      headerName: 'authorization',
      headerValue: `Bearer ${TOKEN}`,
    });
    expect(resolveDastAuth(undefined, `Bearer ${TOKEN}`)).toBeUndefined();
    expect(resolveDastAuth('authorization', undefined)).toBeUndefined();
    expect(resolveDastAuth('host', 'evil.example.org')).toBeUndefined();
    expect(resolveDastAuth('authorization', 'a\r\nb')).toBeUndefined();
    expect(dastAuthMode(undefined)).toBe('NONE');
    expect(dastAuthMode(resolveDastAuth('authorization', 'Bearer x'))).toBe('HEADER');
  });
});

describe('DAST auth: what the engine actually sends and discloses', () => {
  test('without configuration every request is unauthenticated', async () => {
    const { transport, seen } = recordingTransport();
    const engine = createActiveDastEngine({ transport, targetPolicy: policy(), throttleMs: 0 });
    const outcome = await engine.execute(record(), { signal: new AbortController().signal });
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((request) => request.headers === undefined)).toBe(true);
    expect(outcome.dast?.authMode).toBe('NONE');
  });

  test('a configured header is attached to every probe, and disclosed only as a mode', async () => {
    const { transport, seen } = recordingTransport();
    const engine = createActiveDastEngine({
      transport,
      targetPolicy: policy(),
      throttleMs: 0,
      auth: { headerName: 'authorization', headerValue: `Bearer ${TOKEN}` },
    });
    const outcome = await engine.execute(record(), { signal: new AbortController().signal });
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;

    // Every request carried it — the header is what makes an authenticated
    // surface reachable at all.
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) {
      expect(request.headers).toEqual({ authorization: `Bearer ${TOKEN}` });
    }
    // …and the result is still valid, disclosing the mode only.
    expect(outcome.dast?.authMode).toBe('HEADER');
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('the credential never reaches a result, an observation or a finding', async () => {
    const { transport } = recordingTransport();
    const engine = createActiveDastEngine({
      transport,
      targetPolicy: policy(),
      throttleMs: 0,
      auth: { headerName: 'authorization', headerValue: `Bearer ${TOKEN}` },
    });
    const outcome = await engine.execute(record(), { signal: new AbortController().signal });
    expect(outcome.kind).toBe('completed');
    const serialized = JSON.stringify(outcome);
    expect(serialized).not.toContain(TOKEN);
    expect(serialized).not.toContain('authorization');
    expect(serialized).toContain('"authMode":"HEADER"');
  });

  test('a passive DAST result can never claim authenticated probing', async () => {
    const { transport, seen } = recordingTransport();
    const engine = createDastEngine({
      transport,
      targetPolicy: policy(),
      auth: { headerName: 'authorization', headerValue: `Bearer ${TOKEN}` },
    });
    // No `dastMode` → the passive path. It never authenticates and never
    // discloses an authMode, so the shared guard keeps rejecting such a claim.
    const passive = record();
    delete passive.dastMode;
    const outcome = await engine.execute(passive, {
      signal: new AbortController().signal,
    });
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((request) => request.headers === undefined)).toBe(true);
    expect(outcome.dast?.authMode).toBeUndefined();
    expect(isDastResult(outcome.dast)).toBe(true);
  });
});
