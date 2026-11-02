import { describe, expect, test } from 'vitest';
import { isDastResult } from '@drobon/shared';
import { createActiveDastEngine } from '../src/scans/dast/activeEngine.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import type { ScanRecord } from '../src/scans/store.js';
import {
  OPENAPI_MAX_SPEC_PROBES,
  parseOpenApiSpec,
} from '../src/scans/dast/openapi.js';

/**
 * P2-12 — bounded OpenAPI/Swagger ingestion for active DAST.
 *
 * The contract: a specification is a hint list. Nothing in it becomes a
 * request unless the path is a query-free GET, every path parameter has a
 * value the specification itself states, and the URL still passes the target
 * policy, the authorization check and the request budget.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const TARGET = 'https://app.example.org/';
const NOW = '2026-11-02T10:00:00.000Z';
const signal = { signal: new AbortController().signal };

const policy = () => createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });

function record(extra: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000003',
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'DAST',
    status: 'RUNNING',
    dastTargetUrl: TARGET,
    createdAt: NOW,
    updatedAt: NOW,
    startedAt: NOW,
    ...extra,
  };
}

function response(body: string, status = 200, contentType = 'text/html'): DastProbeResponse {
  return {
    status,
    headers: { 'content-type': contentType },
    body,
    bodyTruncated: false,
    elapsedMs: 3,
  };
}

/** A transport that records every URL it is asked to probe. */
function recordingTransport(handler: (url: string) => DastProbeResponse): {
  transport: DastTransport;
  urls: string[];
} {
  const urls: string[] = [];
  return {
    urls,
    transport: {
      probe: async (target) => {
        urls.push(target.url);
        return handler(target.url);
      },
    },
  };
}

const SPEC = {
  openapi: '3.0.3',
  info: { title: 'Fixture API', version: '1.0.0' },
  paths: {
    '/health': { get: { responses: { '200': { description: 'ok' } } } },
    '/users/{id}': {
      get: {
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', example: '42' } }],
        responses: { '200': { description: 'ok' } },
      },
    },
    '/admin/shutdown': { post: { responses: { '200': { description: 'no' } } } },
    '/search': {
      get: {
        parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'ok' } },
      },
    },
    '/orders/{orderId}': {
      get: {
        parameters: [{ name: 'orderId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'needs an id we do not have' } },
      },
    },
  },
};

describe('OpenAPI parsing (P2-12): bounded, literal-only endpoint selection', () => {
  test('only query-free GETs with spec-stated path values are produced', () => {
    const parsed = parseOpenApiSpec(JSON.stringify(SPEC));
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.specVersion).toBe('OpenAPI 3.0.3');
    expect(parsed.endpoints.map((endpoint) => endpoint.path)).toEqual(['/health', '/users/42']);
    // /search needs a required query value, /orders/{orderId} states none.
    expect(parsed.skipped).toBe(2);
    expect(parsed.note).toContain('2 GET operation(s)');
  });

  test('Swagger 2.0 is accepted; YAML, unknown documents and junk are refused honestly', () => {
    const swagger = parseOpenApiSpec(
      JSON.stringify({
        swagger: '2.0',
        paths: {
          '/status': { get: { parameters: [{ name: 'x', in: 'query', required: false }], responses: {} } },
        },
      }),
    );
    expect(swagger.status).toBe('ANALYZED');
    expect(swagger.specVersion).toBe('Swagger 2.0');
    // An optional query parameter does not block the operation.
    expect(swagger.endpoints).toEqual([{ path: '/status' }]);

    const yaml = parseOpenApiSpec('openapi: 3.0.3\npaths:\n  /a:\n    get: {}\n');
    expect(yaml.status).toBe('UNSUPPORTED');
    expect(yaml.endpoints).toEqual([]);
    expect(yaml.note).toContain('JSON');

    expect(parseOpenApiSpec('{"paths":{}}').status).toBe('UNSUPPORTED');
    expect(parseOpenApiSpec('{"openapi":"3.0.3"}').status).toBe('INVALID_INPUT');
    expect(parseOpenApiSpec('{oops').status).toBe('INVALID_INPUT');
    expect(parseOpenApiSpec('').status).toBe('INVALID_INPUT');
    expect(parseOpenApiSpec('[]').status).toBe('INVALID_INPUT');
  });

  test('hostile paths and values never survive parsing', () => {
    const parsed = parseOpenApiSpec(
      JSON.stringify({
        openapi: '3.1.0',
        paths: {
          '/../etc/passwd': { get: {} },
          '//evil.example.org/x': { get: {} },
          '/a%2e%2e/b': { get: {} },
          '/space here': { get: {} },
          '/traversal/{x}': {
            get: {
              parameters: [
                { name: 'x', in: 'path', required: true, schema: { example: '../../../etc/passwd' } },
              ],
            },
          },
          '/safe/{x}': {
            get: { parameters: [{ name: 'x', in: 'path', required: true, schema: { example: 'abc-123' } }] },
          },
        },
      }),
    );
    expect(parsed.endpoints).toEqual([{ path: '/safe/abc-123' }]);
  });

  test('endpoint selection is capped and deterministic', () => {
    const paths: Record<string, unknown> = {};
    for (let index = 0; index < 120; index += 1) {
      paths[`/item-${index}`] = { get: {} };
    }
    const first = parseOpenApiSpec(JSON.stringify({ openapi: '3.0.0', paths }));
    const second = parseOpenApiSpec(JSON.stringify({ openapi: '3.0.0', paths }));
    expect(first.endpoints).toHaveLength(50);
    expect(first.endpoints).toEqual(second.endpoints);
    // The cap must be disclosed, not silently applied.
    expect(first.note).toContain('endpoint limit was reached');
  });
});

describe('OpenAPI ingestion in the active engine (P2-12)', () => {
  test('discovered endpoints are probed exactly once and disclosed honestly', async () => {
    const { transport, urls } = recordingTransport((url) => {
      if (url === 'https://app.example.org/openapi.json') {
        return response(JSON.stringify(SPEC), 200, 'application/json');
      }
      if (url === TARGET) return response('<html><body>home</body></html>');
      return response('{"ok":true}', 200, 'application/json');
    });
    const outcome = await createActiveDastEngine({
      targetPolicy: policy(),
      transport,
      throttleMs: 0,
    }).execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);

    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed' || outcome.dast === undefined) {
      throw new Error('missing DAST result');
    }
    const dast = outcome.dast;
    expect(isDastResult(dast)).toBe(true);
    expect(dast.openApiStatus).toBe('ANALYZED');
    expect(dast.openApiSpecProbes).toBe(1);
    expect(dast.openApiSkipped).toBe(2);
    expect(dast.openApiEndpoints).toBe(2);
    // Exactly the parsed endpoints — no POST, no required-query, no unbound id.
    expect(urls).toContain('https://app.example.org/health');
    expect(urls).toContain('https://app.example.org/users/42');
    expect(urls.some((url) => url.includes('/admin/shutdown'))).toBe(false);
    expect(urls.some((url) => url.includes('/search'))).toBe(false);
    expect(urls.some((url) => url.includes('/orders/'))).toBe(false);
    // Every probed URL is unique (the crawler never re-requests a spec seed).
    expect(new Set(urls).size).toBe(urls.length);
    expect(dast.requestCount).toBe(urls.length);
    expect(dast.crawledCount).toBe(2);
    expect(dast.injectedCount).toBeGreaterThanOrEqual(0);
  });

  test('no specification → NOT_FOUND, and the scan is not marked partial for it', async () => {
    const { transport, urls } = recordingTransport((url) =>
      url === TARGET ? response('<html></html>') : response('not found', 404),
    );
    const outcome = await createActiveDastEngine({ targetPolicy: policy(), transport, throttleMs: 0 })
      .execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.dast.openApiStatus).toBe('NOT_FOUND');
    expect(outcome.dast.openApiSpecProbes).toBe(2);
    expect(outcome.dast.openApiEndpoints).toBe(0);
    expect(outcome.dast.openApiSkipped).toBe(0);
    // Absence of a specification is not itself a partial scan (this scan is
    // still partial for a different, pre-existing reason: no dataset rules).
    expect(outcome.dast.partialReason ?? '').not.toContain('specification');
    expect(urls.filter((url) => url.endsWith('/openapi.json') || url.endsWith('/swagger.json'))).toHaveLength(2);
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('a specification the parser cannot use is disclosed as a partial scan', async () => {
    const { transport } = recordingTransport((url) => {
      if (url === 'https://app.example.org/openapi.json') return response('openapi: 3.0.3\n', 200, 'text/yaml');
      if (url === TARGET) return response('<html></html>');
      return response('nope', 404);
    });
    const outcome = await createActiveDastEngine({ targetPolicy: policy(), transport, throttleMs: 0 })
      .execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.dast.openApiStatus).toBe('UNSUPPORTED');
    expect(outcome.dast.openApiEndpoints).toBe(0);
    expect(outcome.dast.partial).toBe(true);
    expect(outcome.dast.partialReason).toContain('not JSON');
    expect(outcome.resultSummary.partialReason).toContain('not JSON');
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('authorization is still enforced per spec-derived URL', async () => {
    const { transport, urls } = recordingTransport((url) => {
      if (url === 'https://app.example.org/openapi.json') {
        return response(JSON.stringify(SPEC), 200, 'application/json');
      }
      if (url === TARGET) return response('<html></html>');
      return response('{"ok":true}', 200, 'application/json');
    });
    const outcome = await createActiveDastEngine({
      targetPolicy: policy(),
      transport,
      throttleMs: 0,
      // A scope that permits the baseline and the spec document, but none of
      // the endpoints the specification suggests.
      authorize: async (_record, url) =>
        url === TARGET || url.endsWith('/openapi.json'),
    }).execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);

    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(urls).toEqual([TARGET, 'https://app.example.org/openapi.json']);
    // Discovered but never probed — the counts must say so.
    expect(outcome.dast.openApiStatus).toBe('ANALYZED');
    expect(outcome.dast.openApiEndpoints).toBe(0);
    expect(outcome.dast.partial).toBe(true);
    expect(outcome.dast.partialReason).toContain('authorization');
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('a small request budget leaves no room for spec discovery', async () => {
    const { transport, urls } = recordingTransport(() => response('<html></html>'));
    const outcome = await createActiveDastEngine({
      targetPolicy: policy(),
      transport,
      throttleMs: 0,
      maxRequests: 3,
    }).execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.dast.openApiStatus).toBeUndefined();
    expect(urls.some((url) => url.includes('openapi'))).toBe(false);
    expect(OPENAPI_MAX_SPEC_PROBES).toBe(2);
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('passive scans never claim specification discovery', async () => {
    const { transport, urls } = recordingTransport(() => response('<html></html>'));
    const outcome = await createActiveDastEngine({ targetPolicy: policy(), transport, throttleMs: 0 })
      .execute(record(), signal);
    if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
    expect(outcome.dast.mode).toBeUndefined();
    expect(outcome.dast.openApiStatus).toBeUndefined();
    expect(urls).toEqual([TARGET]);
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('identical targets produce identical spec results (determinism)', async () => {
    const run = async () => {
      const { transport } = recordingTransport((url) => {
        if (url === 'https://app.example.org/openapi.json') {
          return response(JSON.stringify(SPEC), 200, 'application/json');
        }
        if (url === TARGET) return response('<html></html>');
        return response('{"ok":true}', 200, 'application/json');
      });
      const outcome = await createActiveDastEngine({ targetPolicy: policy(), transport, throttleMs: 0 })
        .execute(record({ dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, dastOpenApiDiscovery: true }), signal);
      if (outcome.kind !== 'completed' || outcome.dast === undefined) throw new Error('missing DAST result');
      return outcome.dast;
    };
    const first = await run();
    const second = await run();
    expect(second.observations.map((o) => o.endpoint)).toEqual(first.observations.map((o) => o.endpoint));
    expect(second.openApiEndpoints).toBe(first.openApiEndpoints);
    expect(second.requestCount).toBe(first.requestCount);
  });
});
