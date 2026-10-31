import { afterEach, describe, expect, test } from 'vitest';
import type { Route } from '../src/http.js';
import { startTestServer, type TestServer } from './helpers.js';

const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

// Disposable synthetic markers, including an unlabelled short value that no
// generic credential-pattern matcher can reliably recognize.
const PATH_VALUE = 'q7z-fixture-path-value';
const QUERY_VALUE = 'query-fixture-not-for-logs';
const CLIENT_ID = 'client-fixture-not-for-logs';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('request log privacy', () => {
  test('uses a server-generated log ID and templates for successful, rejected and failed requests', async () => {
    const extraRoutes: Route[] = [{ method: 'GET', path: '/test/log/:value', handler: async () => { throw new Error(PATH_VALUE); } }];
    const server = await startTestServer({ logLevel: 'info', corsAllowedOrigins: ['https://allowed.example.test'], extraRoutes });
    servers.push(server);
    const targets = [
      { url: `/missing/${PATH_VALUE}?v=${QUERY_VALUE}`, init: {}, status: 404 },
      { url: `/api/v1/projects/${PATH_VALUE}/scans?value=${QUERY_VALUE}`, init: {}, status: 401 },
      { url: `/api/v1/projects/${PATH_VALUE}/scans`, init: { method: 'POST', headers: { origin: 'https://untrusted.example.test' } }, status: 403 },
      { url: `/test/log/${PATH_VALUE}`, init: {}, status: 500 },
      { url: '/livez', init: { headers: { origin: 'https://allowed.example.test' } }, status: 200 },
    ];
    for (const target of targets) {
      const response = await fetch(`${server.baseUrl}${target.url}`, {
        ...target.init, headers: { ...target.init.headers, 'x-request-id': CLIENT_ID },
      });
      expect(response.status).toBe(target.status);
      expect(response.headers.get('x-request-id')).toBe(CLIENT_ID);
      const logId = response.headers.get('x-log-id');
      expect(logId).toMatch(UUID);
      expect(server.logs.join('\n')).toContain(logId);
      if (target.status === 200) expect(response.headers.get('access-control-expose-headers')).toContain('X-Log-Id');
    }
    const joined = server.logs.join('\n');
    expect(joined).not.toContain(PATH_VALUE);
    expect(joined).not.toContain(QUERY_VALUE);
    expect(joined).not.toContain(CLIENT_ID);
    expect(joined).toContain('[unmatched route]');
    expect(joined).toContain('/api/v1/projects/:projectId/scans');
    expect(joined).toContain('/test/log/:value');
    expect(joined).toContain('Origin guard refused request');
    expect(joined).toContain('Request failed');
    expect(joined).toContain('[REDACTED]');
  });

  test('rate-limit logs do not emit raw path segments, query or caller correlation ID', async () => {
    const server = await startTestServer({ logLevel: 'info', rateLimitMaxRequests: 1 });
    servers.push(server);
    expect((await fetch(`${server.baseUrl}/livez`)).status).toBe(200);
    const response = await fetch(`${server.baseUrl}/api/v1/projects/${PATH_VALUE}/scans?v=${QUERY_VALUE}`, { headers: { 'x-request-id': CLIENT_ID } });
    expect(response.status).toBe(429);
    expect(response.headers.get('x-request-id')).toBe(CLIENT_ID);
    const logId = response.headers.get('x-log-id');
    expect(logId).toMatch(UUID);
    const joined = server.logs.join('\n');
    expect(joined).toContain(logId);
    expect(joined).toContain('Request rate limited');
    expect(joined).toContain('/api/v1/projects/:projectId/scans');
    for (const value of [PATH_VALUE, QUERY_VALUE, CLIENT_ID]) expect(joined).not.toContain(value);
  });
});
