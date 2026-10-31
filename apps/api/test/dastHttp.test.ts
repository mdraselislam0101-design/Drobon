import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import { afterEach, describe, expect, test } from 'vitest';
import { createNodeDastTransport, runBoundedDastProbe, type DastTransport } from '../src/scans/dast/http.js';
import type { ResolvedDastTarget } from '../src/scans/dast/target.js';

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => {
    if (server.listening) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }));
});

async function listen(server: Server): Promise<number> {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('Expected a loopback TCP port.');
  return address.port;
}

function loopbackFixtureTarget(port: number): ResolvedDastTarget {
  // Test-only transport input. The DAST target policy separately proves
  // that production URLs resolving to loopback are blocked; this object
  // bypasses only policy so the HTTP transport can reach our own fixture.
  return {
    url: `http://fixture.example.org:${port}/fixture`,
    hostname: 'fixture.example.org',
    addresses: ['127.0.0.1'],
  };
}

function options(overrides: Partial<{ timeoutMs: number; maxResponseBytes: number; signal: AbortSignal }> = {}) {
  return {
    timeoutMs: 500,
    maxResponseBytes: 32_768,
    signal: new AbortController().signal,
    ...overrides,
  };
}

describe('managed bounds for injected DAST transports', () => {
  test('a pre-aborted operation never calls the injected transport', async () => {
    const controller = new AbortController(); controller.abort();
    let probes = 0;
    const transport: DastTransport = { probe: async () => { probes += 1; throw new Error('must not start'); } };
    await expect(runBoundedDastProbe(transport, loopbackFixtureTarget(1), options({ signal: controller.signal })))
      .rejects.toMatchObject({ kind: 'aborted' });
    expect(probes).toBe(0);
  });

  test('timeout aborts the transport signal and discards a late result', async () => {
    let signal: AbortSignal | undefined; let finish!: () => void;
    const gate = new Promise<void>((resolveGate) => { finish = resolveGate; });
    const transport: DastTransport = { probe: async (_target, probeOptions) => {
      signal = probeOptions.signal; await gate;
      return { status: 200, headers: {}, body: 'late fixture', bodyTruncated: false, elapsedMs: 1 };
    } };
    const result = runBoundedDastProbe(transport, loopbackFixtureTarget(1), options({ timeoutMs: 20 }));
    try {
      await expect(result).rejects.toMatchObject({ kind: 'timeout' });
      expect(signal?.aborted).toBe(true);
    } finally { finish(); }
    await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
  });

  test('cancellation settles without waiting for an uncooperative callback', async () => {
    let signal: AbortSignal | undefined; let finish!: () => void;
    const gate = new Promise<void>((resolveGate) => { finish = resolveGate; });
    const transport: DastTransport = { probe: async (_target, probeOptions) => {
      signal = probeOptions.signal; await gate; throw new Error('late fixture failure');
    } };
    const controller = new AbortController();
    const result = runBoundedDastProbe(transport, loopbackFixtureTarget(1), options({ signal: controller.signal }));
    controller.abort();
    try {
      await expect(result).rejects.toMatchObject({ kind: 'aborted' });
      expect(signal?.aborted).toBe(true);
    } finally { finish(); }
    await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
  });
});

describe('bounded Node DAST HTTP transport (loopback fixture only)', () => {
  test('pins the connection to the supplied address, sends one unauthenticated GET, and stops at the body cap', async () => {
    let observed: Record<string, string | undefined> = {};
    const server = createServer((req, res) => {
      observed = {
        method: req.method,
        url: req.url,
        host: req.headers.host,
        encoding: req.headers['accept-encoding'],
        cookie: req.headers.cookie,
        authorization: req.headers.authorization,
        origin: req.headers.origin,
      };
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('0123456789'.repeat(100));
    });
    servers.push(server);
    const port = await listen(server);
    const result = await createNodeDastTransport().probe(
      loopbackFixtureTarget(port),
      options({ maxResponseBytes: 32 }),
    );
    expect(observed).toMatchObject({
      method: 'GET',
      url: '/fixture',
      host: `fixture.example.org:${port}`,
      encoding: 'identity',
      origin: 'https://drobon-aegis.invalid',
    });
    expect(observed.cookie).toBeUndefined();
    expect(observed.authorization).toBeUndefined();
    expect(result.status).toBe(200);
    expect(Buffer.byteLength(result.body, 'utf8')).toBeLessThanOrEqual(32);
    expect(result.bodyTruncated).toBe(true);
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  test('request timeout is enforced and surfaced as a typed safe error', async () => {
    const server = createServer((_req, _res) => undefined);
    servers.push(server);
    const port = await listen(server);
    await expect(createNodeDastTransport().probe(
      loopbackFixtureTarget(port),
      options({ timeoutMs: 25 }),
    )).rejects.toMatchObject({ kind: 'timeout' });
  });

  test('pre-aborted signals are rejected without opening an HTTP exchange', async () => {
    let requested = false;
    const server = createServer(() => { requested = true; });
    servers.push(server);
    const port = await listen(server);
    const controller = new AbortController();
    controller.abort();
    await expect(createNodeDastTransport().probe(
      loopbackFixtureTarget(port),
      options({ signal: controller.signal }),
    )).rejects.toMatchObject({ kind: 'aborted' });
    expect(requested).toBe(false);
  });
});
