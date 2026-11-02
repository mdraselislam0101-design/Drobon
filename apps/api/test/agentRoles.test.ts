import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import { afterEach, describe, expect, test } from 'vitest';
import {
  AGENT_ROLES, AGENT_ROLE_IDS, AGENT_TOOLS, auditAgentTool, authoriseAgentTool,
  roleForScanType, rolesWithNetworkAccess,
} from '../src/agent/roles.js';
import {
  createLocalModelProvider, isLoopbackEndpoint, type LocalModelFetch, type LocalModelRequest,
} from '../src/agent/localModel.js';

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

const request: LocalModelRequest = {
  role: 'VALIDATION',
  securityPolicy: 'Answer only from supplied evidence.',
  task: 'Is finding f-1 supported?',
  untrustedEvidence: [{ id: 'ev:1', kind: 'SAST', summary: 'rule R1 at src/a.js:12' }],
};
const validAnswer = {
  role: 'VALIDATION', conclusion: 'Supported by one source location.', confidence: 'LOW',
  evidenceIds: ['ev:1'], missingEvidence: ['runtime response'], recommendation: 'Add a DAST observation.',
};

describe('seven logical agent roles', () => {
  test('declares exactly seven roles with responsibility, tools and evidence', () => {
    expect(AGENT_ROLE_IDS).toHaveLength(7);
    for (const id of AGENT_ROLE_IDS) {
      const role = AGENT_ROLES[id];
      expect(role.id).toBe(id);
      expect(role.responsibility.length).toBeGreaterThan(10);
      expect(role.tools.length).toBeGreaterThan(0);
      expect(role.evidenceRequired.length).toBeGreaterThan(0);
      expect(role.maxSteps).toBeGreaterThan(0);
      expect(role.tools.every((tool) => (AGENT_TOOLS as readonly string[]).includes(tool))).toBe(true);
    }
  });

  test('grants each scanner tool only to its own role and refuses everything else', () => {
    for (const [scanType, role] of [['SAST', 'SAST'], ['SCA', 'SCA'], ['SECRETS', 'SECRETS'], ['DAST', 'DAST']] as const) {
      expect(roleForScanType(scanType)).toBe(role);
      expect(authoriseAgentTool(role, `RUN_${scanType}` as never)).toEqual({ allowed: true });
    }
    expect(authoriseAgentTool('VALIDATION', 'RUN_SAST')).toMatchObject({ allowed: false });
    expect(authoriseAgentTool('RECON', 'RUN_DAST')).toMatchObject({ allowed: false });
    expect(authoriseAgentTool('MASTER', 'RUN_DAST')).toMatchObject({ allowed: false });
    expect(authoriseAgentTool('MASTER', 'RUN_SCA')).toMatchObject({ allowed: false });
    expect(authoriseAgentTool('SAST', 'VALIDATE_EVIDENCE')).toMatchObject({ allowed: false });
  });

  test('only the DAST role can hold a network tool', () => {
    expect(rolesWithNetworkAccess()).toEqual(['DAST']);
    for (const id of AGENT_ROLE_IDS) {
      const network = AGENT_ROLES[id].tools.filter((tool) => tool === 'RUN_DAST');
      expect(network.length > 0).toBe(id === 'DAST');
    }
  });

  test('audits both grants and refusals without leaking content', () => {
    expect(auditAgentTool('SAST', 'RUN_SAST')).toEqual({ role: 'SAST', tool: 'RUN_SAST', allowed: true });
    const denied = auditAgentTool('RECON', 'RUN_DAST');
    expect(denied.allowed).toBe(false);
    expect(JSON.stringify(denied)).not.toContain('summary');
  });
});

describe('local-model contract (no model ships with this app)', () => {
  test('is unavailable by default and never calls the network', async () => {
    let called = 0;
    const provider = createLocalModelProvider({ fetchImpl: (async () => { called += 1; throw new Error('must not run'); }) as unknown as LocalModelFetch });
    expect(provider.availability()).toEqual({ state: 'NONE', endpoint: null });
    expect(await provider.complete(request)).toEqual({ state: 'UNAVAILABLE', reason: 'no-local-model-configured' });
    expect(called).toBe(0);
  });

  test('refuses a non-loopback endpoint instead of falling back', () => {
    for (const endpoint of [
      'https://api.example.com/v1/chat', 'http://10.0.0.5:11434', 'http://192.168.1.2:8080',
      'http://127.0.0.1.evil.example:80', 'ftp://127.0.0.1:21', 'http://user:pass@127.0.0.1:80',
    ]) {
      expect(isLoopbackEndpoint(endpoint)).toBe(false);
      expect(() => createLocalModelProvider({ config: { endpoint, model: 'local' } })).toThrow(/loopback/);
    }
  });

  test('accepts literal loopback endpoints', () => {
    for (const endpoint of ['http://127.0.0.1:11434/api', 'http://localhost:8080', 'http://127.9.9.9:1']) {
      expect(isLoopbackEndpoint(endpoint)).toBe(true);
      expect(createLocalModelProvider({ config: { endpoint, model: 'local-test' } }).availability())
        .toEqual({ state: 'READY', endpoint: 'loopback' });
    }
  });

  test('rejects a fabricated evidence id, extra fields and mismatched roles', async () => {
    const cases = [
      { ...validAnswer, evidenceIds: ['ev:999'] },
      { ...validAnswer, extra: 'field' },
      { ...validAnswer, role: 'MASTER' },
      { ...validAnswer, confidence: 'CERTAIN' },
      { ...validAnswer, conclusion: '' },
      { ...validAnswer, evidenceIds: ['ev:1', 'not an id!'] },
    ];
    for (const body of cases) {
      const provider = createLocalModelProvider({
        config: { endpoint: 'http://127.0.0.1:1', model: 'local-test' },
        fetchImpl: (async () => ({ ok: true, status: 200, text: async () => JSON.stringify(body) })) as unknown as LocalModelFetch,
      });
      expect(await provider.complete(request)).toEqual({ state: 'UNAVAILABLE', reason: 'contract-violation' });
    }
  });

  test('returns a strict answer only when the contract is satisfied', async () => {
    const provider = createLocalModelProvider({
      config: { endpoint: 'http://127.0.0.1:1', model: 'local-test' },
      fetchImpl: (async () => ({ ok: true, status: 200, text: async () => JSON.stringify(validAnswer) })) as unknown as LocalModelFetch,
    });
    const result = await provider.complete(request);
    expect(result.state).toBe('ANSWER');
    if (result.state === 'ANSWER') {
      expect(result.answer.evidenceIds).toEqual(['ev:1']);
      expect(result.answer.confidence).toBe('LOW');
    }
  });

  test('bounds the response size, HTTP errors and invalid JSON', async () => {
    const bodies = [
      { ok: true, status: 200, text: async () => 'x'.repeat(70 * 1024) },
      { ok: false, status: 503, text: async () => '{}' },
      { ok: true, status: 200, text: async () => 'not json' },
    ];
    const reasons: string[] = [];
    for (const body of bodies) {
      const provider = createLocalModelProvider({
        config: { endpoint: 'http://127.0.0.1:1', model: 'local-test' },
        fetchImpl: (async () => body) as unknown as LocalModelFetch,
      });
      const result = await provider.complete(request);
      reasons.push(result.state === 'UNAVAILABLE' ? result.reason : 'unexpected-answer');
    }
    expect(reasons).toEqual(['response-too-large', 'http-503', 'invalid-json']);
  });

  test('times out without producing an answer', async () => {
    const provider = createLocalModelProvider({
      config: { endpoint: 'http://127.0.0.1:1', model: 'local-test', timeoutMs: 25 },
      fetchImpl: ((_input: string, init: { signal: AbortSignal }) => new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')));
      })) as unknown as LocalModelFetch,
    });
    expect(await provider.complete(request)).toEqual({ state: 'UNAVAILABLE', reason: 'timeout' });
  });

  test.skipIf(typeof globalThis.fetch !== 'function')('talks to a real loopback stub over HTTP only', async () => {
    let received: Record<string, unknown> | undefined;
    const server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        received = JSON.parse(raw) as Record<string, unknown>;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(validAnswer));
      });
    });
    servers.push(server);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    const provider = createLocalModelProvider({ config: { endpoint: `http://127.0.0.1:${port}/api`, model: 'stub' } });
    const result = await provider.complete(request);
    expect(result.state).toBe('ANSWER');
    expect(received?.['model']).toBe('stub');
    expect(String(received?.['system'])).toContain('Never invent a tool result');
    expect(received?.['untrustedEvidence']).toEqual([{ id: 'ev:1', kind: 'SAST', summary: 'rule R1 at src/a.js:12' }]);
  });
});
