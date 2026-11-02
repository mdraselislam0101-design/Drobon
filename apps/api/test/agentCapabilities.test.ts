import { describe, expect, test } from 'vitest';
import { AGENT_ROLE_IDS } from '../src/agent/roles.js';
import { buildAgentCapabilities } from '../src/agent/capabilities.js';
import { createLocalModelProvider } from '../src/agent/localModel.js';

const input = {
  now: '2026-11-01T00:00:00.000Z',
  executionEnabled: true,
  storageCode: 'STORAGE_READY' as const,
  storageIssues: [],
  model: { state: 'NONE' as const, endpoint: null },
};

describe('agent capability report (honest, derived from code)', () => {
  test('lists exactly the seven logical roles with their tool grants', () => {
    const report = buildAgentCapabilities(input);
    expect(report.roles.map((role) => role.id)).toEqual([...AGENT_ROLE_IDS]);
    expect(report.roles).toHaveLength(7);
    for (const role of report.roles) {
      expect(role.tools.length).toBeGreaterThan(0);
      expect(role.evidenceRequired.length).toBeGreaterThan(0);
      expect(role.integrated).toBe(true);
    }
    expect(report.networkRoles).toEqual(['DAST']);
  });

  test('reports no AI when no model is configured', () => {
    const report = buildAgentCapabilities(input);
    expect(report.model).toMatchObject({ state: 'NONE', provider: 'NONE' });
    expect(report.model.note).toContain('deterministic');
  });

  test('never promises a model verdict when a loopback model is configured', () => {
    const report = buildAgentCapabilities({ ...input, model: { state: 'READY', endpoint: 'loopback' } });
    expect(report.model).toMatchObject({ state: 'READY', provider: 'LOCAL_LOOPBACK' });
    expect(report.model.note).toContain('not used to change finding verdicts');
    expect(report.limitations.join(' ')).toContain('advisory');
  });

  test('propagates the storage verdict and blocks the claim of protection', () => {
    const blocked = buildAgentCapabilities({ ...input, storageCode: 'STORAGE_BLOCKED', storageIssues: ['directory-world-writable'] });
    expect(blocked.storage.code).toBe('STORAGE_BLOCKED');
    expect(blocked.storage.issues).toEqual(['directory-world-writable']);
    expect(blocked.storage.note).toContain('refused');
    expect(buildAgentCapabilities(input).storage.note).toContain('not proof');
  });

  test('reflects the execution gate instead of assuming it', () => {
    expect(buildAgentCapabilities({ ...input, executionEnabled: false }).execution.note).toContain('disabled');
  });

  test('a configured loopback provider is the only route to a READY model state', async () => {
    const provider = createLocalModelProvider({ config: { endpoint: 'http://127.0.0.1:18080', model: 'local-test' } });
    const report = buildAgentCapabilities({ ...input, model: provider.availability() });
    expect(report.model.provider).toBe('LOCAL_LOOPBACK');
    // Availability is a claim about configuration only; nothing was inferred.
    expect(await provider.complete({ role: 'VALIDATION', securityPolicy: 'p', task: 't', untrustedEvidence: [] }))
      .toMatchObject({ state: 'UNAVAILABLE' });
  });
});
