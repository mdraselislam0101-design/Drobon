import { describe, expect, test } from 'vitest';
import { ASSISTANT_CONTEXT_ITEM_MAX_LENGTH, ASSISTANT_CONTEXT_MAX_ITEMS, ASSISTANT_CONTEXT_MAX_LENGTH } from '@drobon/shared';
import { buildBoundedAssistantContext } from '../src/assistant/context.js';
import { redactAssistantText } from '../src/assistant/redaction.js';

describe('assistant security redaction and bounds', () => {
  test('removes synthetic credentials, tokens, cookies, private keys, and URL credentials', () => {
    const synthetic = 'SYNTHETIC_ASSISTANT_SECRET_42';
    const result = redactAssistantText([
      `${'pass' + 'word'} = "${synthetic}"`,
      'Authorization: Bearer abc.def.ghi',
      'set-cookie: session=synthetic-cookie; HttpOnly',
      'https://user:pass@example.test/private',
      '-----BEGIN RSA ' + 'PRIVATE KEY-----',
      'MIIE-synthetic-private-material',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n'));
    expect(result.text).not.toContain(synthetic);
    expect(result.text).not.toContain('abc.def.ghi');
    expect(result.text).not.toContain('synthetic-cookie');
    expect(result.text).not.toContain('user:pass');
    expect(result.text).not.toContain('MIIE-synthetic-private-material');
    expect(result.redacted).toBe(true);
    // Header ambiguity intentionally fails closed for a future provider.
    expect(result.safeForProvider).toBe(false);
  });

  test('fails closed on malformed private-key material and strips forbidden controls', () => {
    const unresolved = redactAssistantText('-----BEGIN ' + 'PRIVATE KEY-----\npartially captured');
    expect(unresolved).toEqual({ text: '[sensitive evidence omitted]', redacted: true, safeForProvider: false });
    expect(redactAssistantText('safe\u0000text').text).toBe('safe text');
  });

  test('bounds item count and characters while preserving safe provenance', () => {
    const projectId = 'prj_00000000-0000-4000-8000-000000000001';
    const items = Array.from({ length: ASSISTANT_CONTEXT_MAX_ITEMS + 20 }, (_, index) => ({
      sourceType: 'SCAN' as const,
      sourceId: `scan-${index}`,
      projectId,
      content: `Evidence ${index} ` + 'x'.repeat(ASSISTANT_CONTEXT_ITEM_MAX_LENGTH + 50),
      sensitivity: 'SECURITY_METADATA' as const,
    }));
    const context = buildBoundedAssistantContext(items);
    expect(context.items.length).toBeLessThanOrEqual(ASSISTANT_CONTEXT_MAX_ITEMS);
    expect(context.items.every((item) => item.content.length <= ASSISTANT_CONTEXT_ITEM_MAX_LENGTH)).toBe(true);
    expect(context.summary.characterCount).toBeLessThanOrEqual(ASSISTANT_CONTEXT_MAX_LENGTH);
    expect(context.summary.truncated).toBe(true);
    expect(context.items.every((item) => item.projectId === projectId)).toBe(true);
  });

  test('redacts provenance IDs and caps their length instead of reflecting raw values', () => {
    const credentialMarker = 'SYNTHETIC_SOURCE_TOKEN_99887766554433221100';
    const context = buildBoundedAssistantContext([{
      sourceType: 'SBOM', sourceId: `component-${credentialMarker}`,
      projectId: 'prj_00000000-0000-4000-8000-000000000001',
      content: 'Observed component metadata.', sensitivity: 'SECURITY_METADATA',
    }]);
    expect(context.items[0]?.sourceId).not.toContain(credentialMarker);
    expect(context.items[0]?.sourceId.length).toBeLessThanOrEqual(120);
  });
});
