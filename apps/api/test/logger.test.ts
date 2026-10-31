import { describe, expect, test } from 'vitest';
import { createLogger, redactValue, REDACTED } from '../src/logger.js';

function collect() {
  const lines: string[] = [];
  const logger = createLogger({
    level: 'debug',
    service: 'test-svc',
    env: 'test',
    now: () => '2026-01-01T00:00:00.000Z',
    out: (line) => {
      lines.push(line);
    },
  });
  return { lines, logger };
}

describe('redactValue', () => {
  test('redacts sensitive keys at any depth, case-insensitively', () => {
    const redacted = redactValue({
      user: 'ada',
      password: 'hunter2-example',
      nested: { apiKey: 'example-key', deep: [{ TOKEN: 'example-token' }] },
      'X-Auth-Token': 'example',
    }) as Record<string, unknown>;
    expect(redacted['user']).toBe('ada');
    expect(redacted['password']).toBe(REDACTED);
    const nested = redacted['nested'] as Record<string, unknown>;
    expect(nested['apiKey']).toBe(REDACTED);
    const deep = nested['deep'] as Array<Record<string, unknown>>;
    expect(deep[0]?.['TOKEN']).toBe(REDACTED);
    expect(redacted['X-Auth-Token']).toBe(REDACTED);
  });

  test('redacts bearer-like values and credentialed URLs', () => {
    expect(redactValue('Bearer example-token-value')).toBe(REDACTED);
    expect(redactValue('plain string')).toBe('plain string');
    const redacted = redactValue({
      url: 'https://user:hunter2@example.test/path',
      cleanUrl: 'https://example.test/path',
    }) as Record<string, unknown>;
    expect(redacted['url']).toBe(REDACTED);
    expect(redacted['cleanUrl']).toBe('https://example.test/path');
  });

  test('survives cycles and deep structures', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;
    const redacted = redactValue(cyclic) as Record<string, unknown>;
    expect(redacted['a']).toBe(1);
    expect(redacted['self']).toBe('[CIRCULAR]');
  });
});

describe('createLogger', () => {
  test('emits structured JSON lines with service and timestamp', () => {
    const { lines, logger } = collect();
    logger.info('hello', { n: 1 });
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(entry).toMatchObject({
      time: '2026-01-01T00:00:00.000Z',
      level: 'info',
      service: 'test-svc',
      msg: 'hello',
      n: 1,
    });
  });

  test('filters below the configured level', () => {
    const lines: string[] = [];
    const logger = createLogger({
      level: 'warn',
      out: (line) => {
        lines.push(line);
      },
    });
    logger.debug('d');
    logger.info('i');
    logger.warn('w');
    logger.error('e');
    expect(lines).toHaveLength(2);
  });

  test('redacts sensitive fields on every line', () => {
    const { lines, logger } = collect();
    logger.info('login', { user: 'ada', password: 'hunter2-example' });
    expect(lines[0]).toContain(REDACTED);
    expect(lines[0]).not.toContain('hunter2');
  });

  test('child loggers inherit bindings', () => {
    const { lines, logger } = collect();
    logger.child({ requestId: 'req-test-1' }).info('scoped');
    const entry = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(entry['requestId']).toBe('req-test-1');
  });

  test('withholds arbitrary exception messages and stacks in every environment', () => {
    // A short unlabeled fixture cannot reliably be recognized as a secret.
    const secret = 'q7z'; // test-only synthetic fixture
    const error = new TypeError(`unstructured ${secret}`);
    error.stack = `TypeError: ${secret}\n    at /tmp/${secret}.js:1:1`;
    for (const env of ['production', 'development', 'test'] as const) {
      const lines: string[] = [];
      const logger = createLogger({ env, out: (line) => lines.push(line) });
      logger.error('failed', { err: error, nested: { exception: error } });
      logger.error('thrown non-error', { err: secret });
      expect(lines.join('\n')).not.toContain(secret);
      const entry = JSON.parse(lines[0]!) as {
        err: { name: string; message: string; stack?: string };
        nested: { exception: { name: string; message: string; stack?: string } };
      };
      expect(entry.err).toEqual({ name: 'TypeError', message: REDACTED });
      expect(entry.nested.exception).toEqual({ name: 'TypeError', message: REDACTED });
      expect(entry.err.stack).toBeUndefined();
    }
    const disguised = new Error('ignored');
    disguised.name = secret;
    expect(redactValue(disguised)).toEqual({ name: 'Error', message: REDACTED });
  });
});
