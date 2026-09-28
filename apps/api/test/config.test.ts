import { describe, expect, test } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  test('applies secure defaults for an empty environment', () => {
    const config = loadConfig({});
    expect(config.env).toBe('development');
    expect(config.host).toBe('127.0.0.1');
    expect(config.port).toBe(3001);
    expect(config.logLevel).toBe('info');
    expect(config.corsAllowedOrigins).toEqual([]);
    expect(config.rateLimitMaxRequests).toBe(100);
    expect(config.rateLimitWindowMs).toBe(60_000);
    expect(config.bodyMaxBytes).toBe(1_048_576);
    expect(typeof config.version).toBe('string');
    // Auth defaults (Pump 2): durable store, cost-32768 scrypt, 7-day
    // sessions, tight credential rate limit, Secure only in production.
    expect(config.authStorePath).toBe('.data/users.json');
    expect(config.authScryptCost).toBe(32_768);
    expect(config.authSessionTtlSeconds).toBe(604_800);
    expect(config.authRateLimitMaxRequests).toBe(30);
    expect(config.authRateLimitWindowMs).toBe(60_000);
    expect(config.cookieSecure).toBe(false);
    // Usage defaults (Pump 5): durable JSON store next to the auth store.
    expect(config.usageStorePath).toBe('.data/usage.json');
    // Projects default (Pump 6): same persistence pattern.
    expect(config.projectStorePath).toBe('.data/projects.json');
  });

  test('authorization probes are on outside production, off in it', () => {
    expect(loadConfig({}).authzProbeRoutes).toBe(true);
    expect(loadConfig({ NODE_ENV: 'development' }).authzProbeRoutes).toBe(true);
    expect(loadConfig({ NODE_ENV: 'test' }).authzProbeRoutes).toBe(true);
    // Production must never register the capability probes — they are
    // development/test observability only and cannot ship by accident.
    expect(loadConfig({ NODE_ENV: 'production' }).authzProbeRoutes).toBe(false);
  });

  test('usage storage is configurable and must be durable in production', () => {
    // Default: a real file, so quota state survives restarts.
    expect(loadConfig({}).usageStorePath).toBe('.data/usage.json');
    expect(loadConfig({ USAGE_STORE_PATH: '/var/lib/drobon/usage.json' }).usageStorePath).toBe(
      '/var/lib/drobon/usage.json',
    );
    // ':memory:' is a test convenience — never allowed in production.
    expect(loadConfig({ NODE_ENV: 'test', USAGE_STORE_PATH: ':memory:' }).usageStorePath).toBe(
      ':memory:',
    );
    expect(() => loadConfig({ NODE_ENV: 'production', USAGE_STORE_PATH: ':memory:' })).toThrow(
      ConfigError,
    );
    expect(() => loadConfig({ USAGE_STORE_PATH: '  ' })).toThrow(ConfigError);
  });

  test('source-snapshot storage is configurable and must be durable in production', () => {
    expect(loadConfig({ SOURCE_STORE_PATH: '/var/lib/drobon/sources.json' }).sourceStorePath).toBe(
      '/var/lib/drobon/sources.json',
    );
    expect(loadConfig({ NODE_ENV: 'test', SOURCE_STORE_PATH: ':memory:' }).sourceStorePath).toBe(
      ':memory:',
    );
    expect(() => loadConfig({ NODE_ENV: 'production', SOURCE_STORE_PATH: ':memory:' })).toThrow(
      ConfigError,
    );
    expect(() => loadConfig({ SOURCE_STORE_PATH: '  ' })).toThrow(ConfigError);
  });

  test('scan storage is configurable and must be durable in production', () => {
    expect(loadConfig({}).scanStorePath).toBe('.data/scans.json');
    expect(loadConfig({ SCAN_STORE_PATH: '/var/lib/drobon/scans.json' }).scanStorePath).toBe(
      '/var/lib/drobon/scans.json',
    );
    expect(loadConfig({ NODE_ENV: 'test', SCAN_STORE_PATH: ':memory:' }).scanStorePath).toBe(
      ':memory:',
    );
    expect(() => loadConfig({ NODE_ENV: 'production', SCAN_STORE_PATH: ':memory:' })).toThrow(
      ConfigError,
    );
    expect(() => loadConfig({ SCAN_STORE_PATH: '  ' })).toThrow(ConfigError);
  });

  test('project storage is configurable and must be durable in production', () => {
    expect(loadConfig({}).projectStorePath).toBe('.data/projects.json');
    expect(loadConfig({ PROJECT_STORE_PATH: '/var/lib/drobon/projects.json' }).projectStorePath).toBe(
      '/var/lib/drobon/projects.json',
    );
    expect(loadConfig({ NODE_ENV: 'test', PROJECT_STORE_PATH: ':memory:' }).projectStorePath).toBe(
      ':memory:',
    );
    expect(() =>
      loadConfig({ NODE_ENV: 'production', PROJECT_STORE_PATH: ':memory:' }),
    ).toThrow(ConfigError);
    expect(() => loadConfig({ PROJECT_STORE_PATH: '  ' })).toThrow(ConfigError);
  });

  test('the scan-consumption probe is on outside production, off in it', () => {
    expect(loadConfig({}).usageConsumeRoutes).toBe(true);
    expect(loadConfig({ NODE_ENV: 'development' }).usageConsumeRoutes).toBe(true);
    expect(loadConfig({ NODE_ENV: 'test' }).usageConsumeRoutes).toBe(true);
    // Production must never register a user-callable consumption
    // endpoint; production scan consumption belongs to the future scan
    // workflow, not to client requests.
    expect(loadConfig({ NODE_ENV: 'production' }).usageConsumeRoutes).toBe(false);
  });

  test('production enables the Secure cookie attribute', () => {
    const config = loadConfig({ NODE_ENV: 'production' });
    expect(config.cookieSecure).toBe(true);
  });

  test('accepts explicitly configured auth settings', () => {
    const config = loadConfig({
      AUTH_STORE_PATH: '/var/lib/drobon/users.json',
      AUTH_SCRYPT_COST: '16384',
      AUTH_SESSION_TTL_SECONDS: '900',
      AUTH_RATE_LIMIT_MAX_REQUESTS: '5',
      AUTH_RATE_LIMIT_WINDOW_MS: '30000',
    });
    expect(config.authStorePath).toBe('/var/lib/drobon/users.json');
    expect(config.authScryptCost).toBe(16_384);
    expect(config.authSessionTtlSeconds).toBe(900);
    expect(config.authRateLimitMaxRequests).toBe(5);
    expect(config.authRateLimitWindowMs).toBe(30_000);
  });

  test('accepts a fully specified valid environment', () => {
    const config = loadConfig({
      NODE_ENV: 'production',
      HOST: '0.0.0.0',
      PORT: '8080',
      LOG_LEVEL: 'warn',
      CORS_ALLOWED_ORIGINS: 'https://app.example.test, http://127.0.0.1:5173',
      RATE_LIMIT_MAX_REQUESTS: '50',
      RATE_LIMIT_WINDOW_MS: '5000',
      BODY_MAX_BYTES: '2048',
      USAGE_STORE_PATH: '/var/lib/drobon/usage.json',
      PROJECT_STORE_PATH: '/var/lib/drobon/projects.json',
      SCAN_STORE_PATH: '/var/lib/drobon/scans.json',
      SOURCE_STORE_PATH: '/var/lib/drobon/sources.json',
    });
    expect(config.env).toBe('production');
    expect(config.host).toBe('0.0.0.0');
    expect(config.port).toBe(8080);
    expect(config.logLevel).toBe('warn');
    expect(config.corsAllowedOrigins).toEqual([
      'https://app.example.test',
      'http://127.0.0.1:5173',
    ]);
    expect(config.rateLimitMaxRequests).toBe(50);
    expect(config.rateLimitWindowMs).toBe(5000);
    expect(config.bodyMaxBytes).toBe(2048);
    expect(config.usageStorePath).toBe('/var/lib/drobon/usage.json');
    expect(config.usageConsumeRoutes).toBe(false);
    expect(config.projectStorePath).toBe('/var/lib/drobon/projects.json');
    expect(config.scanStorePath).toBe('/var/lib/drobon/scans.json');
    expect(config.sourceStorePath).toBe('/var/lib/drobon/sources.json');
  });

  test('normalizes and dedupes origins', () => {
    const config = loadConfig({
      CORS_ALLOWED_ORIGINS: 'HTTPS://APP.EXAMPLE.TEST/,https://app.example.test,,',
    });
    expect(config.corsAllowedOrigins).toEqual(['https://app.example.test']);
  });

  test.each([
    ['bad env', { NODE_ENV: 'staging' }],
    ['blank host', { HOST: '   ' }],
    ['host with whitespace', { HOST: 'a b' }],
    ['non-numeric port', { PORT: 'abc' }],
    ['port too low', { PORT: '0' }],
    ['port too high', { PORT: '70000' }],
    ['bad log level', { LOG_LEVEL: 'verbose' }],
    ['origin with path', { CORS_ALLOWED_ORIGINS: 'https://a.test/x' }],
    ['origin with credentials', { CORS_ALLOWED_ORIGINS: 'https://user@a.test' }],
    ['origin with query', { CORS_ALLOWED_ORIGINS: 'https://a.test/?x=1' }],
    ['non-http origin', { CORS_ALLOWED_ORIGINS: 'ftp://a.test' }],
    ['garbage origin', { CORS_ALLOWED_ORIGINS: 'not a url' }],
    ['zero rate limit', { RATE_LIMIT_MAX_REQUESTS: '0' }],
    ['tiny window', { RATE_LIMIT_WINDOW_MS: '10' }],
    ['tiny body', { BODY_MAX_BYTES: '10' }],
    ['huge body', { BODY_MAX_BYTES: '999999999' }],
    ['blank auth store', { AUTH_STORE_PATH: '   ' }],
    [
      'memory auth store in production',
      { NODE_ENV: 'production', AUTH_STORE_PATH: ':memory:' },
    ],
    ['non-power-of-two scrypt cost', { AUTH_SCRYPT_COST: '3000' }],
    ['tiny scrypt cost', { AUTH_SCRYPT_COST: '512' }],
    ['huge scrypt cost', { AUTH_SCRYPT_COST: '2097152' }],
    ['short session ttl', { AUTH_SESSION_TTL_SECONDS: '30' }],
    ['huge session ttl', { AUTH_SESSION_TTL_SECONDS: '99999999' }],
    ['zero auth rate limit', { AUTH_RATE_LIMIT_MAX_REQUESTS: '0' }],
    ['tiny auth window', { AUTH_RATE_LIMIT_WINDOW_MS: '10' }],
  ])('rejects %s', (_label, env) => {
    expect(() => loadConfig(env)).toThrowError(ConfigError);
  });

  test('collects every issue into a single ConfigError', () => {
    try {
      loadConfig({ NODE_ENV: 'nope', PORT: 'abc', LOG_LEVEL: 'nope' });
      expect.unreachable('expected ConfigError');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      const configError = error as ConfigError;
      expect(configError.issues.length).toBeGreaterThanOrEqual(3);
      expect(configError.message).toContain('NODE_ENV');
      expect(configError.message).toContain('PORT');
      expect(configError.message).toContain('LOG_LEVEL');
    }
  });

  test('reads the version from package.json', () => {
    const config = loadConfig({});
    expect(config.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});
