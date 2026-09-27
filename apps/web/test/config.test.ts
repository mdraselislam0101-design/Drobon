import { describe, expect, test } from 'vitest';
import { PublicConfigError, loadPublicConfig } from '../src/config.js';

describe('loadPublicConfig', () => {
  test('applies safe defaults for an empty environment', () => {
    const config = loadPublicConfig({});
    expect(config.apiBaseUrl).toBe('');
    expect(config.appName).toBe('Drobon Aegis AI');
    expect(config.appEnv).toBe('development');
    expect(config.appVersion).toMatch(/^\d+\.\d+\.\d+/);
  });

  test('accepts valid public values and strips trailing slashes', () => {
    const config = loadPublicConfig({
      VITE_API_BASE_URL: 'https://api.example.test///',
      VITE_APP_NAME: 'Custom Name',
      VITE_APP_ENV: 'production',
    });
    expect(config.apiBaseUrl).toBe('https://api.example.test');
    expect(config.appName).toBe('Custom Name');
    expect(config.appEnv).toBe('production');
  });

  test('accepts a same-origin empty base URL explicitly', () => {
    expect(loadPublicConfig({ VITE_API_BASE_URL: '  ' }).apiBaseUrl).toBe('');
  });

  test.each([
    ['relative URL', { VITE_API_BASE_URL: '/api' }],
    ['non-URL', { VITE_API_BASE_URL: 'not a url' }],
    ['wrong scheme', { VITE_API_BASE_URL: 'ftp://api.example.test' }],
    ['credentials in URL', { VITE_API_BASE_URL: 'https://user:pass@api.example.test' }],
    ['blank app name', { VITE_APP_NAME: '   ' }],
    ['overlong app name', { VITE_APP_NAME: 'x'.repeat(81) }],
    ['unknown app env', { VITE_APP_ENV: 'staging' }],
  ])('rejects %s', (_label, env) => {
    expect(() => loadPublicConfig(env)).toThrowError(PublicConfigError);
  });

  test('ignores non-allowlisted variables entirely', () => {
    const config = loadPublicConfig({
      NODE_ENV: 'production',
      SECRET_SHOULD_BE_IGNORED: 'shx-example-value',
    } as Record<string, string>);
    expect(config).not.toHaveProperty('SECRET_SHOULD_BE_IGNORED');
    expect(JSON.stringify(config)).not.toContain('shx-example-value');
  });
});
