import { version as appVersion } from '../package.json';

/**
 * Public (browser-safe) configuration. This is the ONLY module allowed to
 * touch `import.meta.env` (enforced by `test/static-web.test.ts`), and it
 * reads an explicit allowlist of `VITE_*` keys — nothing else.
 *
 * WARNING: every value read here is embedded in the browser bundle. Never
 * add secrets to this allowlist.
 */
export interface PublicConfig {
  /** API origin, or '' for same-origin. Trailing slashes stripped. */
  apiBaseUrl: string;
  appName: string;
  appEnv: string;
  appVersion: string;
}

export class PublicConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PublicConfigError';
  }
}

const APP_ENVS = ['development', 'test', 'preview', 'production'] as const;

function normalizeApiBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed === '') {
    return '';
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new PublicConfigError('VITE_API_BASE_URL must be a valid absolute http(s) URL or empty.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new PublicConfigError('VITE_API_BASE_URL must use the http or https scheme.');
  }
  if (url.username.length > 0 || url.password.length > 0) {
    throw new PublicConfigError('VITE_API_BASE_URL must not contain credentials.');
  }
  return url.origin + url.pathname.replace(/\/+$/, '');
}

export function loadPublicConfig(env: Record<string, string | undefined>): PublicConfig {
  const apiBaseUrl = normalizeApiBaseUrl(env['VITE_API_BASE_URL'] ?? '');
  const appName = (env['VITE_APP_NAME'] ?? 'Drobon Aegis AI').trim();
  if (appName.length === 0 || appName.length > 80) {
    throw new PublicConfigError('VITE_APP_NAME must be 1–80 characters.');
  }
  const appEnv = (env['VITE_APP_ENV'] ?? 'development').trim();
  if (!(APP_ENVS as readonly string[]).includes(appEnv)) {
    throw new PublicConfigError(`VITE_APP_ENV must be one of ${APP_ENVS.join(', ')}.`);
  }
  return { apiBaseUrl, appName, appEnv, appVersion };
}
