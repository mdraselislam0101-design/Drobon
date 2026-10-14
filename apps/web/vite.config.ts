import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { aegisSecurity } from './vite-plugin-aegis';

function parsePort(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid port: ${raw}`);
  }
  return parsed;
}

/**
 * Hosts allowed to reach the dev/preview server (DNS-rebinding protection).
 * Defaults to loopback; override with ALLOWED_HOSTS="a.test,b.test".
 * "*" disables the check — sanctioned only for throwaway sandboxes.
 */
function parseAllowedHosts(raw: string | undefined): string[] | true {
  if (raw === undefined || raw.trim() === '') {
    return ['localhost', '127.0.0.1', '::1'];
  }
  const hosts = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (hosts.includes('*')) {
    return true;
  }
  return hosts.length > 0 ? hosts : ['localhost', '127.0.0.1', '::1'];
}

export default defineConfig(() => {
  const host = process.env['HOST'] ?? '127.0.0.1';
  const allowedHosts = parseAllowedHosts(process.env['ALLOWED_HOSTS']);
  // Dev/preview same-origin proxy to the API (local split-port development).
  // Production has no such proxy: split hosting must bake VITE_API_BASE_URL
  // into the bundle and list the web origin in CORS_ALLOWED_ORIGINS.
  const apiTarget = `http://127.0.0.1:${parsePort(process.env['PORT'], 3001)}`;
  const proxy = {
    // changeOrigin must stay FALSE (the Pump 2 fix): the proxy must
    // forward the browser's Host (e.g. 127.0.0.1:5173) so the API's
    // CSRF origin guard sees the request as same-origin. Rewriting
    // Host to the API target makes every proxied POST/DELETE fail
    // the guard with 403.
    '/api': { target: apiTarget },
    '/livez': { target: apiTarget },
    '/readyz': { target: apiTarget },
  };
  return {
    plugins: [react(), aegisSecurity({ allowFrameEmbedding: allowedHosts === true })],
    server: {
      host,
      port: parsePort(process.env['WEB_PORT'], 5173),
      allowedHosts,
      strictPort: true,
      proxy,
    },
    preview: {
      host,
      port: parsePort(process.env['PREVIEW_PORT'], 4173),
      allowedHosts,
      strictPort: true,
      proxy,
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      // Never inline assets as data: URIs — keeps the strict CSP valid.
      assetsInlineLimit: 0,
    },
  };
});
