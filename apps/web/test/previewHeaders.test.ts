// @vitest-environment node
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { build, preview, type PreviewServer } from 'vite';

const WEB_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST_DIR = join(WEB_DIR, 'dist');

/** Find a free loopback port without racing the preview server. */
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
  return port;
}

describe(
  'production build + preview server',
  () => {
    let server: PreviewServer | undefined;
    let baseUrl = '';

    beforeAll(async () => {
      await build({ configFile: join(WEB_DIR, 'vite.config.ts'), logLevel: 'silent' });
      const port = await freePort();
      server = await preview({
        configFile: join(WEB_DIR, 'vite.config.ts'),
        logLevel: 'silent',
        preview: { port, strictPort: true, host: '127.0.0.1' },
      });
      server.printUrls();
      baseUrl = `http://127.0.0.1:${port}`;
    }, 120_000);

    afterAll(async () => {
      await new Promise<void>((resolve, reject) => {
        server?.httpServer.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    });

    test('serves the built app with strict security headers', async () => {
      const res = await fetch(`${baseUrl}/`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/html');
      const csp = res.headers.get('content-security-policy') ?? '';
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).not.toContain('unsafe-inline');
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
      expect(res.headers.get('x-frame-options')).toBe('DENY');
      expect(res.headers.get('referrer-policy')).toBe('no-referrer');
      expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
      expect(res.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    });

    test('SPA fallback serves index.html for client routes', async () => {
      const route = await fetch(`${baseUrl}/status`);
      expect(route.status).toBe(200);
      expect(route.headers.get('content-type')).toContain('text/html');
      expect(await route.text()).toContain('<div id="root">');
      // NOTE: `vite preview` itself falls back *every* miss (including
      // missing asset files) to index.html. That is dev-grade behavior:
      // production hosting must only fall back non-file routes and 404
      // missing hashed assets (see docs/SECURITY.md). Our own fallback
      // decision is unit-tested with a truth table in plugin.test.ts.
      const missing = await fetch(`${baseUrl}/assets/does-not-exist.js`);
      expect(missing.status).toBe(200);
      expect(missing.headers.get('content-type')).toContain('text/html');
    });

    test('build output is hashed, external and secret-free', () => {
      const html = readFileSync(join(DIST_DIR, 'index.html'), 'utf8');
      expect(html).toMatch(/\/assets\/index-[A-Za-z0-9_-]+\.js/);
      expect(html).not.toContain('VITE_');
      expect(html).not.toMatch(/<script>(?![^]*src=)/);
      const assets = readdirSync(join(DIST_DIR, 'assets'));
      expect(assets.some((name) => /^index-[A-Za-z0-9_-]+\.js$/.test(name))).toBe(true);
      for (const name of assets.filter((file) => file.endsWith('.js'))) {
        const bundle = readFileSync(join(DIST_DIR, 'assets', name), 'utf8');
        expect(bundle).not.toContain('data:text/html');
        expect(bundle).not.toMatch(/VITE_[A-Z_]*(SECRET|PASSWORD|TOKEN|KEY)/);
      }
    });
  },
  180_000,
);
