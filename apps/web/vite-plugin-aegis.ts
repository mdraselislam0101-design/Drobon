import type { Plugin } from 'vite';

/**
 * Strict headers for the production preview server (mirrors what production
 * hosting must send — see docs/SECURITY.md). The bundle is CSP-clean: no
 * inline scripts, no inline styles, no inlined data-URI assets
 * (`assetsInlineLimit: 0`), same-origin API calls by default.
 */
export function getPreviewSecurityHeaders(): Record<string, string> {
  return {
    'content-security-policy': [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "font-src 'self'",
      "connect-src 'self'",
      "media-src 'none'",
      "worker-src 'none'",
    ].join('; '),
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  };
}

/**
 * Dev-server headers. CSP is intentionally NOT applied here: Vite's HMR
 * client requires inline scripts and websocket connections that a strict
 * policy would break. The production policy above is what ships.
 */
export function getDevSecurityHeaders(): Record<string, string> {
  const headers = getPreviewSecurityHeaders();
  const { 'content-security-policy': _csp, ...rest } = headers;
  void _csp;
  return rest;
}

/**
 * Pure SPA-fallback decision: browser navigations that do not target a file
 * (no extension) rewrite to `/index.html` so BrowserRouter owns the URL.
 */
export function shouldRewriteToIndex(method: string | undefined, url: string | undefined): boolean {
  if (method !== 'GET' || url === undefined) {
    return false;
  }
  const path = url.split('?')[0] ?? '/';
  if (path === '/' || path === '/index.html') {
    return false;
  }
  return !/\.[a-z0-9]+$/i.test(path);
}

function setHeaders(
  res: { setHeader: (name: string, value: string) => void },
  headers: Record<string, string>,
): void {
  for (const [name, value] of Object.entries(headers)) {
    res.setHeader(name, value);
  }
}

/** Dev/preview-only hardening: security headers + SPA fallback for preview. */
export function aegisSecurity(): Plugin {
  return {
    name: 'aegis-security',
    apply: 'serve',
    configureServer(server) {
      const headers = getDevSecurityHeaders();
      server.middlewares.use((_req, res, next) => {
        setHeaders(res, headers);
        next();
      });
    },
    configurePreviewServer(server) {
      const headers = getPreviewSecurityHeaders();
      server.middlewares.use((req, res, next) => {
        setHeaders(res, headers);
        if (shouldRewriteToIndex(req.method, req.url)) {
          req.url = '/index.html';
        }
        next();
      });
    },
  };
}
