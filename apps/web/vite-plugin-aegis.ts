import type { Plugin } from 'vite';

export interface AegisSecurityOptions {
  /**
   * When true (used only when ALLOWED_HOSTS="*" in an ephemeral sandbox
   * preview proxy), omit X-Frame-Options: DENY and allow trusted preview
   * frame ancestors so the sandbox iframe preview can render the app.
   */
  readonly allowFrameEmbedding?: boolean;
}

/**
 * Strict headers for the production preview server (mirrors what production
 * hosting must send — see docs/SECURITY.md). The bundle is CSP-clean: no
 * inline scripts, no inline styles, no inlined data-URI assets
 * (`assetsInlineLimit: 0`), same-origin API calls by default.
 */
export function getPreviewSecurityHeaders(
  options?: AegisSecurityOptions,
): Record<string, string> {
  const allowFrameEmbedding = options?.allowFrameEmbedding === true;
  const frameAncestors = allowFrameEmbedding
    ? "frame-ancestors 'self' https://*.e2b.app https://*.arena.ai"
    : "frame-ancestors 'none'";
  const headers: Record<string, string> = {
    'content-security-policy': [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      frameAncestors,
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
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  };
  if (!allowFrameEmbedding) {
    headers['x-frame-options'] = 'DENY';
  }
  return headers;
}

/**
 * Dev-server headers. CSP is intentionally NOT applied here: Vite's HMR
 * client requires inline scripts and websocket connections that a strict
 * policy would break. The production policy above is what ships.
 */
export function getDevSecurityHeaders(
  options?: AegisSecurityOptions,
): Record<string, string> {
  const headers = getPreviewSecurityHeaders(options);
  const { 'content-security-policy': _csp, ...rest } = headers;
  void _csp;
  return rest;
}

/**
 * Pure SPA-fallback decision: browser navigations that do not target a file
 * (no extension) and do not target API/health endpoints rewrite to
 * `/index.html` so BrowserRouter owns the URL.
 */
export function shouldRewriteToIndex(method: string | undefined, url: string | undefined): boolean {
  if (method !== 'GET' || url === undefined) {
    return false;
  }
  const path = url.split('?')[0] ?? '/';
  if (path === '/' || path === '/index.html') {
    return false;
  }
  if (
    path === '/api' ||
    path.startsWith('/api/') ||
    path === '/livez' ||
    path === '/readyz'
  ) {
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
export function aegisSecurity(options?: AegisSecurityOptions): Plugin {
  return {
    name: 'aegis-security',
    apply: 'serve',
    configureServer(server) {
      const headers = getDevSecurityHeaders(options);
      server.middlewares.use((_req, res, next) => {
        setHeaders(res, headers);
        next();
      });
    },
    configurePreviewServer(server) {
      const headers = getPreviewSecurityHeaders(options);
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
