/** Intentionally unsafe, disposable local lab. Never expose to the Internet. */
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function escapeHtml(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

/** Pure response function shared by the HTTP lab and Drobon's mock transport. */
export function labResponse(rawUrl, method = 'GET') {
  if (method !== 'GET' && method !== 'HEAD') return { status: 405, headers: { allow: 'GET, HEAD' }, body: '' };
  if (typeof rawUrl !== 'string' || rawUrl.length > 2048) return { status: 400, headers: {}, body: '' };
  let url;
  try { url = new URL(rawUrl, 'http://lab.invalid'); } catch { return { status: 400, headers: {}, body: '' }; }
  const headers = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
    'x-frame-options': 'DENY', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'" };
  switch (url.pathname) {
    case '/lab/header-missing': return { status: 200, headers, body: '<p>Local fixture</p>' };
    case '/lab/header-invalid': return { status: 200, headers: { ...headers, 'x-content-type-options': 'invalid' }, body: '<p>Local fixture</p>' };
    case '/lab/header-safe': return { status: 200, headers: { ...headers, 'x-content-type-options': 'nosniff' }, body: '<p>Local fixture</p>' };
    case '/lab/reflect-unsafe': {
      const value = (url.searchParams.get('input') ?? '').slice(0, 200);
      delete headers['content-security-policy'];
      // Deliberately unsafe for this local-only lab; no script is executed here.
      return { status: 200, headers, body: `<p>${value}</p>` };
    }
    case '/lab/reflect-safe': {
      const value = (url.searchParams.get('input') ?? '').slice(0, 200);
      delete headers['content-security-policy'];
      return { status: 200, headers, body: `<p>${escapeHtml(value)}</p>` };
    }
    default: return { status: 404, headers, body: '<p>Not found</p>' };
  }
}

export function createLabServer() {
  return createServer((req, res) => {
    const result = labResponse(req.url ?? '/', req.method ?? 'GET');
    res.writeHead(result.status, result.headers);
    res.end(req.method === 'HEAD' ? undefined : result.body);
  });
}

// This deliberately vulnerable fixture must never be used as a live preview.
// It binds ONLY to loopback and refuses a configurable host.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rawPort = process.env['LAB_PORT'] ?? '0';
  if (!/^\d+$/.test(rawPort) || Number(rawPort) > 65535) throw new Error('LAB_PORT must be an integer from 0 to 65535');
  const server = createLabServer();
  server.listen(Number(rawPort), '127.0.0.1', () => {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Lab listener unavailable');
    console.log(`Local-only test lab: http://127.0.0.1:${address.port}/lab/header-missing`);
  });
}
