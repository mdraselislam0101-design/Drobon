/**
 * Passive/active DAST response surface (GAP-048).
 *
 * Dataset DAST rules read 57 distinct response headers. Forwarding only 11
 * of them made 73 rules structurally unreachable no matter how often they were
 * loaded (Drobon-Dataset interop/app-dast-reachability.json). Every value is
 * still clipped to 2048 chars and at most 5 array entries per header, and the
 * body stays clipped to 32,768 bytes — widening the allowlist adds NO new
 * request, payload or network capability.
 *
 * This is application policy, not dataset data: the names are HTTP field names.
 */
export const INSPECTED_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  'access-control-allow-credentials',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'access-control-allow-origin',
  'access-control-expose-headers',
  'access-control-max-age',
  'allow',
  'alt-svc',
  'cache-control',
  'content-security-policy',
  'content-security-policy-report-only',
  'content-type',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'docker-distribution-api-version',
  'expect-ct',
  'expires',
  'feature-policy',
  'link',
  'location',
  'nel',
  'origin-agent-cluster',
  'p3p',
  'permissions-policy',
  'public-key-pins',
  'referrer-policy',
  'refresh',
  'report-to',
  'server',
  'server-timing',
  'set-cookie',
  'strict-transport-security',
  'timing-allow-origin',
  'via',
  'www-authenticate',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-b3-traceid',
  'x-backend-server',
  'x-cache',
  'x-content-type-options',
  'x-debug-token',
  'x-debug-token-link',
  'x-dns-prefetch-control',
  'x-drupal-cache',
  'x-frame-options',
  'x-generator',
  'x-jenkins',
  'x-permitted-cross-domain-policies',
  'x-powered-by',
  'x-redirect-by',
  'x-runtime',
  'x-served-by',
  'x-ua-compatible',
  'x-varnish',
  'x-xss-protection',
]);
