# Security

Pump 1 treats security as a first-class, **tested** requirement. A control is
listed as VERIFIED only if an automated test or an executed check proves it;
anything else is marked PLANNED or NOT_IMPLEMENTED.

## Threat model (foundation stage)

In scope: Internet clients talking to the API/Web over HTTP; misconfiguration;
secret leakage into code, logs or the browser bundle; dependency risk;
abuse/accidental overload of a single instance.

Out of scope for Pump 1: authenticated threats (no auth exists), persistent
attackers across restarts (no durable state exists), supply-chain compromise
beyond `npm audit`, DDoS/absorption (single-instance limiter only).

## Controls

### API

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Strict security headers on every response (CSP `default-src 'none'`, nosniff, DENY, no-referrer, hardened permissions-policy, COOP/CORP, HSTS) | VERIFIED | `apps/api/test/headers.test.ts` (success + error paths) |
| CORS allowlist, exact-match, fail-closed preflights, `Vary: Origin`, never credentials | VERIFIED | `apps/api/test/cors.test.ts`, `security.test.ts` |
| Fixed-window rate limiting (429 + `Retry-After` + `RateLimit-*`), per-IP buckets | VERIFIED | `apps/api/test/rateLimit.test.ts` |
| Request validation: content-type 415, size cap 413, malformed JSON 400, strict schemas 422 (unknown keys rejected) | VERIFIED | `apps/api/test/echo.test.ts`, `validate.test.ts` |
| Central error mapping: 5xx collapse to `Internal Server Error.`, no stacks/messages leak, request ID always present | VERIFIED | `apps/api/test/errors.test.ts`, `errorDisclosure.test.ts` |
| Correlation IDs: valid `x-request-id` echoed, invalid replaced, always in header + body + logs | VERIFIED | `apps/api/test/requestId.test.ts` |
| Structured JSON logging with deep secret redaction (sensitive keys, bearer-like values, credentialed URLs); stacks dev-only | VERIFIED | `apps/api/test/logger.test.ts` |
| Strict env validation, fail-fast with all issues; loopback bind + empty CORS allowlist by default | VERIFIED | `apps/api/test/config.test.ts` |
| No `eval`/`Function`/child-process/`__proto__` primitives in sources | VERIFIED | `apps/api/test/staticSafety.test.ts` |
| `process.env` readable only in `config.ts` | VERIFIED | `apps/api/test/staticSafety.test.ts` |
| Socket timeouts (`headersTimeout`, `requestTimeout`, `keepAliveTimeout`) | IMPLEMENTED | Code review (`server.ts`); behavior relies on Node runtime |
| No `Server`/`X-Powered-By` fingerprint | VERIFIED | `apps/api/test/headers.test.ts` |

### Web

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Public-config boundary: only 3 allowlisted `VITE_*` keys readable, only from `config.ts`/`main.tsx`; invalid config fails boot visibly | VERIFIED | `apps/web/test/config.test.ts`, `staticWeb.test.ts` |
| No secret-shaped `VITE_*` variable referenced anywhere in browser code | VERIFIED | `apps/web/test/staticWeb.test.ts` |
| No `dangerouslySetInnerHTML`/`innerHTML` (except mount-node clear), no `eval`/`Function`, no `node:` imports in `src/` | VERIFIED | `apps/web/test/staticWeb.test.ts` |
| Strict production CSP + hardening headers on the preview server; SPA fallback; hashed, external, secret-free bundle | VERIFIED | `apps/web/test/plugin.test.ts`, `previewHeaders.test.ts` |
| API client: timeouts, caller cancellation, envelope validation, user-safe errors (transport internals never rendered) | VERIFIED | `apps/web/test/client.test.ts` |
| Host allowlist for dev/preview servers (loopback default; `*` only for sandboxes) | IMPLEMENTED | `vite.config.ts` + manual check |
| Sourcemaps disabled for production builds | IMPLEMENTED | `vite.config.ts` (`sourcemap: false`) |

### Repository / supply chain

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Committed-secret scan (literals, key blocks, `.env.example` naming) with fake-fixture rule + self-test | VERIFIED | `scripts/check-no-secrets.mjs`, `verify` pipeline |
| Scope gates: no DB/ORM/dataset/queue-broker/shell dependencies, filenames or imports | VERIFIED | `scripts/check-boundaries.mjs`, static tests |
| Dependency audit (fails on high/critical) | VERIFIED | `npm run audit` in `verify` |
| Pinned installs (`package-lock.json`), engine pinning (`.nvmrc`, `engines`, `engine-strict`) | IMPLEMENTED | Repo files |
| `.env` gitignored; `.env.example` documents every variable and defines no secrets | VERIFIED | `.gitignore`, secret scan |

## Production hosting notes (for later)

- Terminate TLS at the edge (HSTS header is already sent by the API).
- Serve the Web `dist/` with the headers in
  `getPreviewSecurityHeaders()` and an SPA fallback for non-file routes
  (nginx `try_files`, Vercel/Netlify rewrites, etc.).
- Run the API behind a reverse proxy; keep `HOST` loopback-facing and let
  the proxy own the public socket. Do NOT trust proxy headers until
  trusted-proxy support is explicitly implemented.
- Extend `connect-src` if the API ever lives on a different origin than the
  Web app (same-origin is the default).

## NOT_IMPLEMENTED (do not assume these exist)

Authentication, authorization/sessions, trusted-proxy (`X-Forwarded-For`)
handling, distributed/shared rate limiting, WAF, durable queues, database
(and therefore SQL-injection surface — there is none), dataset ingestion,
file uploads, outgoing fetch/SSRF surface (the API makes no outbound calls),
command execution, metrics/tracing, security-event alerting.

Note on SSRF/path-traversal/command-injection: Pump 1 has no feature that
fetches URLs, resolves file paths from input, or executes commands — the
static tests + scope gates prove the primitives are absent. These threats
become relevant only when such features land, and must be re-assessed then.

## Tooling notes (maintenance, not vulnerabilities)

- `npm audit` reports **0 vulnerabilities** at every level (see verification
  evidence). Dependency upgrades during Pump 1: Vitest 2→4, Vite 5→6,
  React Router 6→7, clearing all advisories including dev-only ones.
- Upstream prints an end-of-life notice for the ESLint 9 line (dev-only
  linter, no audit findings). Upgrading to the next supported ESLint +
  typescript-eslint lines is tracked future maintenance.
- `.npmrc` sets `legacy-peer-deps=true` because npm 10's strict peer
  resolver crashes on Vitest 4's peer graph (arborist bug, worked around —
  the pinned tree installs correctly). Revisit on npm 11+.
