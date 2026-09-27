# Architecture

Pump 1 foundation: an npm-workspaces monorepo with three runtime components
(Web, API, Worker) sharing one contract package. TypeScript everywhere, strict
mode everywhere (`strict`, `exactOptionalPropertyTypes`,
`noUncheckedIndexedAccess`, `verbatimModuleSyntax` — see
`tsconfig.base.json`).

## Components

### `@drobon/shared` — contracts (`packages/shared`)

Runtime-agnostic types + tiny pure helpers (no Node APIs, no DOM), so the
browser bundle and the servers can all consume it:

- `api.ts` — the response envelope: `ApiSuccess<T> | ApiErrorBody`, always
  carrying `meta.requestId`.
- `errors.ts` — the closed `ErrorCode` vocabulary. A code may only exist if
  some component emits it.
- `jobs.ts` — `Job`, `JobResult`, `JobStatus`, `RetryPolicy`, `createJob()`.
- `config.ts` — `EnvironmentName`, `LogLevel`.
- `models.ts` — `HealthResponse`, `ReadinessResponse`, `StatusResponse`,
  `EchoRequest/Response`.
- `guards.ts` — `isApiSuccess/isApiError/isErrorCode` and
  `parseApiResponse()` (structural validation for untrusted payloads).

Consumers import the **built** package (`dist/`), never `src/`.

### `@drobon/api` — HTTP API (`apps/api`, zero runtime dependencies)

Plain Node `http` server with an explicit middleware pipeline (no framework,
minimal attack surface):

```
request → requestId → securityHeaders → cors → rateLimit → router → handler
```

- `config.ts` — the ONLY module that reads `process.env`; validates every
  variable and throws one `ConfigError` listing all issues (fail fast).
- `logger.ts` — structured JSON-lines logger with level filtering and
  deep secret redaction (sensitive keys, bearer-like values, credentialed
  URLs, cycles). Error stacks are logged in dev/test only.
- `errors.ts` + `respond.ts` — central error contract: `AppError`
  (code/status/expose) mapped by `toErrorResponse()` so 5xx internals can
  never leak; every response uses the shared envelope.
- `lib/validate.ts` — strict schema validator (unknown keys rejected).
- `lib/body.ts` — content-type check (415), size-limited stream read (413),
  JSON parsing (400).
- `middleware/` — correlation IDs (echo-if-valid else UUID), strict security
  headers, allowlist CORS (fail closed, no credentials), in-memory
  fixed-window rate limiting with `RateLimit-*` / `Retry-After` headers.
- `routes/` — `GET /livez`, `GET /readyz`, `GET /api/v1/status`,
  `POST /api/v1/echo` (validation showcase). Unknown path → 404, wrong
  method → 405 + `Allow`.
- `app.ts` — composition: per-request context, `next()`-chaining dispatcher,
  centralized catch + structured access log. Accepts `extraRoutes` — the
  extension point future modules (auth, scanning, admin, …) plug into.
- `server.ts` / `index.ts` — socket timeouts, startup, SIGTERM/SIGINT
  graceful shutdown.

Security defaults: binds loopback (`HOST=127.0.0.1`), empty CORS allowlist,
100 req/min/IP, 1 MiB bodies. Proxy headers are never trusted
(`X-Forwarded-For` is ignored — see NOT_IMPLEMENTED).

### `@drobon/web` — web app (`apps/web`, React 18 + Vite 6 + React Router 7)

- `config.ts` — the ONLY browser module allowed near `import.meta.env`, and
  only for three allowlisted keys (`VITE_API_BASE_URL`, `VITE_APP_NAME`,
  `VITE_APP_ENV`). Anything else is ignored by construction. Invalid config
  fails the boot with a visible error, never a half-working app.
- `api/client.ts` — the single HTTP boundary: typed methods, per-request
  correlation IDs, timeout + caller-signal cancellation, envelope validation
  via shared `parseApiResponse()`, user-safe typed errors (`ApiClientError`).
- `routes.tsx` / `App.tsx` — `BrowserRouter` in prod, `MemoryRouter` in
  tests; routes: `/` (Home), `/status` (live API data), `*` (404).
- `components/` — `Layout` (header/nav/main/footer, skip link), `LoadingState`
  (`role=status`), `ErrorState` (`role=alert` + request ID + retry),
  `ErrorBoundary` (render crashes become a message, not a blank page).
- `pages/StatusPage.tsx` — demonstrates the full async lifecycle:
  loading → data | error + retry, with abort-on-unmount.
- `vite-plugin-aegis.ts` — dev/preview-only hardening: security headers on
  every response (strict CSP on preview; CSP omitted in dev because Vite HMR
  needs inline scripts) and SPA fallback for the preview server.
- The bundle is CSP-clean by construction: no inline scripts/styles, no
  data-URI inlining (`assetsInlineLimit: 0`), same-origin API by default.

### `@drobon/worker` — background worker (`apps/worker`, zero runtime deps)

- `queue.ts` — `JobQueue` interface + `InMemoryJobQueue` (FIFO). The
  in-memory queue is explicitly **non-durable** and exists so contracts,
  execution semantics and tests are real — it is not production infra.
- `retry.ts` — `validateRetryPolicy()`, `shouldRetry()`,
  `computeRetryDelayMs()` (exponential backoff with cap).
- `runner.ts` — `createRunner()`: FIFO dequeue, bounded concurrency
  (default 1, deterministic), per-attempt timeouts (handler races a timer),
  cooperative cancellation (abort signal; enforced by timeout even if the
  handler ignores it), retry-while-budget-allows, bounded finished-record
  retention, `waitFor()` with waiter timeout, graceful `stop()`.
- Unknown job types fail with `BAD_REQUEST`; handler errors with
  `INTERNAL_ERROR` (message truncated); overruns with `timed_out`/`TIMEOUT`.

## Request lifecycle (API)

1. Socket accepted; `RequestContext` created (method, normalized pathname,
   direct peer IP, start time).
2. `x-request-id` echoed if valid, else generated; set on the response.
3. Security headers, CORS (preflights short-circuit), rate limit.
4. Router match → handler, or 404/405. Handlers validate input, then
   `sendSuccess()` / throw `AppError`.
5. Central catch maps to the error envelope (4xx exposed, 5xx generic),
   logs appropriately (5xx → error with stack server-side only), and every
   request ends with one structured access-log line.

## Dependency rules

- `shared` depends on nothing.
- `api`/`worker` depend only on `shared` (runtime).
- `web` depends on `shared` + React/Router (runtime); build/test tooling is
  dev-only.
- No workspace may depend on another app. No database, dataset, ORM, queue
  broker, or shell-execution dependency anywhere (enforced by
  `scripts/check-boundaries.mjs` + static tests).

## NOT_IMPLEMENTED (future Pumps)

Authentication/authorization, trusted-proxy support, distributed rate
limiting, durable/persistent queues, database + migrations + repositories,
dataset ingestion/storage, scanning/findings/reports/remediation, AI
assistance, admin, payments, multi-instance deployment, metrics/tracing.
