# Architecture

Pump 1 foundation, extended by Pump 2 (authentication), Pump 3
(authorization) and Pump 4 (plans/subscriptions/entitlements): an
npm-workspaces monorepo with three runtime components
(Web, API, Worker) sharing one contract package. TypeScript everywhere,
strict mode everywhere (`strict`, `exactOptionalPropertyTypes`,
`noUncheckedIndexedAccess`, `verbatimModuleSyntax` — see
`tsconfig.base.json`).

## Components

### `@drobon/shared` — contracts (`packages/shared`)

Runtime-agnostic types + tiny pure helpers (no Node APIs, no DOM), so the
browser bundle and the servers can all consume it:

- `api.ts` — the response envelope: `ApiSuccess<T> | ApiErrorBody`, always
  carrying `meta.requestId`.
- `errors.ts` — the closed `ErrorCode` vocabulary. A code may only exist if
  some component emits it (Pump 2 added `UNAUTHORIZED`, `FORBIDDEN`,
  `CONFLICT`).
- `auth.ts` — auth contracts: `AuthUser` (now including `role` and
  `userType`), `RegisterRequest`, `LoginRequest`, `AuthResponse`,
  `CurrentUserResponse`, `LogoutResponse`, the shared email/password
  policy (`isValidEmail`, `passwordPolicyIssue`) and payload guards
  (`isAuthUser` — also rejects credential material and forged roles).
- `authz.ts` — authorization contracts (Pump 3): `AccountRole`
  (MEMBER/ADMIN/ACCOUNT_OWNER + ranks), `UserType` (classification only),
  the central `PERMISSIONS` table + `hasPermission`/`roleAtLeast`,
  `AuthzContext`, capability-probe types and guards. No scattered role
  strings anywhere else.
- `plans.ts` — commercial contracts (Pump 4): `Plan` (FREE/PRO — the
  closed two-value vocabulary), `SubscriptionStatus`
  (ACTIVE/INACTIVE/CANCELLED/EXPIRED), `Subscription` +
  `SubscriptionResponse` with payload guards, and the shared entitlement
  decision table `SUBSCRIPTION_ENTITLEMENTS` (`feature:pro` exists in
  exactly one cell: PRO + ACTIVE; `plan:manage` in none). Role and
  UserType are deliberately not inputs to any of it.
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
request → requestId → securityHeaders → cors → rateLimit(global)
        → rateLimit(/api/v1/auth) → originGuard(CSRF) → session(cookie→ctx.user+ctx.authz+ctx.subscription+ctx.entitlements)
        → router: match → authenticate (401) → authorize (403) → handler
```

- `config.ts` — the ONLY module that reads `process.env`; validates every
  variable (including the Pump 2 `AUTH_*` set) and throws one `ConfigError`
  listing all issues (fail fast). Rejects `AUTH_STORE_PATH=:memory:` in
  production. Derives `cookieSecure` from the environment.
- `logger.ts` — structured JSON-lines logger with level filtering and
  deep secret redaction (sensitive keys, bearer-like values, credentialed
  URLs, cycles). Error stacks are logged in dev/test only.
- `errors.ts` + `respond.ts` — central error contract: `AppError`
  (code/status/expose) mapped by `toErrorResponse()` so 5xx internals can
  never leak; every response uses the shared envelope. Pump 2 helpers:
  `unauthorized()`, `invalidCredentials()` (always identical), `forbidden()`,
  `conflict()`.
- `lib/validate.ts` — strict schema validator (unknown keys rejected).
- `lib/body.ts` — content-type check (415), size-limited stream read (413),
  JSON parsing (400).
- `middleware/` — correlation IDs (echo-if-valid else UUID), strict security
  headers, allowlist CORS (fail closed; credentials allowed ONLY with an
  exact reflected origin, never `*`), in-memory fixed-window rate limiting
  with `RateLimit-*` / `Retry-After` headers, a path-scoped credential
  rate limit, the CSRF origin guard, and session resolution
  (cookie → store → repository → `ctx.user`, stale cookies actively cleared).
- `auth/` — the authentication core: `passwords.ts` (scrypt hashing,
  constant-time verify, dummy verify for timing equalization),
  `repositories.ts` (`UserRepository` interface + `toAuthUser` projection;
  `UserRecord` carries `role`/`userType` with migration-safe parsing),
  `jsonFileUserRepository.ts` (the minimum durable persistence boundary —
  atomic writes, fail-fast on corruption), `memoryUserRepository.ts`
  (tests + explicit `:memory:`), `sessions.ts` (server-side store keyed by
  SHA-256 of the token, absolute TTL, immediate revocation), `cookies.ts`
  (HttpOnly/SameSite=Strict/Secure-in-production serialization),
  `authorization.ts` (Pump 3: `createAuthzContext`, role/permission
  assertions, ownership helpers, uniform denial message) and
  `subscriptions.ts` (Pump 4: the single entitlement decision point —
  fail-closed normalization of persisted subscription data,
  `resolveSubscription`, `deriveEntitlements`; reads only the account's
  subscription, never role/userType/client input).
- `routes/` — `GET /livez`, `GET /readyz` (checks: configuration,
  accounts), `GET /api/v1/status`, `POST /api/v1/echo`, plus
  `POST /api/v1/auth/register` (201 + session cookie; always MEMBER),
  `POST /api/v1/auth/login` (200 + cookie, generic 401s),
  `POST /api/v1/auth/logout` (idempotent 200 + cookie clear),
  `GET /api/v1/me` (`requireAuth`, public fields only), Pump 3's
  `GET /api/v1/authz/capabilities/*` (role-gated probes, dev/test only)
  and `GET /api/v1/users?id=` (ownership-checked read), plus Pump 4's
  `GET /api/v1/subscription` (self-only read of the caller's own
  subscription + server-derived entitlements; no id parameter, no
  mutation methods).
  Unknown path → 404, wrong method → 405 + `Allow`.
- `app.ts` — composition: per-request context, `next()`-chaining dispatcher,
  centralized catch + structured access log, and the single router choke
  point enforcing authentication (401) then authorization (403) before any
  handler runs. Accepts `extraRoutes` + injectable `users`/`sessions`
  repositories.
- `server.ts` / `index.ts` — socket timeouts, startup (a corrupt account
  store refuses to start), SIGTERM/SIGINT graceful shutdown.

Security defaults: binds loopback (`HOST=127.0.0.1`), empty CORS allowlist,
100 req/min/IP globally + 30 req/min/IP on credential endpoints, 1 MiB
bodies. Proxy headers are never trusted (`X-Forwarded-For` is ignored — see
NOT_IMPLEMENTED).

### `@drobon/web` — web app (`apps/web`, React 18 + Vite 6 + React Router 7)

- `config.ts` — the ONLY browser module allowed near `import.meta.env`, and
  only for three allowlisted keys (`VITE_API_BASE_URL`, `VITE_APP_NAME`,
  `VITE_APP_ENV`). Anything else is ignored by construction. Invalid config
  fails the boot with a visible error, never a half-working app.
- `api/client.ts` — the single HTTP boundary: typed methods (including the
  Pump 2 auth methods `postRegister`/`postLogin`/`postLogout`/`getMe`),
  per-request correlation IDs, timeout + caller-signal cancellation,
  `credentials: 'include'` for the session cookie, envelope validation via
  shared `parseApiResponse()`, auth payload guards, user-safe typed errors
  (`ApiClientError`, now carrying 422 `details`).
- `auth/context.tsx` — `AuthProvider`/`useAuth`: one source of truth for
  session state (`loading`/`ready`/`anonymous`/`error`), mount-time `/me`
  probe, login/register/logout actions. The token itself is never held in
  JavaScript — only the browser's httpOnly cookie.
- `components/RouteGuards.tsx` — `ProtectedRoute` with optional `minRole`
  (loading → spinner, anonymous → /login remembering `from`, probe
  failure → retryable error, ready→anonymous transition flagged as
  *expired*, authenticated-but-insufficient → `ForbiddenState` — never a
  login redirect), `PublicOnlyRoute` (authed visitors bounce off /login
  and /register), and `readSafePath()` (open-redirect defense for
  post-login navigation). `components/ForbiddenState.tsx` is the generic
  403 view (alert, no role hints).
- `routes.tsx` / `App.tsx` — `BrowserRouter` in prod, `MemoryRouter` in
  tests; routes: `/` (Home), `/status` (live API data), `/login`,
  `/register`, `/account` (protected, `minRole="MEMBER"`), `*` (404).
- `components/` — `Layout` (auth-aware header/nav/main/footer, skip link),
  `LoadingState` (`role=status`), `ErrorState` (`role=alert` + request ID +
  retry), `ErrorBoundary`, `AuthFormError` (form-level alert + strict
  422-issue mapping).
- `pages/StatusPage.tsx` — demonstrates the full async lifecycle:
  loading → data | error + retry, with abort-on-unmount.
- `pages/LoginPage/RegisterPage` — accessible forms (labels, `aria-invalid`,
  `role=alert` errors, busy buttons), shared policy validation with the API,
  server-safe error rendering.
- `pages/AccountPage.tsx` — protected page: re-verifies the session on
  mount (session-expiry discovery), shows public account facts, role and
  user-type badges, the Pump 4 plan & subscription section (plan/status
  badges + PRO-feature verdict rendered from `GET /api/v1/subscription`
  — the server's entitlement list, never a local recomputation; errors
  fail closed with no plan shown), live capability checks (each verdict
  is the API's 200/403, not a client guess), a permission-gated
  privileged lookup section, sign-out.
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
3. Security headers, CORS (preflights short-circuit; credentials only with
   an exact allowed origin), global rate limit.
4. Credential endpoints get a second, tighter rate limit; unsafe methods
   pass the CSRF origin guard (Origin must be allowlisted or same-host).
5. Session resolution: session cookie → session store → user repository →
   `ctx.user` + `ctx.authz` (role/userType from the LIVE record) +
   `ctx.subscription`/`ctx.entitlements` (commercial state from the LIVE
   record — Pump 4; operator store changes apply on the next request);
   invalid/stale cookies are cleared on the way through.
6. Router match → authentication boundary (`requireAuth` → 401 if
   anonymous) → authorization boundary (`requireRole`/`requirePermission`
   → 403 if insufficient) → handler. Handlers validate input, then
   `sendSuccess()` / throw `AppError`; ownership-sensitive handlers add
   `assertCanReadUser`.
7. Central catch maps to the error envelope (4xx exposed, 5xx generic),
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

Role management console / first-admin bootstrap and role-change audit
trail (authorization primitives themselves are DONE in Pump 3), payment /
billing integration and any subscription mutation workflow (the
subscription + entitlement foundation itself is DONE in Pump 4 — see
`docs/SUBSCRIPTIONS.md`), account
email verification, password reset, trusted-proxy support, distributed
rate limiting, durable/persistent sessions and queues, the database phase
(migrations + repositories replacing the JSON account store), dataset
ingestion/storage, scanning/findings/reports/remediation, AI assistance,
admin dashboard, multi-instance deployment, metrics/tracing.
