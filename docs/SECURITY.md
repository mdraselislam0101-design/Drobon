# Security

Pump 1 established, Pump 2 extended (authentication), Pump 3 extended
(authorization), Pump 4 extended (plans/subscriptions/entitlements):
security is a first-class, **tested** requirement. A control is listed as
VERIFIED only if an automated test or an executed check proves it;
anything else is marked IMPLEMENTED, PLANNED or NOT_IMPLEMENTED.

## Threat model (foundation + auth + authz + subscription stage)

In scope: Internet clients talking to the API/Web over HTTP; credential
attacks (stuffing, enumeration, brute force); session hijack/CSRF/XSS
against the cookie session; privilege escalation (vertical: MEMBER→ADMIN→
OWNER; horizontal: cross-account IDOR); role tampering via client input;
commercial entitlement fraud (forging PRO via body/query/header/cookie
tampering, client state, UserType or AccountRole; degrading or reading
another account's subscription); misconfiguration; secret leakage into
code, logs or the browser bundle; dependency risk; abuse/accidental
overload of a single instance.

Out of scope for now: persistent attackers across restarts (sessions are
process-local), supply-chain compromise beyond `npm audit`,
DDoS/absorption (single-instance limiter only), attackers with a
*legitimately granted* privileged role acting within their permissions
(no audit trail yet — see NOT_IMPLEMENTED).

## Controls

### API

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Strict security headers on every response (CSP `default-src 'none'`, nosniff, DENY, no-referrer, hardened permissions-policy, COOP/CORP, HSTS) | VERIFIED | `apps/api/test/headers.test.ts` (success + error paths) |
| CORS allowlist, exact-match, fail-closed preflights, `Vary: Origin`; credentials (`Allow-Credentials: true`) ONLY with an exactly reflected origin, never `*` | VERIFIED | `apps/api/test/cors.test.ts`, `security.test.ts`, `authSecurity.test.ts` |
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

### Authentication (Pump 2)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Passwords hashed with scrypt (N=32768 default, r=8, p=1, per-user salt, constant-time compare); plaintext never stored/logged/returned; corrupted hashes fail closed | VERIFIED | `apps/api/test/passwords.test.ts`, `authStore.test.ts` |
| Session cookie: `HttpOnly` + `SameSite=Strict` + `Path=/` + host-only + `Secure` in production; token never in any response body | VERIFIED | `apps/api/test/authSecurity.test.ts`, `cookies.test.ts` |
| Server-side sessions keyed by SHA-256 of the token; absolute TTL; immediate revocation on logout; expired/invalid cookies actively cleared | VERIFIED | `apps/api/test/{sessions,authLogout,authLogin}.test.ts` |
| Generic login failures (unknown email ≡ wrong password: identical status/code/message) with dummy-scrypt timing equalization | VERIFIED | `apps/api/test/authLogin.test.ts` (body equality) |
| Credential-endpoint rate limit (default 30/min/IP, separate from global) with 429 + `Retry-After` | VERIFIED | `apps/api/test/authLogin.test.ts` |
| CSRF origin guard on unsafe methods (Origin must be allowlisted or same-host; absent Origin = non-browser) + `SameSite=Strict` | VERIFIED | `apps/api/test/authSecurity.test.ts` |
| Protected route boundary (`Route.requireAuth` → 401) — bypass attempts: no/garbage/expired/revoked cookies, forged Bearer header, method/path tricks, deleted account | VERIFIED | `apps/api/test/authMe.test.ts` |
| `/me` and auth responses expose ONLY public fields (`id`, `email`, `createdAt`); no hash/token/password in any body; exact-shape assertions | VERIFIED | `apps/api/test/authMe.test.ts`, `authRegistration.test.ts`, `authSecurity.test.ts` |
| Registration: shared email/password policy, 422 field issues, unknown-key rejection (mass assignment), duplicate → 409 without changing the account | VERIFIED | `apps/api/test/authRegistration.test.ts` |
| Auth events logged with correlation IDs but never passwords, hashes, emails or tokens | VERIFIED | `apps/api/test/authSecurity.test.ts` (log scan) |
| Durable account store: atomic writes, fail-fast on corruption, serialized creates (no duplicate races), `:memory:` rejected in production | VERIFIED | `apps/api/test/authStore.test.ts`, `config.test.ts` |
| Web: guarded session state (no token in JS), open-redirect-proof post-login navigation, expiry handling, accessible auth forms, logout honesty (server-confirmed only) | VERIFIED | `apps/web/test/{authClient,authPages,protected}.test.ts` / `.tsx` |

### Authorization (Pump 3)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Role-gated routes: `Route.requireRole`/`requirePermission` enforced at the router (401 anonymous → 403 insufficient); capability matrix proofs 1–6 (MEMBER/ADMIN/OWNER × member/admin/owner) | VERIFIED | `apps/api/test/authzMatrix.test.ts`, `authorization.test.ts` |
| 401 vs 403 semantics kept distinct with uniform messages; denial bodies hint nothing about roles, configuration or account existence | VERIFIED | `authzMatrix.test.ts` (exact envelopes), `authzOwnership.test.ts` |
| UserType never grants access (classification ≠ authorization); role-shaped client headers/body/cookies ignored | VERIFIED | `authzMatrix.test.ts`, `authzSecurity.test.ts` |
| Mass-assignment: `role` rejected as unknown property at register; `userType` validated against the closed enum; new accounts always MEMBER | VERIFIED | `authzMatrix.test.ts` |
| Server-side role state: sessions carry only opaque token → id; live role changes observed next request; client cannot influence | VERIFIED | `authzMatrix.test.ts` (elevation test) |
| Ownership/IDOR: self-read allowed; cross-read only via explicit `users:read:others` (ADMIN+); unknown/malformed/oversized/manipulated ids → byte-identical 403 (no existence oracle, incl. for admins) | VERIFIED | `authzOwnership.test.ts` |
| Forged/expired/empty session cookies → 401 on every capability; Bearer/Basic/API-key headers never authenticate | VERIFIED | `authzSecurity.test.ts` |
| HTTP method tricks cannot bypass role gates (405/204, never a grant) | VERIFIED | `authzSecurity.test.ts` |
| 403 denials keep the full security-header set + exact-origin CORS (`Vary`, credentials reflection) | VERIFIED | `authzSecurity.test.ts` |
| Denial logs carry no role names, emails, tokens or permission names (captured-log scan) | VERIFIED | `authzSecurity.test.ts` |
| Capability probes never register in production (`authzProbeRoutes` derived from env → 404 there) | VERIFIED | `config.test.ts`, `authzMatrix.test.ts` |
| Store: invalid/tampered `role`/`userType` fields refuse to load; Pump 2-era records migrate to MEMBER/null (never elevated) | VERIFIED | `authStore.test.ts` |
| Web: forbidden state (not login redirect) for insufficient roles; role-aware guards; capability verdicts rendered from API responses only; permission-aware UI visibility | VERIFIED | `apps/web/test/authzUi.test.tsx` |
| Web authz payload boundary: guards reject forged role values (`SUPERADMIN` etc.) | VERIFIED | `apps/web/test/authClient.test.ts`, `shared/test/auth.test.ts` |

### Subscriptions & entitlements (Pump 4)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Entitlements derived ONLY from the account's persisted subscription via the shared decision table (`feature:pro` in exactly one cell: PRO + ACTIVE; fail closed) | VERIFIED | `packages/shared/test/plans.test.ts`, `apps/api/test/subscriptionMatrix.test.ts` |
| AccountRole never grants PRO (full MEMBER/ADMIN/ACCOUNT_OWNER × FREE/PRO grid; derivation structurally ignores role/userType) | VERIFIED | `apps/api/test/subscriptionMatrix.test.ts` |
| UserType never grants PRO (all four classifications × FREE/PRO) | VERIFIED | `apps/api/test/subscriptionMatrix.test.ts` |
| Non-ACTIVE PRO (INACTIVE/CANCELLED/EXPIRED) loses `feature:pro` while the plan label stays honest | VERIFIED | `apps/api/test/subscriptionMatrix.test.ts` |
| Registration always writes FREE + ACTIVE server-side; `plan`/`subscription`/`entitlements` in the payload → 422 (mass assignment) | VERIFIED | `apps/api/test/subscriptionApi.test.ts` |
| `GET /api/v1/subscription` is self-only: identity from the session alone, no id parameter exists; `?userId=/?accountId=/?email=`/path manipulation cannot read another account | VERIFIED | `apps/api/test/subscriptionApi.test.ts` |
| Tampering cannot forge PRO: request headers, query strings, extra cookies, forged session cookies (401) and GET bodies are never consulted | VERIFIED | `apps/api/test/subscriptionApi.test.ts` |
| No mutation endpoint: POST/PATCH/PUT/DELETE → 405 + `Allow: GET`, state unchanged | VERIFIED | `apps/api/test/subscriptionApi.test.ts` |
| Anonymous subscription read → 401 | VERIFIED | `apps/api/test/subscriptionApi.test.ts` |
| Live server state: operator subscription changes apply on the next request (no re-login, no cookie reissue) | VERIFIED | `apps/api/test/subscriptionMatrix.test.ts` |
| Store migration: Pump 2/3-era records (no subscription) resolve to FREE + ACTIVE and stay readable; corrupt subscription data fails closed (never PRO, never bricks the store) | VERIFIED | `apps/api/test/authStore.test.ts` |
| Subscription state survives restarts (durable JSON store) | VERIFIED | `apps/api/test/authStore.test.ts` |
| Subscription requests log no plan state, emails, passwords or tokens | VERIFIED | `apps/api/test/subscriptionApi.test.ts` (captured-log scan) |
| Web: plan/PRO verdict rendered only from the server response; errors fail closed (no plan shown, never a silent PRO); no plan state in URL/localStorage/sessionStorage; user payloads can never carry plan material (`isAuthUser` rejects it) | VERIFIED | `apps/web/test/subscriptionUi.test.tsx`, `authClient.test.ts`, `packages/shared/test/plans.test.ts` |

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

Role management console / first-admin bootstrap (elevation is an operator
action on the store today), role-change audit trail, payment/billing
workflows and any subscription mutation path (subscription state changes
only via the operator store-edit + restart workflow — see
`docs/SUBSCRIPTIONS.md`), account email
verification, password reset, MFA, account lockout (deliberate — rate
limits instead), OAuth/OIDC/JWT, attribute-based/relation-based policies
beyond the fixed permission table, distributed sessions or rate limiting,
trusted-proxy (`X-Forwarded-For`) handling, WAF, durable queues, the
database phase, dataset ingestion, file uploads, outgoing fetch/SSRF
surface (the API makes no outbound calls), command execution,
metrics/tracing, security-event alerting.

Note on SSRF/path-traversal/command-injection: the app has no feature that
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
