# Authentication Design (Pump 2)

How authentication works in DROBON AEGIS AI today — what is implemented,
why it is built this way, and exactly what it is not. Everything on this
page is covered by executable tests (see `docs/TESTING.md`).

## Shape of the flow

```
Browser (React)                 API (Node, zero deps)              Account store
────────────────                ─────────────────────              ─────────────
POST /api/v1/auth/register  →   validate (shared policy)
                                hash password (scrypt)         →   JSON file (atomic)
                                create session
                 ←  201 {user} + Set-Cookie: drobon_session
                    (HttpOnly; SameSite=Strict; Path=/; Secure in prod)

GET /api/v1/me (cookie)     →   session store → repository
                 ←  200 {user}   |   401 generic

POST /api/v1/auth/logout    →   revoke token, clear cookie
                 ←  200 {loggedOut}   (idempotent, always 200)
```

Endpoints: `POST /api/v1/auth/register`, `POST /api/v1/auth/login`,
`POST /api/v1/auth/logout`, `GET /api/v1/me`. All run inside the standard
pipeline (request ID → security headers → CORS → global rate limit →
credential rate limit → CSRF origin guard → session resolution → routing).
`GET /api/v1/me` sits behind the router's `requireAuth` boundary — the
single choke point every future protected route reuses.

## Credentials and sessions

- **Passwords**: scrypt (`node:crypto`, memory-hard, OWASP-accepted),
  N=32768 (configurable power of two), r=8, p=1, 16-byte random salt,
  64-byte key, constant-time comparison, parameters embedded in the stored
  string (`scrypt$N$r$p$salt$hash`) so cost can change without a migration
  framework. Plaintext never touches disk, logs or responses; a corrupted
  hash fails closed (login fails, no crash).
- **Sessions**: server-side, in memory, keyed by the SHA-256 of a 32-byte
  random token. The raw token exists only in the client's cookie — a
  memory dump of the store does not yield usable tokens. Absolute TTL
  (default 7 days, `AUTH_SESSION_TTL_SECONDS`), no sliding refresh;
  expired entries are pruned; logout revokes immediately. Restarting the
  API signs everyone out (sessions are deliberately process-local — the
  durable thing is the *account*, not the grant).
- **Cookie**: `drobon_session` — `HttpOnly` (JS/XSS can't read it),
  `SameSite=Strict` (browsers won't attach it cross-site: primary CSRF
  defense), `Path=/`, host-only (no `Domain`), `Secure` when
  `NODE_ENV=production`. The value never appears in any JSON body.
- **Client state**: the Web app holds only the public `AuthUser` in React
  state; the API client sends `credentials: 'include'`. There is no token
  in `localStorage`/`sessionStorage` (XSS cannot exfiltrate what JS never
  sees).

## Enumeration and abuse posture

- **Login answers identically for unknown email and wrong password**
  (same status, code, message: `401 UNAUTHORIZED "Invalid email or
  password."`) and burns the same CPU in both cases — unknown emails run a
  dummy scrypt so timing doesn't leak account existence.
- **Registration's 409** ("An account with this email already exists.")
  is an inherent oracle without an email-verification phase — every
  product that shows inline "email taken" behaves this way. It is
  rate-limited (`AUTH_RATE_LIMIT_MAX_REQUESTS`, default 30/min/IP, default
  strictly tighter than the global limit) and documented rather than
  faked. No password/hash ever appears in the response.
- **Rate limits**: a dedicated limiter scopes `/api/v1/auth/*` per client
  IP; abuse hits 429 + `Retry-After` long before the global budget.
  Single-process by design (same honest limitation as the global limiter).
- **CSRF**: `SameSite=Strict` cookies + an origin guard on unsafe methods
  (Origin must be allowlisted or match the request Host; requests without
  an Origin come from non-browser clients where ambient-cookie CSRF does
  not apply). CORS credentials are enabled only alongside an exactly
  reflected origin — never `*`.
- **Open redirects**: post-login navigation only accepts internal paths
  (`/…`, no `//`, no backslash/CRLF) — tested against `//evil`,
  `https://evil`, `/\evil` payloads.
- **Mass assignment**: credential schemas reject unknown keys (a client
  cannot POST `role: "admin"`), tested.

## Persistence boundary (why a JSON file exists)

Persistent authentication requires durable accounts, and Pump 2 explicitly
forbids starting the broader database phase. The compromise:

- `UserRepository` (interface) is the seam. HTTP routes, middleware and
  shared contracts only ever see the interface.
- `JsonFileUserRepository` is the minimum durable implementation: one JSON
  document (`.data/users.json`, gitignored, mode 0600), read+validated at
  startup (**fail fast on corruption — the process refuses to start**),
  writes are temp-file + rename (atomic), creates are serialized
  (duplicate races impossible), persist-before-observable (memory never
  diverges from disk).
- Honest limits, stated everywhere: single-process, single-writer,
  foundation-scale (thousands of accounts, not millions). The database
  phase replaces this one module with a real store; nothing else changes.
- `:memory:` exists only as an explicit opt-in for dev/test and is
  **rejected by `loadConfig` in production**.

## What this is NOT

- No roles/authorization (the `requireAuth` boundary is authorization-*ready*),
  no email verification, no password reset, no MFA, no OAuth/OIDC/JWT,
  no account lockout (deliberate: lockouts are a DoS vector; rate limits
  instead), no distributed session state, no password history/rotation
  policy. See the NOT_IMPLEMENTED sections in `docs/SECURITY.md`.

## Test coverage map

- Shared: policy/guards — `packages/shared/test/auth.test.ts`.
- API unit: hashing, sessions, cookies, repositories —
  `apps/api/test/{passwords,sessions,cookies,authStore}.test.ts`.
- API integration + security: register/login/logout/me flows, bypass
  attempts, enumeration, brute force, cookie flags, origin guard, CORS
  interaction, disclosure/logging hygiene —
  `apps/api/test/auth{Registration,Login,Logout,Me,Security}.test.ts`.
- Web: client boundary, forms, protected routes, expiry, logout, nav —
  `apps/web/test/{authClient,authPages,protected}.test.tsx? .ts`.
- End-to-end evidence (real HTTP through both servers) is recorded in
  `docs/BUILD_VERIFICATION.md`.
