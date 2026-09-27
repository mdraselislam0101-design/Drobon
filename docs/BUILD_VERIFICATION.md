# Build & verification

## Production builds

```bash
npm run build        # shared → api → worker → web, in dependency order
```

- `@drobon/shared`, `@drobon/api`, `@drobon/worker`: `tsc` project builds
  emitting versioned `dist/` (+ declarations and sourcemaps for the Node
  packages).
- `@drobon/web`: `tsc --noEmit` gate, then `vite build` → hashed,
  cache-friendly `dist/` with sourcemaps disabled and no inlined assets.

Run the production artifacts locally:

```bash
npm run start:api     # build + node apps/api/dist/index.js (HOST/PORT from env)
npm run preview       # build + vite preview of the web bundle (:4173)
```

## The `verify` pipeline

`npm run verify` runs the full regression in dependency order and prints a
per-step summary. Every step must PASS:

1. `check:boundaries` — scope gates (no DB/dataset/shell).
2. Secret-matcher `--self-test` — proves the scanner catches/ignores the
   right shapes.
3. `check:secrets` on sources.
4. `typecheck` — strict `tsc --noEmit` per workspace.
5. `lint` — ESLint over the repo.
6. `test` — shared → api → worker → web (includes the production
   build+preview test).
7. `build` — all production builds.
8. `check:secrets` again — now including `dist/` output.
9. `audit` — `npm audit --audit-level=high`.

Exit code is `0` on PASS, `1` on any FAIL.

## Verification evidence (Pump 1)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-27
- Implementation commit: `58912be` (this section recorded in a follow-up
  docs commit; `verify` re-run green at HEAD afterwards)
- `npm run verify` result: **PASS** — all 9 steps green
  (boundaries, secret self-test, secret scan, typecheck, lint, tests,
  production builds, secret scan incl. builds, dependency audit)
- Test totals: **234 passed, 0 failed** (27 files)
  - `@drobon/shared`: 38 passed (3 files)
  - `@drobon/api`: 122 passed (14 files)
  - `@drobon/worker`: 28 passed (3 files)
  - `@drobon/web`: 46 passed (7 files)
- `npm run audit` result: **0 vulnerabilities** (high gate; also clean at
  every lower level)
- Manual probes against production builds (all executed, all as expected):
  - `GET /livez` → 200, full security-header set, `RateLimit-*` headers,
    `x-request-id`, shared envelope with version `0.1.0`
  - `GET /api/v1/status` → 200 service identity envelope
  - `POST /api/v1/echo` valid → 200 echo; blank message → 422
    `VALIDATION_ERROR` with field issues
  - CORS: disallowed origin → no ACAO (+ `Vary: Origin`); allowed origin →
    exact reflection; preflight → 204 + method/header allowlists
  - Rate limit (max 5): 200s with descending `remaining`, then 429 with
    `Retry-After: 60` and `RATE_LIMITED` envelope; 429s logged at warn
  - `PORT=abc` → `Configuration error: …`, exit 1 (fail fast, stderr)
  - Web preview `/` → 200 + strict CSP (no `unsafe-*`) + hardening headers;
    `/status` → 200 SPA fallback; hashed `/assets/index-*.{js,css}`
  - Web dev proxy: `/api/v1/status` and `/livez` through `:5173` return
    live API JSON (same-origin dev works zero-config)

## Verification evidence (Pump 2 — foundation + authentication)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-27
- `npm run verify` result: **PASS** — all 9 steps green
  (boundaries, secret self-test, secret scan 227 files, typecheck, lint,
  tests, production builds, secret scan incl. builds, dependency audit)
- Test totals: **354 passed, 0 failed** (40 files)
  - `@drobon/shared`: 46 passed (4 files) — Pump 1's 38 + 8 auth-contract
    tests
  - `@drobon/api`: 199 passed (23 files) — Pump 1's 122, of which 8 were
    strengthened (CORS/health/config contracts), + 77 new auth/security
    tests across 8 new suites
  - `@drobon/worker`: 28 passed (3 files) — unchanged
  - `@drobon/web`: 81 passed (10 files) — Pump 1's 46 (2 refactored onto
    shared fixtures, none weakened) + 35 new auth tests across 3 suites
- Pump 1's full suite (234 tests) remains green; the only changes are
  contract strengthenings (CORS credentials, health readiness checks)
  and test-fixture refactoring.
- `npm run audit` result: **0 vulnerabilities**
- Manual E2E probes against the production API build
  (`node apps/api/dist/index.js`, JSON account store):
  - Register → 201; `Set-Cookie: drobon_session=…; HttpOnly; SameSite=Strict;
    Path=/; Max-Age=604800`; body = exact public shape, no password/hash
  - `GET /api/v1/me` with cookie → 200 public shape; without → 401
    `UNAUTHORIZED "Authentication required."`
  - Login wrong password vs unknown email → identical 401 bodies
    (modulo requestId) — enumeration neutralized
  - Duplicate register → 409 `CONFLICT` without account change
  - `Origin: https://evil.example.com` on POST → 403 `FORBIDDEN`
    "Request origin is not allowed."
  - `Authorization: Bearer forged…` on `/me` → 401 (no header auth path)
  - Credential limiter (max 5): 6th auth request → 429 `RATE_LIMITED` +
    `Retry-After: 53`
  - API restart → old session 401 (in-memory grants), account still
    resolvable: login with the original password → 200 (durable store)
  - Logout → 200 `loggedOut:true` + clearing `Max-Age=0` cookie; `/me`
    after → 401; repeat logout → 200 `loggedOut:false` (idempotent)
  - Account store file contains `scrypt$4096…` hashes + emails, **no
    plaintext password**; server logs contain auth events with
    request IDs/user IDs but no email, password, hash or token
- Manual E2E through the Web dev origin (`http://127.0.0.1:5173`, proxy →
  API, `changeOrigin` intentionally removed so the CSRF origin guard sees
  the browser Host):
  - `GET /login` → 200 SPA shell; `/`, `/register`, `/account`, `/status`
    → 200
  - `POST /api/v1/auth/register` with `Origin: http://127.0.0.1:5173` →
    201 + session cookie (origin guard passes same-host)
  - `GET /api/v1/me` with cookie through proxy → 200; without → 401
  - Login through proxy → 200 + cookie → `/me` 200
  - Evil origin through proxy → still 403
- Boundary checks: `check:boundaries` PASS (no DB/dataset/shell);
  `check:secrets` PASS over sources and builds; `.data/` (account store)
  gitignored; final `git status` clean of secrets/datasets/junk after
  commit.

## Verification evidence (Pump 3 — authorization + access control)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-27
- `npm run verify` result: **PASS** — all 9 steps green
  (boundaries, secret self-test, secret scan 243 files, typecheck, lint,
  tests, production builds, secret scan incl. builds, dependency audit)
- Test totals: **413 passed, 0 failed** (44 files)
  - `@drobon/shared`: 59 passed (4 files) — Pump 2's 46 + 13 authz-contract
    tests (plus hardened auth guards)
  - `@drobon/api`: 229 passed (27 files) — Pump 2's 199 (2 exact-shape
    assertions strengthened with role/userType, none weakened) + 30 new
    authorization tests across 4 new suites
  - `@drobon/worker`: 28 passed (3 files) — unchanged
  - `@drobon/web`: 97 passed (11 files) — Pump 2's 81 + 16 new
    authorization tests (UI suite + client boundary)
- Pump 1 + Pump 2 suites remain green; only contract-strengthening
  changes (public user shape gained `role`/`userType`).
- `npm run audit` result: **0 vulnerabilities**
- Manual E2E probes — authorization matrix against the **production API
  build** (`node apps/api/dist/index.js`, three seeded role accounts):
  - Proofs 1–6 exactly as specified:
    member probe → member 200 / admin 200 / owner 200 / anon 401;
    admin probe → member **403** / admin 200 / owner 200 / anon 401;
    owner probe → member 403 / **admin 403** / owner 200 / anon 401
  - 401 body `UNAUTHORIZED "Authentication required."` vs 403 body
    `FORBIDDEN "You do not have access to this resource."` — neither
    hints at roles or accounts
  - Ownership: self 200; member→other 403 (IDOR blocked); admin/owner→
    other 200; unknown id → 403 for member AND admin (no oracle); anon → 401
  - `x-role: ACCOUNT_OWNER` header ignored → still 403; register with
    `role` payload → 422; register with `userType: 'ADMIN'` → 422;
    valid `userType: 'PENTESTER'` → stored, `role` still MEMBER
  - Production posture (`NODE_ENV=production` build): all three probes
    **404 even for a logged-in ADMIN** (cannot ship), `/api/v1/users`
    still registered and enforced (self 200 / anon 401), session cookie
    carries `Secure`, security headers intact, `/me` 200
- Manual E2E through the Web origin (`http://127.0.0.1:5173`, proxy →
  API): register with userType → 201 `role: MEMBER, userType: PENTESTER`;
  `/me` returns both fields (badge source); probes 200/403/403 as member;
  self-lookup 200, other-lookup 403, anon probe 401; **Pump 2-era store
  record (no role fields) logs in and migrates to `MEMBER`/`null`**;
  operator elevation (store edit + restart) → same account now sees
  `role: ADMIN`, admin probe 200, owner probe 403, privileged
  cross-account lookup 200 returning only public fields — proving
  authorization reads live server-side state end to end.
- Boundary checks: `check:boundaries` PASS; `check:secrets` PASS over
  sources and builds; `.data/` (account store, mode 0600) gitignored;
  final `git status` clean of secrets/datasets/junk after commit.
