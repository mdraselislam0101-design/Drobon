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

`npm run verify` is the authoritative full regression pipeline in dependency
order and prints a per-step summary. Every one of its eleven gates must PASS:

1. `check:boundaries` — no database/dataset/shell imports or dependencies.
2. `check-repo-integrity` — npm lock/workspace consistency, credential and
   dataset file inventory, registry-token checks, generated-output exclusion,
   and least-privilege/pinned-action CI policy.
3. Release-evidence self-test — digest determinism and artifact mismatch
   detection.
4. Secret-matcher `--self-test`.
5. `check:secrets` on sources/configuration.
6. `typecheck` — strict TypeScript checks per workspace.
7. `lint` — ESLint over the repo.
8. `test` — complete shared → API → worker → Web regression suite (includes
   the existing production-preview test).
9. `build` — shared, API, worker, and Web production builds.
10. `check:secrets` again — including generated build output.
11. `audit` — `npm audit --audit-level=high`; registry/network failures fail
    closed instead of being downgraded to warnings.

Exit code is `0` only when all required gates pass, otherwise `1`. GitHub
Actions runs this exact command after `npm ci --ignore-scripts`; details and
release-evidence limits are in `docs/CI_RELEASE.md`.

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

## Verification evidence (Pump 4 — plans, subscriptions & entitlements)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-27/28
- `npm run verify` result: **PASS — all 9 steps green**
  (boundaries, secret self-test, secret scan 258 files, typecheck, lint,
  tests, production builds, secret scan incl. builds, dependency audit)
- Test totals: **466 passed, 0 failed** (50 files)
  - `@drobon/shared`: 74 passed (6 files) — Pump 3's 59 + 15 plan/
    subscription/entitlement contract tests (decision table, guards,
    legacy default, plan-material rejection on user payloads)
  - `@drobon/api`: 255 passed (29 files) — Pump 3's 229 + 26 new tests
    across 2 new suites (subscription endpoint security incl. IDOR/
    tamper/405/log hygiene; commercial matrix incl. role×plan,
    UserType×plan, status matrix, live operator flips) and 7 store
    migration/normalization/restart tests in `authStore.test.ts`
  - `@drobon/worker`: 28 passed (3 files) — unchanged
  - `@drobon/web`: 97 → 109 passed (12 files) — +12 tests: Account-page
    plan section (8, incl. fail-closed error + verdict-from-server +
    no-URL/storage-state) and subscription client boundary (4)
- Pump 1–3 suites remain green; no existing test was weakened.
- `npm run audit` result: **0 vulnerabilities**
- Manual E2E — the **real dev workflow** (`dev:api` + `dev:web`,
  durable JSON account store, browser-shaped requests through the Vite
  proxy with a same-origin `Origin` header):
  - Web shell `/`, `/account` → 200; `/livez` + `/api/v1/status` via the
    proxy → live API JSON; direct API `/livez`, `/readyz` → 200
  - Anonymous `GET /api/v1/subscription` → 401 exact envelope; forged
    `drobon_session` cookie → 401
  - Register (with `userType: DEVELOPER`) via proxy → 201, role MEMBER,
    and `GET /api/v1/subscription` → **FREE + ACTIVE** with
    server-written ISO timestamps, entitlements exactly `["plan:view"]`;
    persisted store record matches the response
  - `GET /api/v1/me` with session via proxy → 200 public shape
  - Pump 3 authorization intact: capability probes member 200 / admin
    403 / owner 403; `GET /api/v1/users` self 200 / unknown id 403
    (IDOR blocked)
  - Client tampering on the FREE session — `x-plan: PRO` +
    `x-user-id` headers, `?plan=PRO&userId=&accountId=&email=` query,
    an extra `plan=PRO` cookie, and a raw GET with a JSON body
    `{"plan":"PRO","status":"ACTIVE"}` — all answered **200 FREE**
    (`["plan:view"]`); the API response stayed authoritative
  - Mutation attempts: POST/PATCH/PUT/DELETE `/api/v1/subscription` →
    **405 + `Allow: GET`**, state unchanged afterwards; evil-origin
    register → 403 (CSRF guard intact); direct-API login with a web
    Origin → 403 (origin guard intact)
  - **Operator workflow (store edit + restart — the only PRO path):**
    stopped the API, set the account's subscription to `PRO + ACTIVE`
    in the JSON store, restarted, re-logged in (sessions are
    process-local by design) → `GET /api/v1/subscription` → **PRO +
    ACTIVE, entitlements `["plan:view","feature:pro"]`** — restart
    preserved the subscription state (durable store)
  - Lapse matrix, each via store edit + restart + re-login:
    PRO + **INACTIVE** → `["plan:view"]`; PRO + **CANCELLED** →
    `["plan:view"]`; PRO + **EXPIRED** → `["plan:view"]` — the PRO
    label stayed honest while `feature:pro` disappeared every time
  - **Legacy migration live:** deleted the `subscription` field from
    the record (exact Pump 3-era shape), restarted, re-logged in →
    FREE + ACTIVE with `null` timestamps, `["plan:view"]` — pre-Pump-4
    accounts remain readable with the documented safe default
  - Log hygiene on the live server: subscription request lines carry
    only requestId/method/path/status/durationMs — no plan state,
    emails, passwords or tokens
  - Account store file: scrypt hash + subscription state only, no
    plaintext password, mode 0600, inside gitignored `.data/`
- Boundary checks: `check:boundaries` PASS (no DB/dataset/shell; no
  payment/gateway code); `check:secrets` PASS over sources and builds;
  DATASET LOCK respected — no CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere;
  final `git status` clean of secrets/datasets/junk after commit.

## Verification evidence (Pump 5 — usage quota + device anti-abuse)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-28
- `npm run verify` result: **PASS** — all 9 steps green
  (boundaries, secret self-test, secret scan 282 files, typecheck, lint,
  tests, production builds, secret scan incl. builds, dependency audit)
- Test totals: **533 passed, 0 failed** (55 files)
  - `@drobon/shared`: 84 passed (7 files) — Pump 4's 74 + 10 usage
    contract tests (`usage.test.ts`: quota constants, strict UTC period
    pattern, quota-status vocabulary, response guards incl. cross-field
    invariants)
  - `@drobon/api`: 299 passed (32 files) — Pump 4's 255 + 44: three new
    suites (`usageApi.test.ts` endpoint/authorization/tamper matrix,
    `usageQuota.test.ts` atomicity/boundaries/persistence,
    `usageDevice.test.ts` device model) + 2 config tests; one shared
    error-vocabulary test extended for `QUOTA_EXCEEDED`
  - `@drobon/worker`: 28 passed (3 files) — unchanged
  - `@drobon/web`: 122 passed (13 files) — Pump 4's 109 + 13: Account-page
    usage section (8) + usage client boundary (5)
- `npm run audit` result: **0 vulnerabilities**
- Manual E2E — real dev servers (`dev:api` on :3001 with the durable
  JSON stores, `dev:web` on :5173; curl with cookie headers; fixed
  clock NOT used — live UTC date 2026-09-28):
  1. Anonymous `GET /api/v1/usage` → **401** exact envelope
  2. FREE login → `GET /usage` → **FREE 0/3 OK, period 2026-09**, and
     the first authenticated response issued `drobon_device` with
     `HttpOnly; SameSite=Strict; Path=/; Max-Age=34560000` (no `Secure`
     in dev)
  3. Consumes 1–3 → **200** with used 1,2,3 / remaining 2,1,0
  4. Consume #4 → **429 `QUOTA_EXCEEDED`** + `Retry-After: 267818`
     (exact seconds to 2026-10-01T00:00:00Z)
  5. Denial immutable: `GET /usage` after → still **used 3, remaining 0,
     EXHAUSTED**; repeat consume → 429 again
  6. PRO+ACTIVE account (store-edit workflow) on the SAME device → 5
     consumes all **200**, view **EXEMPT** (`limit`/`remaining` `null`,
     used 5) — and the on-disk store proves the PRO scans never touched
     the device counter (device count stayed 3, all from the FREE
     account)
  7. A second FREE account on the same device → **used 0, remaining 0,
     EXHAUSTED**; its consume → **429** (shared-device allowance)
  8. Cross-account read attempts (`?userId=<other>&email=<other>`) →
     own view only
  9. Plan tampering (`x-plan: PRO`, `x-quota`, `x-remaining` headers +
     `plan=PRO` cookie) → still **FREE/EXHAUSTED**; consume still 429
  10. Quota tampering: body `{used,remaining,plan}` → **422
      VALIDATION_ERROR** ("Unexpected property" ×3); `PATCH`/`DELETE
      /usage` → **405 + Allow: GET**
  11. Malformed device cookies (`garbage`, wrong length,
      `../../etc/passwd`) → **200** + a fresh valid `drobon_device`
      each time (never an error, never trusted)
  12. API restart (SIGTERM → start): re-login → usage intact
      (demo-free **3/0 EXHAUSTED**; the second account's device-shared
      exhaustion persisted too)
  13. UTC month boundary: seeded the durable store with the previous
      period (`2026-08`: account 3 + a valid device token's hash 3),
      restarted → September view on that device **used 0, remaining 3,
      OK** — August never reduces September (Dec→Jan covered by tests)
  14. Production build (`node apps/api/dist/index.js`,
      NODE_ENV=production, :4001, temp store copies): `GET /usage` →
      **200 EXEMPT** (read the persisted PRO count — durable store
      across binaries), device cookie gained **Secure**;
      `POST /usage/consume` → **404** (probe not registered);
      anonymous `GET /usage` → **401**; and
      `USAGE_STORE_PATH=:memory:` refused to boot (**Configuration
      error**, exit 1)
  15. The same usage view through the **web dev proxy** (:5173 → API)
      → identical authoritative JSON (the browser's actual path)
  16. Live log hygiene: consumption/denial lines carry requestId +
      userId only — no device hash, token, email or plan material
      anywhere in the captured server logs
- Boundary checks: `check:boundaries` PASS (no DB/dataset/shell; no
  payment code); `check:secrets` PASS over sources and builds; DATASET
  LOCK respected — no CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere; final
  `git status` clean of secrets/datasets/junk after commit.

## Verification evidence (Pump 6 — projects foundation)

> Re-run `npm run verify` after any change and update this section —
> evidence must always describe the current tree.

- Date: 2026-09-28
- `npm run verify` result: **PASS** — all 9 steps green
  (boundaries, secret self-test, secret scan 297 files, typecheck, lint,
  tests, production builds, secret scan incl. builds, dependency audit)
- Test totals: **593 passed, 0 failed** (58 files)
  - `@drobon/shared`: 94 passed (8 files) — Pump 5's 84 + 10 project
    contract tests (`projects.test.ts`: status vocabulary, id pattern,
    ordering comparator, public-shape and response guards incl. the
    deliberate absence of an owner field)
  - `@drobon/api`: 327 passed (33 files) — Pump 5's 299 + 28: the new
    `projectApi.test.ts` (26: auth matrix, server-controlled create
    fields + 201, strict validation incl. prototype-pollution and
    XSS-as-text and NFC normalization, server-scoped lists +
    deterministic ordering, uniform cross-account 403 across
    roles/user types, update/lifecycle boundaries + idempotence,
    restart persistence incl. multi-line descriptions, corrupt-store
    refusal, 20-way concurrent creation, claims tampering, usage
    non-consumption, router parameterization incl. 405/percent-encoding/
    trailing-slash semantics, log hygiene) + 1 config test
    (`PROJECT_STORE_PATH` default/override/`:memory:`-banned-in-prod/
    blank) + 1 validator regression (prototype-chain keys rejected)
  - `@drobon/worker`: 28 passed (3 files) — unchanged
  - `@drobon/web`: 144 passed (14 files) — Pump 5's 122 + 22:
    `projectUi.test.tsx` (15: server-ordered list, honest empty/loading/
    error states, create + edit flows with exact client calls,
    client-side bounds, XSS-inert rendering, foreign-id honest error,
    archive/unarchive reflection, no ownership/status form fields, no
    storage authority, protected routes for list + deep links) + 7
    projects client-boundary tests in `authClient.test.ts`
- `npm run audit` result: **0 vulnerabilities**
- Manual E2E — real dev servers (`dev:api` on :3001 with the durable
  JSON stores, `dev:web` on :5173; curl with cookie headers; fixed
  clock NOT used — live UTC date 2026-09-28):
  1. Anonymous access to ALL six project routes → **401** exact envelope
  2. Create → **201** with `prj_` + UUID id, trimmed name, ACTIVE
     status, and exactly `{id,name,description,status,createdAt,
     updatedAt}` — no `ownerId`, no storage paths
  3. Ordering live: create A then B, PATCH A → A listed first
     (updatedAt DESC); comparator re-verified independently in tests
  4. Validation matrix: empty PATCH `{}` → 422; `ownerId`/`status`/`id`
     in PATCH or create bodies → **422 Unexpected property** (mass
     assignment impossible); whitespace-only and 121-char names → 422;
     control chars → 422 (names; descriptions) while `\n`/`\t` in
     descriptions are preserved; malformed JSON → 400
  5. Prototype pollution: `__proto__`/`constructor` payloads → **422
     Unexpected property ×2** (the Pump 1 validator fix, live); the
     Node process's `Object.prototype` verified unpolluted afterwards
  6. Lifecycle: archive → ARCHIVED (still listed + readable), repeat
     archive → 200 idempotent WITHOUT bumping updatedAt, unarchive →
     ACTIVE; `PATCH …/archive` → 405 (lifecycle is POST-only);
     `DELETE /projects/:id` → **405 + `Allow: GET, PATCH`** (no hard
     delete); `PUT /projects` → 405
  7. Cross-account (second account, all routes): GET/PATCH/archive/
     unarchive on the owner's id → **403** with the uniform message;
     unknown well-formed id, 80-char oversized id and pattern-failing
     ids → the SAME 403 (no existence oracle; error bodies byte-equal
     modulo requestId); attacker's list stays empty; owner's project
     untouched
  8. Router: `GET /projects/` → 200 (collection trailing-slash
     normalization), `GET /projects//archive` → 404 (empty segment
     never matches), `%zz` → 404 (malformed encoding never matches),
     `prj_…%30` → 200 (percent-encoded param decoded to the real id)
  9. Text security: decomposed `e` + combining accent stored and
     returned as composed `é` (NFC live); `<script>/<img onerror>/<svg
     onload>` payloads stored verbatim as JSON text and echoed as text
  10. Usage boundary: full CRUD + lifecycle cycle → `GET /usage` still
      **used 0, OK, FREE** — project operations never consume a scan
  11. Web dev proxy (:5173 → API): project list via the browser path →
      identical authoritative JSON
  12. Log hygiene on the live server: project log lines carry
      requestId/userId/projectId (+ method/path/status/durationMs)
      only — project names, descriptions and account emails never
      appear in the captured logs
  13. On-disk store: `.data/projects.json` mode 0600, `{version:1,
      projects:[…]}` with internal `ownerId`, and NO email/password
      material in the file
  14. **Restart persistence**: SIGTERM → start → old session cookie
      401 (in-memory sessions die), re-login → all 6 projects intact
      with edits, ARCHIVED status, multi-line description and XSS-text
      name unchanged; usage still used 0
  15. Production binary (`node apps/api/dist/index.js`,
      NODE_ENV=production, :4001, temp copies of the durable stores):
      anonymous → 401; re-login 200 (durable accounts); list 200 with
      the 6 durable projects (binary-to-binary persistence); create →
      ACTIVE; PATCH → 200; archive → 200 — project routes ARE real
      production surface (unlike probes); Pump 3 authz probes and the
      Pump 5 consume probe still **404** in production; usage view
      used 0; device cookie gained **Secure**;
      `PROJECT_STORE_PATH=:memory:` refused to boot (**Configuration
      error**, exit 1)
- **E2E-found defect, fixed and regression-tested**: descriptions may
  contain tab/newline (documented multi-line allowance), but the
  project store's fail-fast load validation rejected ALL control
  characters — so a legitimate write could brick the next startup
  (reproduced live: restart refused with "invalid record at index 3").
  The store backstop now mirrors the API validation policy exactly
  (names: no control chars; descriptions: tab/newline allowed); a
  restart-persistence regression test covers it.
- Boundary checks: `check:boundaries` PASS (no DB/dataset/shell; no
  payment/gateway code); `check:secrets` PASS over sources and builds
  (one test variable renamed to keep the matcher quiet); DATASET LOCK
  respected — no CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere; final `git
  status` clean of secrets/datasets/junk after commit.

## Pump 7 — Secure scan-job foundation (VERIFIED, live E2E included)

**Date:** 2026-09-28 · **Baseline advanced:** 593 → **651 tests** (+58:
shared scans contracts 106, API scan suite +29, API config +1, web
scan UI +11, web scan client +5, shared errors +6 — all suites re-run
green: shared 106/106, API 357/357, worker 28/28, web 160/160).
**Typecheck:** 0 errors (all workspaces). **Lint:** clean.
**`npm run verify`: PASS** (boundaries, secret matcher self-test,
secret scan sources + builds, typecheck, lint, tests, production
builds, dependency audit — 9/9).

### Spec compliance (locked scope, honest delivery)

- Scan jobs exist: POST/GET `/api/v1/projects/:projectId/scans` +
  GET `…/scans/:scanId`; `scan_` UUID ids; server-authoritative
  QUEUED→RUNNING→COMPLETED/FAILED lifecycle; **no client mutation
  endpoint** (405 + Allow on PATCH/DELETE).
- **The scan engine is NOT implemented** — the pump is the secure
  ORCHESTRATION boundary only. `scanType ∈ {SAST,SCA,SECRETS,DAST}`
  is the job vocabulary; with the engine registry empty by design,
  every scan deterministically FAILS `SCAN_ENGINE_NOT_IMPLEMENTED`.
  No fabricated findings/results, ever (tested).
- **NO vulnerability datasets**: the dataset lock holds (no
  CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere; synthetic engines exist
  only inside test files).
- Scanner engines / findings / reports / SBOM / cancellation /
  scheduling remain NOT_IMPLEMENTED (documented in `docs/SCANS.md`).

### Security properties verified by tests (see docs/SECURITY.md)

Ownership chain account→project→scan derived from the session only
(body `id`/`projectId`/`ownerId`/`requestedBy`/`status`/timestamps/
`result`/plan/role claims → 422, proto keys included); uniform
project-level 403 (unknown/foreign/malformed/oversized ids
byte-identical modulo requestId; roles/user types never grant foreign
scans); scan-level uniform 404 inside the caller's own project;
**quota consumed EXACTLY once per created scan, atomically with the
durable append** (UsageService = single authority inside the store's
serialized section — no job can exist without a consumed allowance);
10-way FREE concurrency → exactly 3 grants + 7 uniform 429 +
Retry-After; same-key 10-way retry storm → 1 scan, 1 charge;
cross-project/cross-account/device-shared races; PRO EXEMPT; UTC
month rollover; claims/cookie tampering never changes the verdict;
idempotency (strict format, account-scoped, replay→200 original,
different request→409, bounded 20/account, restart-persistent);
claim-once/finish-once (duplicate delivery cannot execute twice;
terminal records immutable); crash recovery RUNNING→FAILED/
SCAN_INTERRUPTED + QUEUED drain; corrupt/invalid store refuses to
start (state-machine violations and dangling idempotency included);
responses expose the public shape only (no ownerId/worker internals);
log lines ids-only; web honest-FAILED rendering, server-derived quota
hint, archived restriction, XSS-inert, no storage authority.

### Live E2E (dev :3001 API + :5173 web proxy, then production :4001)

1. Register/login (device cookie on first authenticated response);
   create project; usage 0/3 → create scan with Idempotency-Key →
   201 QUEUED (public shape: id, projectId, scanType, status,
   createdAt, updatedAt ONLY); replay same key+request → **200 same
   scan**; usage used=1 (consumed exactly once despite two requests).
2. **Production processor auto-start verified live**: the scan left
   QUEUED within ~1s → FAILED/`SCAN_ENGINE_NOT_IMPLEMENTED`,
   "The SAST scanner engine is not implemented yet.", startedAt +
   completedAt set, resultSummary absent (never fabricated).
3. FREE exhaustion: scans 2,3 → 201; 4th → 429 QUOTA_EXCEEDED +
   Retry-After ≈ next UTC month; usage used=3 EXHAUSTED.
4. Plan tampering on exhausted account (x-plan header, extra cookie)
   → still 429.
5. Cross-account: attacker list/create on foreign project → uniform
   403 (foreign and malformed-uuid ids byte-identical); anonymous →
   401; foreign scan id inside attacker's OWN project → 404 (same as
   unknown scan id — no existence oracle).
6. Idempotency conflict: same key + different scanType → 409
   CONFLICT; malformed keys (short/invalid chars/65 chars) → 422.
7. Router hardening: `%2F`/`%00` → 403 uniform, `%zz`/deep paths/
   trailing slash → 404, `.`/`%20` segments handled, HEAD on the
   collection → 405, no version/server headers leak.
8. Web via Vite proxy (:5173): anonymous API → 401; authed scans via
   proxy 200, server-ordered (createdAt DESC), statuses honest.
9. Archive flow: archive → new scan 409 PROJECT_ARCHIVED ("Archived
   projects cannot start new scans. Unarchive the project first."),
   history (3 scans) still readable; unarchive → 200.
10. **Restart persistence**: SIGTERM → "Shutdown complete"; restart →
    re-login; 3 scans survived with terminal states intact; quota
    used=3 still enforced (4th → 429); the OLD idempotency key still
    replays to the ORIGINAL scan; `scans.json` 0600, no
    emails/passwords/account material (grep clean), record keys
    owner-internal only.
11. Corrupt-store refusal (SCAN_STORE_PATH → garbage): "Fatal startup
    error: … refusing to start with corrupt scan data"; port never
    opens (fail-fast confirmed).
12. PRO flow (store plan flip + restart): usage view plan=PRO,
    limit=null, quotaStatus=EXEMPT; 5 concurrent creates → 5×201
    (3 FREE + 5 PRO = 8 scans, all FAILED honest); web proxy sees
    EXEMPT ("Pro plan: unlimited scans."); store edit reversed after.
13. **Production API build (:4001)**: durable store loads (8 scans
    listed), scan create 201, `/` and `/../` still 404 (probes
    hidden); `SCAN_STORE_PATH=:memory:` in production → configuration
    error, refuses to start (verified on :4002).
14. Production web build present (`apps/web/dist`, scan section in
    the bundle); shutdown hooks stop the processor cleanly.

### Boundary checks

`check:boundaries` PASS (no DB/dataset/shell; no payment/gateway
code); `check:secrets` PASS over sources and builds; **DATASET LOCK
respected** — no CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere; `git
status` clean of secrets/datasets/junk after commit.

## Pump 8 — Real SAST engine (VERIFIED, live E2E included)

**Pipeline:** `npm run verify` — 9/9 PASS (boundaries, secret
matcher self-test, secret scan sources + builds, typecheck, lint,
tests, production builds, dependency audit).

**Test totals:** shared 128, api 432 (incl. `sastRules` 21,
`sastEngine` 22, `sastApi` 30), web 169 (incl. `sastUi` 9) — 729 total.

### Live E2E (production build, `:4101`, fresh stores in `/tmp`)

1. Boot `NODE_ENV=production node dist/index.js` → listening, plain
   startup fatals only.
2. Register + project create → 201s.
3. **Pre-flight quota protection**: SAST on a snapshot-less project →
   `409 CONFLICT` "Upload a source snapshot before requesting a SAST
   scan." and usage stays `used=0` (nothing consumed).
4. Snapshot upload (5 files incl. an `exec` payload + a fake
   credential) → 200; read-back is METADATA ONLY (no content key in
   the response); `.env`, `../traversal`, `__proto__` and `.pem`
   uploads → 422 with the snapshot intact (replace semantics hold:
   the last successful upload wins).
5. **Scan 1** (SAST): QUEUED → COMPLETED via the processor sweep;
   honest counts (filesScanned 4, filesSkipped 1).
6. Idempotent replay (same key) → 200, same scan id, usage unchanged
   (used=1).
7. Snapshot REPLACED with the full 6-rule vulnerable shape → **Scan
   2** (SAST): COMPLETED with **6 findings, severity-ordered**
   (HIGH DG-SAST-001/003/002, MEDIUM DG-SAST-005/004, LOW
   DG-SAST-006), CWE mappings present, **credential redacted**
   (`<redacted>` in evidence; the literal appears nowhere in the
   response).
8. **Analyzed, never executed**: the uploaded payload contained
   ``exec(`touch /tmp/drobon-pump8-marker ${dir}`)`` — the finding
   fires with that evidence, and `/tmp/drobon-pump8-marker` DOES NOT
   EXIST after the scan (checked before and after both SAST scans).
9. **Scan 3** (DAST): FAILED/`SCAN_ENGINE_NOT_IMPLEMENTED` — the
   honest no-engine path.
10. **Quota exhaustion**: 4th request → 429 `QUOTA_EXCEEDED` +
    `Retry-After`; usage `used=3, EXHAUSTED`.
11. **Cross-account isolation**: second account → sources GET/PUT and
    the foreign scan detail all 403 (uniform, no oracle).
12. **Log hygiene**: the full server log carries ids/counts only —
    no source content, no secret value; `scans.json` stores
    `<redacted>` evidence (0 raw occurrences), `usage/projects/users`
    stores clean; the uploaded content lives ONLY in the 0600
    `sources.json` scan-target store (by design — that is the input
    the engine reads; `.data/` is gitignored).
13. **Restart durability**: SIGTERM → reboot on the same stores →
    scan 2 still COMPLETED with 6 findings, **identical finding ids**
    across the restart (deterministic fingerprints), snapshot intact,
    quota continuity (used=3, EXHAUSTED).
14. **Corrupt source store refuses to start** (`:4102`, garbage
    `sources.json`): "Fatal startup error: Source store … is not
    valid JSON — refusing to start with corrupt source data."; exit 1,
    port never opens.
15. Production web build carries the SAST UI (`view-findings`,
    `source-file-input`, `findings-filter` present in the bundle).

### Boundary checks

`check:boundaries` PASS (no DB/dataset/shell; no payment/gateway
code); `check:secrets` PASS over sources and builds (the fake
credential literals in tests carry same-line fake markers);
**DATASET LOCK respected** — no CVE/NVD/GHSA/OSV/KEV/EPSS data
anywhere; `git status` clean of secrets/datasets/junk after commit.

## Pump 9 — Real SCA engine, honest by construction (VERIFIED, live E2E included)

**Pipeline:** `npm run verify` — 9/9 PASS (boundaries, secret
matcher self-test, secret scan sources + builds, typecheck, lint,
tests, production builds, dependency audit).

**Test totals:** shared 140 (incl. `sca` contract suite 12), api 494
(incl. `scaParsers` 27, `scaEngine` 21, `scaApi` 13), web 173 passed
+ 3 skipped (incl. `scaUi` 7), worker 28 — **838 total, 0 failed**.

### Live E2E (production build, `:4101`, fresh stores in `/tmp`)

1. Boot `NODE_ENV=production node dist/index.js` → listening
   (`VULN_INTEL_PROVIDER=none` accepted; any other value refuses).
2. Register + login + project create → 201/200/201.
3. **SCA pre-flight quota protection**: SCA on a snapshot-less
   project → `409 CONFLICT` "Upload a source snapshot before
   requesting a SCA scan." and usage stays `used=0`.
4. Snapshot upload (7 files: package.json, lock v3, requirements.txt,
   pyproject.toml, a `tools/package.json` with a hostile postinstall,
   an `exec` source file) → 200; read-back is METADATA ONLY;
   `../traversal`, `%2e%2e/`, `C:\secret\package.json` and `.env`
   uploads → 422 with the snapshot intact.
5. **Scan 1 (SCA)**: QUEUED → COMPLETED — inventory **7 dependencies
   (6 direct, 1 transitive)**, `transitiveGraph: AVAILABLE`,
   **SBOM with 7 components** anchored at the root `demo-app` 1.4.2;
   5 manifests ANALYZED (incl. the nested `tools/package.json`).
6. **DATASET HONESTY**: the fixture deliberately pins vulnerable-
   LOOKING versions (express 4.17.1, lodash 4.17.15, flask 1.1.1) —
   the assessment is **`NOT_ASSESSED` / `NO_DATA_LOADED`** with
   **ZERO advisories and zero findings**. Nothing fabricated.
7. **Analyzed, never executed**: the uploaded postinstall
   `touch /tmp/pump9-e2e-marker` — the marker DOES NOT EXIST after
   the scan (checked; manifests are inert data).
8. **Lockfile priority**: express keeps declared `^4.18.0` AND
   resolved `4.17.1` (versionSource lockfile, lockfilePath evidence,
   purl `pkg:npm/express@4.17.1`); flask keeps `==1.1.1` declared
   with NO resolved version (never fabricated); `accepts` classified
   transitive from the lockfile closure.
9. Idempotent replay (same key) → 200, same scan id, usage unchanged
   (`used=1`).
10. **Scan 2 (SAST)** on the SAME snapshot: COMPLETED with the exec
    finding (DG-SAST-001) and **NO `sca` payload** — the two engines
    stay distinct on one target.
11. **Scan 3 (DAST)**: FAILED/`SCAN_ENGINE_NOT_IMPLEMENTED` — the
    honest no-engine path.
12. **Quota exhaustion**: 4th scan → `429 QUOTA_EXCEEDED` +
    `Retry-After: 235482`; usage `used=3, EXHAUSTED`.
13. **Cross-account isolation**: second account → sources GET/PUT,
    foreign scan detail and scan request all uniform 403 — no
    inventory leakage, no oracle.
14. **Hygiene**: server log + `scans.json` carry NO manifest content
    and NO advisory identifiers; raw content lives ONLY in the 0600
    `sources.json` scan-target store (by design, gitignored).
15. **Restart durability**: SIGTERM → reboot on the same stores →
    fresh login (sessions are in-memory by design), scan 1 still
    COMPLETED with the **identical sca payload** (identical
    dependency ids AND identical SBOM serial), quota continuity
    (`used=3, EXHAUSTED`); an extra scan still 429s (no free slots).
16. **Forged SCA payload refuses to boot** (`:4102`, fabricated
    `ASSESSED` + `CVE-FAKE` advisory injected on a SAST scan):
    "refusing to start", exit 1, port never opens.
17. Production web build carries the SCA UI (`view-sca`, the honest
    not-assessed banner, the inventory view).

### Boundary checks (§33-style audit)

`check:boundaries` PASS (no DB/dataset/shell; no payment/gateway
code); `check:secrets` PASS over sources and builds (361 files);
**DATASET LOCK respected** — no CVE/NVD/GHSA/OSV/KEV/EPSS data
anywhere (the only advisory-shaped strings in the repo are clearly-
synthetic test fixtures: `GHSA-test-0001`, `CVE-FAKE`, guard-shape
examples); no exec/spawn/eval/child_process in `apps/api/src/scans/sca/`
(0 matches); no npm/pip install anywhere in API src (0 matches); no
`randomUUID` in the SCA engine (deterministic ids only, 0 matches);
no `key in obj` patterns in the SCA parsers (own-property discipline);
the Pump 8 path policy is defined exactly once
(`SOURCE_PATH_PATTERN`) and reused by the SCA guards; `git status`
clean of secrets/datasets/junk after commit.

## Pump 10 — Real SECRETS engine, redaction by construction (VERIFIED, live E2E included)

**Pipeline:** `npm run verify` — 9/9 PASS (boundaries, secret matcher
self-test, secret scan sources + builds, typecheck, lint, tests,
production builds, dependency audit).

**Test totals:** shared 142 (+2 contracts), api 543 (incl.
`secretsRules` 21, `secretsEngine` 19, `secretsApi` 9), web 183
(incl. `secretsUi` 7), worker 28 — **896 total, 0 failed** (was 838).

### Live E2E (production build, `:4171`, fresh stores in `/tmp/pump10-e2e`)

Driver script + fixtures under `/tmp/pump10-e2e/` (synthetic values;
`.pem`/`.env` fixtures never committed to the repo).

1. Boot `NODE_ENV=production node apps/api/dist/index.js` → listening
   (`VULN_INTEL_PROVIDER=none`).
2. Register + login + project create → 201/200/201.
3. **SECRETS pre-flight quota protection**: SECRETS without a snapshot
   → `409 CONFLICT`, usage stays `used=0`.
4. Snapshot upload (6 files: AWS/GitHub keys, bearer+password, PEM
   pasted INTO code, api_key + credentialed db URL in yaml, docs
   examples with UUID/sha256/public-key/AWS-docs-key, ordinary code)
   → 200; `leak.pem` and `secrets.env` uploads → 422, snapshot intact.
5. **Scan 1 (SECRETS)**: QUEUED → COMPLETED — **exactly 7 findings**
   at the right lines with the right rules
   (`DG-SEC-002 ×2`, `-003`, `-004`, `-005`, `-006`, `-001`);
   `filesScanned 5` (docs `.md` skipped), not partial; confidence
   vocabulary in use: `{HIGH, MEDIUM, LOW}` (all rule-defined); PEM
   evidence is **exactly the header**; AWS evidence is
   `export const aws = "<redacted>";`.
6. **THREE-LAYER REDACTION SWEEP**: all six raw synthetic values
   (plus the PEM body) absent from the HTTP response AND the durable
   `scans.json`; server logs carry ids/counts only ("Scan completed",
   `findingsTotal: 7` — verified over the process log). The raw
   values exist ONLY in the 0600 `sources.json` scan-target store
   (the uploaded input, by design, gitignored).
7. **Idempotent replay** (same key) → 200, same scan id, usage
   unchanged (`used=1`).
8. **§30 no-fake snapshot** (UUID, sha256, `<YOUR_API_KEY>`,
   changeme, docs values): COMPLETED with **0 findings**,
   `filesScanned 3`, NO failure code — ANALYZED, not NOT_ASSESSED,
   never "risk unknown".
9. **Findings cap over HTTP**: 205 single-line matches → **200
   findings, `truncated: true`, `partial: true`**, reason mentions
   the cap — visible in the API summary and rendered by the web UI.
10. **FREE quota honesty**: 3rd scan consumes the last slot
    (`used=3, EXHAUSTED`); the 4th → 429.
11. **Cross-account isolation**: the attacker reading the owner's scan
    id inside their own project → the same 404 as an unknown id.
12. **Regressions**: SAST over the same adversarial snapshot →
    COMPLETED (its own rule family); SCA → COMPLETED; DAST → FAILED
    `SCAN_ENGINE_NOT_IMPLEMENTED` (still honest).
13. **Analyzed, never executed**: the uploaded
    `writeFileSync('/tmp/pump10-e2e/MARKER-EXECUTED')` — the marker
    DOES NOT EXIST after all scans.
14. **Restart durability**: SIGTERM → reboot on the same stores →
    fresh login → the SECRETS scan payload is **identical** (ids,
    findings, summary); quota continuity (`used=3, EXHAUSTED`); an
    extra scan still 429s; post-restart responses stay redacted.

E2E tally: 53/54 main-run assertions + 5/5 restart assertions; the
single main-run "FAIL" was a driver-script bug (livez asserted the
wrong envelope path; the endpoint itself returned
`200 {"ok":true,"data":{"status":"ok"}}`), fixed in the driver.

### §40 final repo-wide leakage audit

- `check-no-secrets` PASS over sources AND builds (372 files) — all
  secret-shaped fixtures are same-line-marked synthetic test values.
- Raw synthetic values: **0 occurrences** in non-test sources
  (`apps/*/src`, `packages/*/src`), **0** in the production web
  bundle, **0** in API responses, `scans.json` stores and server logs
  (asserted by suites + swept live above).
- Web: **no** `localStorage`/`sessionStorage` usage (only prohibition
  comments), **no** `console.*`, no URL/query/client state carrying
  findings; findings render as text (React escaping) — whole-DOM
  no-leak sweep is an executable test (`secretsUi.test.tsx`).
- API: no `console.*`; structured logging carries ids/counts only;
  the logger's deep redaction suite stays green.
- DATASET LOCK (extended): no external secret databases/feeds; the
  denylists are heuristic word lists, not vendored data.

### Final security gate — cross-account semantics (403 vs 404)

Investigated on request: the live E2E report showed 404s next to
"cross-account". Verification of the exact requests:

- **True cross-account access** (attacker → the OWNER's project, with
  a real scan id, on `GET /api/v1/projects/:projectId/scans/:scanId`
  and the list route) answers the **uniform 403 `FORBIDDEN`** —
  `ownProjectOr403()` runs BEFORE any scan lookup on every scan
  route, byte-identical to the unknown-project answer (no existence
  oracle). Proven live (production build) and by regression test
  `scanApi.test.ts` → *"cross-account scan DETAIL answers the SAME
  uniform 403 as unknown projects"* (foreign/unknown/malformed
  project + real scan id → identical 403; owner baseline 200).
- The E2E's 404s were **scan-id probing inside the attacker's OWN
  project**: after project ownership is verified, scan lookup is
  scoped to that project only, so unknown/malformed/foreign scan ids
  answer the same 404 — indistinguishable, hence oracle-free. This is
  the documented Pump 6/7 two-level IDOR contract
  (`docs/SECURITY.md`, `docs/SCANS.md`, route comments): project
  level = uniform 403, scan level inside one's own scope = uniform
  404.
- No product code changed: the implementation already ordered
  authorization before existence disclosure. Changes: one new
  regression test (API suite 543 → 544) and the E2E harness's
  stage 11 now asserts the true cross-account detail case (403 +
  FORBIDDEN + oracle-equivalence) alongside the scoped-404 cases
  (E2E: 64 main + 6 restart checks, all green).

## Pump 11 — bounded passive DAST foundation (2026-09-28)

### Scope delivered

- Added project-owner DAST target configuration, API validation, durable project storage, and a project UI that keeps DAST disabled until the server confirms the configured target.
- Registered the bounded passive DAST engine in the existing scan registry and lifecycle. DAST findings/observations use shared contracts, deterministic identities, redacted evidence, and the detail-only read surface; existing scan quota/idempotency paths remain authoritative.
- SSRF defenses cover canonical HTTP(S) URLs, local/private/reserved/metadata IP and hostname classes, all-address DNS validation, resolver timeouts, literal-IP checks, DNS revalidation and pinned transport addresses. Redirects are independently resolved, same-host, limited, and cannot downgrade HTTPS.
- Limits: GET only; at most 3 requests and 2 redirects; 32 KiB body per response; 5-second request timeout; 15-second DAST deadline. No browser, DOM/JavaScript execution, authentication, crawling, fuzzing, injection, exploit execution, or vulnerability-dataset matching.
- Documentation: `docs/DAST.md`, plus cumulative updates to scan/project/security/testing docs and README. No security datasets or imports were added.

### Verification — all gates passed

`npm run verify` completed **PASS** on 2026-09-28:

| Gate | Result |
| --- | --- |
| Scope/boundary checks (no DB/dataset/shell) | PASS |
| Secret matcher self-test + source/build scans | PASS; 395 files scanned in each secret scan |
| Typecheck (shared, API, worker, web) | PASS |
| ESLint | PASS |
| Full tests | PASS — 997 tests across 82 files (shared 158, API 625, worker 28, web 186) |
| Production builds | PASS — shared, API, worker, production Vite bundle |
| Dependency audit | PASS — 0 vulnerabilities |
| `git diff --check` | PASS |

DAST-specific coverage includes 57 target-policy cases, 9 engine cases, 7 passive-rule cases, 3 transport cases, 5 API lifecycle/persistence cases, 16 shared-contract cases, and 2 web UI cases. Existing SAST/SCA/Secrets and broader authz/quota/scan regressions passed in the full suite.

### Controlled fixture verification (honest classification)

- `apps/api/test/dastHttp.test.ts` uses an actual **loopback-only local HTTP server fixture** to verify the production Node transport's pinned-address lookup, one GET, absence of cookies/authorization, response cap, timeout and abort behavior. It bypasses target policy only for this local test object; production loopback/private rejection stays enabled.
- `apps/api/test/dastApi.test.ts` exercises authenticated target configuration, scan execution, persisted observations/findings and a durable restart using the test-only resolver and **synthetic transport response**. This is an API integration/persistence E2E, **not** a real network DAST scan.
- No arbitrary or public host was contacted; there was no public-target probe and no real DNS resolution in DAST fixtures.

## Verification evidence (Pump 12 — findings, reports, SBOM completion)

- Date: 2026-09-28
- `npm run verify`: **PASS** — all 9 gates green (scope boundaries,
  secret matcher self-test, source secret scan, typecheck, lint, full
  workspace tests, production builds, source/build secret scan, dependency
  audit).
- Test totals: **1,014 passed, 0 failed** across 88 files:
  - shared: 163 (14 files)
  - API: 633 (51 files)
  - worker: 28 (3 files)
  - web: 190 (20 files)
- Source/build secret scans: **PASS**, 417 files. Dependency audit:
  **0 package vulnerabilities**. Production builds: shared, API, worker,
  and Vite web bundle all PASS. No dataset or database scope was added.
- Controlled API E2E: `apps/api/test/reportsApi.test.ts` runs real HTTP
  authentication, project, upload, scan, findings and report routes against
  temporary durable JSON stores. It exercises SAST, SCA, SECRETS and DAST;
  deterministic local source and DAST fixtures; findings filtering,
  pagination, detail and validation; JSON and Markdown exports; redaction
  and inert Markdown; owner/account/project isolation; archived history;
  FREE quota exhaustion, PRO exemption and report quota neutrality; and
  API restart with persisted report/finding retrieval. DAST uses a
  test-controlled resolver and synthetic transport; no public or arbitrary
  target was contacted. Sessions intentionally require login again after
  process restart.
- `git diff --check`: PASS. This is unit/integration plus controlled local
  HTTP E2E evidence; it is not a public-target security assessment.

## Verification evidence (Pump 13 — production remediation + lifecycle)

- Date: 2026-09-28
- `npm run verify`: **PASS** — all 9 gates green after the final code
  changes (scope boundaries, secret matcher self-test, source secret scan,
  typecheck, lint, full tests, production builds, build secret scan, audit).
- Test totals: **1,024 passed, 0 failed** across 90 files:
  - shared: 164 (14 files)
  - API: 640 (53 files)
  - worker: 28 (3 files)
  - web: 192 (20 files)
- Secret scans: **PASS**, 426 files at both source and build stages.
  Dependency audit: **0 vulnerabilities**. Shared/API/worker and web
  production builds all passed. Focused API lifecycle/report and web
  workflow/report/client tests passed before the full run.
- Lifecycle/security coverage includes bounded persistent workflows and
  event history, notes validation/redaction, atomic scan observations,
  immutable scanner evidence, deterministic fingerprint reobservation and
  reopening, stale report snapshot rejection/retry, incomplete summary
  handling, project/account isolation, archived-project authorization,
  lifecycle transitions, quota neutrality, and report/UI redaction.
  Existing Pump 1–12 regression suites passed in the same full run.
- Controlled E2E is local only. `apps/api/test/reportsApi.test.ts` drives
  authenticated HTTP routes with temporary durable JSON stores through
  SAST, SCA, Secrets and DAST, report exports, isolation, quota, restart and
  redaction. DAST uses a test-controlled resolver and synthetic transport;
  no public or arbitrary host was contacted. No source is modified, no
  credential is verified/rotated, and no external vulnerability
  intelligence is claimed. SCA remains `NOT ASSESSED` where intelligence
  is unavailable. This is not a public-target security assessment.

## Verification evidence (Pump 14 — AI Security Assistant foundation)

- Date: 2026-09-28
- `npm run verify`: **PASS** — all 9 gates green: scope boundaries,
  secret matcher self-test, source secret scan, typecheck, lint, full tests,
  production builds, build secret scan, and dependency audit.
- Test totals: **1,039 passed, 0 failed** across 95 files:
  - shared: 167 (15 files)
  - API: 649 (56 files)
  - worker: 28 (3 files)
  - web: 195 (21 files)
- Source and build secret scans: **PASS**, 450 files scanned at each
  stage. Dependency audit: **0 vulnerabilities**. Shared, API, worker and
  production Web builds all passed. `git diff --check`: **PASS**.
- Focused assistant coverage includes strict shared request/response/status
  contracts, bounded context and redaction, prompt-like evidence treated as
  inert text, authenticated project-scoped status/ask endpoints, cross-account
  and foreign scan/finding/report ID isolation, deterministic finding and
  SCA explanations, `NOT ASSESSED` / `NO_DATA_LOADED` honesty, read-only
  lifecycle behavior, scan-quota neutrality, and text-only Web rendering.
- Local/synthetic only: API tests use ephemeral loopback servers and
  synthetic accounts, projects, SAST source, and package inventory. No
  public target or vulnerability dataset was used. No provider is active;
  unsupported generation stays unavailable, and chat history is not
  persisted. This is not a public-target security assessment.

## Verification evidence (Pump 15 — manual payment-review foundation)

Pump 16's current full verification includes the payment regression suites:
manual quote/request/state behavior, reviewer allowlist plus live `ADMIN`,
self-review denial, restart recovery, audit pagination and credential-like
reference masking. See `apps/api/test/paymentApi.test.ts`,
`apps/web/test/paymentUi.test.tsx`, and `docs/PAYMENTS.md`. No real payment,
gateway or payment proof was used. The current full-run totals and exact
check results are recorded below; this is not a separate E2E run.

## Verification evidence (Pump 16 — restricted platform operations)

- Date: 2026-09-29
- `npm run verify` result: **PASS** — all 9 verification stages passed:
  scope boundaries, secret matcher self-test, source scan, typecheck, lint,
  tests, production builds, post-build secret scan, dependency audit.
- Secret scan: PASS over 482 source files and again after builds (482 files).
- Typecheck: PASS for shared, API, worker and web workspaces.
- Lint: PASS.
- Tests: **1,091 passed, 0 failed** — shared 172, API 683, worker 28,
  web 208. These are unit, API integration and UI component tests; no
  browser end-to-end test was run.
- Manual local `curl` smoke using a synthetic disposable preview account:
  Web shell GET **200**, proxied login **200**, authenticated dashboard
  **200**; response reports `aiProvider: NONE` and
  `vulnerabilityDataset: NO_DATA_LOADED`. This is a smoke check, not E2E.
- Production builds: PASS for shared, API, worker and web.
- `npm audit --audit-level=high`: PASS, zero vulnerabilities reported.
- Pump 16-specific tests cover platform authorization (allowlist plus live
  role and role revocation), bounded/malformed pagination and filters,
  admin rate limiting, unavailable aggregate handling, status honesty,
  secret/source/evidence/fingerprint redaction, credential-like payment
  reference masking, payment-audit pagination/partial coverage, and
  read-only/denied UI states. Synthetic local fixtures only; no real
  payments, credentials, external targets or vulnerability datasets.
  See `docs/ADMIN.md`, `apps/api/test/adminApi.test.ts`,
  `packages/shared/test/admin.test.ts`, and
  `apps/web/test/adminOperationsUi.test.tsx`.

## Verification evidence (Pump 17 — Developer User Type completion)

- Date: 2026-09-29.
- `npm run verify`: **PASS**, all 9 gates: scope boundaries, secret matcher self-test, source secret scan, typecheck (shared/API/worker/web), ESLint, all workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,098 passed, 0 failed** — shared 172 (17 files), API 684 (59 files), worker 28 (3 files), Web 214 (24 files). This is the repository's full unit/integration/UI suite; no full browser automation was run.
- Secret scanning: PASS, 492 files in the source stage and again after builds. Production builds: PASS for shared, API, Worker, and Web (Vite bundle). `npm audit --audit-level=high`: PASS, 0 vulnerabilities.
- `apps/api/test/reportsApi.test.ts` is the controlled local Developer journey: synthetic Developer FREE registration and a seeded Developer PRO account, real HTTP login/project/source/scan/finding/report/assistant routes, all four existing scanners, lifecycle/note/history, report exports, persisted restart, ownership/IDOR isolation, FREE quota and PRO entitlement checks, and dashboard-summary redaction/status. DAST uses a test-controlled resolver and synthetic transport; no arbitrary/public target was contacted. The assistant provider is `NONE`; unsupported generation remains unavailable.
- `apps/api/test/workspaceApi.test.ts` verifies 401 behavior, non-Developer and Developer session-scoped summaries, foreign-project exclusion, extra query rejection, UserType/role/plan mass-assignment rejection, and strict shared response validation. The summary uses fixed caps (6 projects, 8 scans, 8 finding identities, 5 reports) and omits source/evidence/fingerprint/owner fields.
- `apps/web/test/authPages.test.tsx`, `authClient.test.ts`, and `workspaceDashboardUi.test.tsx` verify Developer registration/login routing, optional classification submission, direct-route UX for non-Developers, server-derived FREE and PRO views, Developer navigation, and non-exposure of MEMBER-level Admin/Pentest controls.
- Existing lifecycle/reverification, scan-recovery, SCA/SBOM, Secrets, passive DAST, report integrity/restart, assistant scope/prompt-injection/redaction, entitlement/quota, and broader security regressions all passed in the same full run. All new journey state is synthetic/local; no production database, vulnerability catalog/feed, real credential, or public target was used. Account enabled/disabled state is not modeled. This is not a production security assessment.
- Final `git diff --check`: **PASS**.
- Live preview smoke (2026-09-29): started the Web and API dev servers bound to `0.0.0.0` (`:5173` / `:3001`) with sandbox-only `ALLOWED_HOSTS=*`. `GET /` and `GET /dashboard` returned **200** with the SPA shell; same-origin proxied `GET /api/v1/status` returned **200**; unauthenticated `GET /api/v1/me/security-overview` returned **401 UNAUTHORIZED**. Dev hardening headers (`nosniff`, `DENY`, referrer/permissions/COOP/CORP) were present. The development server intentionally omits CSP for Vite HMR; strict CSP is covered by the production preview test. This was a route/proxy smoke, not authenticated browser E2E.

## Verification evidence (Pump 18 — Student workspace completion)

- Date: 2026-09-29.
- `npm run verify`: **PASS** — all 9 gates passed: scope boundaries, secret matcher self-test, source secret scan, shared/API/worker/Web typecheck, ESLint, all workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,106 passed, 0 failed** across 103 files — shared 172 (17 files), API 685 (59 files), worker 28 (3 files), Web 221 (24 files). The full run includes the Developer Pump 17 regression and earlier security/lifecycle suites. These are unit, API integration and UI component tests; no full browser automation was run.
- Secret scans: PASS, 493 files in the source stage and again after production builds (the source-stage scan includes existing ignored build output from the prior run). Shared, API, worker and Web production builds: PASS. `npm audit --audit-level=high`: PASS, zero vulnerabilities.
- Student API journey: `apps/api/test/reportsApi.test.ts` verifies Student FREE registration and quota exhaustion, shared-device denial across Student accounts, server-seeded Student PRO entitlement, rejection of client role/plan/owner claims, own project/source, SAST/SCA/SBOM/Secrets/bounded passive DAST, finding evidence and guidance, lifecycle/history/reopen/rescan and honest `NOT_OBSERVED_IN_LATEST_SCAN`, JSON/Markdown report digests and restart persistence, project-scoped deterministic assistant/provider-unavailable behavior, cross-account resource isolation and archive lifecycle. The Student journey uses synthetic local fixtures and injected DAST resolver/transport only; no public or arbitrary host was contacted.
- Student Web coverage verifies registration/login/existing-session routing, dashboard/progress/history and shared workflow links, non-Student direct-route UX, role-backed privileged navigation, and Developer regression. The route/proxy and visual experience still require the separate live-preview smoke below; no browser E2E is claimed.
- Boundaries remain unchanged: no PostgreSQL/production database or real/bundled vulnerability dataset; SCA without intelligence is `NOT_ASSESSED` / `NO_DATA_LOADED`; provider state is `NONE`; no fake findings, scores, fixes, credential verification or AI output. This is not a production security assessment.


## Verification evidence (Pump 19 — Security Professional workspace completion)

- Date: 2026-09-29.
- `npm run verify`: **PASS** — all 9 gates passed: scope boundaries, secret matcher self-test, source secret scan, typecheck, ESLint, all workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,115 passed, 0 failed** across 103 files — shared 172 (17 files), API 687 (59 files), worker 28 (3 files), Web 228 (24 files). This includes Developer/Student journeys and historical security regressions. No full browser automation was run.
- Secret scan: PASS, 494 files at the source stage and 494 after production builds. Shared/API/worker/Web production builds: PASS. `npm audit --audit-level=high`: PASS, zero vulnerabilities.
- Security Professional UI coverage verifies classification selection, registration/login/existing-session routing, dashboard labels and links, server-backed bounded overview display, DAST observation and SCA `NOT_ASSESSED` / `NO_DATA_LOADED` metadata, and role—not UserType—privileged navigation. These are component/route tests.
- Controlled Professional API journey in `apps/api/test/reportsApi.test.ts`: synthetic Professional FREE registration, 3-scan quota and exhausted denial, same-device cross-account denial, seeded PRO Professional entitlement, client role/plan/entitlement tampering, all four existing scanner engines, finding evidence/guidance, lifecycle/note/history/reopen/retest, honest clean-scan `NOT_OBSERVED_IN_LATEST_SCAN`, reports and restart persistence, account/project isolation, and deterministic Professional assistant questions. API journey uses temporary JSON stores and injected DAST fixtures; no public/arbitrary target was contacted.
- Assistant coverage verifies assessment summaries, unresolved workflow and project-wide verification summaries (including a previously observed finding after a clean retest), DAST observation descriptions, attention items, SBOM/intelligence state, finding evidence/remediation and unsupported-question behavior from persisted records only. Evidence references remain project-scoped and bounded. Provider remains `NONE`; no LLM output, security score, fix claim or unsupported intelligence is fabricated.
- Boundaries remain unchanged: no PostgreSQL/production database or real/bundled vulnerability/security dataset; SCA without data remains `NOT_ASSESSED` / `NO_DATA_LOADED`; account enabled/disabled state is not modeled. This is not a public-target security assessment.
- Route/proxy smoke (2026-09-29): started the Web/API development servers on `0.0.0.0` with sandbox-only `ALLOWED_HOSTS=*` and in-memory stores. `GET /`, `/login`, and `/security-professional/dashboard` each returned **200** SPA responses; same-origin proxied `GET /api/v1/status` returned **200**; unauthenticated proxied `GET /api/v1/me/security-overview` returned **401** with the normal API security headers. The servers were stopped after the smoke. This verifies route fallback and proxy reachability only—not an authenticated browser journey or browser E2E.

## Verification evidence (Pump 20 — Pentester user type)

- Date: 2026-09-29.
- `npm run verify`: **PASS** — all 9 gates passed: scope boundaries, secret matcher self-test, source secret scan, shared/API/worker/Web typecheck, ESLint, all workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,121 passed, 0 failed** across 103 files: shared 172 (17), API 688 (59), worker 28 (3), Web 233 (24). The full run includes all prior Developer, Student, Security Professional and security regression suites; no browser E2E was run.
- Secret scans: PASS, 494 files at the source stage and 494 after production builds (the prior production output was present during this repeat run). Shared/API/worker/Web builds: PASS. `npm audit --audit-level=high`: PASS, zero vulnerabilities.
- Pentester API journey in `apps/api/test/reportsApi.test.ts` uses temporary JSON stores and controlled DNS/transport fixtures. It verifies session registration and classification, role/plan/target-authorization request tampering rejection, owner-configured DAST target, GET-only observations/findings, finding evidence/lifecycle/history and retest, deterministic project-scoped assistant response with provider state `NONE`, DAST report persistence, cross-account project/scan/target isolation, FREE three-scan quota and exhaustion, seeded PRO entitlement/exemption, and restart-persisted overview, findings and reports. No public/arbitrary target or real model provider was contacted.
- `apps/api/test/workspaceApi.test.ts` verifies exact owner-derived configured-target indicators/count, cross-account omission and strict contract rejection for invalid counts/flags. Web tests verify Pentester registration/login/existing-session routing, classification-only dashboard guard, server-backed target presentation and links while retaining Developer/Student/Professional UI regressions.
- Safety boundaries remain: UserType is classification only; target indicators do not prove legal authorization. Existing DAST DNS/SSRF/redirect/transport controls, project ownership, FREE/PRO plan separation, quota/device anti-abuse, entitlements, rate limits, assistant scope/redaction/prompt-injection behavior, reports and scan lifecycle regressions passed. No PostgreSQL/production database, bundled security dataset, active exploitation, fabricated finding/fix/score, or unsupported LLM output was introduced.
- Live development-preview route/proxy smoke (2026-09-29): started Web and API dev servers bound to `0.0.0.0` with sandbox-only `ALLOWED_HOSTS=*` and in-memory stores. `/`, `/login`, `/register` and `/pentester/dashboard` each returned **200** SPA responses; same-origin proxied `/api/v1/status` returned **200**; anonymous `/api/v1/me/security-overview` returned the expected **401**. The Pentester route is present, but this is route fallback/proxy reachability only—not authenticated browser E2E. The preview server remains running for inspection.

## Verification evidence (Pump 21 — independent UserType capability audit)

- Date: 2026-09-29.
- `npm ci`: completed from the checked-in lockfile; dependency audit reported zero vulnerabilities.
- `npm run verify`: **PASS** — all 9 gates passed: scope boundaries, secret matcher self-test, source secret scan, typecheck (shared/API/worker/web), ESLint, full workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,122 passed, 0 failed** across 103 files — shared 172 (17 files), API 688 (59 files), worker 28 (3 files), Web 234 (24 files). This includes the four controlled profile HTTP journeys in `apps/api/test/reportsApi.test.ts` and all cumulative Pumps 1–20 regression suites.
- Secret scan: PASS over 495 files at the source stage and 495 files including production build output. Shared/API/worker/Web builds: PASS. `npm audit --audit-level=high`: PASS, zero vulnerabilities. `git diff --check`: PASS after the documentation updates.
- Focused Pentester/DAST UI regression: `npm run test --workspace @drobon/web -- test/workspaceDashboardUi.test.tsx test/dastUi.test.tsx` — 15 passed across two suites, including the explicit `UNVERIFIED` target-permission label and fallback to `/projects` when a configured target is outside the fixed-cap recent-project slice.
- The four profile journeys use real local HTTP/API routes, temporary JSON stores and controlled scanner/DAST fixtures. DAST tests use the synthetic resolver/transport or a controlled loopback-only transport fixture; no arbitrary/public target was contacted. The journeys are API integration E2E, not browser E2E. Web route/dashboard tests are React Testing Library component/route tests. The production preview-header suite checks static serving, headers and SPA fallback, not an authenticated browser workflow. No manual authenticated route/proxy journey or browser E2E was performed in Pump 21.
- Audit outcome: existing shared project/scan/finding/remediation/report workflows already served all four UserTypes; no duplicate engine/store or profile-based server privilege was added. Corrected Pentester dashboard labels from “authorized” to “configured” and ensured bounded overview data cannot route a target shortcut to an unrelated active project. The project target UI explicitly shows `UNVERIFIED`; no client authorization claim or legal-permission proof was introduced.
- Honest remaining limits: no independent third-party engagement verification or structured scope object; no Git/CI integration, course/grade system, production database/separate worker deployment, account enable/disable state, generative assistant provider/history, or loaded SCA intelligence. SCA remains `NOT_ASSESSED` / `NO_DATA_LOADED`; assistant provider remains `NONE`. No public-target, active-exploitation, external credential verification, or fabricated finding/fix/score/output activity occurred.
- This test evidence is not a security certification or production readiness assessment. The exact local/remote SHA, active branch and final worktree status are reported in the completion summary; the commit cannot embed its own hash.


## Verification evidence (Pump 22 — structured owner/project assessments)

- Date: 2026-09-29.
- `npm ci`: **PASS** from the checked-in lockfile; 341 packages installed, 0 vulnerabilities reported by the install audit.
- `npm run verify`: **PASS**, all 9 gates: scope boundaries, secret matcher self-test, source secret scan, typecheck (shared/API/worker/web), ESLint, all workspace tests, production builds, post-build secret scan, and dependency audit.
- Tests: **1,131 passed, 0 failed across 106 files** — shared 175 (18 files), API 691 (60 files), Worker 28 (3 files), Web 237 (25 files). This includes the new assessment contracts/API/UI plus all existing Developer, Student, Security Professional, Pentester, scanner, ownership, quota, lifecycle and report regressions.
- Secret scans: PASS over 510 files at the source stage and 510 files including production build output (the prior build output was present at the start of the final repeat run). Lint and all workspace typechecks/production builds passed. `npm audit --audit-level=high`: PASS, 0 vulnerabilities.
- Focused API regression: `assessmentsApi.test.ts`, `config.test.ts`, `scanApi.test.ts`, `dastApi.test.ts`, `dastTarget.test.ts`, `authzMatrix.test.ts`, `authzOwnership.test.ts`, `authzSecurity.test.ts`, `usageQuota.test.ts`, and `reportsApi.test.ts` — **170 passed across 10 files**. Shared assessment contracts: **3 passed**; Web assessment UI component tests: **3 passed**.
- `apps/api/test/assessmentsApi.test.ts` exercises real local HTTP ownership/authentication, malformed and foreign IDs, forged body fields, bounded exact-host scope, active-scope immutability, lifecycle/idempotency/stale-state checks, linked passive DAST/report association, user-declaration/withdrawal history (never proof), active-scan and FREE-quota closure guards, mismatched replay, archived state and JSON restart persistence. DAST is test-injected; no public target is contacted. `reportsApi.test.ts` independently retains the four-profile FREE/PRO shared-platform regression.
- Controlled live-preview/proxy smoke: `GET /`, `/security-professional/dashboard`, and `/projects/demo` returned **200** SPA responses; proxied `GET /api/v1/status` returned **200**; anonymous project assessment-list returned **401 UNAUTHORIZED**. A synthetic local Professional registration/login then created a project, uploaded a safe source constant, created and activated an assessment, created a linked SAST scan (**201**, response carried the assessment ID), and read assessment detail (**200**, one linked scan). Servers were bound to `0.0.0.0` on Web `:5173` and API `:3031`; wildcard host allowance and `:memory:` stores were used only for this disposable sandbox preview. No public target/DAST request was made.
- Route/proxy smoke verified; browser E2E runner unavailable. The local HTTP journey, Vite SPA fallback and React component tests do not constitute browser E2E. The live preview process is available for inspection while this session remains active.
- Product boundaries remain: assessment scope is metadata, not project/target/DAST permission; a target declaration is only `USER_DECLARED`/`UNVERIFIED`, never independently verified; existing passive DAST policy and FREE/PRO entitlement/quota are unchanged. No real/bundled vulnerability dataset, PostgreSQL, arbitrary target scan, active exploitation, or provider-backed Git/CI/course/grade integration was added.
- This is test/route evidence, not a security certification or production readiness assessment. Commit and remote SHA verification are reported separately after repository synchronization.

## Verification evidence (MAIN APP Pump 17 — CI/CD and engineering security)

This is **Main App Pump 17**, separate from the Developer/UserType Pump 17 entry above and UserType Pumps 18–22. It adds release/verification automation without replacing product or scanner functionality.

- Date: 2026-09-29.
- Clean locked install: `npm ci --ignore-scripts --no-audit --no-fund` **PASS** (341 packages installed). The separate full `npm audit --audit-level=high` gate remains authoritative.
- `npm run verify`: **PASS**, all 11 required gates: scope boundaries; repository/lock/workspace/credential/dataset/CI integrity; release-evidence self-test; secret-matcher self-test; source secret scan; strict typechecks; ESLint; complete workspace tests; shared/API/worker/Web production builds; post-build secret scan; npm audit. No gate is warn-and-pass.
- Tests: **1,131 passed, 0 failed across 106 files** — shared 175 (18 files), API 691 (60 files), worker 28 (3 files), Web 237 (25 files). The API suite includes the four controlled UserType account journeys and regressions for auth/ownership, plan/quota/device limits, all scan engines, findings/remediation, reports, assistant, payments, admin/operations and assessments. These are local synthetic-fixture tests; they do not contact a public target or use production credentials.
- Both secret scans passed over 513 files (sources and current build outputs). All four production builds passed. `npm audit --audit-level=high`: **0 vulnerabilities**. The repository-integrity and release-evidence policy self-tests passed; the CI YAML parsed locally and the static checks confirmed full-SHA action pins, read-only permissions, no privileged PR trigger/secrets/deployment, and verification-before-artifact ordering.
- Release evidence is generated only by the post-verification GitHub Actions job: it binds the manifest to the exact workflow SHA and version, hashes the lockfile and every payload file, compares two clean builds, and uploads an unsigned, 14-day artifact. No signing, certificate, signed attestation/provenance, tag/release creation, or deployment is claimed. The remote workflow result/artifact is reported separately after the push.
- Product security boundaries are unchanged: no vulnerability catalog/data is imported, downloaded, bundled or required. SCA remains `NO_DATA_LOADED` / `NOT_ASSESSED`; UserType is classification only; existing auth, ownership, entitlement, quota, rate-limit, payment, admin, SSRF/DAST and legal-authorization constraints remain in force.
- Browser E2E is **not claimed**: the Web suite covers component/route behavior and its production-preview test, but no real browser automation runner is configured. Local HTTP/API integration E2E and manual preview/API smoke are reported separately.
- GitHub branch protection/required checks remain owner-managed settings; workflow YAML does not assert that those external settings are active. Production deployment remains deferred.

## Verification evidence (Forensic baseline + core application upgrade)

- Date: 2026-09-29.
- `npm run verify`: **PASS**, all 11 required gates: scope boundaries; repository integrity; release-evidence self-test; secret-matcher self-test; source secret scan; strict typechecks; ESLint; complete workspace tests; shared/API/worker/Web production builds; post-build secret scan; npm audit.
- Tests: **1,139 passed, 0 failed across 106 files** — shared 175 (18 files), API 691 (60 files), worker 28 (3 files), Web 245 (25 files).
- Core application and preview upgrades verified:
  - `PUT` and `DELETE /api/v1/projects/:projectId/dast-target` now enforce `409 PROJECT_ARCHIVED` on archived projects (`apps/api/src/routes/projects.ts`, `apps/api/test/dastApi.test.ts`), and `DastTargetSection` in `apps/web/src/pages/ProjectDetailPage.tsx` renders read-only `archived-dast-target-note` when a project is archived (`apps/web/test/dastUi.test.tsx`).
  - `shouldRewriteToIndex` in `apps/web/vite-plugin-aegis.ts` excludes `/api`, `/api/*`, `/livez`, and `/readyz`, `apps/web/vite.config.ts` shares the `/api`, `/livez`, `/readyz` same-origin proxy across `server` and `preview`, and `allowFrameEmbedding` is enabled only when `ALLOWED_HOSTS=*` in the sandbox preview while preserving default `X-Frame-Options: DENY` and `frame-ancestors 'none'` (`apps/web/test/plugin.test.ts`, `apps/web/test/previewHeaders.test.ts`).
  - `ProjectDetailPage.tsx` now renders the uploaded file list (`snapshot-file-list`), supports inline relative-path text source uploads alongside file-input uploads (`apps/web/test/sastUi.test.tsx`), automatically polls active (`QUEUED`/`RUNNING`) scans until completion, and synchronizes completed scans with `AssistantSection`.
- Dataset and database separation locks remain enforced: SCA remains `NO_DATA_LOADED` / `NOT_ASSESSED` (`vulnIntelProvider: 'none'`), assistant remains deterministic (`providerState: 'NONE'`), and persistence uses the existing atomic JSON stores.

## Verification evidence (Account, authentication, authorization, and security hardening)

- Date: 2026-09-29.
- `npm run verify`: **PASS**, all 11 required gates: scope boundaries; repository integrity; release-evidence self-test; secret-matcher self-test; source secret scan; strict typechecks; ESLint; complete workspace tests; shared/API/worker/Web production builds; post-build secret scan; npm audit.
- Tests: **1,149 passed, 0 failed across 106 files** — shared 175 (18 files), API 701 (60 files), worker 28 (3 files), Web 245 (25 files).
- Account, Authentication, Authorization, and Security Hardening verified:
  - **Session rotation & cookie deduplication**: `POST /api/v1/auth/register` and `POST /api/v1/auth/login` now revoke any prior `drobon_session` token sent on the request before issuing a new session (`apps/api/src/routes/auth.ts`), and `sendJson` deduplicates `Set-Cookie` headers by cookie name when an authoritative cookie is set (`apps/api/src/respond.ts`, `apps/api/test/authSecurity.test.ts`).
  - **CSRF Origin & Referer hardening**: `originGuardMiddleware` now requires `normalizeOrigin(origin)` to succeed (`http:`/`https:`, no credentials/path) before the same-host check runs, and validates `Referer` origin via `extractRefererOrigin` when `Origin` is absent on unsafe methods (`apps/api/src/lib/security.ts`, `apps/api/src/middleware/originGuard.ts`, `apps/api/test/security.test.ts`, `apps/api/test/authSecurity.test.ts`).
  - **CORS preflight header alignment**: `ALLOW_HEADERS` in `apps/api/src/middleware/cors.ts` now includes `Idempotency-Key` alongside `Content-Type` and `X-Request-Id` (`apps/api/test/cors.test.ts`).
  - **Strict query, path, and body validation**: `/api/v1/auth/register`, `/api/v1/auth/login`, `/api/v1/auth/logout`, and `/api/v1/me` reject unexpected query parameters and non-empty logout bodies (`apps/api/src/routes/auth.ts`); `GET /api/v1/users` rejects repeated (`?id=a&id=b` HPP) or unexpected query parameters (`apps/api/src/routes/authz.ts`, `apps/api/test/authzOwnership.test.ts`); and payment/admin-payment routes enforce `/^pay_[0-9a-f-]{36}$/i` path validation and reject unexpected query parameters (`apps/api/src/routes/payments.ts`, `apps/api/test/paymentApi.test.ts`).
- Live security verification against the running preview server (`http://127.0.0.1:5173` proxied to `127.0.0.1:3001`) confirmed API health (`200`), Web availability (`200`), login + session rotation (old session `401`, new session `200`), unauthenticated rejection (`401`), cross-account isolation (`403`/`404`), `PENTESTER` UserType non-privilege (`role: 'MEMBER'`, `plan: 'FREE'`, `limit: 3`, admin endpoints `403`), concurrent FREE quota enforcement (`3` `200`, `7` `429`), and CSRF Origin/Referer + HPP/logout body rejection (`403`/`422`).
- Database/production data and security dataset separation remain intact: zero database schemas/migrations/seeds and zero CVE/NVD/GHSA/OSV/KEV/EPSS/exploit datasets (`NO_DATA_LOADED` / `NOT_ASSESSED`).
