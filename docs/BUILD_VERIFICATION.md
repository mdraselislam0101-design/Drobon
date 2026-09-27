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
