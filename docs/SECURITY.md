# Security

Pump 1 established, Pump 2 extended (authentication), Pump 3 extended
(authorization), Pump 4 extended (plans/subscriptions/entitlements),
Pump 5 extended (usage quota + device anti-abuse), Pump 6 extended
(projects foundation), Pump 7 extended (secure scan-job foundation):
security is a first-class, **tested** requirement. A control is listed as
VERIFIED only if an automated test or an executed check proves it;
anything else is marked IMPLEMENTED, PLANNED or NOT_IMPLEMENTED.

## Threat model (foundation + auth + authz + subscription + usage + projects + scans stage)

In scope: Internet clients talking to the API/Web over HTTP; credential
attacks (stuffing, enumeration, brute force); session hijack/CSRF/XSS
against the cookie session; privilege escalation (vertical: MEMBER→ADMIN→
OWNER; horizontal: cross-account IDOR); role tampering via client input;
commercial entitlement fraud (forging PRO via body/query/header/cookie
tampering, client state, UserType or AccountRole; degrading or reading
another account's subscription); **quota abuse (multi-account farming of
the FREE scan allowance, racing concurrent consumes, forging/altering the
device cookie, tampering with usage counts or periods)**; **project
ownership fraud (claiming another account's project via ownerId/headers/
query, cross-account reads/writes, injecting lifecycle status,
prototype-pollution payloads, XSS/HTML in project text)**; **scan fraud
(quota bypass via concurrency/retries/multiple projects/types, forging
scan status or results, claiming another account's scans, replaying
idempotency keys, resurrecting or double-executing jobs)**;
misconfiguration;
secret leakage into code, logs or the browser bundle; dependency risk;
abuse/accidental overload of a single instance.

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

### Usage quota & device anti-abuse (Pump 5)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| FREE allowance (3 scans/UTC month) enforced by a single server-side consumption authority; routes contain no duplicate quota logic | VERIFIED | `apps/api/test/usageQuota.test.ts`, `usageApi.test.ts` |
| Atomic consumption: serialized check-both-limits → increment → persist; 10 concurrent consumes → exactly 3 grants + 7 denials (memory store, durable store, and two accounts racing on one device token) | VERIFIED | `apps/api/test/usageQuota.test.ts` |
| Denials mutate nothing (no counter, device, period or subscription changes) and carry a stable `QUOTA_EXCEEDED` code + `Retry-After` | VERIFIED | `apps/api/test/usageApi.test.ts` |
| PRO exemption only via the Pump 4 entitlement pipeline (PRO + ACTIVE); ADMIN/ACCOUNT_OWNER/UserTypes never exempt; lapsed PRO falls back to FREE | VERIFIED | `apps/api/test/usageApi.test.ts`, `usageQuota.test.ts` |
| PRO consumption never counts against the shared FREE device allowance | VERIFIED | `apps/api/test/usageQuota.test.ts` |
| UTC month rollover is natural (lazy period keys) — September never reduces October, Dec→Jan tested, clock injection supported | VERIFIED | `apps/api/test/usageQuota.test.ts` |
| Usage counters survive API restart (durable JSON store, atomic writes; corrupt documents refuse to start) | VERIFIED | `apps/api/test/usageQuota.test.ts` |
| Device identity: opaque 32-byte base64url server-issued cookie (`HttpOnly`, `SameSite=Strict`, `Secure` in production, ~400d); only a SHA-256 hash is stored; token/hash never logged or returned | VERIFIED | `apps/api/test/usageDevice.test.ts`, `usageApi.test.ts` (captured-log scan) |
| Malformed/missing device cookies are ignored and replaced; shape-valid client-forged tokens are treated as unknown devices (no trust, no crash) | VERIFIED | `apps/api/test/usageDevice.test.ts` |
| Cookie rotation cannot bypass the quota: the ACCOUNT allowance binds on every device | VERIFIED | `apps/api/test/usageDevice.test.ts` |
| `GET /api/v1/usage`: self-only (no id parameter exists), 401 anonymous, 405 for mutation methods, no device hash/other accounts' data in any response | VERIFIED | `apps/api/test/usageApi.test.ts` |
| Production protection: the consume probe is not registered in production (404); `USAGE_STORE_PATH=:memory:` rejected in production | VERIFIED | `apps/api/test/usageApi.test.ts`, `config.test.ts` |
| Client tampering (headers, cookies, query, body fields, localStorage) never changes usage or exemption decisions; exact body validation rejects any property | VERIFIED | `apps/api/test/usageApi.test.ts`, `usageDevice.test.ts` |
| Web: usage section display-only (client exposes exactly one usage method, `getUsage`), numbers rendered exclusively from the server response, errors fail closed | VERIFIED | `apps/web/test/usageUi.test.tsx`, `authClient.test.ts` |

Known, documented limits (see `docs/USAGE.md`): cookie rotation starts a
fresh DEVICE identity (backstopped by the account quota, credential rate
limits, and the hashed opaque cookie — no fingerprinting is used);
honest users sharing a browser share the device allowance.

### Projects foundation (Pump 6)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Ownership from the authenticated session only; body `ownerId`/`status`/`id`/timestamps are unknown properties → 422 (mass-assignment impossible) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Cross-account GET/PATCH/archive answer the SAME uniform 403 as unknown/malformed/oversized ids — no existence oracle, no IDOR | VERIFIED | `apps/api/test/projectApi.test.ts` |
| AccountRole never grants project ownership (ADMIN, ACCOUNT_OWNER × cross-account all 403) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| UserType never grants project ownership (all four classifications tested cross-account) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| List is server-scoped to the caller; a foreign project never appears in another account's list (no frontend filtering relied upon) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Anonymous access to every project route → 401; forged and expired sessions → 401 | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Strict input validation: empty/whitespace/oversized names, oversized descriptions, control characters, malformed JSON, non-object bodies (415/400/422) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Prototype pollution: `__proto__`/`constructor` payloads rejected (includes the Pump 6 audit fix to the Pump 1 validator — see below) and never merged | VERIFIED | `apps/api/test/projectApi.test.ts`, `apps/api/test/validate.test.ts` |
| XSS/HTML payloads stored as inert text and rendered as text (React escaping; no dangerous HTML API anywhere in web src) | VERIFIED | `apps/api/test/projectApi.test.ts`, `apps/web/test/projectUi.test.tsx`, `staticWeb.test.ts` |
| NFC Unicode normalization + bounded lengths for all project text | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Ids: `prj_` + `crypto.randomUUID()` (never counters); responses never expose `ownerId` or storage paths | VERIFIED | `packages/shared/test/projects.test.ts`, `apps/api/test/projectApi.test.ts` |
| Deterministic ordering (updatedAt DESC, then id ASC) verified against an independent reimplementation | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Lifecycle: creation always ACTIVE; status changes ONLY via explicit owner-only archive/unarchive (idempotent); generic PATCH cannot touch status; archived projects stay listed/readable; NO hard delete | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Persistence: atomic temp+rename writes (0600), serialized mutations, 20 concurrent creates lose/duplicate nothing, corrupt store refuses to start, restart persistence (incl. the E2E-found multi-line-description load-validation mismatch, fixed + regression-tested) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Usage boundary: project CRUD never calls the usage service (scan counter untouched after full CRUD cycle) | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Log hygiene: project logs carry requestId/userId/projectId only — never names, descriptions, emails | VERIFIED | `apps/api/test/projectApi.test.ts` |
| Web: protected routes (anonymous → login redirect), fail-closed list/detail errors, no project/ownership state in localStorage/sessionStorage/URL, edit form has no ownership/status fields at all | VERIFIED | `apps/web/test/projectUi.test.tsx` |

**Pump 6 audit fix to Pump 1 code**: the strict validator's unknown-key
check used `key in shape`, which the well-known prototype-chain keys
(`__proto__`, `constructor`) always satisfy — so those two field names
were silently DROPPED instead of rejected with 422 (values were never
merged, so no prototype pollution occurred, but the documented
"unknown keys rejected" contract had a bypass). Fixed to
`Object.prototype.hasOwnProperty.call(shape, key)` with a regression
test in `apps/api/test/validate.test.ts`.

### Scan jobs (Pump 7)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Ownership chain account→project→scan derived from the session ONLY; body `id`/`projectId`/`ownerId`/`requestedBy`/`status`/timestamps/`result`/plan/role claims are unknown properties → 422 | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Project-level uniform 403 (unknown/foreign/malformed/oversized ids byte-identical modulo requestId) on every scan route; AccountRole and UserType never grant foreign scans | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Scan-level uniform 404 inside the caller's own project — cross-account scan-id probing cannot distinguish existence | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Quota consumed EXACTLY once per created scan, atomically with the durable append (UsageService = single authority inside the store's serialized section); no job without a consumed allowance is constructible | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Concurrency: 10 simultaneous FREE creates → exactly 3 grants + 7 uniform 429+Retry-After; same-key 10-way retry storm → 1 scan, 1 consumption; cross-project/cross-account/device-shared races; PRO concurrent never denied | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Tampering (plan/role/entitlement headers, cookies, body claims) never changes the quota verdict | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Idempotency keys: strict format, account-scoped, replay returns the original scan without a second charge, different-request reuse → 409, bounded memory, restart-persistent | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Exactly ONE server-authoritative transition path; NO client mutation endpoint (405 + Allow); claim-once/finish-once — duplicate worker delivery cannot execute a job twice; terminal scans are immutable | VERIFIED | `apps/api/test/scanApi.test.ts` |
| No engine registered → deterministic FAILED/SCAN_ENGINE_NOT_IMPLEMENTED, never a fabricated completion or findings; crashed engines fail closed with generic messages (no internals leak) | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Startup recovery: interrupted RUNNING scans → FAILED/SCAN_INTERRUPTED; QUEUED scans drain; the process never boots with ambiguous scan state | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Archived projects reject new scans (409 PROJECT_ARCHIVED — reachable only for owned projects); history stays readable; no scan deletion exists | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Persistence: atomic temp+rename 0600 writes, serialized mutations, corrupt/invalid state refuses to start (incl. state-machine violations and dangling idempotency entries), restart persistence with quota/idempotency continuity | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Responses expose the public scan shape only — no ownerId, no worker internals, no filesystem paths, no stack traces | VERIFIED | `apps/api/test/scanApi.test.ts`, `packages/shared/test/scans.test.ts` |
| Log hygiene: scan lines carry requestId/userId/projectId/scanId only — no emails, passwords or device material | VERIFIED | `apps/api/test/scanApi.test.ts` |
| Web: honest FAILED rendering (never a fake completion), server-derived quota hint, archived restriction, XSS-inert scan text, no storage authority, fail-closed errors | VERIFIED | `apps/web/test/scanUi.test.tsx` |
| Dataset lock: no CVE/NVD/GHSA/OSV/KEV/EPSS data anywhere; synthetic engines exist only in tests | VERIFIED | `check:boundaries`, `check:secrets` |

### Static analysis — SAST engine (Pump 8)

| Control | Status | Evidence |
| ------- | ------ | -------- |
| Analysis only: source snapshots are read and regex-matched, NEVER executed/imported/sandboxed — `exec('touch /tmp/…')` in uploaded code is REPORTED (DG-SAST-001), never run (marker file absent after scans) | VERIFIED | `apps/api/test/sastEngine.test.ts`, `apps/api/test/sastApi.test.ts` |
| Bounded work: 200 files / 256 KiB file / 1 MiB total / 200 findings / 10 s processing deadline / 10 000 lines per file; every limit breach fails closed with a closed code | VERIFIED | `apps/api/test/sastEngine.test.ts` |
| Linear-time rules only (ReDoS-shaped patterns rejected by the rule suite); whole-corpus timing pinned | VERIFIED | `apps/api/test/sastRules.test.ts` |
| Deterministic findings (content fingerprints → stable ids; identical rescans yield identical ids) ordered most-severe-first; severities rule-fixed, never client-influenced | VERIFIED | `apps/api/test/sastEngine.test.ts`, `apps/api/test/sastApi.test.ts` |
| Evidence discipline: ≤ 200-char windowed, control-character-free (no CRLF/tab/NUL), credential values redacted BEFORE persistence (length-neutral) | VERIFIED | `apps/api/test/sastEngine.test.ts` |
| No content exfiltration: sources read API returns metadata only; logs carry counts/ids, never content or secret values | VERIFIED | `apps/api/test/sastApi.test.ts` |
| Snapshot upload policy: single server-side path policy (no traversal/absolute/dotfiles, len/seg/depth caps), blocked key-material extensions (.env/.pem/.key/...), binary rejection, duplicate/unknown/proto-key rejection → 422/413 with nothing stored | VERIFIED | `apps/api/test/sastApi.test.ts` |
| SAST pre-flight: no snapshot → 409 BEFORE quota consumption (a FREE account cannot burn allowance on an impossible scan) | VERIFIED | `apps/api/test/sastApi.test.ts` |
| Findings persist only with the terminal COMPLETED transition (atomic); findings on any other state = corrupt store → refuses to start; the detail route is the only findings read surface | VERIFIED | `apps/api/test/sastApi.test.ts` |
| Snapshot/scan ownership: snapshot is project-scoped, owner-checked at scan time; cross-account answers stay uniform (403/404 — no oracle) | VERIFIED | `apps/api/test/sastApi.test.ts` |
| Corrupt/poisoned stores (invalid JSON, traversal-shaped stored paths, findings injected into non-terminal records) refuse to start — no silent repair | VERIFIED | `apps/api/test/sastApi.test.ts` |
| Web: findings render as literal text (injection payloads displayed, never executed), secrets stay redacted client-side, lazy detail loading, archived projects cannot replace snapshots | VERIFIED | `apps/web/test/sastUi.test.tsx` |
| Static safety: no eval/Function/child_process surface in engine code; rules are pure data (the forbidden-pattern scan exempts nothing by suppression — rules.ts patterns are data, not matchers) | VERIFIED | `apps/api/test/staticSafety.test.ts` |

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
`docs/SUBSCRIPTIONS.md`), per-feature metering beyond the single scan
allowance, usage analytics/history, operator quota adjustments,
device-management UI (the usage quota + device foundation itself is DONE
in Pump 5 — see `docs/USAGE.md`), project deletion (hard delete is
deliberately absent — ARCHIVED is the lifecycle end-state; the projects
foundation itself is DONE in Pump 6 — see `docs/PROJECTS.md`),
project sharing/collaboration, admin/operator project visibility,
scan cancellation (deliberately absent until explicitly designed —
the scan-job foundation itself is DONE in Pump 7 — see
`docs/SCANS.md`), the remaining engines SCA/SECRETS/DAST and
findings-aggregation reports (the REAL SAST engine is DONE in Pump 8 —
see `docs/SAST.md`; source "upload" is a JSON-body snapshot, NOT
multipart file storage), admin/operator scan
visibility,
account email
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
