# Drobon Aegis AI

Cybersecurity application — **Pump 4: foundation + authentication +
authorization + plans/subscriptions/entitlements**, cumulative on top of
the verified Pump 1 + Pump 2 + Pump 3 base.

Pump 1 established the clean technical base (Web, API, Worker, shared
contracts, security, testing, build, docs). Pump 2 added real
authentication (registration/login/logout, httpOnly sessions, protected
routes, minimal durable account persistence). Pump 3 added the
authorization + access-control foundation (account roles
MEMBER < ADMIN < ACCOUNT_OWNER, shared permission table, router guards,
ownership checks, role-aware UI). Pump 4 adds the commercial foundation
on top: exactly two plans (**FREE**, **PRO**), a minimal subscription
state (ACTIVE/INACTIVE/CANCELLED/EXPIRED) on the existing account
store, a single server-authoritative entitlement decision point, a
read-only self-only `GET /api/v1/subscription`, and plan/entitlement
views on the Account page. Role and UserType never grant PRO.
There is still **no database phase, no payment implementation, no
security dataset, and no product features** (scanning, findings, admin
console, etc. arrive later).

## Layout

```
Drobon/
├── apps/
│   ├── api/          # HTTP API (zero runtime dependencies) + auth layer
│   ├── web/          # React + Vite web application (auth UI + guards)
│   └── worker/       # Background worker (in-memory execution)
├── packages/
│   └── shared/       # Contracts: API envelopes, errors, jobs, auth, config
├── scripts/          # dev runner, secret scan, scope gates, verifier
└── docs/             # Architecture, development, testing, security, auth, builds
```

## Quickstart

Prerequisites: Node.js 20.11+ / 22 (see `.nvmrc`), npm 10.

```bash
npm ci          # install (pinned by package-lock.json)
npm run dev     # API (:3001) + Web (:5173) with live reload
```

Then open http://127.0.0.1:5173 and check the **Service status** page (served
by the API). Copy `.env.example` to `.env` to override ports, CORS or limits.

## Commands

| Command                  | What it does                                                              |
| ------------------------ | ------------------------------------------------------------------------- |
| `npm ci`                 | Clean install from the lockfile                                           |
| `npm run dev`            | API + Web dev servers together                                            |
| `npm run dev:api`        | API dev server only (`tsx watch`)                                         |
| `npm run dev:web`        | Web dev server only (`vite`)                                              |
| `npm run test`           | Full test suite, workspace by workspace (shared → api → worker → web)     |
| `npm run typecheck`      | Strict TypeScript check for every workspace                               |
| `npm run lint`           | ESLint over the whole repo                                                |
| `npm run build`          | Production builds (shared → api → worker → web)                           |
| `npm run preview`        | Build + serve the production Web bundle locally                           |
| `npm run start:api`      | Build + run the production API server                                     |
| `npm run audit`          | `npm audit` (fails on high/critical)                                      |
| `npm run check:secrets`  | Scan for committed secrets / key blocks                                   |
| `npm run check:boundaries` | Enforce scope gates (no DB, dataset, shell)                             |
| `npm run verify`         | Full regression pipeline (everything above, in order)                     |

Per-workspace commands work too, e.g. `npm run test --workspace @drobon/api`.
Note: API/Worker/Web consume the **built** `@drobon/shared` package, so the
root commands always build it first; see `docs/DEVELOPMENT.md`.

## Documentation

- `docs/ARCHITECTURE.md` — components, contracts, request lifecycle
- `docs/AUTHENTICATION.md` — auth design: sessions, hashing, persistence
- `docs/AUTHORIZATION.md` — roles, permission table, guards, ownership
- `docs/SUBSCRIPTIONS.md` — plans, subscription states, entitlement authority
- `docs/USAGE.md` — usage quota, UTC periods, device policy, consume boundary
- `docs/PROJECTS.md` — project model, ownership, CRUD, lifecycle, scan boundary
- `docs/SCANS.md` — scan jobs, quota atomicity, idempotency, processor, engine boundary
- `docs/SAST.md` — the real SAST engine: rules, snapshot policy, redaction, bounds
- `docs/DEVELOPMENT.md` — setup, workflow, conventions, environment
- `docs/TESTING.md` — test strategy and how to run everything
- `docs/SECURITY.md` — threat model, controls, verified status, limitations
- `docs/BUILD_VERIFICATION.md` — builds and the `verify` pipeline

## Scope (Pump 7, cumulative)

**Included:** everything from Pumps 1–4 (Web shell, typed API client,
versioned JSON API with validation/correlation/rate limiting/security
headers, worker contracts, redacted structured logging, authentication
with sessions/scrypt/persistence, roles + permission table + router
enforcement + ownership checks + role-aware UI, plans/subscriptions/
entitlements) **plus**: the usage quota foundation — `FREE_MONTHLY_SCAN_QUOTA`
(3 scans/UTC month) and the shared `UsageResponse` contract with strict
guards, a single server-authoritative usage service (UTC period
derivation, account + shared-device counters, atomic
check-and-increment consumption, PRO exemption through the Pump 4
entitlement pipeline), a durable JSON usage store surviving restarts
(atomic writes, corrupt documents refuse to start), the opaque
server-issued `drobon_device` cookie (hashed at rest, hardened
attributes, shared-device allowance for FREE accounts), read-only
self-only `GET /api/v1/usage` (401 anonymous, no IDOR, no mutation
methods, no device identifiers exposed), a dev/test-gated consumption
probe (404 in production), and the Account-page monthly usage section
(display-only, fail-closed). See `docs/USAGE.md`.

**PLUS Pump 6 (Projects foundation)**: the user-owned Project container
for all future security work — shared `Project` contract with strict
guards (no owner field in responses), server-authoritative ownership
(uniform 403 cross-account, role/UserType never grant it), REST CRUD +
explicit archive/unarchive lifecycle on parameterized routes, durable
JSON project store (atomic, serialized, restart-persistent,
fail-fast), NFC-normalized bounded text validation, and the Projects
web experience (list/create/edit/lifecycle, protected routes,
fail-closed states). Project CRUD never consumes a scan. See
`docs/PROJECTS.md`.

**PLUS Pump 7 (Secure scan-job foundation)**: the orchestration boundary
future scanner engines plug into — durable scan jobs (`scan_` UUID ids,
server-authoritative QUEUED→RUNNING→COMPLETED/FAILED lifecycle, no
client mutation path), quota consumed EXACTLY once per created scan and
atomically with the durable append (FREE 3/month + shared-device pool
enforced under 10-way concurrency; PRO exempt), idempotency keys scoped
per account for retry safety, a durable worker loop with
claim-once/finish-once semantics, crash recovery (interrupted scans →
FAILED/SCAN_INTERRUPTED), the empty-by-design scanner-engine registry
(every scan honestly fails SCAN_ENGINE_NOT_IMPLEMENTED — never a fake
result; NO vulnerability datasets, the dataset lock holds), archived
projects reject new scans while history stays readable, and the web
scan experience inside the project page. See `docs/SCANS.md`.

**PLUS Pump 8 (Real SAST engine)**: the first REAL scanner — static
analysis of an uploaded source snapshot (project-scoped, path-policy
validated, 200 files / 256 KiB / 768 KiB caps, key material rejected).
Six deterministic rules (command injection, SQL injection, raw-HTML
sinks, eval, hardcoded credentials, weak hashes) produce genuine
findings: stable rule ids, fixed severities, CWE mappings, bounded
redacted evidence and remediation. Analysis only — source files are
NEVER executed; every dimension is capped (files, bytes, findings,
10 s deadline) with fail-closed codes. Findings persist atomically
with COMPLETED, are readable only via the scan detail route, and
render in the web UI as text. SCA/SECRETS/DAST still fail honestly
with SCAN_ENGINE_NOT_IMPLEMENTED; the dataset lock holds. See
`docs/SAST.md` and `docs/SCANS.md`.

**NOT included:** the remaining scan engines (SCA/SECRETS/DAST —
SAST ships above), vulnerability
datasets, the broader database phase,
payments/billing (no gateway, coupons, partner/referral or approval
UI), plan mutation workflow (`plan:manage` is granted to no one), usage
analytics/history, operator quota adjustments, device-management UI,
any security dataset (CVE/NVD/GHSA/OSV/KEV/EPSS catalogs or feeds),
role management console, email verification, password reset, MFA,
findings, reports, remediation, AI assistance, admin dashboard,
UserType-specific product features. See the NOT_IMPLEMENTED sections in
`docs/`.

## Status

Pump 7 — foundation + authentication + authorization + plans/
subscriptions/entitlements + usage quota & device anti-abuse +
projects + secure scan-job foundation. See `docs/BUILD_VERIFICATION.md`
for the latest
verification evidence and `git log` for history.
