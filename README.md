# Drobon Aegis AI

Cybersecurity application — **Pump 20: cumulative security foundation + Pentester workspace**, adding Pentester routing and authorized passive DAST assessment presentation alongside the shared Developer, Student and Security Professional workspaces, reusing existing authorization, plans/entitlements, projects, scan lifecycle, SAST, SCA/SBOM, Secrets, limited passive DAST, bounded findings, persisted reports, remediation lifecycle, read-only AI Security Assistant, manual payment review, and restricted read-only platform operations.

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
Pump 17 added a Developer classification selector, Developer-first login routing and a bounded self-scoped overview. Pump 18 added Student-first routing and progress/history over the shared overview. Pump 19 added Security Professional-first routing and a bounded assessment dashboard over the same overview and shared engines. Pump 20 adds Pentester-first routing and server-derived project target indicators over that same owner-scoped workflow. `UserType` remains classification only; role, server entitlement, ownership, quota, rate limits and DAST safety remain authoritative. There is still **no database phase, online payment gateway, automated payment verification, account enabled/disabled model, or bundled security dataset**. Pump 15 provides manual reference submission and allowlisted admin review; Pump 16 platform operations remain gated by a server-configured administrator ID list plus the live `ADMIN` role. Existing scanners are bounded analysis tools; Pump 11 DAST is strictly passive HTTP, not a browser or full DAST crawler.

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
- `docs/SCA.md` — the real SCA engine: manifest parsing, inventory, SBOM, the dataset lock
- `docs/DAST.md` — limited passive DAST: target authorization, SSRF controls, request bounds and limitations
- `docs/FINDINGS.md` — lifecycle transitions, verification semantics, notes, guidance, authorization and persistence
- `docs/REPORTS.md` — findings routes, persisted single-scan reports, workflow snapshots, exports, digests and honesty limits
- `docs/ASSISTANT.md` — Pump 14 assistant authorization, evidence, no-provider behavior, redaction, bounds and limitations
- `docs/PAYMENTS.md` — Pump 15 manual payment request, audit/state lifecycle, platform reviewer allowlist, consistency saga and gateway-unavailable boundary
- `docs/DEVELOPER.md` — Pump 17 Developer registration, account-scoped dashboard/history, shared project workflow, limits and verification
- `docs/STUDENT.md` — Pump 18 Student capability gap matrix, shared workflow and verified limits
- `docs/SECURITY_PROFESSIONAL.md` — Pump 19 Professional dashboard, assistant scope, FREE/PRO workflow and verified limits
- `docs/DEVELOPMENT.md` — setup, workflow, conventions, environment
- `docs/TESTING.md` — test strategy and how to run everything
- `docs/SECURITY.md` — threat model, controls, verified status, limitations
- `docs/BUILD_VERIFICATION.md` — builds and the `verify` pipeline

## Scope (Pump 20, cumulative)

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
server-authoritative QUEUED→RUNNING→COMPLETED/FAILED/TIMED_OUT lifecycle, no
client mutation path), quota consumed EXACTLY once per created scan and
atomically with the durable append (FREE 3/month + shared-device pool
enforced under 10-way concurrency; PRO exempt), idempotency keys scoped
per account for retry safety, a durable worker loop with
claim-once/finish-once semantics, crash recovery (interrupted scans →
FAILED/SCAN_INTERRUPTED), and a server-only engine registry. Archived
projects reject new scans while history stays readable, and the web
scan experience lives inside each project. See `docs/SCANS.md`.

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
render in the web UI as text. SECRETS (Pump 10) detects hardcoded
secrets over the same snapshot with mandatory redaction. No source code
is executed, and the dataset lock holds. See `docs/SAST.md` and
`docs/SCANS.md`.

**PLUS Pump 9 (Real SCA engine — honest by construction)**: software-
composition analysis of the same uploaded snapshot's dependency
manifests (package.json, package-lock.json v1–v3, requirements.txt,
pyproject.toml PEP 621 + Poetry). Defensive parsers (prototype-key
discipline, entry/line bounds, invalid data dropped — never guessed)
build a normalized inventory: direct vs transitive with lockfile
evidence, declared AND resolved versions both preserved, deterministic
fingerprints/ids (no random UUIDs), and a CycloneDX 1.5-subset SBOM
with a content-derived serial. Analysis only — nothing is ever
installed or executed (postinstall scripts are inert data, verified by
marker-file tests). THE DATASET LOCK: no CVE/NVD/GHSA/OSV/KEV/EPSS
data enters the repo; with no dataset the assessment is honestly
NOT_ASSESSED with `NO_DATA_LOADED`; the advisory collection stays
empty without claiming zero vulnerabilities. The
VulnerabilityIntelligenceProvider boundary is injectable and tested
with synthetic fixtures (tests only). SCA payloads persist atomically,
ride the detail route only, survive restarts, and render distinctly
from SAST in the web UI. See `docs/SCA.md`.

**PLUS Pump 11 (limited passive DAST)**: one explicitly configured,
project-associated HTTP(S) target. The project owner must configure only a
target they have permission to assess; the server validates its destination
safety but does not independently establish third-party authorization. A
bounded GET-only engine uses SSRF-safe URL/DNS/address checks,
pre-request DNS revalidation, pinned public addresses, independently
validated same-host redirects, request/body/time caps, and passive
response-header/body observations. Findings are actual observations
with deterministic identities and redacted evidence, persisted through
the existing scan lifecycle and rendered in the project UI. It does not
use a browser, execute JavaScript, authenticate, crawl, fuzz, inject, or
exploit; tests use synthetic transport responses and controlled local
fixtures only. See `docs/DAST.md`.

**PLUS Pump 12 (production findings and reports):** scanner-aware,
project-aware deterministic finding fingerprints; redacted bounded
evidence; authenticated, ownership-scoped finding pages/details with
validated server-side severity/scanner filters and bounded pagination;
and an overview inside each project with persisted finding totals,
severity and scanner run breakdowns. The report layer creates one
canonical JSON report per completed scan and persists it in the existing
scan JSON store; authorized retrieval survives API restart. JSON and
escaped human-readable Markdown downloads use generated safe filenames,
real SHA-256 digests (not signatures), source context, scanner coverage,
SCA inventory/SBOM when actually present, and bounded DAST observations.
SCA vulnerability intelligence remains `NO_DATA_LOADED` /
`NOT_ASSESSED`; empty advisories do not mean zero vulnerabilities.
Reports do not consume quota. See `docs/REPORTS.md`.

**PLUS Pump 13 (finding remediation lifecycle):** authenticated owner-only
workflow transitions, bounded audit history and safe plain-text notes are
persisted atomically with the existing scan JSON store. Reobserved resolved
findings reopen by deterministic fingerprint; absence is only recorded as
not observed in the latest completed same-scanner scan with complete finding details. Rule-specific
read-only guidance and point-in-time report snapshots never modify source
or claim a user-marked resolution is technically fixed. Workflow changes
do not consume scan quota; verification scans use the existing quota.
Archived projects remain read-only for workflow mutations. See
`docs/FINDINGS.md` and `docs/REPORTS.md`.

**PLUS Pump 14 (AI Security Assistant foundation):** project-owner-only,
read-only deterministic answers over bounded provenance-bearing saved
scan, finding, workflow, report, SCA/SBOM, and DAST evidence. The default
provider state is `NONE`: unsupported generative questions explicitly
return unavailable, with no fake model output or external provider call.
Credential/evidence redaction is applied again before response/provider
boundaries, and no tools, arbitrary network access, chat persistence,
source mutation, lifecycle mutation, or scan-quota consumption is added.
Dependency intelligence preserves `NOT ASSESSED` / `NO_DATA_LOADED`.
See `docs/ASSISTANT.md`.

**NOT included:** browser/full DAST, vulnerability
datasets, the broader database phase,
online payment gateway/webhooks/automatic verification, coupons/discounts,
partner/referral/commission; plan mutation outside the authorized payment
approval workflow (`plan:manage` is granted to no plan), usage
analytics/history, operator quota adjustments, device-management UI,
any security dataset (CVE/NVD/GHSA/OSV/KEV/EPSS catalogs or feeds),
role management console, email verification, password reset, MFA,
external generative AI provider, durable assistant chat history, partner/referral workflows, or other
user-type-specific workflows beyond the shared Developer/Student/Security Professional/Pentester presentations, UserType-based authorization or entitlements,
multi-scan reports, PDF/signature workflows, and a database-backed report store. See the NOT_IMPLEMENTED sections in
`docs/`.

## Status

Pump 20 — the cumulative workflow includes Developer, Student, Security Professional and Pentester workspace presentations over the same account-owned overview and shared project, scan, finding/remediation, report and assistant features. Pentester target indicators reflect saved owner-managed settings only; UserType-first routing and persisted history do not grant authority or imply scanner completeness. FREE remains 3 scans/month per account with device anti-abuse; PRO exemptions continue to come from server entitlements. The overview is not an overall security verdict and includes only persisted, account-owned projections. No account enable/disable model, online payment gateway, separate production worker or generative provider was introduced; SCA vulnerability intelligence remains `NOT_ASSESSED` / `NO_DATA_LOADED` without a configured provider/dataset. See `docs/DEVELOPER.md`, `docs/STUDENT.md`, `docs/SECURITY_PROFESSIONAL.md`, `docs/DAST.md` and `docs/BUILD_VERIFICATION.md` for scope and limitations.
