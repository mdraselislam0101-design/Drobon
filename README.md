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
- `docs/DEVELOPMENT.md` — setup, workflow, conventions, environment
- `docs/TESTING.md` — test strategy and how to run everything
- `docs/SECURITY.md` — threat model, controls, verified status, limitations
- `docs/BUILD_VERIFICATION.md` — builds and the `verify` pipeline

## Scope (Pump 4, cumulative)

**Included:** everything from Pumps 1–3 (Web shell, typed API client,
versioned JSON API with validation/correlation/rate limiting/security
headers, worker contracts, redacted structured logging, authentication
with sessions/scrypt/persistence, roles + permission table + router
enforcement + ownership checks + role-aware UI) **plus**: `Plan`
(FREE/PRO) and `SubscriptionStatus` contracts, the shared entitlement
decision table, server-written FREE default on registration,
subscription state on the existing account store with fail-closed
migration/normalization, a single server-authoritative entitlement
derivation (role/UserType never contribute), read-only self-only
`GET /api/v1/subscription` (401 anonymous, no IDOR, no mutation
methods), and the Account-page plan/subscription section (fail-closed
display, no client recomputation, no web-storage plan state).

**NOT included:** the broader database phase, payments/billing (no
gateway, coupons, partner/referral or approval UI), plan mutation
workflow (`plan:manage` is granted to no one), any security dataset
(CVE/NVD/GHSA/OSV/KEV/EPSS catalogs or feeds), role management console,
email verification, password reset, MFA, scanning, findings, reports,
remediation, AI assistance, admin dashboard, UserType-specific product
features. See the NOT_IMPLEMENTED sections in `docs/`.

## Status

Pump 4 — foundation + authentication + authorization + plans/
subscriptions/entitlements. See `docs/BUILD_VERIFICATION.md` for the
latest verification evidence and `git log` for history.
