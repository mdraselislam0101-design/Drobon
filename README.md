# Drobon Aegis AI

Cybersecurity application — **Pump 2: foundation + authentication**,
cumulative on top of the verified Pump 1 base.

Pump 1 established the clean technical base (Web, API, Worker, shared
contracts, security, testing, build, docs). Pump 2 added the real
authentication layer: registration, login, logout, httpOnly sessions,
protected routes and a minimal durable account store — wired end to end
through the existing pipeline. There is still **no database phase, no
security dataset, and no product features** (scanning, findings, etc.
arrive in later Pumps).

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
- `docs/DEVELOPMENT.md` — setup, workflow, conventions, environment
- `docs/TESTING.md` — test strategy and how to run everything
- `docs/SECURITY.md` — threat model, controls, verified status, limitations
- `docs/BUILD_VERIFICATION.md` — builds and the `verify` pipeline

## Scope (Pump 2, cumulative)

**Included:** everything from Pump 1 (Web shell, typed API client, versioned
JSON API with validation/correlation/rate limiting/security headers, worker
contracts, structured logging with redaction, docs, one-command verification)
**plus**: registration/login/logout flows, `GET /api/v1/me`, httpOnly +
SameSite=Strict session cookies, server-side session store with absolute TTL,
scrypt password hashing, a dedicated credential rate limit, CSRF origin
guard, protected-route machinery in the Web app (loading/error/expiry
states), and the minimum durable account persistence (single JSON document
behind a repository interface).

**NOT included:** the broader database phase (projects/scans/findings), any
security dataset (CVE/NVD/GHSA/OSV/KEV/EPSS catalogs or feeds), roles/
authorization, plans/entitlements, scanning, findings, reports, remediation,
AI assistance, admin, payments. Anything in that list is future work — see
the NOT_IMPLEMENTED sections in `docs/`.

## Status

Pump 2 — foundation + authentication. See `docs/BUILD_VERIFICATION.md` for
the latest verification evidence and `git log` for history.
