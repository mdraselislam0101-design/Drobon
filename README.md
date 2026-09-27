# Drobon Aegis AI

Cybersecurity application — **Pump 1: production-oriented foundation**, built from zero.

Pump 1 establishes the clean technical base (Web, API, Worker, shared contracts,
security, testing, build, docs) on which all later Pumps build. It deliberately
contains **no database, no security dataset, no auth, and no product features yet**.

## Layout

```
Drobon/
├── apps/
│   ├── api/          # HTTP API (zero runtime dependencies)
│   ├── web/          # React + Vite web application
│   └── worker/       # Background worker (in-memory execution)
├── packages/
│   └── shared/       # Contracts: API envelopes, errors, jobs, config, models
├── scripts/          # dev runner, secret scan, scope gates, verifier
└── docs/             # Architecture, development, testing, security, builds
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
- `docs/DEVELOPMENT.md` — setup, workflow, conventions
- `docs/TESTING.md` — test strategy and how to run everything
- `docs/SECURITY.md` — threat model, controls, verified status, limitations
- `docs/BUILD_VERIFICATION.md` — builds and the `verify` pipeline

## Scope (Pump 1)

**Included:** Web shell + routing + typed API client, versioned JSON API with
validation/correlation/rate limiting/security headers, worker with job
contracts/timeouts/cancellation/retry, structured logging with secret
redaction, strict config validation, liveness/readiness probes, test suites
for every package, docs, and one-command verification.

**NOT included:** database of any kind, security datasets (CVE/NVD/GHSA/OSV/
KEV/EPSS catalogs or feeds), authentication/authorization, scanning, findings,
reports, remediation, AI assistance, admin, payments. Anything in that list is
future work — see the NOT_IMPLEMENTED sections in `docs/`.

## Status

Pump 1 — foundation. See `docs/BUILD_VERIFICATION.md` for the latest
verification evidence and `git log` for history.
