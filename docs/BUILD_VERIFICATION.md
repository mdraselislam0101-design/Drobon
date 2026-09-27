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
