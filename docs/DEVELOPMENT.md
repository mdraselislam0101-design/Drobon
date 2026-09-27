# Development guide

## Prerequisites

- Node.js `>=20.11 <23` (`.nvmrc` pins 22; `engine-strict=true` enforces it).
- npm 10 (`packageManager` field; install with `npm ci`).

## Setup

```bash
npm ci
cp .env.example .env   # optional: local overrides (never commit .env)
npm run dev            # API on :3001, Web on :5173
```

`npm run dev` runs both servers with prefixed output (`[api]`, `[web]`);
Ctrl-C stops both. Run one side with `npm run dev:api` / `npm run dev:web`.

Useful URLs in dev:

- Web: http://127.0.0.1:5173 (home + `/status` page)
- API: http://127.0.0.1:3001/livez, `/readyz`, `/api/v1/status`

The Web dev server proxies `/api/*`, `/livez` and `/readyz` to
`http://127.0.0.1:${PORT:-3001}`, so the app works same-origin with zero
config. To exercise the real cross-origin path instead, set
`VITE_API_BASE_URL=http://127.0.0.1:3001` and add the web origin to
`CORS_ALLOWED_ORIGINS`. The proxy is dev-only: production preview/hosting
serves the static bundle, so split hosting must bake `VITE_API_BASE_URL`
into the build.
- Echo probe: `curl -X POST 127.0.0.1:3001/api/v1/echo -H 'content-type: application/json' -d '{"message":"hi"}'`

## Environment

All variables are documented in `.env.example`. Highlights:

| Variable                | Default                 | Notes                                  |
| ----------------------- | ----------------------- | -------------------------------------- |
| `NODE_ENV`              | `development`           | `development \| test \| production`    |
| `HOST` / `PORT`         | `127.0.0.1` / `3001`    | API bind; loopback is the secure default |
| `LOG_LEVEL`             | `info`                  | `debug \| info \| warn \| error`       |
| `CORS_ALLOWED_ORIGINS`  | (empty = none)          | Comma-separated exact `http(s)` origins |
| `RATE_LIMIT_*`          | `100` / `60000`         | Max requests per window, per IP        |
| `BODY_MAX_BYTES`        | `1048576`               | JSON body cap                          |
| `AUTH_STORE_PATH`       | `.data/users.json`      | Durable account store; `:memory:` = explicit ephemeral opt-in (rejected in production) |
| `AUTH_SCRYPT_COST`      | `32768`                 | scrypt N (power of two, 1024–1048576)  |
| `AUTH_SESSION_TTL_SECONDS` | `604800`             | Absolute session lifetime (7 days)     |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` / `_WINDOW_MS` | `30` / `60000` | Credential-endpoint limiter |
| `ALLOWED_HOSTS`         | loopback                | Vite host allowlist (`*` = sandbox only) |
| `VITE_API_BASE_URL`     | (empty = same-origin)   | Public; baked into the browser bundle  |
| `VITE_APP_NAME/ENV`     | `Drobon Aegis AI` / `development` | Public display values        |

Invalid values fail startup with a `ConfigError` listing every issue — fix
the environment, don't patch the validator.

## Monorepo notes

- Workspaces: `@drobon/shared`, `@drobon/api`, `@drobon/worker`, `@drobon/web`.
- `api`/`worker`/`web` consume the **built** `@drobon/shared` (`dist/`).
  Root `test`/`typecheck`/`build` scripts build it first, in order — that
  ordering is load-bearing, not cosmetic.
- Per-workspace runs (`npm run test --workspace @drobon/api`, …) assume
  `packages/shared/dist` is fresh; rebuild it with
  `npm run build --workspace @drobon/shared` after contract changes.
- Node packages use NodeNext ESM: relative imports carry the `.js` extension
  (`./config.js`) even though the file is `.ts`. The Web uses bundler
  resolution (extensionless).

## Conventions

- TypeScript strict everywhere; no `any` (use `unknown` + narrowing);
  `import type` / `export type` for type-only traffic.
- No `console` in app code — API/Worker log through the structured logger;
  Web renders state instead of logging it. (`scripts/*.mjs` may use console.)
- No new runtime dependency without a written reason; no database/dataset/
  shell dependency at all in Pump 1 (scope gates enforce this).
- Errors: API throws `AppError` (or lets the center map unknowns to generic
  500s); Worker returns `JobResult` failures; Web surfaces `ApiClientError`
  kinds. Never leak stack traces or internals to clients.
- Tests live next to their package in `test/`; name files `*.test.ts(x)`.
- `main` moves via PRs from feature branches; every PR runs `npm run verify`
  (see `docs/BUILD_VERIFICATION.md`).

## Adding an API route (example of the intended workflow)

1. Add the model to `packages/shared/src/models.ts` (+ test the contract).
2. Add a route factory in `apps/api/src/routes/` using `readJsonBody`,
   `lib/validate.ts` schemas, and `sendSuccess`.
3. Register it in `apps/api/src/app.ts` (or pass via `extraRoutes`).
4. Add integration tests in `apps/api/test/` (happy path + 4xx edges).
5. Rebuild shared, run `npm run verify`.
