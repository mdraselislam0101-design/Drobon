# Testing guide

Every package ships real tests; nothing passes because of a placeholder.
Framework: Vitest 4 everywhere (`vitest run` per workspace), React Testing
Library + jsdom for the Web.

## Suites

| Workspace         | What's covered                                                                 |
| ----------------- | ------------------------------------------------------------------------------ |
| `@drobon/shared`  | Error-code vocabulary, guard narrowing, envelope parsing (valid + 12 invalid shapes), job factory + validation |
| `@drobon/api`     | Config (defaults/valid/16 invalid cases), logger (redaction/levels/error stacks), error mapping + disclosure, validator lib, security predicates, `/livez` `/readyz` `/api/v1/status` `/api/v1/echo`, security headers, CORS (7 cases), rate limiting (429/reset/isolation), request IDs, 500 non-disclosure + recovery, static safety (no exec primitives, env boundary, no DB imports) |
| `@drobon/worker`  | FIFO/cancel/clear queue, retry validation/math, runner: success, unknown type, retry-then-recover with backoff delays, exhaustion, message truncation, timeout, queued-cancel, running-cancel, waiter timeout, concurrency bound, record eviction, graceful stop, option validation |
| `@drobon/web`     | Public config (defaults/valid/7 invalid cases + allowlist proof), API client (headers/same-origin/echo/http-mapping/network/timeout/abort/malformed), components (a11y roles, retry), routing (home/404/loading→data/error→retry/nav), plugin header maps + SPA-fallback truth table, static web safety (env boundary, VITE allowlist, no dangerous primitives), **production build + preview server** (headers, fallback, hashed/secret-free output) |

## Running

```bash
npm run test                                   # everything, in order
npm run test --workspace @drobon/api           # one package (rebuild shared first if contracts changed)
npx vitest run --workspace @drobon/web         # from repo root, web only
```

Watch mode during development: `npx vitest --workspace @drobon/api`
(or `cd apps/api && npx vitest`). Typecheck and lint are separate gates:
`npm run typecheck`, `npm run lint`.

## Notes

- API tests boot real servers on ephemeral loopback ports and speak real
  HTTP via `fetch` — no supertest, no mocks of the app itself.
- The Web `previewHeaders` test runs a real `vite build` + `vite preview`
  and asserts production headers, SPA fallback and bundle hygiene. It is the
  slowest test (~tens of seconds) and doubles as the production-build proof.
- Worker tests use millisecond budgets and injected sleeps — no fake timers,
  no flakes by design (timeouts in tests are generous relative to budgets).
- Static tests (`staticSafety`, `staticWeb`) scan `src/` for forbidden
  patterns (exec primitives, env reads outside the boundary, dangerous DOM
  APIs). Keep them green by construction, not by carve-out.
- Coverage thresholds are NOT configured in Pump 1 (deliberate — the suite
  asserts behaviors and contracts, not line percentages). Revisit in a later
  Pump if coverage gating is wanted.
