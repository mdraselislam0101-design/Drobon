# Testing guide

Every package ships real tests; nothing passes because of a placeholder.
Framework: Vitest 4 everywhere (`vitest run` per workspace), React Testing
Library + jsdom for the Web.

## Suites

| Workspace         | What's covered                                                                 |
| ----------------- | ------------------------------------------------------------------------------ |
| `@drobon/shared`  | Error-code vocabulary (incl. Pump 2 auth codes), guard narrowing, envelope parsing (valid + 12 invalid shapes), job factory + validation, **auth contracts: email/password policy, auth guards (reject credential material), response guards** |
| `@drobon/api`     | Config (defaults/valid/invalid incl. AUTH_* cases), logger (redaction/levels/error stacks), error mapping + disclosure, validator lib, security predicates, `/livez` `/readyz` `/api/v1/status` `/api/v1/echo`, security headers, CORS (incl. credential-mode contract), rate limiting (429/reset/isolation), request IDs, 500 non-disclosure + recovery, static safety; **Pump 2: scrypt hashing, session store, cookie serialization, JSON account store (persistence/corruption/races), register/login/logout/me integration, protected-route bypass attempts, enumeration/brute-force/origin-guard/disclosure/log-hygiene security suites** |
| `@drobon/worker`  | FIFO/cancel/clear queue, retry validation/math, runner: success, unknown type, retry-then-recover with backoff delays, exhaustion, message truncation, timeout, queued-cancel, running-cancel, waiter timeout, concurrency bound, record eviction, graceful stop, option validation |
| `@drobon/web`     | Public config (defaults/valid/7 invalid cases + allowlist proof), API client (headers/same-origin/echo/http-mapping/network/timeout/abort/malformed **+ auth methods, credentials mode, 422 details, payload guards**), components (a11y roles, retry), routing (home/404/loading→data/error→retry/nav), plugin header maps + SPA-fallback truth table, static web safety, **production build + preview server** (headers, fallback, hashed output); **Pump 2: login/register form validation + server-error rendering + busy states, protected-route redirects, session-expiry flow, logout honesty, open-redirect sanitizer table, auth-aware nav** |

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
