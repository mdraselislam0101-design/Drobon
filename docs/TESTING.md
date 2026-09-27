# Testing guide

Every package ships real tests; nothing passes because of a placeholder.
Framework: Vitest 4 everywhere (`vitest run` per workspace), React Testing
Library + jsdom for the Web.

## Suites

| Workspace         | What's covered                                                                 |
| ----------------- | ------------------------------------------------------------------------------ |
| `@drobon/shared`  | Error-code vocabulary (incl. auth + FORBIDDEN codes), guard narrowing, envelope parsing (valid + 12 invalid shapes), job factory + validation, **auth contracts: email/password policy, auth guards (reject credential material + forged roles), response guards; Pump 3: account roles/ranks, user types, central permission table, capability guards; Pump 4: plan vocabulary, entitlement decision table (fail-closed, `plan:manage` granted to no cell), subscription payload guards, legacy default, plan material rejected on user payloads; Pump 5: usage contracts — quota constants, strict UTC period pattern, quota-status vocabulary, usage-response guards incl. cross-field invariants; Pump 6: project contracts — status vocabulary, id pattern, ordering comparator, payload guards (no owner field in the public shape); Pump 7: scan contracts — job types, status/failure vocabularies, scan+idempotency-key patterns, state-machine-invariant guards, response guards** |
| `@drobon/api`     | Config (defaults/valid/invalid incl. AUTH_* + probe-gating cases), logger (redaction/levels/error stacks), error mapping + disclosure, validator lib, security predicates, `/livez` `/readyz` `/api/v1/status` `/api/v1/echo`, security headers, CORS (incl. credential-mode contract), rate limiting (429/reset/isolation), request IDs, 500 non-disclosure + recovery, static safety; Pump 2: scrypt, sessions, cookies, JSON store, auth integration + security suites; **Pump 3: authorization matrix (roles × capabilities, 401/403, UserType bypass, mass-assignment, live role reads), ownership/IDOR suite, authorization security regression (forged/expired sessions, header smuggling, method tricks, denial-path headers/CORS, log disclosure), helper units + route-level gates, store role migration; Pump 4: subscription endpoint suite (registration defaults, mass-assignment, anonymous 401, self-only/IDOR, header/query/cookie/body tampering, 405 method safety, log hygiene), subscription commercial matrix (role×plan, UserType×plan, status matrix, live operator flips, derivation independence), store subscription migration/normalization/restart; Pump 5: usage endpoint suite (auth/self-only/tamper matrices, role/UserType non-exemption, lapsed-PRO fallback, exact body validation, production probe gating, device-cookie issuance attributes, multi-cookie responses, log hygiene), quota mechanics (UTC period math incl. Dec→Jan, 10-way concurrent atomicity on memory + durable stores + shared-device races, month-boundary resets via clock injection, restart persistence, PRO exemption not touching the device allowance), device suite (token shape/randomness, cookie security matrix, shared-device allowance, malformed/modified/forged/rotated cookies, device-cookie-alone grants nothing), the usage config additions, the Pump 6 suite: projects API (anonymous/forged/expired auth, server-controlled create fields, strict validation incl. prototype-pollution + XSS-as-text + NFC normalization, server-scoped lists, uniform cross-account 403 across roles/user types, update/lifecycle boundaries, restart persistence, corrupt-store refusal, 20-way concurrent creation, claims tampering, usage non-consumption, router parameterization incl. 405/percent-encoding/trailing-slash semantics, log hygiene) plus the Pump 1 validator prototype-chain fix regression; and the Pump 7 suite: scan API (auth matrix, uniform project 403 + scan 404 policies, strict body validation incl. proto keys, QUOTA ATOMICITY under 10-way concurrency/retry storms/cross-project/cross-account/device-shared races, PRO exemption, month rollover, tamper matrix, idempotency replay/conflict/scoping/format, processor lifecycle incl. claim-once/finish-once/no-fake-results/scan-interrupted recovery, restart persistence with quota+idempotency continuity, corrupt/invalid-store refusal, log hygiene) + the scan store-path config test** |
| `@drobon/worker`  | FIFO/cancel/clear queue, retry validation/math, runner: success, unknown type, retry-then-recover with backoff delays, exhaustion, message truncation, timeout, queued-cancel, running-cancel, waiter timeout, concurrency bound, record eviction, graceful stop, option validation |
| `@drobon/web`     | Public config (defaults/valid/7 invalid cases + allowlist proof), API client (headers/same-origin/echo/http-mapping/network/timeout/abort/malformed **+ auth methods, credentials mode, 422 details, payload guards, Pump 3 capability/user methods + 403 mapping**), components (a11y roles, retry), routing (home/404/loading→data/error→retry/nav), plugin header maps + SPA-fallback truth table, static web safety, **production build + preview server**; Pump 2: auth forms/session flows/open-redirect/nav; **Pump 3: role/user-type badges, capability verdicts from API, forbidden-vs-login states, ProtectedRoute minRole, permission-aware lookup visibility; Pump 4: plan section (server-provided plan/status/verdict, verdict-from-entitlement-list not local recomputation, lapsed-PRO honesty, fail-closed errors with retry, no URL/storage plan state), subscription client boundary (endpoint shape, 401 mapping, guard rejections, no mutation method); Pump 5: usage section (server-provided FREE counts + UTC period, EXHAUSTED honesty, PRO exempt state, fail-closed errors, display-only with no consumption path, storage/URL tampering never changes rendered numbers), usage client boundary (endpoint shape, 401 mapping, guard rejections incl. cross-field forgeries, exactly one usage method); Pump 6: projects pages (server-ordered list, honest empty/loading/error states, create + edit forms calling the API, explicit archive/unarchive, XSS-as-text rendering, foreign-id honest error, no ownership/status form fields, no storage authority, protected routes for list + deep links), projects client boundary (endpoints/methods, id encoding, body shapes without ownership fields, 401/403 mappings, guard rejections); Pump 7: scans section (honest status pills incl. not-implemented failures, server-derived quota hint, scan requests sending only type+key then refreshing from the server, quota-denial rendering, archived restriction with readable history, fail-closed errors with retry, XSS-inert scan text, no storage authority, protected routes, real engine summaries only) + scans client boundary (endpoints/methods, idempotency-key header, exact body shape, guard rejections incl. forged owner/state, 401/403/429 mappings)** |

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
