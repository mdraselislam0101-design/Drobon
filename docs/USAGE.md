# Usage Quota & Device Anti-Abuse Foundation (Pump 5)

How the cumulative scan allowance works: the FREE monthly quota, the UTC
period, the shared-device allowance, the consumption boundary future
scans will call, and the honest limits of cookie-based device identity.
Everything here is covered by executable tests (see `docs/TESTING.md`).

This pump delivers the **quota foundation** — the server-authoritative
boundary — not the scan engine itself. When the Scan/Job/Worker system
arrives (later pumps), it will call the usage service described here
instead of implementing its own quota logic.

## The model in one table

| Rule | Value | Enforced by |
| ---- | ----- | ----------- |
| FREE account allowance | **3 scans / UTC calendar month** | `UsageService.consumeScan` (server) |
| Shared FREE device allowance | **3 scans / UTC calendar month per device** | `UsageService.consumeScan` (server) |
| Effective FREE allowance | the **stricter** of the two above | server view + consumption |
| PRO (ACTIVE) | **exempt** — no monthly limit, usage still tracked | server entitlement |
| Period identifier | `YYYY-MM`, **UTC** (never browser/Bangladesh time) | server clock |
| Month reset | natural UTC rollover — no cron, no manual job | period key on every access |
| Denial code | `QUOTA_EXCEEDED` (HTTP `429` + `Retry-After`) | shared error vocabulary |

Constants live in the shared contract
(`packages/shared/src/usage.ts`): `FREE_MONTHLY_SCAN_QUOTA = 3`,
`FREE_DEVICE_MONTHLY_SCAN_QUOTA = 3`. The API is their only consumer
that matters — the web never recomputes anything from them.

## Periods are UTC, server-computed, never client-supplied

- The period id (`2026-09`) is derived **on the server** from the
  server clock at request time (`usagePeriodIdAt`). No query parameter,
  body field, header or cookie can select a period — the API decides.
- `usagePeriodInfo(period)` exposes `{ period, startUtc, endUtc }` with
  an end-**exclusive** month window (`endUtc` = first millisecond of the
  next month), including the December → January year rollover (tested).
- **Month reset is lazy**: counters are stored per `period` key, so a
  new month starts with an empty key by construction. September usage
  never reduces October (tested, including Dec→Jan).
- The clock is injectable (`createUsageService({ store, now })`,
  `USAGE_NOW`-style test injection via `startTestServer({ usageNow })`),
  which is how month boundaries are tested deterministically.

## Who is exempt — and who never is

Exemption is decided by the **existing Pump 4 entitlement pipeline**:
`hasEntitlement(deriveEntitlements(record), 'feature:pro')`, i.e.
exactly `PRO + ACTIVE`. It follows that:

- **ADMIN and ACCOUNT_OWNER on FREE are NOT exempt** (role never grants
  commercial entitlements — Pump 4 rule, re-tested here).
- **No UserType is exempt** (DEVELOPER/STUDENT/… — classification only).
- **Lapsed PRO** (`INACTIVE`/`CANCELLED`/`EXPIRED`) falls back to the
  FREE allowance, keeping the honest `PRO` plan label (tested).
- Client claims (`{"plan":"PRO"}`, `x-plan`, `plan=PRO` cookie,
  localStorage, body mutation) never affect the verdict (tamper-tested).

Exempt consumption is tracked on the **account only** and never touches
the shared device allowance: a PRO user scanning heavily on a device
does not reduce any FREE account's allowance on that device (tested).

## The device model (anti-abuse foundation)

Problem being addressed: without a device signal, one operator can
create unlimited FREE accounts and get 3 scans each. The device
allowance makes FREE accounts **sharing a recognized device share the
same 3 scans/month**.

- **Identity**: an opaque, server-issued cookie `drobon_device`.
  - Value: 32 crypto-random bytes, base64url-encoded (43 chars,
    `^[A-Za-z0-9_-]{43}$`), no personal information, no account id.
  - Attributes: `HttpOnly`, `SameSite=Strict`, `Path=/`,
    `Max-Age=400d`, plus `Secure` when the config is production
    (all attribute combinations tested).
  - Issued lazily on the **first authenticated request** (anonymous
    requests never receive one), and never re-issued while a valid
    cookie is presented.
- **Storage**: the server persists **only a SHA-256 hash** of the token.
  The raw token exists only in the cookie; it is never logged, never
  returned in a response body, never stored (captured-log and
  response-body tests).
- **Never trusted from the client**: a missing, malformed or
  shape-invalid cookie is ignored and replaced with a fresh server
  identity (each malformed class tested). Only a correctly-shaped token
  is accepted — and then it is looked up by hash in the server's own
  counters; there is nothing in the token to "claim".
- **No invasive fingerprinting**: no canvas/font/UA fingerprinting, no
  IP tracking, no permanent IP bans. The device signal is a cookie and
  nothing else.

### Honest security limits (documented, not hidden)

- **Cookie rotation**: a user who deletes the cookie (or forges a fresh
  correctly-shaped token) starts a *new* device identity with a fresh
  **device** allowance. This is the known limit of cookie-based device
  identity. **Backstops**: the **account quota still binds** — an
  account that consumed 3 scans this month is denied on *every* device,
  so rotation cannot buy extra scans for the same account (tested);
  existing **credential rate limiting** throttles account creation and
  login; the opaque+hashed cookie prevents device stalking across
  accounts.
- **Shared machines**: two honest users on one browser share the device
  allowance. This is deliberate (cost of the anti-abuse rule) and
  visible in each user's remaining count.
- **No cross-device correlation**: we do not attempt to link devices to
  a person; that would require fingerprinting, which is out of scope.

## Storage & atomicity

The usage store (`apps/api/src/usage/store.ts`) has one interface, two
implementations: a durable JSON file store (default
`.data/usage.json`, temp-file + rename, `0600`, validated on load —
corrupt documents refuse to start) and an in-memory store
(`:memory:`, tests). Production configuration rejects `:memory:`
(`USAGE_STORE_PATH` must be a real path when `NODE_ENV=production`).

Document shape (`{ version: 1, accounts, devices }`) stores
`accountId → { period → count }` and `deviceHash → { period → count }`.
Only opaque ids/hashes appear; no emails, no raw tokens, no plan data.

**Atomicity**: every mutation runs inside a serialized promise queue
(`runExclusive`): check **both** limits → increment **both** counters →
persist to disk → only then acknowledge. There is no read-then-write
window. Tested: 10 simultaneous consumes on a fresh FREE account yield
exactly 3 grants and 7 `QUOTA_EXCEEDED` denials — on the memory store,
on the durable file store, and with two accounts racing on the same
device token.

**Persistence**: counters survive an API restart (tested with the file
store: stop server → start new server on the same store → counts,
including the device count, are intact). Denials increment nothing and
mutate nothing (denial immutability tested).

## API surface

### `GET /api/v1/usage` (registered in every environment)

- Authentication required — anonymous → `401 UNAUTHORIZED` (exact
  envelope tested).
- Returns **only the authenticated caller's own** view (shared
  `UsageResponse` contract): `{ plan, period, used, limit, remaining,
  quotaStatus }` where `quotaStatus` ∈ `OK | EXHAUSTED | EXEMPT`.
- Self-only by construction: no account-id parameter exists (tamper
  tests: `?userId=`, `?accountId=`, `?email=` — all ignored).
- Never exposes: device hash/token, other accounts' usage, internal
  storage paths, or any sensitive identifier (body + log assertions).
- Read-only: `POST`/`PATCH`/`PUT`/`DELETE` on the path answer `405` +
  `Allow: GET` (tested). **There is no user-callable way to mutate
  usage in production.**

### `POST /api/v1/usage/consume` (development/test ONLY)

- Registered **only when `config.usageConsumeRoutes`** is true, which is
  `NODE_ENV !== 'production'` (mirrors the Pump 3 authz probe gating).
  In production the route is not registered → `404` (tested).
- Purpose: make the consumption boundary observable and E2E-testable
  **before** the Scan/Job system exists. It is not a product feature.
- Behavior: consumes exactly one scan for the authenticated caller +
  presented device. Body is optional; if present it must be `{}` — any
  property (`plan`, `remaining`, `used`, `period`, `deviceId`, …) is
  rejected with `422` (exact validation, tested). Nothing in the
  request can influence the decision except the session and device
  cookie.
- Success: `200` + the updated view. Denial: `429` with
  `QUOTA_EXCEEDED`, a stable message, and `Retry-After` (whole seconds
  until the next UTC month).

### Where production consumption will happen

When the scan engine lands, its job/worker code will call
`UsageService.consumeScan` (the same service) **inside** the scan
workflow, before results are produced. The HTTP probe stays gated off
in production forever; `GET /usage` remains the user-facing read.

## Web (display, never authority)

The existing Account page (`/account`) gained a "Monthly scan usage"
section — no new page, no new client:

- FREE: current UTC period, `used of 3`, remaining, quota status
  (`Available` / `Monthly allowance used`), reset note.
- PRO (exempt): "No limit (PRO)", usage still tracked.
- Rendered exclusively from `GET /api/v1/usage` through the existing
  API client (`getUsage`, validated by the shared `isUsageResponse`
  guard, which also rejects cross-field inconsistencies like an
  "EXEMPT view with a numeric limit").
- Fail closed on any error: honest error panel + retry, no numbers.
- Display-only: the web has **no** consumption or usage-mutation code
  path at all (the client exposes exactly one usage method, `getUsage`).

## Security boundaries (summary)

- Server-authoritative quota; single consumption authority
  (`UsageService`); no duplicate quota checks in routes.
- Atomic check-and-increment under concurrency; persistence across
  restarts; denial mutates nothing.
- Stable denial contract: `QUOTA_EXCEEDED` / `429` / `Retry-After`.
- Device identity: opaque, server-issued, hashed at rest, hardened
  cookie attributes, never logged, never exposed.
- Production: no user-callable consume endpoint (404), memory store
  refused, `Secure` cookie attribute on.
- Log hygiene: consumption logs carry `requestId` + `userId` only —
  no device hash, no email, no token (captured-log test).
- Dataset lock unchanged: no external security datasets anywhere.

## NOT_IMPLEMENTED (later roadmap, do not assume)

The scan engine itself (SAST/SCA/DAST scanning, scan jobs, queued
workers calling this boundary), per-feature metering beyond the single
scan allowance, usage history/analytics views, operator quota
adjustments, paid overage handling, device management UI ("devices"
list, revoke device), any form of billing (see `docs/SUBSCRIPTIONS.md`).
