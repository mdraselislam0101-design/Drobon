# Plans, Subscriptions & Entitlements (Pump 4)

How the commercial foundation works: what a plan is (and is not), how
subscription state is stored, who decides entitlements, and what is
deliberately NOT implemented yet. Everything here is covered by
executable tests (see `docs/TESTING.md`).

Pump 5 builds directly on this foundation: the FREE monthly scan
allowance and the PRO exemption live in the usage service and reuse
`deriveEntitlements` unchanged — see `docs/USAGE.md`. In particular,
"exempt from the quota" means exactly `PRO + ACTIVE` here, and lapsed
PRO accounts fall back to the FREE allowance.

## Four concepts, never conflated

| Concept | Values | Purpose | Grants PRO? |
| ------- | ------ | ------- | ----------- |
| `AccountRole` | `MEMBER` < `ADMIN` < `ACCOUNT_OWNER` | Authorization: what the account may do (Pump 3) | **Never** |
| `UserType` | `DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, `PENTESTER` | Classification/visibility only | **Never** |
| `Plan` | `FREE`, `PRO` | The commercial tier on the account's subscription | It is the tier itself |
| `SubscriptionStatus` | `ACTIVE`, `INACTIVE`, `CANCELLED`, `EXPIRED` | Lifecycle state of the subscription | Only `PRO + ACTIVE` |

- `UserType` is NOT a plan; `AccountRole` is NOT a plan. Neither can grant
  PRO entitlements — an `ACCOUNT_OWNER` `PENTESTER` on FREE has exactly
  FREE entitlements (tested across the full role×plan and
  userType×plan grids).
- A `STUDENT`, `DEVELOPER`, `SECURITY_PROFESSIONAL` or `PENTESTER` can be
  FREE or PRO — classification describes the person, the plan describes
  the commercial state.

## Plans (exactly two in Pump 4)

`FREE` and `PRO` — the complete, closed vocabulary
(`PLANS` in `packages/shared/src/plans.ts`; type-safe, no arbitrary
client strings). Every newly registered account is created as
**FREE + ACTIVE** by the server. No registration parameter, query
parameter, header, cookie, body field, UserType or AccountRole can
select PRO: `plan`/`subscription` keys in the register payload are
rejected as unknown properties (mass-assignment defense, tested).

## Subscription model (minimal by design)

The subscription lives on the existing account record
(`UserRecord.subscription`) as `{ plan, status, createdAt, updatedAt }`.
Nothing more — no payment data, no renewal metadata, no billing events.

Migration/default behavior (backward compatible, tested):

- **Pump 2-era records** (no `role`/`userType`/`subscription`) load as
  before and resolve to `FREE + ACTIVE` (timestamps `null` — no
  subscription record ever existed).
- **Pump 3-era records** (`role`/`userType`, no `subscription`) resolve
  to `FREE + ACTIVE` the same way.
- **Pump 4 records** round-trip exactly as stored.

Fail-closed normalization of corrupt persisted data
(`auth/subscriptions.ts`):

| Persisted subscription | Effective plan | Effective status |
| ---------------------- | -------------- | ---------------- |
| absent / `null` (legacy) | `FREE` | `ACTIVE` |
| non-object garbage | `FREE` | `INACTIVE` |
| invalid/missing `plan` | `FREE` | (status rule below) |
| valid plan, invalid/missing `status` | as stored | `INACTIVE` |
| invalid timestamps | (unchanged) | (unchanged), timestamps `null` |

Rationale: corrupt **authorization** fields refuse the store (fail
fast, Pump 3 posture — access decisions are untrustworthy); corrupt
**commercial** data degrades instead — the account stays readable while
entitlements can only be LOST, never gained. `feature:pro` requires an
explicit, fully valid stored `PRO` + `ACTIVE`.

## The entitlement decision (single, server-authoritative)

`deriveEntitlements(record)` in `apps/api/src/auth/subscriptions.ts` is
the one decision point. It reads **only** the account's subscription —
role and userType are structurally not inputs — and applies the shared
decision table `SUBSCRIPTION_ENTITLEMENTS`:

| Plan | Status | Entitlements |
| ---- | ------ | ------------ |
| FREE | any | `plan:view` |
| PRO | `ACTIVE` | `plan:view`, `feature:pro` |
| PRO | `INACTIVE` / `CANCELLED` / `EXPIRED` | `plan:view` (PRO lost) |

- **Fail closed**: `feature:pro` exists in exactly one cell of the table
  (asserted by iterating every cell in tests). Non-ACTIVE PRO keeps the
  honest `PRO` label but loses the entitlement.
- **`plan:manage` is granted to no one** in Pump 4: the contract key
  exists (closed vocabulary) but no (plan, status) cell contains it,
  because no authorized mutation workflow exists yet. Nobody — not even
  ACCOUNT_OWNER — holds a "plan management" capability; there is nothing
  fake to expose.
- Never trusted for entitlement decisions: request bodies, query
  parameters, headers, cookies, frontend state, localStorage,
  sessionStorage, UserType, AccountRole. The server derives entitlement
  from the authenticated account's live state on every request (session
  middleware sets `ctx.subscription`/`ctx.entitlements` from the
  repository record — operator store changes apply on the next request,
  no re-login, tested).

## API surface

`GET /api/v1/subscription` (registered in every environment):

- Authentication required — anonymous → `401 UNAUTHORIZED`.
- Returns **only the authenticated caller's own** subscription and the
  entitlements derived from it (shared `SubscriptionResponse` contract).
- No account-id parameter exists — identity comes exclusively from the
  session, so cross-account reads (IDOR) are structurally impossible
  (tamper-tested via `?userId=`, `?accountId=`, `?email=`, `x-user-id`,
  path manipulation, extra cookies and GET bodies — all ignored).
- Read-only by construction: there is **no** `POST`/`PATCH`/`PUT`/
  `DELETE` on this path (they answer `405` + `Allow: GET`, tested).
  Subscription mutation belongs to a later, explicitly authorized
  workflow (payments phase). Today the only way subscription state
  changes is the documented operator workflow: edit the account store
  and restart (same as role elevation in Pump 3).

## Web (display, never authority)

Pump 17's Developer overview consumes the same server-reported subscription
and entitlement response as the Account page; the classification tag does not
change the result.

The existing Account page (`/account`) gained a "Plan & subscription"
section — no second account page, no second client:

- Plan and status badges plus subscription timestamps, rendered from
  `GET /api/v1/subscription` through the existing API client
  (`getSubscription`, validated by the shared
  `isSubscriptionResponse` guard).
- The "PRO features" verdict renders the **server's entitlement list** —
  the page never recomputes it from the plan name, never caches it in
  localStorage/sessionStorage, and never puts plan state in the URL.
- Fail closed on any error: an honest error panel with a retry — no plan
  value at all is displayed, never a silent PRO (tested).
- `AuthUser` payloads can never carry plan material: the shared
  `isAuthUser` guard rejects user payloads containing `plan`/
  `subscription` keys, so commercial state has exactly one channel.

## Security boundaries (summary)

- Server-authoritative entitlements; the API response is the only truth.
- Self-only subscription reads; no existence oracle; uniform errors.
- Mass-assignment (`plan` in register payload) → 422.
- Log hygiene: subscription requests log method/path/status only — no
  plan state, emails, tokens or entitlement lists (captured-log test).
- No payment data exists anywhere: no gateway, no coupons, no
  partner/referral, no manual-approval UI (nothing to steal or abuse).

## NOT_IMPLEMENTED (later roadmap, do not assume)

Payments/billing integration (gateway, invoices, webhooks), coupon and
promotion codes, partner/referral programs, trials/grace periods,
proration, plan changes by users, an operator subscription console,
`plan:manage` grant path, entitlement changes audit trail,
database-backed subscription store, any PRO-only product feature itself
(scanning etc. arrive in later pumps). Per-plan usage limits themselves
ARE implemented as of Pump 5 (the single scan allowance — see
`docs/USAGE.md`); richer per-feature metering is not.
