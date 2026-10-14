# Partners, coupons and commissions — Pump 7

## Scope and honest model

Pump 7 adds an admin-selected partner program on top of the existing manual payment foundation. It is a **manual, server-authoritative, aggregate-only** system:

- There is no self-service partner signup, no referral-code system, no online redemption and no automated payout. The coupon code itself is the partner attribution identity.
- No external partner network, CRM, affiliate feed or dataset is contacted or bundled.
- Partners never see customer-level data — their dashboard is an aggregate projection, and the API enforces that boundary independently of the UI.

## Partner identity

- Only platform administrators (live `ADMIN` role **and** `PLATFORM_ADMIN_IDS` allowlist — the same dual gate as `docs/ADMIN.md`) can activate a partner. Any existing account may be selected; a user cannot activate themselves.
- One partner identity per user: a second activation for the same account returns `409`. Multiple distinct users may each become partners, each with a different coupon.
- Partner statuses: `ACTIVE` / `DEACTIVATED`. Deactivation blocks new coupon redemptions and new partner-quote resolution; reactivation restores them. Previously approved attributed payments keep their attribution snapshot.
- Activation grants **complimentary PRO** through the existing `UserRepository.activatePro()` path: entitlement only. It creates no payment record, adds no revenue, generates no commission and never appears in payment history.

## Coupons

- One primary coupon per partner, globally unique, normalized (trimmed, uppercased) and matched case-insensitively. Shape: 3–40 characters of `A–Z`, `0–9` and dashes.
- Coupon properties are server-owned: `status` (`ACTIVE`/`INACTIVE`), integer `discountPercent` (0–90), integer `commissionPercent` (0–50), optional `expiresAt` (ISO 8601 or null). All updates are admin-only and audited.
- Redemption validation at payment time is fail-closed: the partner must be `ACTIVE`, the coupon `ACTIVE` and unexpired. Unknown, inactive, expired or malformed codes are rejected with a uniform `422`.
- A coupon may be redeemed on unlimited payments, including by the partner's own accounts; each qualifying approved payment earns its own commission. The partner's complimentary PRO is never a coupon transaction.

## Payment integration

- `GET /api/v1/payments/quote?couponCode=…` (authenticated) returns the server-computed quote: base PRO price, discount percent, discount amount and final amount. Without a code it returns the base price with `coupon: null`.
- `POST /api/v1/payments` accepts an optional `couponCode`. The server re-resolves the coupon, recomputes the required amount and stores an immutable attribution snapshot on the payment record. Client-supplied discount, commission, price, partner identity or entitlement fields are never accepted; unknown body fields fail validation.
- Idempotency-Key semantics include the coupon: replaying an identical request returns the stored payment; reusing a key with a different coupon (or any other field) is a `409` mismatch.
- The payment state machine is unchanged (`PENDING → UNDER_REVIEW/APPROVING → APPROVED | REJECTED | CANCELLED`). Coupons never bypass reviewer authorization or the self-review prohibition.

## Commission

- Commission is created **only** when a coupon-attributed payment reaches `APPROVED`. Settlement is idempotent by payment: duplicate approvals, saga recovery and startup recovery (`recoverUnsettledCommissions`) never create a second commission.
- Amounts are integer poisha computed on the server: `collected = base − floor(base × discountPercent / 100)`, `commission = floor(collected × commissionPercent / 100)`. The remainder belongs to the business. Attribution snapshots (percent values frozen at payment creation) keep later coupon edits from rewriting history.
- Lifecycle: `PENDING → AVAILABLE → PAID`, advanced only by platform admins; each transition is audited. No other transitions exist; there is no automated payout integration.
- Rejected, cancelled or expired payments generate no commission. There is no refund/reversal flow in the current architecture — if refunds are ever added, commission reversal must be designed then rather than faked now.

## Routes

Partner self-service (session identity only):

- `GET /api/v1/partners/me/dashboard` — aggregate projection for the caller's own coupon; `404` for non-partners; rejects any query string.

Platform admin (dual allowlist gate):

- `GET /api/v1/admin/partners` — bounded list (`status` filter optional).
- `POST /api/v1/admin/partners` — activate `{ userId, couponCode, discountPercent, commissionPercent }` → `201`.
- `GET /api/v1/admin/partners/:partnerId` — summary + aggregates + audit trail.
- `POST /api/v1/admin/partners/:partnerId/deactivate|reactivate` — idempotent status changes.
- `PATCH /api/v1/admin/partners/:partnerId/coupon` — partial update of `status`, `discountPercent`, `commissionPercent`, `expiresAt`.
- `GET /api/v1/admin/partners/:partnerId/payments` — attributed-payment inspection: payment ID, account ID, status, amount, timestamps. References, proofs and customer contact details are deliberately excluded.
- `GET /api/v1/admin/commissions` — bounded list (`partnerId`/`status` filters optional).
- `POST /api/v1/admin/commissions/:commissionId/available|paid` — lifecycle transitions.

All routes use the uniform query-rejection discipline (unexpected/repeated query parameters → `422`), bounded pagination (`page ≤ 1000`, `pageSize ≤ 50`), strict ID shapes (`ptr_`/`cms_`/`pay_` UUID patterns → `404` on mismatch) and the dedicated payment-mutation rate limiter.

## Privacy boundary

The partner dashboard response contains **only**: coupon code/status/rules, partner status, complimentary-PRO grant timestamp, and aggregate counters (attributed/approved/rejected/cancelled counts, collected amount, commission totals). It never contains customer names, emails, account IDs, payment references or TrxIDs, projects, scans, findings, reports, SBOM, session data or rejection reasons. The API projection is the enforcement point; the UI merely renders it.

## Free vs paid accounts (anti-abuse rules)

- Multiple FREE accounts on one device share the single device-level FREE allowance (existing Pump 2 device-quota model, preserved unchanged); creating extra free accounts does not grant fresh free benefit.
- Multiple PAID accounts are allowed: each FREE account may independently pay for PRO, and coupon-attributed payments are unaffected by prior payments from the same person. Paid upgrades are never blocked by free-account history.
- The two rules cannot conflict because paid upgrade eligibility depends only on the account's own FREE subscription state, never on device identity.

## Persistence and security

Partner, coupon, commission and partner-audit records share one atomic JSON document (`PARTNER_STORE_PATH`, default `.data/partners.json`): temp-file `0600` write + rename, exclusive in-process mutation queue, fail-fast corruption handling, bounded capacities and duplicate-identity refusal at load time. `:memory:` is rejected in production, matching every other store. Audit details pass the credential-redaction pass before persistence; no customer secrets, payment proofs or raw authentication material are stored in partner audit events.

## Verification

`apps/api/test/partnerApi.test.ts` covers activation authority, one-identity/unique-coupon rules, complimentary PRO without payment history, coupon redemption/normalization/expiry, server-authoritative pricing and discount math, idempotent replay with coupon identity, approve → PRO + single commission, reject/cancel → no commission, commission lifecycle strictness, multi-partner isolation, multiple paid accounts per person, deactivation/reactivation semantics, dashboard privacy projection, cross-partner/cross-role authorization matrix, free-anti-abuse + paid-freedom coexistence, durable restart and recovery idempotence. Web tests cover the partner dashboard, admin console and coupon payment flow. `npm run verify` remains the cumulative gate; no security dataset or production data is introduced.
