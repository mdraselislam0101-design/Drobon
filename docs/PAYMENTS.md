# Payment and PRO upgrade foundation — Pump 15

## Scope and honest availability

Pump 15 adds a durable, manually reviewed FREE → PRO request foundation. It is not an online payment integration and does not verify money movement. `GET /api/v1/payments/config` reports `onlineGateway: UNAVAILABLE`; there is no payment-provider charge operation, production webhook, gateway credential, fake-success endpoint, or automatic verification. The current manual method vocabulary contains only `MANUAL_TRANSFER`. Default instructions explicitly tell users to contact support before sending money. A submitted reference is user-provided evidence only.

Exactly two plans remain: FREE and PRO. Price defaults to **BDT 1,000.00** (`PRO_PRICE_MINOR_UNITS=100000`, one BDT taka = 100 poisha) and is configurable only on the server. Currency is currently fixed to BDT. The client sends plan, price and currency only so the API can validate the displayed quote; the record is persisted from server configuration. Zero, negative, arbitrary or mismatched prices are rejected. Since Pump 7, `GET /api/v1/payments/config` reports `coupons: SUPPORTED`: an optional partner coupon code may accompany a request, and the server recomputes the discounted amount itself (see the partner coupon section below). Online payment gateways, recurring billing and automatic refunds remain `NOT_IMPLEMENTED`.

## Existing entitlement authority

Payments do not create a second PRO flag. Approval calls `UserRepository.activatePro()` on the existing account repository; the Pump 4 subscription record remains the only entitlement input, and the shared decision table grants `feature:pro` only for server-persisted `PRO + ACTIVE`. `UserType`, account role, payment request bodies and UI state cannot grant PRO. Existing FREE quota/device enforcement and the existing PRO scan exemption remain unchanged. Payment requests consume no scan quota.

## Records, lifecycle and API

The payment record and its audit events share one versioned JSON document (`PAYMENT_STORE_PATH`, default `.data/payments.json`), with mode `0600`, atomic same-directory temp-file + rename writes, fail-fast corruption handling, serialized single-process mutation, and a hard store capacity. Like the rest of the JSON persistence layer, it is a foundation store, not a multi-process database.

User routes (session identity determines the account; no account ID is accepted as authority):

- `GET /api/v1/payments/config` — current server plan, PRO quote, manual method/instructions and explicit gateway/coupon availability (`coupons: SUPPORTED` since Pump 7).
- `GET /api/v1/payments/quote?couponCode=…` — optional server-authoritative quote: base price, and for a currently valid coupon the discount percent, discount amount and final amount. Unknown/inactive/expired coupons answer `422`; the quote never grants anything.
- `POST /api/v1/payments` — authenticated FREE account submits a PRO request, the server-computed amount (full price or quoted coupon total), manual method, bounded reference and an optional `couponCode`. Requires an 8–128 character `Idempotency-Key`. The server re-resolves the coupon and recomputes the amount; a coupon code alone never changes the price — amount and code must agree with the server quote.
- `GET /api/v1/payments` and `GET /api/v1/payments/:paymentId` — self-only, bounded history/detail.
- `POST /api/v1/payments/:paymentId/cancel` — owner can cancel only a still-PENDING request.

Reviewer routes are under `/api/v1/admin/payments`. Review access requires both the live server-resolved `ADMIN` account role and that exact user ID in `PAYMENT_REVIEWER_IDS`; neither an ADMIN role nor an allowlist entry for a non-ADMIN account is sufficient alone. The server checks both on every request, and reviewers cannot review, approve or reject their own submissions. Normal account administrators are deliberately insufficient unless a trusted operator separately places that exact account ID in the platform allowlist.

States and allowed lifecycle:

- `PENDING` — user submitted a reference; no payment verification has happened.
- `UNDER_REVIEW` — authorized reviewer started review.
- `APPROVING` — internal durable approval-saga reservation; PRO activation may be in progress and this is never presented as approved.
- `APPROVED` — an authorized, non-self reviewer explicitly accepted the request; the existing subscription is durably activated before the state is finalized.
- `REJECTED` — reviewer decision with bounded, normalized requester-visible reason; no entitlement mutation.
- `CANCELLED` — owner cancelled a request that had not entered review.

Approval and rejection retries are idempotent; final states cannot be reversed through these APIs. Duplicate active PRO requests, duplicate payment references, reused idempotency keys with different payloads, malformed/replayed mutations and invalid transitions are rejected. A rejected/cancelled request does not change subscription state.

## Consistency and audit limits

An approval spans two existing atomic JSON files (account/subscription and payment/audit), so there is no cross-file database transaction. The service uses a recoverable saga: persist `APPROVING` and the approval-start audit event first; persist PRO on the authoritative account record second; persist `APPROVED` and its audit event last. Startup recovery completes an interrupted `APPROVING` saga before the API begins listening. If an account mutation fails, the payment remains detectably `APPROVING` and the service fails closed rather than reporting approval. This is single-process/single-writer protection, not a distributed lock; do not run multiple API writers against these JSON stores.

Audit events include payment/account IDs, server-derived actor, previous/new state, timestamp and a bounded reason only where appropriate. Passwords, session tokens, provider credentials and private keys are not written to payment audit records or logs. Owner projections omit idempotency keys, reviewer IDs and audit events. Audit data and cross-account payment lists are reviewer-only. User list pages are bounded; stored records/event counts have hard caps and reject new writes rather than silently truncating financial history. Pump 16 adds a separate platform-admin payment-event audit projection (`coverage: PAYMENT_EVENTS_ONLY`) and per-account summary counts; it does not replace or widen the Pump 15 reviewer routes. See `docs/ADMIN.md` for the distinct platform-admin allowlist and audit limitations.

## Abuse, privacy and proof boundaries

Payment mutation routes use the existing global rate limiter plus a dedicated per-IP fixed-window limiter. Inputs are strict, unknown properties fail validation, amounts/currency/method are server constrained, transaction references are normalized and bounded, and no payment proof files or public URLs are accepted. The current store retains a reference as financial metadata; do not include passwords, credentials, card data or other secrets in it. Cross-account reviewer projections mask reference values that match credential/opaque-token patterns. Rejection reasons are length-bounded plain text, redact credential-like material before persistence, and render as text.

## Partner coupons and commissions (Pump 7)

The coupon model is deliberately manual and admin-provisioned — there is no self-service partner enrollment and no separate referral-code system. Full route/API detail lives in `docs/PARTNERS.md`; the payment-side facts:

- **Attribution is the coupon.** Admins activate an existing user as a partner with one globally unique coupon code (`A–Z0–9-`, normalized case-insensitively). That code is the only attribution identity; payments record an immutable attribution snapshot (coupon code, partner ID, base price, discount amount, commission percent) at creation time.
- **Server-authoritative pricing.** `GET /api/v1/payments/quote?couponCode=…` returns the base price and the server-computed discount/final amount. `POST /api/v1/payments` accepts an optional `couponCode`; the server re-resolves the coupon (partner ACTIVE, coupon ACTIVE, unexpired) and recomputes the required amount. A client-supplied amount must equal the server-computed total; discounts, commission rates, partner IDs and entitlements are never client-set. Invalid, inactive, expired or unknown coupons answer `422`.
- **Coupon is reusable and non-exclusive.** One coupon may be used on unlimited approved payments across any number of accounts, including the partner's own accounts. Redeeming a coupon never consumes a scan quota and never blocks a later paid upgrade.
- **Commission lifecycle.** An approved coupon-attributed payment settles exactly one `PENDING` commission (idempotent by payment; duplicate approvals or recovery replays never duplicate it). Admin transitions move it `PENDING → AVAILABLE → PAID`; rejected or cancelled payments create none. Commission = floor(collected amount × commission percent / 100); the remainder is business revenue.
- **Complimentary partner PRO.** Activation grants PRO entitlement via the same `activatePro()` path as paid approvals — entitlement only, never a payment record, revenue entry or commission trigger. Deactivating a partner stops new redemptions; previously attributed approved payments keep their snapshots.
- **Audit.** `PAYMENT_COUPON_ATTRIBUTED` joins the payment audit vocabulary; partner-side actions (activation, deactivation/reactivation, coupon configuration changes, commission lifecycle) are audited on the partner record with redaction applied to free-text details.

## Future gateway and partner boundaries

The provider seam currently resolves to provider `none` with `UNAVAILABLE` status. No webhook route exists. A future real provider must be explicitly configured and tested and must authenticate signed events, validate merchant/order/amount/currency, enforce replay/idempotency protection, and reconcile the provider transaction before it can activate PRO. No user-controlled `paymentStatus=SUCCESS` is accepted.

Partner coupons, discounts and commissions are implemented (Pump 7) as a manual, admin-provisioned, server-authoritative model documented in `docs/PARTNERS.md` — no online redemption, no payout automation, no referral-code system. Recurring billing, receipt uploads, automatic refunds and online bKash/Nagad/Rocket/bank integrations remain deferred. The generic `MANUAL_TRANSFER` label is not a claim that any specific financial institution or gateway is integrated. No security/vulnerability dataset is used or included.

## Verification

`apps/api/test/paymentApi.test.ts` uses synthetic local fixtures only for registration, submission, reviewer authorization, account/payment IDOR, exact pricing, idempotency, duplicate references, state transitions, rejection, cancellation, approval/recovery, audit privacy, rate limiting and JSON restart behavior. Web tests cover the user request panel, plain-text rejection display, honest unavailable states and reviewer UI. No real payment or external financial service is contacted. `npm run verify` is the full cumulative Pump 1–15 regression gate.
