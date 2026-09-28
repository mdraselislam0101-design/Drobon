# Payment and PRO upgrade foundation — Pump 15

## Scope and honest availability

Pump 15 adds a durable, manually reviewed FREE → PRO request foundation. It is not an online payment integration and does not verify money movement. `GET /api/v1/payments/config` reports `onlineGateway: UNAVAILABLE`; there is no payment-provider charge operation, production webhook, gateway credential, fake-success endpoint, or automatic verification. The current manual method vocabulary contains only `MANUAL_TRANSFER`. Default instructions explicitly tell users to contact support before sending money. A submitted reference is user-provided evidence only.

Exactly two plans remain: FREE and PRO. Price defaults to **BDT 1,000.00** (`PRO_PRICE_MINOR_UNITS=100000`, one BDT taka = 100 poisha) and is configurable only on the server. Currency is currently fixed to BDT. The client sends plan, price and currency only so the API can validate the displayed quote; the record is persisted from server configuration. Zero, negative, arbitrary, discounted or mismatched prices are rejected. Coupons and discounts are `NOT_IMPLEMENTED`. No commission, partner or referral attribution exists.

## Existing entitlement authority

Payments do not create a second PRO flag. Approval calls `UserRepository.activatePro()` on the existing account repository; the Pump 4 subscription record remains the only entitlement input, and the shared decision table grants `feature:pro` only for server-persisted `PRO + ACTIVE`. `UserType`, account role, payment request bodies and UI state cannot grant PRO. Existing FREE quota/device enforcement and the existing PRO scan exemption remain unchanged. Payment requests consume no scan quota.

## Records, lifecycle and API

The payment record and its audit events share one versioned JSON document (`PAYMENT_STORE_PATH`, default `.data/payments.json`), with mode `0600`, atomic same-directory temp-file + rename writes, fail-fast corruption handling, serialized single-process mutation, and a hard store capacity. Like the rest of the JSON persistence layer, it is a foundation store, not a multi-process database.

User routes (session identity determines the account; no account ID is accepted as authority):

- `GET /api/v1/payments/config` — current server plan, PRO quote, manual method/instructions and explicit gateway/coupon availability.
- `POST /api/v1/payments` — authenticated FREE account submits a PRO request, configured positive BDT amount, manual method and bounded reference. Requires an 8–128 character `Idempotency-Key`.
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

## Future gateway and partner boundaries

The provider seam currently resolves to provider `none` with `UNAVAILABLE` status. No webhook route exists. A future real provider must be explicitly configured and tested and must authenticate signed events, validate merchant/order/amount/currency, enforce replay/idempotency protection, and reconcile the provider transaction before it can activate PRO. No user-controlled `paymentStatus=SUCCESS` is accepted.

Partner/referral, discount/coupon, commissions, recurring billing, receipt uploads, automatic refunds and online bKash/Nagad/Rocket/bank integrations remain deferred. The generic `MANUAL_TRANSFER` label is not a claim that any specific financial institution or gateway is integrated. No security/vulnerability dataset is used or included.

## Verification

`apps/api/test/paymentApi.test.ts` uses synthetic local fixtures only for registration, submission, reviewer authorization, account/payment IDOR, exact pricing, idempotency, duplicate references, state transitions, rejection, cancellation, approval/recovery, audit privacy, rate limiting and JSON restart behavior. Web tests cover the user request panel, plain-text rejection display, honest unavailable states and reviewer UI. No real payment or external financial service is contacted. `npm run verify` is the full cumulative Pump 1–15 regression gate.
