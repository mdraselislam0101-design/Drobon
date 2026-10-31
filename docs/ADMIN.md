# Platform operations — Pump 16

## Authority model

Platform operations are read-only except for the existing Pump 15 payment-review workflow. An operations read requires both (1) the caller's **live** account role to be `ADMIN`, loaded through the session middleware on every request, and (2) the caller's server-configured ID to appear in `PLATFORM_ADMIN_IDS`. Neither a client-supplied role/UserType/`is_platform_admin` field nor an `ACCOUNT_OWNER` account role grants platform access. An ordinary account `ADMIN` is not automatically a platform administrator.

Payment review remains a distinct capability: each payment-review action requires the live `ADMIN` role and membership in `PAYMENT_REVIEWER_IDS`. Reviewers cannot review their own requests. An account being a platform administrator does not implicitly make it a payment reviewer; operators must configure both allowlists where both capabilities are intended.

Partner/coupon/commission management (Pump 7) is a platform-admin capability using the same `PLATFORM_ADMIN_IDS` + live-role dual gate: `POST /api/v1/admin/partners` (activate an existing user with a unique coupon and integer discount/commission rules), deactivate/reactivate, coupon rule updates (`PATCH …/coupon`), partner list/detail, attributed-payment inspection, commission listing and `available`/`paid` lifecycle transitions. Activation grants complimentary PRO as entitlement only — it never creates a payment, revenue or commission record. Full route detail and the business rules (one identity per user, coupon-as-attribution, commission lifecycle, partner privacy boundary) are documented in `docs/PARTNERS.md`. Partner mutations run under the dedicated payment-mutation limiter and produce audited events with redaction applied to free-text details.

Both allowlists default to empty. There is no API/UI for self-promotion, bootstrap, role changes, platform-ID edits, account deletion, account suspension, UserType mutation, or manual subscription adjustment. The account store does not currently model account status; account rows explicitly report `accountStatus: UNAVAILABLE`. The existing payment saga is the only supported subscription transition.

## Admin Complimentary PRO grants (entitlement ≠ payment)

Platform admins (same `PLATFORM_ADMIN_IDS` + live ADMIN-role dual gate) can grant a **persistent complimentary PRO entitlement** to any account without taking any payment:

- `POST /api/v1/admin/entitlements/pro` — body `{ accountId, expiresAt?, reason? }`. The server supplies the acting admin identity and timestamps; the client can never set a price, amount, plan level, actor, or commission (closed schema, fail-closed 422).
- `GET /api/v1/admin/entitlements/pro` — paged grant list (filters: `accountId`, `status`).
- `GET /api/v1/admin/entitlements/pro/audit` — the grants' own append-only audit trail (`coverage: ENTITLEMENT_EVENTS_ONLY`; the payment audit route remains `PAYMENT_EVENTS_ONLY`).
- `POST /api/v1/admin/entitlements/pro/:grantId/revoke` — revoke an ACTIVE grant (optional reason; second revoke conflicts).

Business rules (all enforced server-side and covered by tests):

- **A grant is NOT a payment.** It never creates a payment record, never touches the payment ledger, submitted/approved amounts, partner commissions, or coupon attribution. The user-facing payment history stays exactly as it was. `paymentRequired` is a fixed `false`.
- **Entitlement sources stay separate.** The account's persisted subscription is written ONLY by the payment approval saga (plus the legacy partner-complimentary activation, which shares that seam and is documented in `docs/PARTNERS.md`). Admin grants live in their own store (`.data/entitlements.json`, atomic JSON like the payment store) with their own lifecycle and audit. The two are never merged or re-labeled.
- **Effective plan** = PRO when the persisted subscription is PRO+ACTIVE **or** at least one ADMIN_GRANT is ACTIVE and unexpired; otherwise FREE. Consequently: revoking/expiring a grant with paid PRO underneath keeps the account PRO (paid survives); with nothing underneath the account returns to FREE. Grants never modify, reset, or delete paid state.
- **Persistence.** Grants survive logout/login, browser refresh, API restarts, and deployment restarts (durable JSON store; production refuses `:memory:`). No hardcoded user IDs or frontend flags exist.
- **Idempotency.** At most one effectively-active grant per account exists; duplicate submissions (including concurrent ones) return the existing grant unchanged (200 vs 201) and never duplicate audit effects. An EXPIRED grant no longer blocks a fresh grant.
- **Expiry** is derived at read time from `expiresAt` (nullable = open-ended, bounded at 3660 days ahead). No background mutator rewrites history.
- **Quota.** Effective PRO is quota-exempt exactly like paid PRO (3 scans/month FREE limit not applied). The usage counters are authoritative throughout; revoke/expiry falls back to the stored accounting without resets. UserType switching never creates or removes an entitlement.
- **Audit.** Every grant and revoke appends an immutable audit event with the server-derived actor; the client cannot forge actor, time, or outcome. Free-text reasons are sanitized/redacted like all admin free text.
- **Presentation.** `GET /api/v1/subscription` reports `proEntitlementSource: ADMIN_GRANT | PAID` only when an active admin grant or an auditable paid activation supports it. The field is omitted for FREE and for PRO with unverified provenance (including legacy or partner-issued subscriptions). The Account page distinguishes an admin grant and shows an unverified-source badge when appropriate. No fake receipts, amounts, or transactions are shown anywhere.
- **Database separation.** The grant store is the existing local JSON persistence seam (application-level). Any future migration of entitlements to a production database belongs to the separate Database / Production Data workstream; no production schema or data ships with this feature.

## Read routes and bounds

All routes below require authentication, platform allowlist + live role authorization, the dedicated `ADMIN_RATE_LIMIT_*` limiter, strict query-key validation, and bounded page sizes/page numbers. Responses use closed shared runtime guards.

- `GET /api/v1/admin/dashboard` — aggregate counts from the loaded account/subscription, project, scan/finding, and payment records. It rejects query parameters.
- `GET /api/v1/admin/accounts` — redacted account projection and per-account payment summary. Supports page/pageSize, role, UserType, plan, and bounded email search. Account roles and subscriptions are read-only here.
- `GET /api/v1/admin/scans` — metadata-only scan pages, filterable by status, type, account, project, and bounded calendar-date range. Does not return DAST target URLs, source, findings, worker internals, or failure messages.
- `GET /api/v1/admin/findings` — metadata-only finding pages, filterable by severity, scanner, lifecycle state, project, and bounded date range. Includes a within-scan ordinal instead of the stable finding ID (which is derived from a fingerprint hash). It does not expose finding IDs/hashes, source paths, target URLs, titles, descriptions, evidence, remediation text, or private source.
- `GET /api/v1/admin/audit` — paginated payment audit events with action/account/payment/date filters. It explicitly returns `coverage: PAYMENT_EVENTS_ONLY`; it is not a full system-wide audit.

Page limits are at most 50 accounts, 100 scans, 100 findings, or 100 payment audit events per response. Page-number ceilings cap each listing at a finite visible range; date ranges are limited to 366 days. No export, arbitrary store query, write operation, or unbounded route is provided. Existing reviewer-only `/api/v1/admin/payments` remains the sole cross-account payment list and is not duplicated under the platform routes.

## Privacy and audit boundaries

Account projections exclude password hashes. Scan and finding list projections are deliberately narrower than project-owner detail APIs and omit private source and DAST target material. The UI only renders the fields returned by these read projections. No finding fingerprint or stable finding ID is sent by the platform findings index.

Payment audit records are appended to the same bounded JSON payment document as payment events and persisted atomically before a state transition becomes visible. Free-form rejection reasons are redacted before persistence and again at cross-account administrative projections; reviewer-visible references that match credential/opaque-token patterns are shown as `REDACTED` (the submitter can still see their own submitted reference). Capacity/corruption errors fail closed rather than silently deleting history. This is an append-only application behavior within one local store, **not cryptographic immutability**, tamper-evident storage, or complete audit coverage. Account role and UserType changes are not implemented or audited because no such mutation route exists.

The dashboard is intentionally conservative: API `SERVING` only means it answered the request; the browser/web is `NOT_ASSESSED`; JSON account/payment state is `LOADED_AT_STARTUP` or `EPHEMERAL`; an API-attached scan processor is `RUNNING`/`NOT_STARTED`, while a separate worker is `NOT_INTEGRATED`; assistant behavior is deterministic/read-only with AI provider `NONE`; online payment gateway is `UNAVAILABLE`; vulnerability/security datasets report `NO_DATA_LOADED` / `SEPARATE_NOT_LOADED`. DAST observations and submitted/approved payment totals are not proof of independent verification, money movement, or revenue.

The stores are local JSON, single-process/single-writer foundation stores. Corrupt stores refuse startup, so no dashboard response with invented zero counts is emitted for them. There is no external dataset import, vulnerability catalog, separate production worker, online payment service, or generative AI provider implied by this console.

## Verification

API boundary, filters, pagination, authentication/allowlist/live-role checks, rate limiting, redaction, status wording, and partial audit coverage are covered by `apps/api/test/adminApi.test.ts` and `packages/shared/test/admin.test.ts`. Dashboard, denial, read-only account wording and payment-audit scope are covered by `apps/web/test/adminOperationsUi.test.tsx`. These are unit/API/UI tests, not an end-to-end browser test.
