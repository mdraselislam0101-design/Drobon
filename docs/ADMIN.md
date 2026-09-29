# Platform operations — Pump 16

## Authority model

Platform operations are read-only except for the existing Pump 15 payment-review workflow. An operations read requires both (1) the caller's **live** account role to be `ADMIN`, loaded through the session middleware on every request, and (2) the caller's server-configured ID to appear in `PLATFORM_ADMIN_IDS`. Neither a client-supplied role/UserType/`is_platform_admin` field nor an `ACCOUNT_OWNER` account role grants platform access. An ordinary account `ADMIN` is not automatically a platform administrator.

Payment review remains a distinct capability: each payment-review action requires the live `ADMIN` role and membership in `PAYMENT_REVIEWER_IDS`. Reviewers cannot review their own requests. An account being a platform administrator does not implicitly make it a payment reviewer; operators must configure both allowlists where both capabilities are intended.

Both allowlists default to empty. There is no API/UI for self-promotion, bootstrap, role changes, platform-ID edits, account deletion, account suspension, UserType mutation, or manual subscription adjustment. The account store does not currently model account status; account rows explicitly report `accountStatus: UNAVAILABLE`. The existing payment saga is the only supported subscription transition.

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
