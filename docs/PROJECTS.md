# Projects Foundation (Pump 6)

A Project is the primary user-owned container for source snapshots,
scan jobs, findings, SBOMs, and one optional DAST target. Pump 6
established the secure ownership boundary and CRUD lifecycle; later
pumps add bounded scan engines without changing that ownership model.
Everything here is covered by executable tests (see `docs/TESTING.md`).

## The model

| Field | Set by | Notes |
| ----- | ------ | ----- |
| `id` | server | `prj_` + `crypto.randomUUID()` — same convention as `usr_` account ids; never counters, never storage internals |
| `ownerId` | server | The authenticated account at creation. Stored internally, **never returned** (self-only API — the caller is by construction the owner of everything it can see) |
| `name` | client → validated | 1–120 chars, trimmed, NFC-normalized, no control characters (single line) |
| `description` | client → validated | 0–2000 chars, trimmed, NFC-normalized; tabs/newlines allowed (multi-line by design), all other control characters rejected |
| `status` | server only | `ACTIVE` (always at creation) or `ARCHIVED`; changes ONLY through the explicit archive/unarchive operations |
| `dastTargetUrl` | server-validated, owner-configured | Optional canonical HTTP(S) URL for the limited passive DAST engine; no owner or scan request claim can set it |
| `createdAt` / `updatedAt` | server | ISO-8601 UTC; `updatedAt` bumps on every successful mutation that changes something |

The public contract (`packages/shared/src/projects.ts`) exposes the
project fields `{ id, name, description, status, createdAt, updatedAt }`
and, only when configured, the optional `dastTargetUrl`. It never exposes
owner IDs, storage paths, or internal metadata. Guards reject forged
shapes, including cross-field junk (`status: 'DELETED'`, empty names,
malformed IDs, or a target on a non-HTTP(S) URL).

## Ownership (server-authoritative, always)

- Ownership comes from the authenticated session, nothing else. Body
  `ownerId`, headers, query parameters, hidden fields, cookies and
  localStorage are never consulted for ownership — an `ownerId` in a
  payload is an unknown property → **422** (tested).
- **AccountRole never grants ownership**: ADMIN and ACCOUNT_OWNER
  receive the same uniform denial as a stranger for another account's
  project (tested across MEMBER/ADMIN/ACCOUNT_OWNER × every UserType).
- **UserType never grants ownership**: DEVELOPER, STUDENT,
  SECURITY_PROFESSIONAL, PENTESTER are classification only.
- Future admin/operator visibility is a later, explicitly designed
  feature — access is deliberately NOT broadened now.
- Cross-account responses are indistinguishable from nonexistent ones:
  unknown, malformed, oversized and foreign ids all answer the SAME
  `403 FORBIDDEN` with the uniform message — no existence oracle, no
  IDOR (mirrors the Pump 3 `GET /api/v1/users` policy).

## API

All routes require authentication (anonymous → `401`) and ride the
existing middleware pipeline (security headers, CORS, rate limiting,
CSRF origin guard, session + device resolution).

| Method | Path | Behavior |
| ------ | ---- | -------- |
| `POST` | `/api/v1/projects` | Create. Body `{ name, description? }` only — strict validation rejects `ownerId`, `status`, `id`, timestamps and every other unknown property (422). Returns `201` + the project. |
| `GET` | `/api/v1/projects` | List OWN projects only (server-scoped; never frontend filtering). Ordered deterministically: `updatedAt` DESC, then `id` ASC. |
| `GET` | `/api/v1/projects/:projectId` | Read one of the caller's projects; anything else → uniform 403. |
| `PATCH` | `/api/v1/projects/:projectId` | Update `name` and/or `description` (at least one required — empty PATCH → 422). `status`/`ownerId`/`id`/timestamps are unknown properties → 422. |
| `POST` | `/api/v1/projects/:projectId/archive` | Explicit lifecycle operation (owner only, idempotent). |
| `POST` | `/api/v1/projects/:projectId/unarchive` | Explicit lifecycle operation (owner only, idempotent). |

Registered in every environment (these are real product features —
unlike the Pump 3 authz probes and the Pump 5 consume probe, nothing
here is dev/test-gated). Wrong methods answer `405` + `Allow`; unknown
paths `404`. The router's `:projectId` segments decode percent-encoding
safely (malformed encodings never match — never a 500) and empty
segments never match.

Ordering (documented contract): `updatedAt` DESC (most recently touched
first), then `id` ASC as the stable tie-breaker — identical for
identical data, on every request.

## Text security (untrusted input)

- Strict bounded validation (name 120, description 2000) + trim.
- **NFC Unicode normalization** — visually identical text has exactly
  one stored form (tested: decomposed `e` + combining accent stores as
  the composed `é`).
- Control characters (C0/C1) rejected — names fully; descriptions allow
  tab/newline only.
- **Stored verbatim as text; never rendered as HTML.** The API does not
  sanitize into HTML (that is a rendering concern); the Web renders
  project text through React's text escaping only — no
  `dangerouslySetInnerHTML`, no `innerHTML`, anywhere (tested with
  script/img/svg payloads: rendered as literal text, zero elements
  created).
- Prototype pollution: `__proto__`/`constructor` payloads are rejected
  as unknown properties (see the Pump 6 audit fix below) and never
  merged into any object.
- Log hygiene: project logs carry `requestId` + `userId` + `projectId`
  only — names and descriptions never enter logs (tested).

## Persistence

The same minimum-persistence architecture as the account (Pump 2) and
usage (Pump 5) stores — no database, no ORM, no queue infrastructure:

- One JSON document (`{ version: 1, projects: [...] }`) at
  `PROJECT_STORE_PATH` (default `.data/projects.json`, mode 0600,
  gitignored; `:memory:` for ephemeral dev/test — **rejected in
  production**, quota state must persist).
- Atomic writes: temp file + rename in the same directory.
- Every mutation runs inside the serialized in-process queue and
  persists BEFORE it is observable — concurrent creates cannot lose
  records, overwrite each other or duplicate ids (tested with 20
  concurrent creates and two accounts racing).
- Loaded at startup with full fail-fast validation: a corrupt document
  or an invalid record **refuses to start** (no silent erase; tested).
  The load-time text policy mirrors the API validation policy exactly
  (names: no control characters; descriptions: tab/newline allowed) —
  a store must always accept back what the API legitimately wrote
  (an early mismatch that could brick startup after a multi-line
  description was found in E2E and fixed with a regression test).
- Projects survive API restarts (tested, including status and edits).
- The stored record carries `ownerId`; the on-disk file contains no
  emails, passwords or other account material (tested).

## Usage and subscription boundaries

- **Project CRUD never consumes a scan.** Creating, listing, viewing,
  editing, archiving and unarchiving projects do not touch the Pump 5
  usage service at all (tested: the usage view stays `used: 0` after a
  full CRUD cycle). Real scan creation uses `UsageService.consumeScan()`
  through the existing server-authoritative scan lifecycle.
- **No invented plan limits.** Projects work identically for FREE and
  PRO. `UserType` does not determine project entitlements; ADMIN is not
  automatically PRO; creating projects grants nothing. Pump 4
  entitlements are not consulted by project routes at all (there is no
  project entitlement to check yet — inventing one is out of scope).
- Rate limiting: project routes sit behind the existing global
  per-IP fixed-window limiter like every other `/api/v1` route — no
  second limiter was introduced.

## Web

The existing authenticated app gained a Projects experience — no second
shell, no second client:

- `/projects` (protected, `minRole="MEMBER"`): list with status badges,
  honest empty state, loading state, fail-closed error + retry, and a
  create form (client-side bounds mirror the shared contract for
  instant feedback; the server re-validates and its 422 field issues
  are rendered per-field).
- `/projects/:projectId` (protected): view (name, status, description,
  id/created/updated facts), edit form (name/description only — no
  ownership or status fields exist in the form at all), explicit
  archive/unarchive buttons.
- A foreign/unknown/missing project renders the honest error — exactly
  what the server answered; nothing else.
- Anonymous users hitting either route get the established
  ProtectedRoute behavior (redirect to `/login` with a `from` path).
- No project state in localStorage/sessionStorage or the URL beyond
  the id itself; the server response is the only source of truth.
- Navigation: a "Projects" link joins the auth-aware header nav.

## Scans (Pump 7 — implemented foundation)

Scan jobs now exist: `POST/GET /api/v1/projects/:projectId/scans` +
`GET …/scans/:scanId`. Creating a scan consumes the account's scan
allowance exactly once, atomically with the durable job append (the
Pump 5 UsageService stays the single quota authority); ACTIVE projects
only (archived → 409 PROJECT_ARCHIVED, history stays readable); the
client may supply only the scan type (+ an idempotency key). Existing
SAST, SCA/SBOM, Secrets and bounded passive DAST engines use this same
lifecycle. See `docs/SCANS.md`.

## Existing findings and report relationship

```
Authenticated account (server-derived ownership)
  └── Project
        ├── source snapshot (SAST/SCA/SECRETS)
        ├── optional owner-configured DAST target
        └── Scan / Job (existing quota + lifecycle)
              ├── findings (SAST/Secrets/DAST) and bounded DAST observations
              ├── SCA inventory, CycloneDX-subset SBOM, honest intel state
              └── one persisted report per completed scan (JSON / Markdown)
```

Every child route resolves the caller's own project on the server before
reading findings or reports; a client-supplied `projectId`, `ownerId`,
role, UserType or plan is never authority. Findings and reports link
back to the stored project/scan context. Reports do not consume scan
quota. There are no placeholder scan records or relational schemas;
JSON stores remain the current durable persistence implementation. See
`docs/REPORTS.md`.

## DAST target configuration (Pump 11)

An owner may configure or remove one HTTP(S) target on their project
through the authenticated owner-only `PUT` / `DELETE
/api/v1/projects/:projectId/dast-target` routes. The target is validated
server-side, stored on the project, and omitted from scan request input;
DAST scan creation rechecks it before quota use and the engine rechecks
DNS before each bounded request. This is a limited passive HTTP feature,
not browser DAST; see `docs/DAST.md`.

## NOT_IMPLEMENTED (later roadmap, do not assume)

Multi-scan reports, PDF/signatures, remediation history, browser/full
DAST and active testing, per-plan project limits, project sharing/collaboration, organization
accounts, project deletion (hard delete is deliberately absent —
ARCHIVED is the lifecycle end-state until an explicit, authorized
deletion design exists), admin/operator project visibility,
project-level usage analytics, database-backed project store.
