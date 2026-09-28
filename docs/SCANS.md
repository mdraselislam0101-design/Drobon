# Scan Jobs (Pump 7 — secure orchestration; Pump 8–9 — real engines)

A Scan Job is a request to run ONE security scan of ONE type against
ONE project. Pump 7 established the secure orchestration boundary the
scanner engines plug into. **Pump 8 registered the first REAL engine:
SAST** (static analysis of the uploaded source snapshot — see
`docs/SAST.md`). **Pump 9 registers the second REAL engine: SCA**
(software-composition analysis of the snapshot's dependency manifests
— see `docs/SCA.md`). The boundary contract is unchanged:

- `SAST` scans complete with genuine, deterministic findings
  (rule id, severity, CWE, bounded redacted evidence, remediation) —
  analysis only, source files are never executed.
- `SCA` scans complete with a genuine, deterministic dependency
  inventory (direct/transitive with lockfile evidence), a CycloneDX
  1.5-subset SBOM and an honest assessment state — analysis only,
  manifests are never installed or executed. Without a loaded
  vulnerability-intelligence dataset the assessment is honestly
  `NOT_ASSESSED` with zero advisories (the dataset lock holds); the
  inventory and SBOM are still real. The SCA payload rides the same
  detail route as SAST findings (`scan.sca`, detail-only).
- **SECRETS and DAST still have no engine.** Those types remain
  supported job types of the orchestration layer with zero engines
  registered, so every such scan deterministically FAILS with
  `SCAN_ENGINE_NOT_IMPLEMENTED` — the system NEVER fabricates
  findings, results or "completed" states.
- **No vulnerability datasets.** No CVE/NVD/GHSA/OSV/KEV/EPSS data is
  imported, bundled or referenced — the dataset lock holds; real
  dataset integration is a separate later workstream.
- Everything below is covered by executable tests (see
  `docs/TESTING.md`).

## Ownership chain (server-authoritative, always)

```
Authenticated account (ownership source — never client-supplied)
  └── Project (Pump 6 — ACTIVE required for new scans)
        └── Scan Job (Pump 7 — this document)
              └── source snapshot (Pump 8 — the SAST/SCA scan target)
              └── engine results / findings (SAST findings; SCA inventory+SBOM;
                  SECRETS/DAST future)
```

The client may submit ONLY the scan type (plus an optional idempotency
key). The server derives — on every request — the account, the project
ownership, the entitlement (Pump 4), the quota decision (Pump 5), the
job id, the status, and every timestamp. Body fields such as `id`,
`projectId`, `ownerId`, `requestedBy`, `status`, timestamps, `result`,
`plan`, `role` or `userType` are unknown properties → **422**
(structurally impossible to inject; the prototype-chain keys
`__proto__`/`constructor` are rejected the same way — the Pump 6
validator fix).

## API

All routes require authentication and enforce the Pump 6 project
ownership policy first: unknown, foreign and malformed project ids
answer the SAME uniform 403 (no existence oracle). `AccountRole` and
`UserType` never grant access to another account's project or scans.

| Method | Path | Behavior |
| ------ | ---- | -------- |
| `POST` | `/api/v1/projects/:projectId/scans` | Request a scan. Body exactly `{ scanType }`. Project must be the caller's own AND `ACTIVE` (archived → `409 PROJECT_ARCHIVED`). Consumes quota atomically with creation. Returns `201` + the QUEUED scan, or a replayed scan (`200`). |
| `GET` | `/api/v1/projects/:projectId/scans` | The project's scans, server-ordered `createdAt` DESC then `id` ASC. |
| `GET` | `/api/v1/projects/:projectId/scans/:scanId` | One scan of the caller's own project **plus its engine payload** (Pump 8: COMPLETED SAST scans carry the full ordered, redacted findings list — the ONLY findings read surface; Pump 9: COMPLETED SCA scans carry `scan.sca` — summary, dependency inventory, manifest outcomes, SBOM and advisories — the ONLY SCA payload read surface). Unknown/malformed/foreign scan ids answer a uniform `404` there — scan lookup never leaves the caller's scope, so cross-account probing cannot distinguish "exists elsewhere" from "does not exist". |

There is deliberately **NO scan mutation endpoint** — no PATCH, no
DELETE, no status route. `PATCH`/`DELETE` on a scan answer `405 +
Allow`. The processor owns every transition.

## Quota + creation atomicity (the core guarantee)

- Scan creation consumes exactly **one** scan allowance, and the
  consumption and the durable job append are ONE linearized operation
  (`createScanWithQuota` runs inside the scan store's serialized
  mutation queue; the queue calls the Pump 5 `UsageService.consumeScan`
  — the single quota authority — and persists the job only on grant).
- FREE accounts: 3 scans per UTC calendar month per account, pooled
  with the shared-device allowance (the stricter of the two — Pump 5
  device anti-abuse unchanged). PRO + ACTIVE (`feature:pro`): exempt.
  Quota is account-wide: multiple projects are NOT a bypass, and
  neither is a different scan type.
- Denied → uniform `429 QUOTA_EXCEEDED` + `Retry-After` (next UTC
  month), nothing appended, no hint which limit tripped.
- Concurrency: 10 simultaneous FREE requests → exactly 3 grants.
  Replays and parallel requests cannot create a scan without a
  corresponding consumption, and cannot consume twice for one logical
  request. The only possible failure direction is fail-closed: a crash
  in the millisecond window between consumption and persistence can
  lose a consumed slot, NEVER grant a free scan (no job can exist
  without a consumed allowance — enforced by construction and tests).
- Project CRUD still consumes nothing; only scan-job creation does.

## Idempotency (retry safety)

- Optional `Idempotency-Key` header on creation: 8–64 chars
  (`[A-Za-z0-9_-]`), validated before anything is consumed. Malformed
  or duplicated (joined) keys → 422.
- Scoped to the authenticated account (another account's key is simply
  unknown — no cross-account interference, tested).
- Same key + same request (project + type) → the ORIGINAL scan is
  returned (`200`), no second consumption — even under 10 simultaneous
  retries.
- Same key + different request → `409 CONFLICT`.
- Bounded memory: the newest 20 keys per account are kept (oldest
  evicted first, deterministically); entries live in the durable store
  and survive restarts. The web client always sends a generated key
  (`crypto.randomUUID()`), so ordinary network retries are safe.

## Lifecycle (one server-authoritative path)

```
QUEUED ──→ RUNNING ──→ COMPLETED   (engine produced a real summary)
   │           └───→ FAILED        (deterministic failure)
   └───────────────→ FAILED        (never claimed + engine missing)
RUNNING at boot ────→ FAILED / SCAN_INTERRUPTED   (startup recovery)
```

- `QUEUED` → `RUNNING` happens exactly once per scan: claiming is a
  serialized store transition, so duplicate worker delivery cannot
  execute a job twice, and `COMPLETED → RUNNING` / `FAILED → RUNNING`
  do not exist.
- Terminal records are immutable: re-finalize attempts are no-ops.
- `COMPLETED` requires an engine-produced `resultSummary` (e.g.
  `{ findingsTotal: n }`); `FAILED` requires a closed-vocabulary
  `failureCode` + a safe bounded message. The shared guard enforces
  these invariants on every untrusted payload.
- Failure codes (scan-domain, stable, safe to expose):
  `SCAN_ENGINE_NOT_IMPLEMENTED`, `SCAN_INTERRUPTED`,
  `SCAN_ENGINE_ERROR` (orchestration) plus the Pump 8 SAST engine's
  closed set — `SAST_TARGET_NOT_FOUND`, `SAST_TARGET_TOO_LARGE`,
  `SAST_FILE_LIMIT_EXCEEDED`, `SAST_SCAN_TIMEOUT`, `SAST_INPUT_INVALID`,
  `SAST_UNSUPPORTED_LANGUAGE` — and the Pump 9 SCA engine's closed set
  — `SCA_TARGET_NOT_FOUND`, `SCA_TARGET_TOO_LARGE`, `SCA_INPUT_INVALID`,
  `SCA_MANIFEST_LIMIT_EXCEEDED`, `SCA_SCAN_TIMEOUT`,
  `SAST_UNSUPPORTED_LANGUAGE`. A crashed engine fails closed with a
  generic message — internals never leak.

## The engine boundary (Pump 8 registers the SAST engine)

`apps/api/src/scans/engines.ts` defines the only thing that may
produce a result: a server-side `ScanEngine` registry entry
(`execute(record, ctx) → completed|failed`), composed at process
startup — nothing client-facing can register, discover or influence
engines. Pump 8 registers the REAL SAST engine
(`apps/api/src/scans/sast/` — rules + engine, documented in
`docs/SAST.md`); `SCA`/`SECRETS`/`DAST` remain unregistered and fail
with `SCAN_ENGINE_NOT_IMPLEMENTED`. Future engines plug in here with
zero route/store changes. Test suites also inject synthetic engines to
prove processor edge cases (synthetic fixtures are allowed ONLY in
tests).

## The processor (worker integration)

`apps/api/src/scans/processor.ts` is the durable worker loop:

1. **claim** — the oldest QUEUED scan → RUNNING (persisted before
   observable);
2. **execute** — only the registered engine boundary (30s defensive
   timeout; a hung engine fails the scan closed);
3. **finish** — COMPLETED with the engine's summary **and findings**
   (Pump 8: persisted atomically with the terminal transition) or
   FAILED with a closed code (persisted);
4. **recover** — on boot, every RUNNING scan (a crash interrupted it)
   deterministically becomes FAILED/`SCAN_INTERRUPTED`, then QUEUED
   scans drain; a periodic sweep (5s, unref'd) backs the loop.

The durable scan store IS the queue — that is why processing survives
restarts, which the Pump 1 `apps/worker` in-memory runner/queue (a
foundation for future out-of-process engine hosts, unchanged here)
explicitly does not guarantee. Scan log lines carry
requestId/userId/projectId/scanId only — never account material.

## Persistence

Same minimum-persistence architecture as the account/usage/project
stores: one JSON document (`{ version: 1, scans: [...], idempotency:
[...] }`) at `SCAN_STORE_PATH` (default `.data/scans.json`, mode 0600,
gitignored), atomic temp+rename writes, serialized mutations,
persist-before-observable, fail-fast load validation:

- a corrupt document, an invalid record (state-machine violations
  included) or a dangling idempotency entry **refuses to start** —
  security state is never silently repaired;
- `:memory:` is rejected in production (scan state must persist);
- the stored record carries `ownerId` internally; responses never do,
  and the file contains no emails, passwords or device material;
- scans survive restarts with their terminal states, timestamps and
  idempotency entries intact (tested, including quota continuity).

## Project state rule

- `ACTIVE` project: scan creation allowed (subject to auth + quota).
- `ARCHIVED` project: new scans denied (`409 PROJECT_ARCHIVED`);
  historical scans stay listed and readable. Archiving never deletes
  scans, and project hard-delete does not exist (Pump 6 rule).

## Web

The project detail page carries a **Source snapshot** section and a
**Security scans** section (no separate dashboard):

- **Source snapshot (Pump 8):** honest empty state (no snapshot yet),
  metadata after upload (file count, bytes, timestamp — content is
  never read back), file picker → `PUT` (file names become paths; the
  server's path policy is the only policy), server-rejected uploads
  shown verbatim, archived projects cannot replace the snapshot.
- **Scans:** server-ordered scan list with honest status pills, a
  scan-type selector + request button (ACTIVE projects only), the
  quota/entitlement hint from the server's usage view, honest
  `FAILED/SCAN_ENGINE_NOT_IMPLEMENTED` rendering for engine-less types
  (never a fake completion), and — for COMPLETED SAST scans — a lazy
  **View findings** view: server-ordered findings with severity,
  rule, location, redacted evidence and remediation, all rendered as
  text (React escaping — an injection payload in evidence is
  displayed, never executed), plus a client-side severity filter that
  never triggers a second request. Fail-closed loading errors with
  retry. No scan state in localStorage/sessionStorage.

## Error contract

`PROJECT_ARCHIVED` (409, new stable code — emitted only for a project
the caller already owns, so it leaks nothing), `QUOTA_EXCEEDED` (429 +
Retry-After), `CONFLICT` (409, idempotency reuse with a different
request), `FORBIDDEN` (uniform 403, project-level), `NOT_FOUND`
(uniform 404, scan-level), `VALIDATION_ERROR` (422), standard
400/401/405/415. Scan failure codes are the scan-domain vocabulary
above, not HTTP codes.

## NOT_IMPLEMENTED (later roadmap, do not assume)

SAST/SCA/SECRETS/DAST engines themselves (parsing, taint analysis,
dependency resolution, secret detection, active DAST), vulnerability
datasets and matching, findings/records per finding, reports, SBOM,
remediation history, scan cancellation (deliberately absent — a
half-implemented cancel would be worse than none), per-scan artifacts
storage, scan scheduling/recurring scans, out-of-process engine
workers, project-level usage analytics, admin/operator scan
visibility.
