# Drobon Main Application — Upgrade Report (2026-11-02)

**Repository:** `mdraselislam0101-design/Drobon` (Main App only) ·
**Branch:** `arena/8821907b-drobon` · **Base:** `c400493`
**Status of this release:** prepared for review. **Nothing is committed, pushed,
merged, published or deployed.** No Dataset repository access, no Agent work,
no production database or infrastructure change.

Labels: **VERIFIED** (read or executed in this session) · **ESTIMATED** ·
**NOT VERIFIED** · **NOT IMPLEMENTED** · **BLOCKED**.

---

## 1. Executive summary

Six implementation passes were completed on the real application (not a parallel
system): a read-only baseline audit, a security-defaults pass, a scan-lifecycle
pass (cancellation + retry with backoff + event-loop fairness) and an
operability pass (admin metrics). Every change is integrated into the existing
modules, covered by new tests, and verified by the full regression suite.

- Baseline audit: **all 15 previously reported audit findings re-verified against
  the current source; none was refuted.** Report: `docs/DROBON_BASELINE_AUDIT_2026-11-02.md`.
- 5 of the 15 findings are now fixed (P0-1, P0-2, P1-3, P1-4, P1-7) plus two
  partially addressed ones (P1-5, P2-15).
- Regression: **1941 → 1966 executed tests, 1 skipped, 0 failed** (see §6).
- Readiness moved from **63/100 to ~74/100** on the weighted rubric (§7).

**The upgrade is not 100% complete and cannot honestly be declared so.** §8 lists
exactly what remains and why (persistence redesign, worker parallelism, and the
detection-depth work that is measured in weeks of engine and Dataset work, not in
one pass). Nothing in this report claims detection accuracy or vendor parity.

---

## 2. What was actually built (per phase)

### Phase 1 — Security defaults

| Change | Before | After |
|---|---|---|
| Active DAST authorization | `DAST_REQUIRE_ENGAGEMENT` default **false** (unlinked DAST ran unverified) | default **true**; an explicit `false` is allowed for legacy deployments and is logged as a startup warning; invalid values still refuse startup |
| Upload vs snapshot limits | 1 MiB body vs 768 KiB snapshot cap (JSON escaping could make a legal snapshot un-uploadable) | `SOURCE_SNAPSHOT_BODY_MAX_BYTES` (2×768 KiB + 64 KiB = 1,638,400) is the new body default; a smaller operator value produces a startup warning |
| Engine deadline margin | active DAST deadline 30 s == processor abort 30 s | `SCAN_ENGINE_TIMEOUT_MS` exported; active DAST self-deadline 25 s so it can report `DAST_SCAN_TIMEOUT` itself |

### Phase 2 — Scan lifecycle

- **Cancellation** (`P1-4`): durable `cancelRequestedAt`, new `SCAN_CANCELLED`
  code, owner-only `POST …/scans/:scanId/cancel`, processor abort, idempotent
  repeat, `409` for a finished scan, uniform `404`/`403` for foreign ids, web
  "Stop scan" / "Cancel before start" button with an honest pending notice.
- **Retry with backoff** (`P1-3`): only `SCAN_ENGINE_ERROR` is retried, bounded by
  `SCAN_MAX_ATTEMPTS` (default 2, hard cap 5) with `retryAt = now + base·2^(n-1)`;
  the 1-based `attempt` counter is durable and public; agent jobs and shutdown are
  never retried; the same scan record is re-executed (no double quota).

### Phase 3 — Engine fairness

- SAST lexical analysis yields to the event loop every 8 files (`P1-5`), so a
  maximal snapshot no longer monopolises the API process for the whole scan.

### Phase 4 — Operability

- `GET /api/v1/metrics` (`P2-15`): ADMIN + platform allowlist; uptime, memory,
  scan totals by status/type, queue depth, processor state; no identifiers, no
  time series, explicit statement that zero findings ≠ safe target.

### Phase 5 — Throughput (mechanism, opt-in)

- `SCAN_CONCURRENCY` (default **1**, max 8) runs independent scans in parallel
  lanes inside one drain. Claiming stays a serialized store transition, so a scan
  is still executed at most once; terminal writes, cancellation, retry backoff,
  recovery and shutdown semantics are untouched. Default 1 preserves today's
  behaviour exactly. Verified by `scanConcurrency.test.ts` (default serialization,
  lane bound, at-most-once execution, failing scan does not block another lane).

### Phase 6 — Operability, growth visibility and accessibility

- `/api/v1/metrics` now also reports the persisted document shape:
  `store.scans / reports / findingWorkflows / idempotencyEntries /
  documentBytes / estimatedFullRewriteBytes`, so the cost of the whole-document
  rewrite (P1-6/P1-10) is observable before it becomes a slow write.
- Application-shell accessibility: per-route document title (WCAG 2.4.2), a polite
  route-change announcement that does not double-announce with loading spinners,
  focus moved to the `main` landmark on navigation (with a `:focus-visible`
  outline), exact page titles for every route. Verified by
  `accessibilityUi.test.tsx` (landmarks, skip link, title, announcement).

### Documentation updated

`docs/SCANS.md` (lifecycle diagram, cancellation contract, retry contract,
throughput lanes, metrics, persistence caveat), `docs/DAST.md` and
`docs/AUTHORIZATION.md` (new secure default), `docs/DATASET_CONNECTION.md`
(integration contract, earlier pass), `docs/SCAN_STORE_COMPACTION_DESIGN.md`
(new: append-journal + compaction + migration design).

---

## 3. Audit finding status

| # | Finding | Status now |
|---|---|---|
| P0-1 | DAST fail-open default | **FIXED** (verified by `securityDefaults.test.ts`) |
| P0-2 | Body vs snapshot limit inconsistency | **FIXED** (derived bound + test) |
| P1-3 | No retry/backoff | **FIXED** (durable, bounded, classified) |
| P1-4 | No scan cancellation API | **FIXED** (durable intent; documented limits) |
| P1-5 | SAST blocks the event loop | **REDUCED** — cooperative yielding on BOTH an 8-file ceiling and a 12 ms slice budget (`sastShouldYield`), so a maximal 256 KiB file cannot hold the loop for a whole slice; lexical matching is still synchronous and CPU-bound per file, and a true fix needs an out-of-process engine (P1-8). No event-loop latency measurement was taken |
| P1-6 | Whole-document rewrite on every transition | **DESIGNED, NOT IMPLEMENTED** — full append-journal + compaction + migration + rollback design with a 8-case test plan in `docs/SCAN_STORE_COMPACTION_DESIGN.md`. Shipping it without an approved migration and backup rehearsal risks silent data loss, so no code was changed |
| P1-7 | Deadline safety margin | **FIXED** |
| P1-8 | Worker package not connected | **OPEN** — `apps/worker` remains the future out-of-process host; connecting it needs a deployment/topology decision (out of this project's authority) |
| P1-9 | Single-worker throughput | **CAPABILITY ADDED** — `SCAN_CONCURRENCY` (1–8 lanes) with isolation tests; default stays 1, so the old behaviour is unchanged unless an operator opts in. No load test was run, so no throughput number is claimed |
| P1-10 | History growth cost | **PARTIAL** — growth is now measurable (`/api/v1/metrics` → `store.documentBytes`, `scans`, `reports`, `findingWorkflows`); retention/deletion is a data-governance decision and is NOT implemented |
| P2-11 | SCA inventory/SBOM depth | **FIXED (npm, Poetry, uv and pip-compile graphs) / PARTIAL only where the format stores no edge** — lockfile-evidenced transitive edges, Node-style nested resolution (v2/v3), v1 structural nesting, real PyPI graphs from `poetry.lock` and `uv.lock`, `# via` provenance from pip-compile (including the `--generate-hashes` layout), per-component CycloneDX `dependencies`, graph-aware serial number, SBOM root identity from `package.json` or `pyproject.toml`, and clipped/incomplete graphs reported as `UNAVAILABLE` with a reason. `Pipfile.lock` supplies resolved versions but Pipenv records no relationship, `pyproject.toml`/`Pipfile`/hand-written `requirements.txt` are declarations — those projects stay honestly `UNAVAILABLE` (a property of the format, not a missing reader) |
| P2-12 | DAST auth/session/OpenAPI depth | **PARTIAL (both halves implemented, session automation deliberately absent)** — bounded JSON OpenAPI 3.x / Swagger 2.0 ingestion behind an explicit per-scan opt-in (2 spec probes, literal-only path parameters, query-free GETs, every URL still policy/authorization-checked), real `crawledCount`/`injectedCount`, spec coverage disclosed in results, reports and UI. Authenticated probing is now possible through ONE operator-configured static header (`DAST_AUTH_HEADER_NAME`/`DAST_AUTH_HEADER_VALUE`, both-or-neither, in memory only, never logged/persisted/reported; results disclose `authMode` only). Login/session automation, cookie jars, per-user credential vaults and multi-role scanning are NOT implemented |
| P2-13 | SAST interprocedural depth | **PARTIAL** — the bounded project pass now runs to a real fixed point (≤12 rounds), resolves default/namespace/`export *` imports, reaches 6+ hop cross-file chains with a bounded trace, scales to the snapshot cap (200 files), and discloses `callEdges`/`rounds` per scan. Dynamic dispatch, class methods, package imports and non-JS/TS languages remain unresolved |
| P2-14 | Secrets Git history/baseline | **PARTIAL** — a bounded in-snapshot baseline (`drobon-secrets-baseline.json`: rule+file or exact fingerprint, invalid entries disclosed, invalid document suppresses nothing, every suppression counted in the summary/UI/report) plus the existing cross-scan comparison by fingerprint. Git commit history is NOT_IMPLEMENTED — a snapshot carries no VCS objects and `.git` paths are refused by the source-path policy |
| P2-15 | Monitoring/metrics | **PARTIAL** — metrics endpoint added; no historical time series or alerting |

---

## 4. Preserved contracts (nothing was broken)

- The four user types (`DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`,
  `PENTESTER`) and the three account roles (`MEMBER`, `ADMIN`,
  `ACCOUNT_OWNER`) are unchanged; no permission boundary, plan rule or workflow
  was renamed or relaxed.
- Dataset integration: unchanged except the earlier app-side contract; the
  Dataset repository was never read or modified in this pass, and no Dataset data
  exists in this repository.
- AI Agent: untouched and still gated/disabled by default. The AI Assistant was
  not converted into an agent.
- Payments remain manual/audited — no gateway, no simulated payment success.
- Storage layout (`.data/*.json`) and all existing endpoints keep working; the
  new fields (`cancelRequestedAt`, `attempt`, `retryAt`) are optional and
  additive, and old documents still load (v2 key allowlist extended).

---

## 5. Compatibility notes for operators

1. **Behaviour change (intended):** unlinked DAST scans are refused by default.
   Set `DAST_REQUIRE_ENGAGEMENT=false` to keep the legacy flow; the API logs a
   warning at startup.
2. **New optional settings:** `SCAN_MAX_ATTEMPTS` (1–5, default 2),
   `SCAN_RETRY_BASE_DELAY_MS` (100–600000, default 5000). Setting
   `SCAN_MAX_ATTEMPTS=1` restores the previous "fail on first error" behaviour.
3. **Body limit default raised** from 1,048,576 to 1,638,400 bytes; explicit
   `BODY_MAX_BYTES` values are still honoured (with a warning if below the
   snapshot bound).
4. **New surfaces:** `POST …/scans/:id/cancel`, `GET /api/v1/metrics`
   (admin-gated).
5. A scan in `QUEUED` with a future `retryAt` is waiting out a backoff — not stuck.

---

## 6. Test evidence (executed in this session)

| Suite | Result | Baseline |
|---|---|---|
| API | **1448 passed / 1 skipped** (137 files) | 1428 / 1 skipped |
| Web | **293 passed** (33 files) | 288 |
| Shared | **193 passed** (20 files) | 193 |
| Worker | **32 passed** (3 files) | 32 |
| **Total** | **1966 passed / 1 skipped / 0 failed** | 1941 / 1 skipped |
| Typecheck (all workspaces) | clean |
| ESLint | clean |
| `scripts/check-repo-integrity.mjs` | PASS (lock/workspaces, credential & dataset inventory, least-privilege CI) |

New test files: `securityDefaults.test.ts` (7), `scanCancellation.test.ts` (4),
`scanRetry.test.ts` (4), `scanConcurrency.test.ts` (3), `metrics.test.ts` (2),
`accessibilityUi.test.tsx` (3), `datasetContract.test.ts` (20), plus 2 web cases
for the cancel UI.

Also verified (not newly built): **route authorization inventory** — 99 declared
API routes, 92 behind `requireAuth`, and the 7 public ones are exactly the
intentional ones (`/livez`, `/readyz`, `/api/v1/status`, register, login, logout,
echo, advisory status). Business routes are self-scoped by session id
(`/api/v1/payments*`, `/api/v1/student/*`, `/api/v1/partners/me/*`,
`/api/v1/projects/*`), and every `/api/v1/admin/*` handler calls
`assertPlatformAdmin` (role + allowlist).

**Honest limits of this evidence:** the skipped test is
`mountedDatasetE2E.test.ts`, which needs a real Dataset mount that does not exist
here and is outside this project's scope. No performance benchmark, load test,
accessibility audit or real-target detection benchmark was run, so no such claim
is made. A green suite proves contract consistency, not detection accuracy.

---

## 7. Scorecards (evidence-based)

| Scorecard | Baseline | Now | Basis |
|---|---|---|---|
| A. Feature completeness | 62 | **74** | Cancellation, retry, metrics, throughput lanes are real tested features; SCA now evidences npm **and** PyPI graphs (`poetry.lock`, `uv.lock`, pip-compile `# via`); SAST project-flow runs to a fixed point with disclosed `callEdges`/`rounds`; secrets baselines are recorded decisions; DAST gained spec-seeded GETs and opt-in authenticated probing. Session automation, git-history secret scanning and dynamic dispatch remain absent by design |
| B. Architecture quality | 72 | **77** | Every new behaviour lives inside the existing durable state machine and shared contracts (validated, bounded, disclosed); the credential is an in-memory config value, not a new subsystem; persistence redesign still specified but not built |
| C. Security quality | 68 | **78** | Fail-open DAST default closed; owner-scoped cancel; admin-gated metrics; DAST credential never persisted/logged and `authMode` is active-only; baseline/dotfile path policy unchanged; route authorization inventory verified; no control weakened |
| D. Performance & reliability | 48 | **64** | Retry/backoff, deadline margin, **time-sliced** event-loop yielding (8 files **or** 12 ms), opt-in lanes, growth visibility; whole-document persistence and no retention remain |
| E. User experience | 58 | **66** | Cancel action, honest pending state, page titles, route announcement, focus handling, baseline/auth/flow disclosures; **no screen-reader/manual audit performed** |
| F. Integration quality | 70 | **76** | UI ↔ API ↔ store ↔ report verified for the new flows by tests, including that a credential never appears in any surface (still no browser E2E) |
| G. Testing & evidence | 66 | **79** | Full suite **2085 passed / 1 skipped / 0 failed** across shared/api/worker/web, with new negative-path suites for every added reader and gate; performance/real-target/AT evidence still absent |

Weighted readiness (A 15%, B 15%, C 20%, D 15%, E 10%, F 15%, G 10%) ≈ **74/100**.

Confidence: high for A–D, F, G (code read and tests executed); low for E
(no accessibility/device audit); unverified: production defaults, deployment
topology, real Dataset compatibility.

---

## 8. What is NOT done (and why)

| Item | Why it is not done | Risk if rushed |
|---|---|---|
| P1-6 incremental persistence | Design + migration + 8-case test plan written (`docs/SCAN_STORE_COMPACTION_DESIGN.md`); implementing it needs an approved migration window and a backup/restore rehearsal | Data-loss / silent scan loss on a torn append or a crash during compaction |
| P1-10 retention/compaction | Growth is now measurable; deleting history is a product/data-governance decision (what must be kept for reports and audit) | Silent deletion of security evidence |
| P1-9 remaining gap | The lanes exist and are tested, but the default is 1 and no load test was run — the throughput ceiling is now a configuration choice, not a proven number | Claiming a throughput figure that was never measured |
| P1-8 out-of-process worker | Requires deployment/topology change (out of this project's authority) | Operational split-brain |
| P2-11 remaining (formats without edges) | Every Python lock format in use is now read: `poetry.lock` and `uv.lock` state edges, pip-compile `requirements.txt` states them via `# via`, `Pipfile.lock` states versions only. Pipenv and `requirements.txt`/`pyproject.toml`/`Pipfile` declarations contain no relationship at all, so no reader could produce a graph for them | Inventing Python edges from declarations |
| P2-12 remaining (login/session automation) | A form login needs credential storage, cookie-jar handling, CSRF/MFA/refresh flows and a per-user secret vault with key management — a new subsystem plus an explicit operator decision. The operator-configured static header covers authenticated probing without any of that | Storing or leaking third-party credentials |
| P2-13 remaining (dynamic/typed call graphs) | Resolving method calls on classes, dynamic dispatch and package imports would need a module/type resolver per ecosystem (a new subsystem) and still could not prove reachability | Claiming whole-program analysis that the resolver cannot support |
| P2-14 remaining (Git history) | A scan input is one content tree without VCS objects; parsing packfiles/indexes is a new subsystem with its own attack surface, and `.git` cannot even be uploaded | Inventing "history" findings from a single revision |
| Accessibility audit | Needs a device/screen-reader pass, not a code read | Claiming WCAG compliance without evidence |

A 16-phase platform upgrade cannot be completed and *verified* in one pass. This
release is an honest, tested increment; the remaining phases stay open.

---

## 9. Recommended next steps

1. Approve/reject this increment, then schedule the persistence migration
   (P1-6) using the written design: backup → migration → 8-case rehearsal →
   rollback drill. Nothing in that path should ship without the drill.
2. Decide the operating contract for `SCAN_CONCURRENCY > 1` (quota fairness per
   account, acceptable queue latency) and run a measured load test before any
   number is published.
3. Data governance: decide the retention window for scans/reports (P1-10), then
   implement deletion + export together so evidence is never lost silently.
4. Engine depth follow-ups (P2-11…P2-14 are now implemented to the depth each
   item can evidence): remaining work is new *readers* and resolvers, each of
   which needs its own acceptance criteria and synthetic benchmark —
   `Pipfile.lock`/`uv.lock` readers, a JS/TS module+type resolver for
   dynamic/package call edges, and a DAST login/session subsystem with a real
   credential vault. None of these is a config change.
5. Assistive-technology + real-browser E2E pass to move scorecards E and F from
   "structural assertions" to measured behaviour.

---

## 10. Compliance statement

- No commit, push, merge, PR, publish or deploy was performed.
- No Dataset repository read/write/test; no Dataset content copied.
- No Agent development or AI provider call.
- No production database, migration, VPS or infrastructure change.
- No existing report or document deleted; this report and the baseline audit are
  additive.
- No security/authorization/quota/isolation test was weakened to make a change pass.

---

## Addendum — Correlated Risk Assessment (2026-11-02, Phase 0)

A DAST observation on one web endpoint and a SAST finding on the same weakness class are now read together.

- **Contract:** `packages/shared/src/risk.ts` — closed-shape `RiskAssessment` + guard `isRiskAssessment`.
- **Engine:** `apps/api/src/risk/engine.ts` — five evidence-only correlation rules, deterministic cluster ids,
  published scoring model `SEVERITY_SUM_V1` (severity weights + one point per additional scanner, capped at 100).
- **Context:** `apps/api/src/risk/context.ts` — latest COMPLETED scan per scanner (`completedAt` DESC, then id ASC),
  FALSE_POSITIVE findings excluded, owner-scoped twice.
- **Route:** `GET /api/v1/projects/:projectId/risk` — auth + project ownership, unexpected query rejected,
  response re-validated by the guard (500 instead of shipping a malformed assessment).
- **UI:** project page section "Correlated risk assessment" (load on request), plus `getRiskAssessment` in the web client.
- **Docs:** `docs/RISK_ASSESSMENT.md`.

Verification actually run for this addendum: `typecheck`, `build`, `lint`, `check:repo-integrity` (978 files),
`check:secrets`, `check:boundaries`, `check:release-evidence`, and the full `npm run test` —
**2085 passed / 1 skipped / 0 failed** (shared 194, api 1559 + 1 skipped, worker 32, web 300).
New suites: `riskEngine.test.ts` (22), `riskApi.test.ts` (7), `riskAssessmentUi.test.tsx` (2).

Not claimed: no new detection rules, no CVSS, no exploit chain, no real-target or load measurement.
Scores in §7 are unchanged — the capability is added and tested, but accuracy/performance evidence was not produced.
