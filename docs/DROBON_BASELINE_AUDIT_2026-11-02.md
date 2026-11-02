# Drobon Main Application — Baseline Audit (2026-11-02)

**Mode:** Existing application upgrade · pre-implementation baseline
**Repository:** `mdraselislam0101-design/Drobon` (Main App only)
**Branch:** `arena/8821907b-drobon` (base commit `c400493`)
**Nature of this document:** read-only inspection. No implementation change was
made to produce it.

Labels used throughout: **VERIFIED** (read in current source and/or executed now),
**ESTIMATED** (reasoned, not measured), **NOT VERIFIED** (not checked),
**NOT IMPLEMENTED**, **BLOCKED**.

---

## 1. Workspace baseline (recorded before any change)

| Item | Value |
|---|---|
| Branch | `arena/8821907b-drobon` |
| HEAD | `c400493` (merge of PR #8) |
| Staged changes | none |
| Modified (unstaged) | 24 files |
| Untracked | 14 files |
| Diff size | 636 insertions / 18 deletions |
| Workspaces | `apps/*`, `packages/*` (api, web, worker, shared) |

The uncommitted set is prior approved-scope work (rounds 1–5: storage boundary,
per-job scan boundary, agent capability/orchestration contracts, Dataset
integration contract). It is preserved untouched by this audit.

---

## 2. Architecture as it actually exists — **VERIFIED**

| Layer | Reality |
|---|---|
| HTTP API | Custom Node `http` server + hand-rolled router (`apps/api/src/http.ts`, `server.ts`, `app.ts`). No Express/Fastify dependency. |
| Persistence | 11 JSON document stores under `.data/` (users, usage, scans, assessments, student-progress, sources, projects, payments, partners, payment-config, entitlements). No SQL database, no ORM, no external service. |
| Durability | Atomic private-file writes (`lib/writePrivateJson.ts`), write fences (`lib/jsonFileWriteFence.ts`), store leases (`lib/jsonStoreLease.ts`), storage boundary (`lib/storageBoundary.ts`). |
| Frontend | React 18 + React Router 7 + Vite SPA, 15 pages, 36 source files. |
| Shared contracts | `packages/shared` (20 modules, 6.7k LOC) — types/guards used by API and Web. |
| Worker | `apps/worker` exists (queue/retry/runner, in-memory) but is **not** wired to API scan execution. |
| Size | api 145 files / 33.2k LOC · web 8.3k LOC · shared 6.8k LOC · api tests 32.7k LOC. |

### Identity and authorization model — **VERIFIED**

- `AccountRole`: `MEMBER < ADMIN < ACCOUNT_OWNER` — the only thing that grants access.
- `UserType`: `DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, `PENTESTER` — a classification tag that grants nothing.
- Capability table `PERMISSIONS` declares each protected capability's minimum role; backend enforces, UI only reflects.
- This matches the four user types the upgrade brief names; no type or role renaming is required.

---

## 3. Module inventory — **VERIFIED** (existence and code path), status judged from code

| Area | Module(s) | Status |
|---|---|---|
| SAST | `scans/sast/*` + `external/*` rules | Implemented; lexical + structured AST (TypeScript, Lezer Python/Java, php-parser). Rules come only from Dataset packs — `SAST_RULES = []`. |
| SCA | `scans/sca/*` (two readers), `external/scaDeclaration.ts` | Implemented; manifest/lockfile inventory + CycloneDX SBOM + advisory integration. Advisory data absent by default. |
| DAST | `scans/dast/{engine,activeEngine,authorization,targetPolicy,transport}.ts` | Implemented; passive + active, engagement authorization available, DNS/IP policy, redirect re-authorization. |
| Secrets | `scans/secrets/*` | Implemented; entropy + pattern families; framework-level rules present, pattern intelligence expected from Dataset. |
| Processing | `scans/{processor,store,engines,request,sources}.ts` | Durable store-as-queue, claim/QUEUED→RUNNING at-most-once, startup recovery, serialized single drain. |
| Findings | `scans/{findingIdentity,findingWorkflow,remediationGuidance,advisoryFindings}.ts`, `routes/reports.ts` | Fingerprints, lifecycle (history/notes), dedupe, triage, compare-to-baseline. |
| Reports | `reports/{build,pdf,portfolio}.ts` | JSON, Markdown, SARIF 2.1.0, PDF (embedded Unicode font), CycloneDX SBOM, portfolio export. |
| Auth | `auth/*`, `routes/auth.ts` | Register/login/logout/session (opaque cookie + device binding), scrypt password hashing, rate limits, account mutation lock. |
| Accounts | `routes/workspace.ts`, `routes/authz.ts`, `AccountPage` | Self-service account, security overview, capability probes. |
| Subscriptions | `entitlements/*`, `payments/*`, `routes/{subscription,payments}.ts` | FREE/PRO plans, entitlements derived from subscription status, audited manual PRO grant. |
| Payments | `payments/{service,store,configStore}.ts` | **No live gateway.** Provider boundary with no charge/verify/webhook methods until a real integration is configured; never simulates payment success. |
| Student | `student/*`, `routes/student.ts`, `StudentLearnPage` | Lessons, progress, quizzes, practice stages, progress store. |
| Admin | `routes/admin.ts`, `auth/adminProjection.ts`, admin pages | Dashboard, account list/patch, scan oversight, partner admin, payment admin, audit actions. |
| Partner | `partners/*`, `routes/partners.ts`, partner pages | Partner accounts, coupon/commission config, dashboard, admin lifecycle ops. |
| SOC/workspace | `routes/soc.ts`, `routes/workspace.ts` | Project SOC posture view; per-user security overview. |
| Assistant | `assistant/*`, `routes/assistant.ts` | Context-bounded, redacted assistant. **Not an agent**; no autonomous execution. |
| Agent | `agent/*`, `routes/agent.ts` | Present but gated (capabilities/orchestration are declared, execution gated, disabled by default). Out of scope for this project. |
| Observability | `logger.ts`, `/livez`, `/readyz`, `/api/v1/status` | Structured logs with redaction. **No metrics endpoint** (see finding 15). |
| Dataset boundary | `external/*` (`contract.ts` new) | Filesystem adapter, versioned contract, fail-closed verdicts; zero Dataset content in repo. |

API surface: **101 declared endpoints** across 21 route modules.

---

## 4. Test infrastructure and baseline result (executed now)

| Suite | Files | Tests |
|---|---|---|
| API | 132 (131 pass, 1 skip) | 1428 pass / 1 skip |
| Web | 20 | 193 pass |
| Worker | 3 | 32 pass |
| Shared | 32 | 288 pass |
| **Total** | **187** | **1941 pass / 1 skip** |

- The single skip is `apps/api/test/mountedDatasetE2E.test.ts` — it requires a real
  Dataset mount that does not exist in this environment. It is *not* a passing test
  and must not be counted as evidence of Dataset integration.
- Historical reference: 1921 pass / 1 skip before the round-5 integration-contract
  work; the +20 are the new contract tests.
- Lint: clean. Typecheck (all workspaces): clean. Repo integrity script: PASS.

**A green suite proves contract consistency, not detection accuracy.** No real-world
detection benchmark was executed in this audit.

---

## 5. Verification of the 15 previously reported audit findings

Every item below was re-checked against the current tree. "Open" means the code still
shows the condition today.

| # | Finding | Verdict | Evidence |
|---|---|---|---|
| P0-1 | DAST active scanning can run without mandatory engagement authorization when config defaults to false | **CONFIRMED OPEN** | `config.ts:500` default `'false'`; `scans/dast/authorization.ts:22,44` returns `true` for an unlinked scan when no authorizer; `scans/request.ts:111` enforces engagement only when the flag is true. |
| P0-2 | Upload body limit inconsistent with snapshot limit | **CONFIRMED OPEN (minor)** | `BODY_MAX_BYTES` default 1 MiB (`config.ts:272`) vs snapshot total 786,432 B (`packages/shared/src/sources.ts:36`). JSON escaping can inflate a legal snapshot past 1 MiB, so a valid snapshot can be un-uploadable. |
| P1-3 | No retry/backoff for normal scans | **CONFIRMED OPEN** | `processor.ts` lifecycle has no attempt counter; FAILED is terminal; `apps/worker/src/retry.ts` is unused by the API path. |
| P1-4 | No cancellation API for normal scans | **CONFIRMED OPEN** | No cancel route in `routes/scans.ts` (only create/list/get/compare). Cancellation exists only for Agent scans (`routes/agent.ts`). |
| P1-5 | SAST analysis can block the event loop | **CONFIRMED OPEN (bounded)** | `sast/engine.ts:328-360` scans file content synchronously; deadline is checked every 512 lines and between files, but there is no yield to the event loop. Bounded by `maxFiles: 200` and a 10 s deadline. |
| P1-6 | Persistence rewrites the whole JSON document on each terminal transition | **CONFIRMED OPEN** | `scans/store.ts:934` `persistWith(scans, idempotency, reports, workflows)` serializes the whole scan document per transition. |
| P1-7 | Active DAST and processor deadlines have no safety margin | **CONFIRMED OPEN** | `activeEngine.ts:44` 30,000 ms vs `processor.ts:129` `engineTimeoutMs = 30_000` — equal, so the processor aborts at the same instant the engine expects to finish. |
| P1-8 | Worker package not connected to API scan execution | **CONFIRMED OPEN** | `processor.ts:13-16` documents `apps/worker` as "future out-of-process engine host"; in-process drain is the live path. |
| P1-9 | Single-worker execution restricts throughput | **CONFIRMED OPEN** | `processor.ts:81-85` serializes drains: "different queued scans could execute concurrently without a …" guard. |
| P1-10 | Scan history growth increases persistence cost | **CONFIRMED OPEN** | No retention/pruning/compaction of scan records or security reports anywhere in `scans/store.ts` or `config.ts`; cost compounds with P1-6. |
| P2-11 | SCA inventory/SBOM limited | **CONFIRMED (scope-limited)** | Manifest + lockfile readers and CycloneDX export exist; direct-dependency inventory only, no transitive graph resolution. |
| P2-12 | DAST auth/session/POST/JSON/API-spec support limited | **CONFIRMED** | `activeEngine.ts` sends controlled GET/POST probes; no session login flow, no OpenAPI ingestion, no endpoint crawl. |
| P2-13 | SAST interprocedural/repo-scale limited | **CONFIRMED** | Structured AST analysis is per file; a project-flow pass exists but is bounded and partial by design. |
| P2-14 | Secrets Git history/baseline limited | **CONFIRMED** | Scans operate on uploaded snapshots only; no `.git` history walk, no baseline file. |
| P2-15 | Monitoring/metrics insufficient | **CONFIRMED OPEN** | No metrics surface; only `/livez`, `/readyz`, `/api/v1/status` and structured logs. |

No finding was refuted. No finding was silently repaired by earlier rounds except
Dataset-contract fail-closed behaviour (round 5), which is unrelated to this list.

---

## 6. Security posture — current controls **VERIFIED**

Present and backend-enforced: opaque session cookies with device binding, scrypt
password hashing, login/auth rate limits, CSRF-style origin guard, request IDs,
security headers, CORS allowlist, body limits, path-traversal-safe private writes,
tenant isolation per `ownerId`, admin/partner/payment authorization, webhook-free
payment boundary, secret redaction in logs, scanner target policy (DNS/IP/redirect),
resource caps on all four engines, static-safety scan in CI.

Known weaknesses (mapped to findings above): DAST fail-open default (P0-1), no scan
cancellation (P1-4), no retry (P1-3), no metrics (P2-15), event-loop exposure on
large SAST snapshots (P1-5), unbounded history growth (P1-10).

**Not claimed:** independent permission proof for DAST engagements, OS-level egress
sandbox, distributed rate limiting, or pen-test-level assurance. None was performed.

---

## 7. Performance and reliability bottlenecks — **ESTIMATED** unless noted

| Area | Observation |
|---|---|
| Scan throughput | Strictly one scan at a time per API process (P1-9). Concurrency is a product decision, not an accident. |
| Persistence cost | O(document size) per terminal transition; grows with history (P1-6 + P1-10). |
| API latency | Not measured this round. No load test was run, so no latency figure is claimed. |
| Memory | Bounded by snapshot caps (200 files / 256 KiB each / 768 KiB total) and per-scan finding caps. |
| Recovery | Startup converts interrupted RUNNING scans to FAILED/SCAN_INTERRUPTED deterministically. |

---

## 8. Baseline scorecards (evidence-based, pre-upgrade)

| Scorecard | Score | Basis |
|---|---|---|
| A. Feature completeness | **62** | All listed module groups exist and are wired; SCA/DAST/Secrets depth and student content are thin; payments are deliberately manual. |
| B. Architecture quality | **72** | Clear module boundaries, shared contracts, durable state machine; in-process worker and monolithic store cap the score. |
| C. Security quality | **68** | Broad backend enforcement; P0-1 fail-open default and missing scan cancellation pull it down. |
| D. Performance & reliability | **48** | Serialized execution, full-document persistence, no retry, no cancellation, no metrics. |
| E. User experience | **58** | Complete page set with loading/error/empty states; not audited against WCAG this round — accessibility is ESTIMATED, not measured. |
| F. Integration quality | **70** | UI↔API↔store paths exist for the main workflows; end-to-end browser verification was not executed. |
| G. Testing & evidence | **66** | 1941 executed tests with strong negative-path coverage; one Dataset E2E permanently skipped; no performance benchmark. |

Weighted readiness (A 15%, B 15%, C 20%, D 15%, E 10%, F 15%, G 10%) = **63 / 100**.

Confidence: **medium-high** for A–D, F, G (code + tests read/executed);
**low** for E (no accessibility or device audit performed).

---

## 9. Phase plan derived from this baseline

| Phase | Planned work | Findings addressed |
|---|---|---|
| 1 | DAST authorization default, deadline margin, body/snapshot bound | P0-1, P0-2, P1-7 |
| 2 | Scan retry/backoff, cancellation API, idempotency on rerun | P1-3, P1-4 |
| 3 | Persistence: incremental append, retention/compaction, history caps | P1-6, P1-10 |
| 4 | Worker: bounded parallelism with per-job isolation; worker package evaluation | P1-8, P1-9 |
| 5 | SAST: event-loop yielding, incremental analysis | P1-5, P2-13 |
| 6 | SCA/DAST/Secrets depth (transitive inventory, session+API-spec DAST, secrets baseline) | P2-11, P2-12, P2-14 |
| 7 | Observability: metrics endpoint, queue/latency counters | P2-15 |
| 8 | Frontend/UX + accessibility pass, integration verification | E, F |
| 9 | Full regression, final report and seven scorecards | all |

Each phase: targeted tests → relevant integration tests → typecheck → lint →
repo integrity → diff inspection. No commit, push, merge or deploy happens without
explicit approval.

---

## 10. Explicit non-actions taken during this audit

- No file was created, modified, renamed or deleted — except this report.
- No branch change, no stage, no commit, no push, no PR.
- No Dataset repository access, inspection, copy or test.
- No Agent development, no AI provider call.
- No database, infrastructure or deployment change.
- No test was executed against an external target.

## 11. Assumptions that remain unverified

1. That the four user types are used as the business intends (code confirms they exist; product intent is not provable from source).
2. That production runs with the same defaults audited here (deployment env is outside this repository).
3. That the Dataset shipped in production matches the layout the app-side contract expects (cannot be checked without Dataset access, which is out of scope).

---

## Appendix A — Phase 1 implementation log (added after the audit)

Sections 1–11 above describe the **pre-implementation** state and were not
rewritten. This appendix records what changed afterwards.

| Finding | Change | Verification |
|---|---|---|
| P0-1 DAST fail-open default | `DAST_REQUIRE_ENGAGEMENT` now defaults to `true` (`apps/api/src/config.ts`). Explicit `false` still allowed for legacy deployments and logs a startup warning in `apps/api/src/server.ts`; invalid values still refuse startup. Docs updated: `docs/DAST.md`, `docs/AUTHORIZATION.md`. | `test/securityDefaults.test.ts` (config default + opt-out + authorizer fail-closed), `config.test.ts`, full DAST API/engagement/boundary suites. |
| P0-2 body vs snapshot inconsistency | `SOURCE_SNAPSHOT_BODY_MAX_BYTES` added to `packages/shared/src/sources.ts` (`2 × 786,432 + 64 KiB`); `BODY_MAX_BYTES` default now equals it (1,638,400). Startup warning when an operator sets a smaller limit. | `test/securityDefaults.test.ts` encodes a maximal escaped snapshot and asserts it fits under the default. |
| P1-7 missing deadline margin | `SCAN_ENGINE_TIMEOUT_MS = 30_000` exported from `scans/processor.ts`; active DAST self-deadline reduced `30_000 → 25_000` so it can report `DAST_SCAN_TIMEOUT` instead of being aborted mid-flight. | `test/securityDefaults.test.ts` asserts ≥ 5 s margin and that passive DAST/SAST deadlines also stay inside the bound. |

Post-change verification (executed): typecheck all workspaces clean, lint clean,
repo-integrity PASS, **1948 tests pass / 1 skipped** (was 1941 / 1).

Not yet addressed (unchanged from §5): P1-3, P1-4, P1-5, P1-6, P1-8, P1-9,
P1-10, P2-11…P2-15.

---

## Appendix B — Phase 2–4 implementation log (added after the audit)

| Finding | Change | Where |
|---|---|---|
| P1-4 no cancellation API | Durable owner cancellation. New `POST /api/v1/projects/:projectId/scans/:scanId/cancel`; `ScanRecord.cancelRequestedAt`; `SCAN_CANCELLED` failure code; `ScanStore.requestScanCancellation()` (QUEUED cancelled immediately, RUNNING records intent); processor `cancelScan()` aborts the attempt and its finalizer honours the intent; web client + "Stop scan" / "Cancel before start" button and pending-cancel notice. | `scans/store.ts`, `scans/processor.ts`, `routes/scans.ts`, `packages/shared/src/scans.ts`, `apps/web/src/api/client.ts`, `apps/web/src/pages/ProjectDetailPage.tsx` |
| P1-3 no retry/backoff | Bounded retry for transient engine crashes only. `SCAN_MAX_ATTEMPTS` (default 2, ≤5) + `SCAN_RETRY_BASE_DELAY_MS` (default 5 s); durable `RUNNING → QUEUED` requeue with `retryAt`; 1-based `attempt` counter (shared hard limit 5); `isRetryableFailure()` allows only `SCAN_ENGINE_ERROR`; agent jobs and shutdown are never retried. | `scans/processor.ts`, `scans/store.ts`, `config.ts`, `packages/shared/src/scans.ts`, `docs/SCANS.md` |
| P1-5 SAST blocks the event loop (bounded) | The lexical pass yields to the event loop every 8 files (`SAST_YIELD_EVERY_FILES`); deadline checkpoints unchanged. | `scans/sast/engine.ts` |
| P2-15 no metrics | `GET /api/v1/metrics` (ADMIN + platform allowlist): uptime, memory, scan totals by status/type, queue depth, processor state; no identifiers, no time series, explicit "zero findings ≠ safe" note. | `routes/metrics.ts`, `app.ts`, `docs/SCANS.md` |

Post-change verification (executed): typecheck + lint clean, repo integrity PASS.
New tests: `scanCancellation.test.ts` (4), `scanRetry.test.ts` (4),
`metrics.test.ts` (2), `scanUi.test.tsx` (+2), `securityDefaults.test.ts` (7).

Still open after this pass: **P1-6** (whole-document persistence), **P1-8/P1-9**
(worker package + single-worker throughput), **P1-10** (no retention), and the
depth items **P2-11 … P2-14**.

---

## Appendix C — Phase 5–6 implementation log (added after the audit)

| Finding | Change | Where |
|---|---|---|
| P1-9 single-worker throughput | Opt-in parallel scan lanes: `SCAN_CONCURRENCY` (default 1, range 1–8) → `createScanProcessor({ concurrency })`. Claiming remains a serialized store transition, so at-most-once execution is preserved; cancellation, retry backoff, recovery and shutdown are unchanged. `MAX_SCAN_CONCURRENCY = 8` caps it. | `scans/processor.ts`, `config.ts`, `app.ts`, `docs/SCANS.md` |
| P1-10 growth cost (visibility) | `ScanStore.documentStats()` + `/api/v1/metrics` now report `scans`, `reports`, `findingWorkflows`, `idempotencyEntries`, `documentBytes`, `estimatedFullRewriteBytes`. Read-only; no retention or deletion implemented (data-governance decision). | `scans/store.ts`, `routes/metrics.ts` |
| P1-6 whole-document rewrite | **Designed, not implemented.** `docs/SCAN_STORE_COMPACTION_DESIGN.md`: append-only journal + snapshot + crash-safe compaction + v2→v3 migration with mandatory backup, an 8-case test plan (torn tail, checksum, crash at each compaction step, idempotent compaction, migration equivalence, v2 refusal) and a stated risk of data loss if rushed. | docs only |
| E (UX/accessibility) | Per-route `document.title` (WCAG 2.4.2), polite route-change announcement (deliberately not `role="status"`, which the loading spinners own), focus moved to the `main` landmark on navigation with a `:focus-visible` outline. | `components/Layout.tsx`, `styles.css` |

Route authorization inventory re-verified: **99 declared routes, 92 behind
`requireAuth`**; the 7 public routes are exactly the intentional ones
(`/livez`, `/readyz`, `/api/v1/status`, register, login, logout, echo, advisory
status). Every `/api/v1/admin/*` handler calls `assertPlatformAdmin`; payment,
student, partner and project routes are scoped by the session account id.

New tests: `scanConcurrency.test.ts` (3), `accessibilityUi.test.tsx` (3),
`metrics.test.ts` extended (store shape). Totals after this pass:
**1966 passed / 1 skipped / 0 failed** across API, web, shared and worker.

Still open: **P1-6** (designed only), **P1-8** (out-of-process worker),
**P2-11 … P2-14** (engine depth), retention policy for **P1-10**.

---

## Appendix D — Phase 7 implementation log: engine depth (added after the audit)

| Finding | Change | Where |
|---|---|---|
| P2-11 no transitive graph | Lockfile-evidenced dependency edges. `parsePackageLock` now returns `entries` with their installation `pathKey` plus `edges`; npm v2/v3 resolve each node's declared names with Node's own upward `node_modules` walk (nested copy beats hoisted copy, unresolvable declaration → no edge), npm v1 emits structural parent → child edges from its nested maps. `buildInventory` translates path keys to retained fingerprints, drops edges with non-retained endpoints, and reports `edges` + `graph {nodes, edges, maxDepth, dependentNodes, truncated}`. `buildSbom` emits the root edge from the evidenced graph (falling back to direct declarations) plus one edge per component with evidenced children; every `dependsOn` ref is a `bom-ref` in the same document. The SBOM serial number hashes components **and** edges. `transitiveGraph` is `AVAILABLE` only with a complete, unclipped, evidenced graph — otherwise `UNAVAILABLE` with a bounded partial reason. Parser budget `LOCK_MAX_EDGES = 4000`; a clipped graph is flagged (`edgesTruncated`), never presented as complete. | `apps/api/src/scans/sca/{parsers,inventory,engine}.ts`, `docs/SCA.md` |

Deliberately NOT done in this pass: Python installation graphs. `requirements.txt`
and `pyproject.toml` declare names and (sometimes) exact pins but never an
installed tree, so inventing edges there would be fabrication; those projects keep
`transitiveGraph: UNAVAILABLE`. The PyPI half was closed later with a real
`poetry.lock` reader — see **Appendix D.1**.

New tests: `scaTransitiveGraph.test.ts` (13) — nested resolution, absent targets,
v1 structural nesting, malformed locks, dangling-ref rejection, graph-aware serial,
clipped graph → `UNAVAILABLE` + reason, 200-component/SBOM bound.

Open after this pass: **P1-6** (designed only), **P1-8** (out-of-process worker),
**P2-11** (Python half — closed in D.1), **P2-12** (authentication — closed in
D.2b as an operator header, session automation still absent), **P2-13** (D.3),
**P2-14** (D.4), and retention for **P1-10**.

### Appendix D.1 — P2-11 (PyPI half): `poetry.lock` graph

| Change | Where |
|---|---|
| A bounded `poetry.lock` reader (`[[package]]` → resolved `name@version` nodes, `[package.dependencies]` → real parent → child edges; `python` constraints, extras and sources excluded). A companion `pyproject.toml` supplies the direct set and the declared ranges; `pyproject.toml` `[project]`/`[tool.poetry]` `name`+`version` now provide the SBOM root identity for Python-only projects. Bounds: 10 000 lines, 500 packages, 200 dependency entries per package, 4 000 edges. A locked dependency naming an unlisted package, or a declaration the lock does not resolve, makes the manifest `PARTIAL` with a bounded note and forces `transitiveGraph: UNAVAILABLE` — never a silently thinned graph. | `apps/api/src/scans/sca/parsers.ts` (`parsePoetryLock`), `inventory.ts` (Poetry lock↔pyproject pairing, root identity, `kindOf`), `engine.ts` (manifest discovery/ecosystem/summary), `apps/api/test/scaParsers.test.ts`, `apps/api/test/scaPoetryLock.test.ts` |

Follow-up (same round) — the rest of the Python story:

| Format | Evidence | Graph |
|---|---|---|
| `uv.lock` | resolved `name@version` nodes; `dependencies = [{ name = … }]` edges; the `editable`/`virtual` project entry is the root, never a dependency | **yes** — ambiguous bare names (several locked versions) are refused and counted, explicit `version` references resolve exactly |
| pip-compile `requirements.txt` | `# via <parent>` provenance (plus `# via -r requirements.in` for the direct set), including the backslash-joined `--generate-hashes` layout | **yes** — an edge needs both endpoints pinned in the file; an unpinned parent or a pin without provenance makes the manifest `PARTIAL` |
| `Pipfile` / `Pipfile.lock` | direct declarations + every resolved pin (`default`/`develop`) | **no** — Pipenv records no inter-package relationship, so the format itself cannot evidence one |

Tests: `scaPythonLocks.test.ts` (17) — root-is-not-a-dependency, unresolved and
ambiguous uv edges, hostile names/versions, Pipfile direct/dev split, Pipfile
lock version pins with no edges, pip-compile single/multi-parent/`-r`
provenance, hash-pinned provenance, and the end-to-end engine/SBOM assertions
(including that a hand-written requirements file still claims no graph).

### Appendix D.2 — P2-12 (first half): bounded OpenAPI/Swagger ingestion

| Change | Where |
|---|---|
| Active-safe DAST can read ONE JSON OpenAPI 3.x / Swagger 2.0 document from `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs` (≤2 probes), only as an explicit per-scan opt-in (`dastOpenApiDiscovery: true`, requires `ACTIVE_SAFE` + consent; refused on other scan types and for the agent path; part of the idempotency identity). Endpoints are query-free `GET`s only; path parameters are filled ONLY from values the document states (`example`, schema `example`/`default`/`enum[0]`, `default`) and must match `^[A-Za-z0-9._~-]{1,32}$`; operations without such values are counted as skipped. Hostile paths (traversal, `//`, `%`, whitespace, control characters, query/fragment) are refused at parse time. Bounds: 512 KiB document, 500 inspected paths, 50 endpoints; caps are disclosed in a note. Every resulting URL still passes target policy + authorization + throttle + request budget. | `apps/api/src/scans/dast/openapi.ts`, `apps/api/src/scans/dast/activeEngine.ts`, `apps/api/src/scans/{request,store}.ts`, `apps/api/src/routes/scans.ts` |
| Honest disclosure: `openApiStatus` / `openApiSpecProbes` / `openApiEndpoints` / `openApiSkipped` in the DAST payload (active only), plus real `crawledCount`/`injectedCount` (previously never set). `NOT_FOUND` explicitly is not evidence that the API is undocumented; a found-but-unusable document marks the scan partial. Reports and the project UI state these counts instead of implying a full crawl. | `packages/shared/src/dast.ts`, `apps/api/src/reports/build.ts`, `apps/web/src/pages/ProjectDetailPage.tsx` |

New tests: `dastOpenApi.test.ts` (11), `scanApi.test.ts` (+1 opt-in gating),
`dastUi.test.tsx` (+2), `socSac.test.ts` (+1 report disclosure).

Still NOT implemented for P2-12: authenticated sessions. No credential, token or
session cookie is ever sent; sending operator or third-party credentials to a
user-configured target needs a credential-storage design and an explicit
operator decision, which was not taken.

### Appendix D.2b — P2-12 (second half): operator-configured authenticated probing

| Change | Where |
|---|---|
| One optional static credential header for active-safe DAST, supplied by the deployment (`DAST_AUTH_HEADER_NAME` + `DAST_AUTH_HEADER_VALUE`). Both-or-neither validation (token header name, client-owned headers refused, single printable line ≤ 4096 chars, non-empty); a bad pair is a startup error that never echoes the value. Held in memory only, attached to each probe of the authorized target, never written to a scan record, observation, finding, report, metric or log. Results disclose `authMode` (`NONE`/`HEADER`) only, and the shared `isDastResult` guard accepts `authMode` solely on `ACTIVE_SAFE` results. | `apps/api/src/scans/dast/auth.ts`, `http.ts` (`extraHeaders`), `activeEngine.ts`, `engine.ts`, `apps/api/src/config.ts`, `apps/api/src/app.ts`, `packages/shared/src/dast.ts`, `apps/api/src/reports/build.ts`, `apps/web/src/pages/ProjectDetailPage.tsx`, `.env.example` |

Tests: `dastAuth.test.ts` (7) — header-name/value validation, both-or-neither,
per-request attachment, no attachment when unconfigured, credential absent from
the serialized outcome, passive result cannot claim `authMode`; `config.test.ts`
(startup failure without echoing the value); `packages/shared/test/dast.test.ts`
(closed vocabulary, active-only); `apps/web/test/dastUi.test.tsx` (mode
disclosure without the credential).

Deliberately absent: form login, cookie-jar sessions, CSRF/MFA/refresh handling,
per-user credential vaults, multi-role scanning.
### Appendix D.3 — P2-13 (interprocedural SAST depth)

| Change | Where |
|---|---|
| The bounded project pass propagates to a real **fixed point** (summary equality, ≤ 12 rounds, shared work budget) instead of a hard 4 iterations; resolves **default import/export**, **`import * as ns` + `ns.fn()`** and **`export * from './x'`** chains (cycle-safe); records a **6-step** cross-file trace; scales to the snapshot upload cap (200 files / 768 KiB) with function/node/work caps. Every scan now discloses `projectFlow.callEdges` (matched call edges) and `projectFlow.rounds`; not reaching a fixed point is `INCOMPLETE` + a partial reason. | `apps/api/src/scans/sast/projectAst.mjs`, `structuredAstSession.ts`, `engine.ts`, `packages/shared/src/scans.ts`, `apps/api/src/reports/build.ts`, `apps/web/src/pages/ProjectDetailPage.tsx` |

Tests: `astImprovements.test.ts` extended (6-hop chain to a fixed point, namespace/default/`export *` resolution, cyclic re-export termination, 200-file cap); UI/report assertions updated.

### Appendix D.4 — P2-14 (secrets baseline)

| Change | Where |
|---|---|
| One baseline document at the snapshot root (`drobon-secrets-baseline.json`, `version: 1`). Entries are `{ruleId, file, reason?}` or `{fingerprint}`; an entry suppresses only what it names. Bounds: 64 KiB, 500 entries, ≤ 200-char reason, paths re-validated by the shared source-path policy. Any malformed entry is counted (`invalid`); a malformed/oversized/wrong-version document is `INVALID`, suppresses nothing and marks the scan partial. Every scan carries `secretsBaseline: { status, entries, applied, invalid }`, shown in the summary contract, the scan UI and the report. | `apps/api/src/scans/secrets/baseline.ts`, `apps/api/src/scans/secrets/engine.ts`, `packages/shared/src/scans.ts`, `apps/api/src/reports/build.ts`, `apps/web/src/pages/ProjectDetailPage.tsx` |

Tests: `secretsBaseline.test.ts` (12) — document parsing/bounds/containment, rule+file suppression, exact-fingerprint suppression, invalid document disclosure, "cannot hide a rule it does not name", redaction preserved, determinism; `secretsUi.test.tsx` (+2) for the disclosure lines.

Git commit history remains **NOT_IMPLEMENTED** with a stated reason (a snapshot
is one content tree; `.git` paths are refused by the shared path policy;
packfile parsing would be a new subsystem). Cross-scan comparison by finding
fingerprint is the supported history view.

