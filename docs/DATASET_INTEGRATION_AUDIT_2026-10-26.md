# Drobon ↔ Drobon-Dataset — Integration Audit

**Date:** 2026-10-26 · **App:** `mdraselislam0101-design/Drobon` @ branch `arena/5bb07bd8-drobon` (base `9360dd1`) · **Dataset:** `mdraselislam0101-design/Drobon-Dataset` @ `3986082`
**Evidence:** [`DATASET_INTEGRATION_EVIDENCE.json`](DATASET_INTEGRATION_EVIDENCE.json) · **Verification script:** [`scripts/verify-dataset.mjs`](../scripts/verify-dataset.mjs) · **Operator guide:** [`DATASET_CONNECTION.md`](DATASET_CONNECTION.md)

> **সারাংশ (বাংলা):** দুটি repo-র তুলনা, integration যাচাই, dataset→app sync এবং পূর্ণ অডিট — চারটিই করা হয়েছে। আগে ২২টি টেস্ট ফেল করছিল, ১২০টি lint error ছিল, secret-scan ৪ জায়গায় ফেল করছিল এবং `npm run verify` মোটেই পাস হচ্ছিল না। এখন **১১/১১ verification step PASS**, ১,৩০৫টি টেস্ট পাস, lint ০ error, এবং বাস্তব dataset দিয়ে `verify:dataset` PASS। আগে ৮৪০/১,০০০ SAST rule ও ৯৩৪/১,০০৭ DAST rule অ্যাপে পৌঁছাতেই পারত না, আর ৪,০০৭টি remediation এর কোনোটিই ইউজারের কাছে যেত না — এখন যথাক্রমে ১,০০০/১,০০০, ১,০০৭/১,০০৭ এবং ৪/৪ নমুনা (সম্পূর্ণ catalog surface) পৌঁছায়। দুটি জিনিস এখনো owner decision / future work: active-DAST boundary (P0) আর SCA declaration pack-এর scan evaluator।

---

## 1. Scope and method (what was actually checked)

The dataset repo was cloned **read-only, outside the app repo** (`../Drobon-Dataset`). No dataset bytes were copied into this repository — the absolute dataset lock still holds and is machine-checked by `npm run check:boundaries` + `npm run check:repo-integrity`.

Everything below was produced by running the **real app modules** through `tsx`, not by re-implementing the dataset's validator in a script:

```bash
npm run verify:dataset -- --path ../Drobon-Dataset --write   # real integration probe
npm run verify                                              # authoritative repo pipeline
```

`verify:dataset` is a new, non-network, fail-closed gate. It exercises `createDatasetService`, `validatePackRules`, `evaluatePackDastCheck`, `resolvePackLanguages`, `INSPECTED_RESPONSE_HEADERS`, `createGuidanceLookup`, `remediationGuidanceForFinding` and `createFilesystemIntelligenceProvider` — the same code paths used by the running API.

### 1.1 Repository comparison

| | [Drobon](https://github.com/mdraselislam0101-design/Drobon) (this repo) | [Drobon-Dataset](https://github.com/mdraselislam0101-design/Drobon-Dataset) |
|---|---|---|
| Role | Main product: API, Web, Worker, scanners, **logic** | Datacenter: vulnerability intel, rule packs, knowledge, audience **data** |
| Default branch | `main` (work here: `arena/5bb07bd8-drobon`) | `main` |
| Last push before this audit | 2026-10-20 (`9360dd1`, merge PR #5) | 2026-10-26 (`3986082`, merge PR #8) |
| Language mix | TypeScript ~3.0 MB, JavaScript, CSS | JavaScript ~1.0 MB, mostly JSON data |
| Repo size (API) | ~3.4 MB | ~15.3 MB (21,355 files in a full clone) |
| Licence | none declared | none declared (`BLOCKED_OWNER` in the dataset completion ledger) |
| Open issues / PRs checked | 0 | 0 |
| Sibling | — | `Drobon-Database` (one README-only commit, no coupling today) |

**Relationship.** The App enforces an absolute dataset lock: no advisory, rule, remediation or lesson data may be committed here. It reads the external checkout at runtime from `DATASET_PATH` when `VULN_INTEL_PROVIDER=filesystem`. Default is `none`, which is an honest degraded mode (SCA `NOT_ASSESSED`, scanners with 0 rules), not a silent "clean" result. The dataset repo's `interop/APP_CONFORMANCE.md` and `DROBON_REMAINING_WORK.csv` contain a pinned App-side defect register (`GAP-040…GAP-048`) measured against App commit `9360dd1`; that register is the backbone of this audit.

**Data flow (after this work):**

```
Drobon-Dataset (external checkout)
  vuln-intel/{npm,pypi} ──► sca/filesystemProvider ──► SCA advisories (16/16 pinned vectors)
  packs/{sast,secrets,dast,sca}/v1 ──► external/conformance ──► packIntegration ──► engines
  knowledge/remediation ──► external/guidance ──► assistant · finding detail · reports
  knowledge/cwe, learning, assessments, engagements ──► dataset status + lesson provider
```

---

## 2. Integration check and repair (GAP-040…GAP-048)

### 2.1 Baseline: the checkout at `9360dd1` was not release-ready

Measured before any change (reproduced from a clean `git archive HEAD` copy):

| Check | Baseline |
|---|---|
| `npm test` | **FAIL** — shared 182/183, api 785/801, web 261/266 (**22 failing tests**) |
| `npm run typecheck` | **FAIL** — 3 unused-import errors in `api` tests |
| `npm run lint` | **FAIL** — 120 errors (56 `no-explicit-any`, 49 `no-useless-escape`, 13 `no-empty`, …) |
| `npm run check:secrets` | **FAIL** — 4 synthetic fixture strings looked like committed secrets |
| `npm audit --audit-level=high` | **FAIL** — 1 high advisory in `vite@6.4.3` |
| `npm run verify` | **FAIL** (consequence of all of the above) |
| `docs/DATASET_CONNECTION.md` | Claimed 50 built-in SAST rules, 8 built-in DAST checks, 4 embedded lessons, 950/97/263/1310/68 counts — all stale after decoupling |

Two of the failing test suites exposed **real product bugs**, not just stale assertions:

1. **Secrets evidence could leak a second credential.** `secrets/engine.ts` did neighbour redaction and the defensive re-scan against the *empty production registry* (`SECRETS_RULES`) instead of the active rule set. After decoupling, an AWS key appearing twice on one line survived in the persisted evidence. Fixed by passing `effectiveRules` into `evidenceFromLine`.
2. **Every SAST flow finding was silently dropped.** `sast/engine.ts` looked up flow-rule metadata with `sastRuleById()` — also the empty registry. Fixed by resolving from the same `effectiveRules` map that produced the flow refs.

Other test failures were stale expectations about deleted embedded rules: fixed with **test-only** flow fixtures (`TEST_SAST_FLOW_RULES`), honest `PARTIALLY_SUPPORTED` assistant states when no dataset is mounted, and updated closed-vocabulary / UI expectations. No production data was reintroduced.

### 2.2 Gap-by-gap result

| Gap | Dataset's finding at `9360dd1` | Status now | What changed |
|---|---|---|---|
| **GAP-040** language reachability | 840/1,000 SAST rules reachable; 66 pack ids had no App family | **CLOSED** (1,000/1,000) | `external/languageAliases.ts` (declared aliases + `config-file` family), `sast/languages.ts`, `packProvider.ts`, and `sast/engine.ts` now analyze a catalog family when a loaded rule targets it. 115/115 ids resolve, 0 unresolved. 72 rules reach previously `SYNTAX_ONLY`/`UNSUPPORTED` families through loaded rules. |
| **GAP-041** DAST evaluator parity | 15 diverging declared tests on 9 rules (cookie model, blank header arrays, cross-value matches) | **CLOSED** (0/3,673 mismatches) | `external/evaluator.ts` + `external/setCookie.ts` port the browser-accurate semantics: per-value evaluation, case-folded/OWS-trimmed names, blank header = absent, RFC 6265 cookie storage model. |
| **GAP-042** loader checklist | 2/6 steps done; unknown check types, no declared-test execution, no ReDoS lint, no pack identity | **4 fully + 2 partial** | `external/conformance.ts`: closed-field schema validation, static ReDoS lint, load-time execution of 12,376 declared tests (SAST 4,043 + secrets 4,660 + DAST 3,673), refused-rule reporting; `pack.json` identity surfaced on status + inspection routes. **Partial:** step 3 asks for a bounded-time runtime ReDoS regression (we ship the static lint only) and step 6 asks for per-finding pack stamping (we ship pack identity on the status/inspection surface; per-finding needs a shared-contract change). |
| **GAP-043** counting + zero-match mapping | App reported 100 files while docs said 84 items / 78 ids; mapping undocumented | **CLOSED** | `vulnIntelCounts: {files:100, identityItems:84, advisoryIds:78}` computed at load time and exposed in `/api/v1/dataset/status`; the datasetStatus→scan-state table is now written in `DATASET_CONNECTION.md` and matches the dataset's `interop/APP_CONFORMANCE.md` §5. |
| **GAP-044** range drift | App's `range.ts` never tested against `interop/provider-vectors.json` | **CLOSED** (16/16) | `verify:dataset` runs all 16 pinned vectors through `createFilesystemIntelligenceProvider`; a divergence fails the probe (and can be wired into CI). |
| **GAP-045** active-DAST boundary | Active crawl + injection payloads exist while both repos' written boundaries forbid active probing; P0 owner decision | **OPEN — not decided here** | No product decision was presumed. Documented in `DATASET_CONNECTION.md` §"Known limits". Requires owner action (revert or written authorization + amended boundary docs + consent/rate-limit evidence). |
| **GAP-046** doc drift + silent start | Docs claimed a built-in floor that no longer exists | **CLOSED** | `DATASET_CONNECTION.md` rewritten with measured counts and honest degraded mode; `docs/SAST.md` carries a "CURRENT STATE" banner + corrected catalog counts; startup now logs a **WARN** naming exactly what is disabled when no dataset is configured. |
| **GAP-047** failing suites | 16 api + 1 shared failures (dataset's count); web had 5 more | **CLOSED** | 22 tests fixed (plus 2 real engine bugs). Now 1,305/1,305 tests pass. |
| **GAP-048** DAST header allowlist | 11 headers forwarded → 73 rules unreachable | **CLOSED** (1,007/1,007) | `scans/dast/observedHeaders.ts` — one shared bounded set of 57 names imported by both passive and active engines. Values still clipped to 2,048 chars / 5 entries; body still 32,768 bytes. No new request capability. |

### 2.3 Additional repairs found while verifying

- **Remediation was 0/4,007 surfaced.** `external/knowledge.ts` existed but nothing consumed it. Added `external/guidance.ts` (one cached lookup per process), extended `remediationGuidanceForFinding` to emit `RULE_SPECIFIC` guidance from dataset entries, and wired the same resolver into the assistant, finding-detail and reports surfaces. Without a dataset it returns a scanner-aware honest `UNAVAILABLE` fallback (never fabricated advice, never echoes evidence).
- **SCA declaration pack was invisible.** `service.ts` now loads and validates all 1,000 `packs/sca/v1` rules, exposes `scaPacks` + `conformance.sca` on the status route and `/api/v1/dataset/packs/sca`. Its 4,001 declared tests are reported as `skippedTests` with `scaDeclarationEvaluator: "NOT_IMPLEMENTED"` — explicitly not counted as passing.
- **Dataset lock preserved.** `npm run check:boundaries` and `check:repo-integrity` pass; the evidence JSON contains counts only.

---

## 3. Sync — measured before → after

| Dimension | Before (dataset ledger at `9360dd1`) | After (`verify:dataset` evidence) |
|---|---:|---:|
| SAST rules reachable through the App gate | 840 / 1,000 (84%) | **1,000 / 1,000** |
| DAST rules evaluable through the response surface | 934 / 1,007 (92.8%) | **1,007 / 1,007** |
| Distinct pack language ids resolved | 49 / 115 | **115 / 115** (0 unresolved) |
| Inspected response headers | 11 | **57** (bounded allowlist) |
| DAST declared-test parity | 3,658 / 3,673 (15 divergences) | **3,673 / 3,673** (0 divergences) |
| App loader checklist steps | 2 / 6 | **4 full + 2 partial** (static lint; pack identity on API surface) |
| Declared tests executed at load | 0 | **12,376** (0 failures, 0 rejected rules) |
| Remediation entries surfaced | 0 / 4,007 | **4,007 available**, 4/4 sampled rules resolve to `RULE_SPECIFIC` |
| SCA declaration rules loaded | 0 | **1,000 loaded** (0 evaluated in scans — declared as open) |
| Pinned SCA provider vectors asserted inside the App | 0 / 16 | **16 / 16** |
| Canonical vuln-intel counters on the status surface | files only (100) | **100 files / 84 identity items / 78 advisory ids** |
| Pack identity (`packId@version`) on the API | none | **4 packs** on status + inspection routes |
| Categories mounted | 9 | **10** |

**Category counts now loaded from the real checkout:** vuln-intel 100 files · SAST 1,000 · secrets 1,000 · DAST 1,007 · SCA declaration 1,000 · remediation 4,007 · CWE 102 · lessons 6 · assessment templates 3 · engagement templates 2.

### 3.1 What "sync" deliberately did NOT do

- It did **not** copy any dataset file into this repo. Runtime reads only.
- It did **not** change any pack rule, declared test, severity or advisory. Dataset semantics won every disagreement; the App evaluator was ported to match.
- It did **not** claim the 1,000 SCA declaration rules are active in scans. They are loaded, validated and inspectable; 0 are evaluated because the App has no declaration-document evaluator. Pretending otherwise would recreate the exact honesty problem this work removes.
- It did **not** widen scanning capability: no new HTTP request type, payload, crawler or execution path was added.

---

## 4. Audit — verification, residual risk, owner decisions

### 4.1 Verification results (all commands run in this workspace)

| Gate | Result |
|---|---|
| `npm run verify` | **VERIFY: PASS** — 11/11 steps (boundaries, repo integrity, release evidence, secret matcher, secret scan, typecheck, lint, tests, production builds, post-build secret scan, dependency audit) |
| `npm test` | **1,305 passed / 0 failed** — shared 183, api 828, worker 28, web 266 |
| `npm run typecheck` | PASS (all 5 workspaces) |
| `npm run lint` | PASS — 0 errors (baseline 120) |
| `npm run build` | PASS (shared → api → worker → web) |
| `npm run check:secrets` | PASS — 642 files scanned (baseline 4 findings) |
| `npm run check:boundaries` / `check:repo-integrity` | PASS / PASS — dataset lock intact |
| `npm audit --audit-level=high` | PASS after `vite` 6.4.3 → **6.4.5** (high advisory removed; 2 moderate vitest advisories remain and are below the configured gate) |
| `npm run verify:dataset -- --path ../Drobon-Dataset --write` | **verify-dataset: PASS** — all 9 hard checks |

The `verify:dataset` gate checks: category counts, loader conformance (0 rejected / 0 failed tests), DAST parity, DAST reachability, SAST reachability, SCA vectors, canonical counters, remediation surfacing, and pack identity. It exits non-zero on any failure.

### 4.2 Residual risk / open work (honest register)

| # | Item | Severity | Owner | Why it is not closed here |
|---|---|---|---|---|
| 1 | **Active DAST boundary** (`apps/api/src/scans/dast/activeEngine.ts`, `crawler.ts`, `payloads.ts`) contradicts both repos' written "active probing is out of scope" boundary (dataset GAP-045) | **P0** | Product owner | Reverting or authorizing is a product/legal decision, not an engineering fix. Consent + rate-limit evidence and amended boundary docs must ship with the decision. |
| 2 | SCA declaration pack: 1,000 rules / 4,001 declared tests loaded but **0 evaluated in scans** | P1 | App workstream | Needs a declaration-document evaluator (6 check types incl. `sca-name-distance`) and a parser contract that keeps raw manifest documents. Reported as `NOT_IMPLEMENTED`, never as success. |
| 3 | Per-finding `packId@version` stamping | P2 | App + shared contract | `Finding` is a closed shared shape; adding a field changes guards, reports and fingerprints across all clients. Pack identity is currently on the status/inspection surface only. |
| 4 | Config language ids share one `config-file` family | P3 | App workstream | A rule tagged `nginx` may also be evaluated on `sshd_config`; its own pattern decides. Dedicated families per daemon would be more precise. |
| 5 | Dataset licence grant + production vuln-intel ingestion (100 → 100,000 target) | P1 | Dataset owner | `BLOCKED_OWNER` in the dataset completion ledger; no legal decision was made here. Coverage remains a growing seed — an empty result never means "not vulnerable". |
| 6 | 2 moderate `@vitest/mocker` advisories | P3 | Dependency maintenance | Below the repo's `--audit-level=high` gate; `npm audit fix` can address them when a compatible release is available. |
| 7 | `docs/SAST.md`, `SECRETS.md`, `DAST.md` still contain historical `DG-*` rule enumerations | P3 | Docs | `SAST.md` now has a prominent CURRENT STATE banner; a full rewrite of all four docs is a separate documentation pump. |

### 4.3 Files changed (summary)

**New application logic:** `external/conformance.ts`, `external/setCookie.ts`, `external/languageAliases.ts`, `external/guidance.ts`, `scans/dast/observedHeaders.ts`.
**Rewritten/tightened:** `external/evaluator.ts`, `external/service.ts`, `external/types.ts`, `external/routes.ts`, `external/packProvider.ts`, `scans/remediationGuidance.ts`, `scans/sast/languages.ts`, `scans/sast/engine.ts`, `scans/secrets/engine.ts`, `scans/dast/{engine,activeEngine,packTypes}.ts`, `assistant/service.ts`, `routes/{assistant,reports}.ts`, `app.ts`.
**New tests (27):** `datasetConformance`, `dastEvaluator`, `datasetLanguageAliases`, `datasetGuidance`, `datasetService`, `dastSurface`.
**Tooling/docs:** `scripts/verify-dataset.mjs`, npm script `verify:dataset`, `docs/DATASET_CONNECTION.md` (rewritten), `docs/SAST.md` (banner + counts), this audit, `docs/DATASET_INTEGRATION_EVIDENCE.json`, `apps/web/package.json` + lock (`vite` patch).
**Legacy lint/secret hygiene:** scoped eslint directives and fake-fixture markers in pre-existing files; no behavior change.

### 4.4 Reproduce

```bash
git clone https://github.com/mdraselislam0101-design/Drobon.git
cd Drobon
npm ci
npm run sync:dataset                       # → ../Drobon-Dataset
npm run verify:dataset -- --write          # integration evidence, no server needed
npm run verify                             # full repo pipeline
```

For the product itself: `VULN_INTEL_PROVIDER=filesystem DATASET_PATH=../Drobon-Dataset npm run dev`, then check authenticated `GET /api/v1/dataset/status`.

---

**Audit conclusion:** the two repositories are now genuinely connected and measured end-to-end. Every App-side engineering gap in the dataset's register is closed except the one that requires an owner decision (active DAST) and the explicitly-declared SCA declaration evaluator. The App no longer reports coverage it cannot deliver, and no dataset byte crossed into the App repository.
