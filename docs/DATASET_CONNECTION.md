# Dataset Connection — Main App ↔ Drobon-Dataset

**Verified 2026-10-26** against App branch `arena/5bb07bd8-drobon` and
`mdraselislam0101-design/Drobon-Dataset` @ `3986082`. Machine-readable evidence:
[`DATASET_INTEGRATION_EVIDENCE.json`](DATASET_INTEGRATION_EVIDENCE.json) (counts only,
no dataset bytes). Full analysis: [`DATASET_INTEGRATION_AUDIT_2026-10-26.md`](DATASET_INTEGRATION_AUDIT_2026-10-26.md).

The app enforces an **absolute dataset lock**: no advisory, rule, remediation or
lesson *data* is committed here (`scripts/check-boundaries.mjs`,
`scripts/check-repo-integrity.mjs`). The data lives in its own repo; this app only
**reads** it at runtime from a server-side filesystem path. Code (engines,
evaluators, validators, resolvers) lives here — that split is the product design.

## What is actually loaded (measured, not assumed)

| Category | Dataset path | App consumer | Loaded | Runtime status |
|---|---|---|---:|---|
| SCA vuln-intel | `vuln-intel/{npm,pypi}/*.json` | `scans/sca/filesystemProvider.ts` | 100 files / 84 identity items / 78 advisory ids | `DATASET_AVAILABLE` |
| SAST packs | `packs/sast/v1/rules/*.json` | `external/conformance.ts` → `packIntegration.ts` → `SastEngine` | 1,000 | `AVAILABLE` (`drobon-sast-starter@1.0.0`) |
| Secrets packs | `packs/secrets/v1/rules/*.json` | same → `SecretsEngine` | 1,000 | `AVAILABLE` (`drobon-secrets-starter@1.0.0`) |
| DAST packs | `packs/dast/v1/rules/*.json` | same → `DastEngine` / active engine | 1,007 | `AVAILABLE` (`drobon-dast-starter@1.0.0`) |
| SCA declaration packs | `packs/sca/v1/rules/*.json` | `external/service.ts` → `external/scaDeclaration.ts` → `scans/sca/declarationScan.ts` → `ScaEngine` | 1,000 | `AVAILABLE` (`drobon-sca-dependency-hygiene@1.0.0`) — **evaluated** (all 4,001 declared tests; 9 parser kinds have bounded readers; upload and format limitations still apply) |
| Remediation | `knowledge/remediation/*.json` | `external/guidance.ts` → assistant / finding detail / reports | 4,007 | `AVAILABLE`, surfaced as `RULE_SPECIFIC` |
| CWE | `knowledge/cwe/*.json` | `external/knowledge.ts` | 102 | `AVAILABLE` |
| Lessons | `learning/lessons/*.json` | `external/lessonProvider.ts` | 6 (2 `lsn_dev_*`) | `AVAILABLE` |
| Assessment templates | `assessments/templates/*.json` | dataset status surface | 3 | `AVAILABLE` |
| Engagement templates | `engagements/*.json` | dataset status surface | 2 | `AVAILABLE` |

**There is no built-in fallback.** `SAST_RULES`, `SECRETS_RULES`, the old DAST
checks and the embedded lesson/remediation catalogs are empty by design. With
`VULN_INTEL_PROVIDER=none` the app starts — loudly — with 0 scanner rules, 0
lessons, `UNAVAILABLE` guidance and SCA `NOT_ASSESSED`. Startup log:

```
[dataset] STARTUP: VULN_INTEL_PROVIDER=none — no external Drobon-Dataset.
SAST/Secrets/DAST have 0 rules, remediation is UNAVAILABLE, SCA stays NOT_ASSESSED.
```

That is an honest degraded mode, **not** a silent product that "detects nothing
but looks fine". Operators must mount the dataset.

## Architecture

```
Drobon/                                   (code only; no dataset bytes)
  apps/api/src/scans/sca/
    filesystemProvider.ts                — advisory matches from DATASET_PATH
    range.ts                             — npm semver / PEP 440 evaluator
  apps/api/src/external/
    service.ts                           — one cached loader for all 10 categories
    conformance.ts                       — closed-field validation, ReDoS lint, declared tests
    evaluator.ts / setCookie.ts          — browser-accurate DAST check semantics
    languageAliases.ts                   — 115 pack language ids → App families
    packProvider.ts / packIntegration.ts — DPK-* → engine rules
    knowledge.ts / guidance.ts           — remediation + CWE lookups (cached)
    lessonProvider.ts                    — dataset lesson catalog
    routes.ts / types.ts                 — honest status surface
  apps/api/src/scans/dast/observedHeaders.ts — 57 inspected response headers
  scripts/verify-dataset.mjs            — real integration verification (tsx)

Drobon-Dataset/                           (external, never committed here)
  vuln-intel/ · packs/{sast,secrets,dast,sca}/v1/ · knowledge/ · learning/
  assessments/ · engagements/ · interop/provider-vectors.json
```

Status endpoint: `GET /api/v1/dataset/status` (auth required) returns every
category plus `vulnIntelCounts` (files / identity items / advisory ids), `packs`
(packId + version per family) and `conformance` (accepted, declared/executed/
skipped/failed tests, rejected rules). Inspection:
`GET /api/v1/dataset/packs/:kind` (`sast|secrets|dast|sca`) and
`GET /api/v1/dataset/lessons`.

## Loader contract (fail closed)

1. Every pack file is checked against a **closed field set**, its
   `schemaVersion`, id pattern, severity and check type. Unknown fields or an
   unknown check type are refused, not silently evaluated as `false`.
2. Every regex passes a conservative **static ReDoS lint** and must compile.
3. Every **declared test** is executed at load time through the same app
   evaluator used in scans. A rule whose own examples disagree is refused.
   Measured: SAST 4,043 / secrets 4,660 / DAST 3,673 / **SCA 4,001** declared
   tests — **0 failures, 0 skipped, 0 rejected rules**.
4. SCA declaration rules (1,000) are compiled by the app's own
   `external/scaDeclaration.ts` evaluator (six closed predicates, bounded
   path/name walks). Status now reports
   `scaDeclarationEvaluator: "AVAILABLE"`, `scaDeclarationScanParsers:
   all 9 kinds]`, `scaDeclarationScanReachableRules` counts potentially eligible rules, excluding blocked artifacts. Pump 18 added
   bounded readers for the eight remaining kinds (TOML/YAML/XML/INI/properties/
   Gradle/requirements/lockfile-text) — see [`SCA_READERS.md`](SCA_READERS.md).
   Real SCA scans can evaluate non-JSON manifests, but bounded readers can also misinterpret unsupported shapes. These scans are marked partial; not every mismatch becomes `declarationRulesNotEvaluated`. Dotfile artifacts (`.npmrc`, `.yarnrc.yml` …) remain blocked by
   the source-path policy and are reported separately in the evidence JSON.
5. `pack.json` identity (`packId` + `version`) is surfaced on the status and
   pack-inspection routes, so a finding's `DPK-*` rule id can be traced to a
   dataset version. Per-finding stamping still requires a shared-contract
   change and is listed as remaining work in the audit.

## Provider status mapping (dataset ↔ scan state)

Both repos now state the same table (dataset `interop/APP_CONFORMANCE.md` §5):

| Provider dataset status | Advisories | Scan state | Honest meaning |
|---|---|---:|---|---|
| `NO_DATA_LOADED` (provider `none`) | 0 | `NOT_ASSESSED` | no data was consulted |
| `DATASET_UNAVAILABLE` (bad path) | 0 | `NOT_ASSESSED` | data not reachable at scan time |
| `DATASET_AVAILABLE`, coordinate absent | 0 | `NOT_ASSESSED` | not in this corpus — **not** "clean" |
| `DATASET_AVAILABLE`, version outside every range | 0 | `NOT_ASSESSED` | no advisory in this dataset version applies |
| `DATASET_AVAILABLE`, range matched | ≥1 | `ASSESSED` | verified match with provenance |

**Counting:** the App's `vulnIntel.count` is the raw **file** count (100).
`vulnIntelCounts.identityItems` (84) and `advisoryIds` (78) are the canonical
deduplicated counters defined by the dataset's `docs/COUNTING_POLICY.md`.
All three are now reported; none is presented as the other.

## Local development

```bash
# 1. One-time: clone the dataset OUTSIDE the app repo
npm run sync:dataset                      # → ../Drobon-Dataset
npm run check:dataset                     # verify the checkout

# 2. Configure (or put these in .env)
export VULN_INTEL_PROVIDER=filesystem
export DATASET_PATH=../Drobon-Dataset

# 3. Verify the connection with REAL app modules (needs no server, no network)
npm run verify:dataset -- --path ../Drobon-Dataset --write

# 4. Run the product
npm ci && npm run dev
```

`verify:dataset` prints and (with `--write`) saves a JSON evidence file. Its
checks: all category counts, loader conformance, DAST declared-test parity,
DAST header reachability, SAST language reachability, the 16 pinned
`interop/provider-vectors.json` SCA vectors, and remediation surfacing. It
exits non-zero on any failure, so it is usable as a CI gate when a dataset
checkout is available.

Verify endpoints (authenticated): `/api/v1/dataset/status`,
`/api/v1/dataset/packs/dast`, `/api/v1/dataset/lessons`. SCA example:
`fast-jwt@6.2.4` → 6 advisories, `ASSESSED` / `DATASET_AVAILABLE`.

## Known limits / owner decisions

- **New CVEs / runtime-engine bugs (e.g. PHP2Shell)**: the dataset packs above
  classify *declared dependencies and source patterns*, not installed runtime
  versions. That is the job of the separate, data-driven
  [`ADVISORY_ENGINE.md`](ADVISORY_ENGINE.md) (`ADVISORY_PATH`), which is
  language-agnostic and needs no dataset-repo change. A live licensed advisory
  feed + refresh cadence is still an owner/licence decision (GAP-001..004).
- **SCA declaration pack (1,000 rules)**: the evaluator now exists in the app
  and all 4,001 declared tests execute at load time. Scan-time coverage is
  all nine parser kinds now have bounded readers (`SCA_READERS.md`). Residual
  limits: ~95% round-trip verdict parity on dataset-declared shapes and 41
  rules whose artifact is a dotfile that the upload policy cannot accept —
  both reported in `DATASET_INTEGRATION_EVIDENCE.json` and counted honestly
  per scan.
- **Active DAST** (`apps/api/src/scans/dast/activeEngine.ts`) exists behind a
  consent gate while both repos' written boundaries say active probing is out
  of scope (dataset `DROBON_REMAINING_WORK.csv` GAP-045, P0). This is an
  **owner decision**: revert the feature or authorize it in writing and amend
  both repos' boundary docs together with consent + rate-limit evidence. No
  code change here presumes that decision.
- Widening the DAST header allowlist to 57 names adds **observation surface
  only**. Values stay clipped to 2,048 chars / 5 array entries, body to 32,768
  bytes. No new request, payload or crawling capability was added.
- Language aliases for 60+ config ids share one `config-file` family. A rule
  tagged `nginx` can therefore also be evaluated on an `sshd_config`; its own
  pattern decides whether it fires. Per-format families are future work.

## Related docs

- `docs/SCA.md`, `SAST.md`, `SECRETS.md`, `DAST.md`
- Dataset: `docs/FORMAT.md`, `PROVIDER_MAPPING.md`, `PACKS.md`, `AUDIENCES.md`,
  `COUNTING_POLICY.md`, `HONESTY.md`, `interop/APP_CONFORMANCE.md`
- This repo: `docs/DATASET_INTEGRATION_AUDIT_2026-10-26.md`
