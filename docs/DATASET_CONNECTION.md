# Dataset Connection — Main App ↔ Drobon-Dataset (Full Unlock)

This document explains how the **main app** (`mdraselislam0101-design/Drobon`) connects to the **external dataset repo** (`mdraselislam0101-design/Drobon-Dataset`) **without ever committing dataset files into the app repo**.

The app repo enforces an absolute dataset lock: no `cve/nvd/ghsa/osv/cve` files may be committed (checked by `scripts/check-boundaries.mjs`). The dataset lives in its own repo; the app only *reads* it at runtime via server-side filesystem providers.

## What is now unlocked (all UserTypes)

A single env switch unlocks **all** dataset-backed categories. `VULN_INTEL_PROVIDER` was the original SCA lock; it now gates the entire external content surface (SCA + packs + knowledge + audiences) — one mount, one honesty model.

| Category | Dataset path | App consumer | UserType | Honest state |
|---|---|---|---|---|
| **SCA vuln-intel** | `vuln-intel/{npm, pypi}/*.json` (100 GHSA) | `createFilesystemIntelligenceProvider` → `assess(coordinates)` | All | `DATASET_AVAILABLE`/`UNAVAILABLE`/`NOT_CONFIGURED` |
| **SAST packs** | `packs/sast/v1/rules/*.json` (950) | `SastEngine` merges `DG-SAST-*` (50 built-in) + `DPK-SAST-*` (dataset) per scan | All (Student/Developer verify via practice) | `AVAILABLE` when 950 loaded else embedded-only |
| **Secrets packs** | `packs/secrets/v1/rules/*.json` (97) | `SecretsEngine` merges `DG-SEC-*` + `DPK-SEC-*` | All | Same |
| **DAST packs** | `packs/dast/v1/rules/*.json` (263) | `DastEngine` evaluates built-in 8 DG-DAST-* + dataset checks via `http-url`/`missing-header`/etc. | PENTESTER (passive) | Same |
| **Remediation** | `knowledge/remediation/*.json` (1310) | `assistant` + `reports` + finding `remediation` (dataset value preferred) | DEVELOPER (primary) | `AVAILABLE` 1310 |
| **CWE** | `knowledge/cwe/*.json` (68) | CWE reference resolver | All | `AVAILABLE` 68 |
| **Lessons** | `learning/lessons/*.json` (6; 2 `lsn_dev_*`) | `GET /api/v1/student/lessons` merges 4 embedded + 6 dataset = 10 | STUDENT (6), DEVELOPER (2) | `byUserType: {DEVELOPER:2, STUDENT:6}` |
| **Assessment templates** | `assessments/templates/*.json` (3) | `GET /api/v1/dataset/status` + future assessment-create template picker | SECURITY_PROFESSIONAL | `AVAILABLE` 3 |
| **Engagement templates** | `engagements/*.json` (2) | Same status surface | PENTESTER (passive-only) | `AVAILABLE` 2 |

Shared status endpoint: `GET /api/v1/dataset/status` (auth required) — honest counts for every category, plus `/api/v1/dataset/packs/:kind` and `/api/v1/dataset/lessons` for inspection.

## Architecture

```
Drobon/                     (main app — code only, VULN_INTEL_PROVIDER=none by default)
  apps/api/src/scans/sca/
    provider.ts            — Null provider (locked default, NO_DATA_LOADED)
    filesystemProvider.ts  — Filesystem provider (DATASET_AVAILABLE, loads external corpus)
    range.ts               — npm semver + PEP 440 evaluator (copied from dataset repo)
  apps/api/src/external/   — Unified dataset service (filesystem, read-only, cached)
    service.ts             — Loads all categories from DATASET_PATH, exposes status
    packProvider.ts        — DPK-* → engine rule conversion (validated, ReDoS-linted)
    lessonProvider.ts      — Merges embedded 4 + dataset 6 lessons
    evaluator.ts           — 7 DAST pack check types (PACKS.md)
    knowledge.ts           — Remediation/CWE lookups
  .env                     — VULN_INTEL_PROVIDER=filesystem + DATASET_PATH=../Drobon-Dataset

Drobon-Dataset/             (external — never committed to Drobon/)
  vuln-intel/npm|pypi      — 100 GHSA advisories
  packs/sast|secrets|dast  — 1310 rules (950/97/263)
  knowledge/remediation|cwe — 1310 + 68
  learning/lessons         — 6 (2 dev)
  assessments/templates    — 3
  engagements              — 2 (passive-only)
  interop/provider-vectors — 16 pinned vectors
```

In production the dataset can be mounted as a volume, EFS/NFS, or a future DB service — the app only needs a filesystem path. No dataset is ever vendored.

## How engines use the dataset

1. **Inventory first**: SCA/SAST/Secrets/DAST ALWAYS produce inventory/findings even with no dataset — honest `NOT_ASSESSED`/`NO_DATA_LOADED` when nothing loaded.
2. **Provider seams**: 
   - SCA: `assess(coordinates)` receives only `{ ecosystem, name, version?, dependencyId }`
   - SAST/Secrets: engine receives merged rule list (`DG-*` + `DPK-*`) per scan (dataset packs validated, ReDoS-linted, compiled to RegExp; failures fail-closed)
   - DAST: built-in 8 checks + dataset pack checks evaluated per response
   - Lessons: merged catalog, `answerIndex` stripped for public projection (same as embedded)
3. **Honest states** for every category: `AVAILABLE` (loaded, count), `UNAVAILABLE` (path wrong), `NOT_CONFIGURED` (provider `none`). Scans still COMPLETE with `NOT_ASSESSED` when unavailable — never fabricate.

See `docs/SCA.md`, `docs/SAST.md`, `docs/SECRETS.md`, `docs/DAST.md` and dataset's `docs/PROVIDER_MAPPING.md`/`PACKS.md`/`AUDIENCES.md`.

## Local Development — 3 Steps

### 1. Clone the dataset as a sibling (one time)

```bash
node scripts/sync-dataset.mjs
# → clones https://github.com/mdraselislam0101-design/Drobon-Dataset.git to ../Drobon-Dataset
# Or custom:
node scripts/sync-dataset.mjs --path /opt/drobon-dataset
# Verify:
node scripts/sync-dataset.mjs --check
```

Does NOT modify app repo git index — outside, ignored by `.gitignore`.

### 2. Configure the app to use it

```bash
VULN_INTEL_PROVIDER=filesystem
DATASET_PATH=../Drobon-Dataset
```

- Must be `none` or `filesystem` (any other fails fast)
- `DATASET_PATH` only allowed when `filesystem` (fail-closed)
- In `production`, `:memory:` stores rejected but filesystem provider allowed

### 3. Run

```bash
npm ci
npm run dev
# or
VULN_INTEL_PROVIDER=filesystem DATASET_PATH=../Drobon-Dataset npm run dev:api
```

Verify:
- `GET /api/v1/dataset/status` → all `AVAILABLE` with counts 100/950/97/263/1310/68/6/3/2
- `GET /api/v1/student/lessons` → 10 (4 embedded + 6 dataset)
- SCA: `fast-jwt@6.2.4` → 6 advisories ASSESSED/DATASET_AVAILABLE
- SAST: `eval(userInput)` → `DPK-SAST-001` finding
- Secrets: `AKIA...` → `DPK-SEC-001` finding

Without dataset: same calls → `NOT_CONFIGURED`/`NO_DATA_LOADED` + embedded-only findings (4 lessons, 50 SAST rules) — honest absence.

## Production Options

| Mode | Setup | Pros |
|------|-------|------|
| **Sidecar volume** | Mount at `/opt/drobon-dataset` in API container | Simple, no network |
| **Shared NFS/EFS** | One mount, many replicas | One pull |
| **HTTP provider (future)** | `createHttpIntelligenceProvider` → `GET /vuln-intel?...` | Independent scaling |

All providers read-only, bounded, side-effect-free — never execute dataset content.

## Updating the dataset

```bash
node scripts/sync-dataset.mjs  # pull --ff-only
# No rebuild needed — next assess/scan loads via lazy cache; restart to force reload
```

## Verification

```bash
npm run check:boundaries   # PASS
npm run test --workspace @drobon/api  # 812/812
npm run test --workspace @drobon/shared # 183/183
GET /api/v1/dataset/status --auth   # counts validated
GET /api/v1/student/lessons --auth  # 10 when configured
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `VULN_INTEL_PROVIDER must be one of none, filesystem` | lowercase `filesystem` |
| `DATASET_PATH must be set when ...filesystem` | Set `DATASET_PATH` |
| `DATASET_UNAVAILABLE` | `node scripts/sync-dataset.mjs --check` |
| `NO_DATA_LOADED` | Switch to `filesystem` |

## Related docs

- `docs/SCA.md`, `SAST.md`, `SECRETS.md`, `DAST.md`
- Dataset: `docs/FORMAT.md`, `PROVIDER_MAPPING.md`, `PACKS.md`, `AUDIENCES.md`, `HONESTY.md`
