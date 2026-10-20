# Dataset Connection — Main App ↔ Drobon-Dataset

This document explains how the **main app** (`mdraselislam0101-design/Drobon`) connects to the **external dataset repo** (`mdraselislam0101-design/Drobon-Dataset`) **without ever committing dataset files into the app repo**.

The app repo enforces an absolute dataset lock: no `cve/nvd/ghsa/osv/cve` files may be committed (checked by `scripts/check-boundaries.mjs` and `scripts/check-repo-integrity.mjs`). The dataset lives in its own repo; the app only *reads* it at runtime via a server-side filesystem provider.

## Architecture

```
Drobon/                     (main app — code only, VULN_INTEL_PROVIDER=none by default)
  apps/api/src/scans/sca/
    provider.ts            — Null provider (locked default, NO_DATA_LOADED)
    filesystemProvider.ts  — Filesystem provider (DATASET_AVAILABLE, loads external corpus)
    range.ts               — npm semver + PEP 440 evaluator (copied from dataset repo)
  .env                     — VULN_INTEL_PROVIDER=filesystem + DATASET_PATH=../Drobon-Dataset

Drobon-Dataset/             (external — never committed to Drobon/)
  vuln-intel/npm/*.json    — 50 GHSA npm advisories (100 files, 78 ids)
  vuln-intel/pypi/*.json   — 50 GHSA pypi advisories
  packs/                   — 1310 rule packs (future loader)
  interop/provider-vectors.json — 16 pinned vectors for provider testing
```

In production the dataset can be mounted as a volume, an EFS/NFS mount, or a separate API service — the app only needs a filesystem path. No dataset is ever vendored.

## How SCA uses the dataset

1. **Inventory first**: SCA scans ALWAYS produce the real inventory + SBOM (manifest parsing, no execution) — even with no dataset.
2. **Provider seam**: `assess(coordinates)` receives only `{ ecosystem, name, version?, dependencyId }` — never manifest content.
3. **Honest states**:
   - `VULN_INTEL_PROVIDER=none` → `NO_DATA_LOADED` + `NOT_ASSESSED` (zero advisories, never "0 vulns")
   - `VULN_INTEL_PROVIDER=filesystem` + valid `DATASET_PATH` + no matches → `DATASET_AVAILABLE` + `NOT_ASSESSED` (checked, no proven matches)
   - `filesystem` + matches → `DATASET_AVAILABLE` + `ASSESSED` (+ advisories)
   - `filesystem` + missing path → `DATASET_UNAVAILABLE` + `NOT_ASSESSED` (scan still completes)

See `docs/SCA.md` and the dataset repo's `docs/PROVIDER_MAPPING.md`.

## Local Development — 3 Steps

### 1. Clone the dataset as a sibling (one time)

```bash
# From the Drobon repo root:
node scripts/sync-dataset.mjs
# → clones https://github.com/mdraselislam0101-design/Drobon-Dataset.git to ../Drobon-Dataset

# Or custom path:
node scripts/sync-dataset.mjs --path /opt/drobon-dataset

# Verify:
node scripts/sync-dataset.mjs --check
node scripts/sync-dataset.mjs --path /opt/drobon-dataset --check
```

This does NOT modify the app repo's git index — the dataset is outside, ignored by `.gitignore` (`.data/`).

### 2. Configure the app to use it

Copy `.env.example` to `.env`, then set:

```bash
VULN_INTEL_PROVIDER=filesystem
DATASET_PATH=../Drobon-Dataset
# or absolute:
DATASET_PATH=/opt/drobon-dataset
```

- `VULN_INTEL_PROVIDER` must be `none` or `filesystem` (any other value fails fast at startup with `ConfigError`).
- `DATASET_PATH` is only allowed when provider is `filesystem` (fail-closed).
- In `production`, `:memory:` stores are rejected but `filesystem` provider is allowed — it just needs a real path.

### 3. Run

```bash
npm ci
npm run dev   # API :3001 + Web :5173
# or
VULN_INTEL_PROVIDER=filesystem DATASET_PATH=../Drobon-Dataset npm run dev:api
```

Create a project, upload a snapshot containing a vulnerable package, run an SCA scan:

- `fast-jwt@6.2.4` (npm) → should match 6 advisories (VEC-001)
- `handlebars@4.7.9` (npm) → 3 advisories (VEC-003)
- `django@5.2.16` (pypi) → 1 advisory (VEC-009)

Check the scan detail → SCA section → `DATASET_AVAILABLE` + advisories. With no dataset, the same scan shows `NOT_ASSESSED` / `NO_DATA_LOADED` — honest absence.

## Production Options

| Mode | Setup | Pros |
|------|-------|------|
| **Sidecar volume** | Mount Drobon-Dataset at `/opt/drobon-dataset` in the API container | Simple, no network; use `DATASET_PATH=/opt/drobon-dataset` |
| **Shared NFS/EFS** | Mount once, share to all API replicas | One pull, many readers |
| **HTTP provider (future)** | Implement `createHttpIntelligenceProvider` fetching `GET /vuln-intel?ecosystem=&name=&version=` | Scales independently; add `VULN_INTEL_PROVIDER=http` + `DATASET_URL` |

The current `filesystem` provider is read-only, bounded, and side-effect-free — it never executes dataset content, installs packages, or writes.

## Updating the dataset

```bash
# Pull latest vetted advisories:
node scripts/sync-dataset.mjs
# or
git -C ../Drobon-Dataset pull --ff-only

# No app rebuild needed — provider loads on next assess (lazy, cached per process).
# Restart the API to reload: npm run dev:api
```

The dataset repo is the source of truth for `FORMAT.md`, `range.mjs`, and `provider-vectors.json`. The app's `range.ts` is a copy — when the dataset repo updates range semantics, copy `scripts/range.mjs` → `apps/api/src/scans/sca/range.ts`.

## Verification

```bash
# App-side:
npm run check:boundaries   # PASS — no dataset files in app repo
npm run test --workspace @drobon/api -- sca  # provider honnesty + inventory tests

# Dataset-side (in ../Drobon-Dataset):
npm test                   # advisories + packs + vectors
npm run test:vectors       # provider interop vectors (16 must pass)
node scripts/check-vectors.mjs

# End-to-end honesty:
# 1. Without dataset: SCA → NOT_ASSESSED / NO_DATA_LOADED (inventory still complete)
# 2. With dataset, non-vuln package: SCA → NOT_ASSESSED / DATASET_AVAILABLE (checked, no matches)
# 3. With dataset, vuln package: SCA → ASSESSED / DATASET_AVAILABLE + advisories
```

## What NOT to do

- ❌ `cp -r ../Drobon-Dataset/vuln-intel ./vuln-intel` — violates `check-boundaries` and `check-repo-integrity` (commit will be rejected in CI).
- ❌ Add `ghsa`/`cve` packages to `package.json` — denied dependencies.
- ❌ Set `VULN_INTEL_PROVIDER=filesystem` without `DATASET_PATH` — startup fails.
- ❌ Commit `.env` with `DATASET_PATH` — it contains no secret but is gitignored; use `.env.example` as template.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ConfigError: VULN_INTEL_PROVIDER must be one of none, filesystem` | Typo like `fileSystem` | Lowercase `filesystem` |
| `DATASET_PATH must be set when ...filesystem` | Missing env | Set `DATASET_PATH=../Drobon-Dataset` |
| `DATASET_PATH is only allowed when ...filesystem` | Leftover path with `none` | Unset `DATASET_PATH` or switch to `filesystem` |
| Scan shows `DATASET_UNAVAILABLE` | Path wrong or no `vuln-intel/` | `node scripts/sync-dataset.mjs --check` |
| Scan shows `NO_DATA_LOADED` | Provider still `none` | `VULN_INTEL_PROVIDER=filesystem` |

## Related docs

- `docs/SCA.md` — SCA engine, limits, honesty
- `docs/SECURITY.md` — threat model, SSRF, redaction
- Dataset repo: `docs/FORMAT.md` (record shape), `docs/PROVIDER_MAPPING.md` (field mapping), `docs/HONESTY.md` (no-fabrication rules)
