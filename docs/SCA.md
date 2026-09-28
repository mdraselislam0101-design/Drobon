# SCA (Pump 9 — real software-composition analysis, honest by construction)

Pump 9 delivers the second REAL scanner engine: **software-composition
analysis of the uploaded source snapshot's dependency manifests**. SCA
scans complete with a genuine, deterministic dependency inventory, a
CycloneDX-subset SBOM and an honest assessment state — produced entirely
server-side. **Analysis only: manifests are read and parsed as data,
NEVER installed, NEVER executed.** No `npm install`, no `pip install`,
no lifecycle hooks, no `setup.py` — a `postinstall: "touch /tmp/pwned"`
script inside an uploaded `package.json` is inert text (verified by
end-to-end marker-file tests).

SECRETS (Pump 10) and limited passive DAST (Pump 11) are also real
engines (see `docs/SECRETS.md` and `docs/DAST.md`).

## THE DATASET LOCK (absolute)

**No CVE / NVD / GHSA / OSV / KEV / EPSS data may ever enter this
repository** — not vendored, not embedded, not synthesized into a
"demo database". The consequence is deliberate and shipped as a
feature:

- With no real vulnerability-intelligence dataset loaded, an SCA scan
  reports **`NOT_ASSESSED`** with `datasetStatus: NO_DATA_LOADED`. Its
  advisory collection is empty because no provider data was loaded; this
  is **not** a zero-vulnerabilities verdict, even for a snapshot that
  "looks" vulnerable (old `express`, old `lodash` pins). Nothing is
  fabricated. Ever.
- The scan still SUCCEEDS: the inventory, the direct/transitive
  classification and the SBOM are real work and are fully delivered.
  A missing dataset never fails a scan and never burns analysis.
- `VULN_INTEL_PROVIDER` must be `none` (see `.env.example`); any other
  value fails configuration validation at startup. The lock is
  enforced in config, in code (`apps/api/src/scans/sca/provider.ts`)
  and in tests (`staticSafety`, engine honesty suites).

The advisory→finding path is nevertheless REAL: the
`VulnerabilityIntelligenceProvider` boundary is injectable, and a
test-only stub provider flows verified synthetic records through the
same validation, dedup and persistence path a future dataset will use.
The boundary exists; the data does not. That is the honest state.

## The pipeline

```
source snapshot (Pump 8 upload policy, unchanged)
  → manifest discovery        (apps/api/src/scans/sca/engine.ts)
  → defensive parsing         (apps/api/src/scans/sca/parsers.ts)
  → normalized inventory      (apps/api/src/scans/sca/inventory.ts)
  → deterministic SBOM        (inventory.ts, CycloneDX 1.5 subset)
  → OPTIONAL intelligence     (provider.ts — Null provider today)
  → honest assessment         (NOT_ASSESSED unless a provider assessed)
```

The engine plugs into the EXACT Pump 7/8 orchestration: same job
store, same processor, same quota/idempotency/lifecycle rules, same
pre-flight (an SCA scan without a snapshot is a 409 before quota
consumption). There is no parallel system.

## Supported manifests (and what "unsupported" means)

| Manifest | Ecosystem | Status | Notes |
| -------- | --------- | ------ | ----- |
| `package.json` | npm | ANALYZED | dependencies/devDependencies/optionalDependencies/peerDependencies; runtime wins on duplicate names; name+version give the root identity |
| `package-lock.json` v3/v2 | npm | ANALYZED | `packages` map: root `""` entry supplies the direct set; nested `node_modules/...` keys resolve to the innermost package; `link: true` and version-less entries are skipped |
| `package-lock.json` v1 | npm | ANALYZED | flat `dependencies` map; classes are `unknown` until a companion `package.json` in the same directory classifies them (declared = direct, rest = transitive) |
| `requirements.txt` | pypi | ANALYZED | pins, ranges, extras (stripped from the name), environment markers (after `;`), continuation lines, `--hash` evidence; options/flags and bare URLs are skipped and counted |
| `pyproject.toml` | pypi | ANALYZED | PEP 621 `[project]` `dependencies` + `optional-dependencies` groups; Poetry `[tool.poetry]` dependency tables (`python` key excluded) |
| anything else (e.g. `Pipfile`, `Gemfile`, `go.mod`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.toml`, `pom.xml`) | — | UNSUPPORTED | counted honestly with a bounded note; never a fake parse |

Discovery ignores `node_modules/`, `dist/`, `build/`, `out/`,
`coverage/`, `vendor/`, `target/`, `cache/` (case-insensitive) —
skipped files are counted, never silently dropped. Monorepos work:
manifests in subdirectories are analyzed with their paths kept as
evidence.

## Direct vs transitive, and version truth

- **Direct** = declared by the project author in a manifest
  (`package.json` sections, `requirements.txt`, `pyproject.toml`).
  Dev dependencies are direct AND typed `development`.
- **Transitive** = present in a lockfile closure without a direct
  declaration (npm lockfiles only).
- **Unknown** is honest: a lockfile v1 without a companion manifest
  leaves classes unknown — never guessed.
- `transitiveGraph` is `AVAILABLE` only when lockfile evidence exists
  AND every dependency is classified. A requirements/pyproject-only
  project reports `UNAVAILABLE` — those formats list direct
  declarations; there is no closure to report.
- **Declared and resolved versions are both preserved, never
  merged**: `declaredVersion` (e.g. `^4.18.0`) comes from the
  manifest; `resolvedVersion` (e.g. `4.17.1`) exists only when a
  lockfile provided it and carries `lockfilePath` + `versionSource:
  'lockfile'` as evidence. The shared guard rejects a resolved version
  without lockfile provenance (a fabricated pin) and a lockfile path
  without a resolution.

## Determinism (no random identities)

- Dependency fingerprint = `sha256` over a canonical coordinate
  (ecosystem, name, resolved-or-declared version, evidence paths).
- `dependencyId` = `dep_` + fingerprint prefix — identical snapshots
  produce identical ids across rescans and restarts (tested).
- The SBOM `serialNumber` is a content-hash-derived UUID — same input,
  same serial; a changed dependency changes the serial (tested).
- Inventory order is a stable total order (ecosystem, name, version,
  path) — no map-iteration luck.

## The SBOM (CycloneDX 1.5 JSON subset — exactly this)

Emitted fields: `bomFormat` (`CycloneDX`), `specVersion` (`1.5`),
`serialNumber` (`urn:uuid:…`, deterministic), `version` (1),
`metadata.tools.components[0]` (the analyzer), `metadata.component`
(root application, when a single named `package.json` provides it),
`components[]` (`type: library`, `bom-ref` = the dependency id, name,
resolved-or-exact-pin version, `scope` required/optional/excluded by
type, `purl` when constructible, `hashes` from lockfile integrity —
never fabricated), `dependencies[]` (only evidenced edges:
root → direct). Deliberately omitted: timestamps, suppliers, licenses,
external references, contacts — everything without evidence in the
snapshot. purls are `pkg:npm/name[@version]` / `pkg:pypi/name[@version]`
(PEP 503-normalized), emitted only when constructible; scoped npm
names percent-encode the scope separator per the purl spec.

## Vulnerability intelligence boundary

`VulnerabilityIntelligenceProvider` (`apps/api/src/scans/sca/provider.ts`)
is the single seam a real dataset plugs into:

```
assess(coordinates) → { providerId, datasetStatus, advisories[] }
```

- The Null provider (`createNullIntelligenceProvider`, id `none`)
  answers `NO_DATA_LOADED` with zero advisories — the shipped default,
  composed in `app.ts` from `VULN_INTEL_PROVIDER=none`.
- Provider advisories are re-validated against the shared closed
  contract, deduplicated, dropped when they reference dependencies not
  in this scan, and `ASSESSED` is claimed only when a provider with
  loaded data actually matched records. `ASSESSED` under provider
  `none` is structurally rejected by the shared guard.
- Synthetic advisory fixtures exist ONLY inside tests (clearly marked)
  — they are the boundary proof, never product data.

## Limits (deliberately reused, not raised)

| Limit | Value | Source |
| ----- | ----- | ------ |
| Snapshot files / per-file / total | 200 / 256 KiB / 768 KiB | Pump 8 upload caps — unchanged |
| Manifests per scan | 50 | `SCA_MAX_MANIFESTS_PER_SCAN` (breach → `SCA_MANIFEST_LIMIT_EXCEEDED`) |
| Manifest bytes (total, pre-parse) | 768 KiB | breach → `SCA_TARGET_TOO_LARGE` |
| Inventory entries persisted | 200 | `SCA_MAX_DEPENDENCIES_PER_SCAN` — the summary keeps the honest total + `truncated: true` |
| Parser entries per manifest | 500 | breach → manifest PARTIAL with a bounded note |
| Parser lines per manifest | 10 000 | breach → manifest INVALID_INPUT |
| Processing deadline | 10 s | breach/abort → `SCA_SCAN_TIMEOUT` |

Known, documented limitation: a monolithic `package-lock.json` larger
than the 256 KiB per-file snapshot cap cannot be uploaded (the cap is
a security bound and is NOT raised for SCA). Real-world lockfiles of
small/medium projects fit; large ones are honestly out of scope today.

## Failure codes (closed set)

`SCA_TARGET_NOT_FOUND` (no snapshot), `SCA_TARGET_TOO_LARGE`
(byte budget), `SCA_INPUT_INVALID` (owner mismatch, traversal-shaped
stored path), `SCA_MANIFEST_LIMIT_EXCEEDED`, `SCA_SCAN_TIMEOUT`
(deadline or abort). All fail the scan closed — never a partial
result presented as complete.

## Parser security (the manifest is attacker input)

- **Own-property discipline**: prototype keys (`__proto__`,
  `constructor`, `prototype`) are skipped as data everywhere —
  checked with `Object.prototype.hasOwnProperty`-style access, never
  `key in obj`, never square-bracket assignment into shared shapes.
- **No recursion** on JSON structure: iteration is flat over sections;
  200-deep nesting is ignored by construction.
- **Bounded everything**: entry caps, line caps, name/version/note
  length caps; control characters rejected (versions, names, notes).
- **Invalid data is dropped, never guessed**: malformed JSON →
  INVALID_INPUT with a bounded note (no content echo); invalid names,
  non-string versions, junk requirement lines are dropped — a bare
  name is kept only when the line legitimately declared one.
- **Path policy reuse**: evidence paths must satisfy the Pump 8
  `SOURCE_PATH_PATTERN` (checked again in the shared guard) —
  traversal, absolute paths, backslashes, drive letters and percent
  encoding are unrepresentable. There is no second path
  implementation.
- `staticSafety` enforces that no exec primitive appears in the SCA
  sources, with a narrowly-scoped structural exemption for the
  prototype-key denylist DATA in `parsers.ts` (compensated by a test
  that pins the denylist to data, not access).

## API surface (no new routes)

- `POST /api/v1/projects/:projectId/scans` with `{ scanType: "SCA" }`
  — same job creation, same pre-flight 409 without a snapshot.
- `GET /api/v1/projects/:projectId/scans/:scanId` — the detail route
  is the ONLY surface carrying the SCA payload (`scan.sca`: summary,
  dependencies, manifests, sbom, advisories). List responses stay
  lean (counts only).
- The payload is server-authoritative: request bodies accept only
  `scanType` (injected `sca`/`resultSummary` → 422), and the store
  refuses to boot on a forged `sca` on a non-SCA or non-terminal scan
  or a structurally invalid payload (fail-fast, no silent repair).
- SCA payloads persist atomically with the COMPLETED transition and
  survive restarts byte-identically (tested).

## UI

The project page renders SCA scans distinctly from SAST: dependency
counts in the list ("Dependencies: 7 (5 direct)" vs "Findings: 6"), a
lazy "View dependency analysis" view with the honest assessment banner
("Not assessed — vulnerability intelligence dataset unavailable"),
summary facts (direct/transitive/unknown, transitive graph, SBOM
availability), manifest outcomes (ANALYZED/PARTIAL/UNSUPPORTED/
INVALID_INPUT all visible), the inventory as text with declared +
resolved versions and evidence paths, truncation surfaced ("N of M"),
and advisories only when a real provider produced them. The SAST
findings view is untouched and clearly separate.

## Testing map

| Suite | Covers |
| ----- | ------ |
| `apps/api/test/scaParsers.test.ts` | name normalization (npm/pypi), all four manifests, adversarial matrices (proto keys, deep nesting, huge maps, malformed locks, invalid versions/names, control chars, traversal-shaped names), bounds (entry cap → PARTIAL, line cap → INVALID_INPUT), shell-looking strings as data |
| `apps/api/test/scaEngine.test.ts` | multi-ecosystem end-to-end, determinism (ids + SBOM serial), lockfile-priority truth, transitive-graph honesty (pypi-only → UNAVAILABLE), Null-provider honesty (NOT_ASSESSED, 0 advisories), stub-provider reality (validated advisories, phantom/malformed dropped), marker-file non-execution, path/owner fail-closed, caps (manifests/bytes/inventory truncation), deadline/abort, malformed-manifest honesty, default limits |
| `apps/api/test/scaApi.test.ts` | pre-flight 409 (quota protected), real scan over HTTP (validated payload, detail-route only), idempotent replay, archived 409, cross-account isolation, no content leakage, persistence/restart determinism, tamper guards (forged sca on SAST/QUEUED/malformed → refuse to boot; client injection → 422), SAST/SECRETS regressions and passive DAST integration (Pump 11) |
| `packages/shared/test/sca.test.ts` | closed vocabularies, id/fingerprint patterns, caps constants, guard rejections (unknown keys, out-of-vocabulary, fabricated pins, fake hashes/URLs, traversal evidence paths), cross-field honesty (NOT_ASSESSED↔advisories, ASSESSED requires provider+advisories, counts match arrays, manifest cap), deterministic ordering |
| `apps/web/test/scaUi.test.tsx` | list distinction SCA/SAST, honest banner, inventory/manifests/SBOM rendering as text, client-side ecosystem filter, truncation visibility, ASSESSED-with-advisories path, error/retry honesty |
