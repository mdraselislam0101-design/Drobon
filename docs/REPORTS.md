# Findings and security reports (Pumps 12–13)

Pump 12 completes the existing persisted Finding and scan-result surfaces. Pump 13 adds the lifecycle, notes, and safe rule-based guidance described in [`FINDINGS.md`](./FINDINGS.md). Neither introduces a parallel scan, authorization, quota, or storage system.

## Finding reads

All routes require an authenticated account and resolve the requested project through the existing server-side ownership resolver before looking up scan data:

- `GET /api/v1/projects/:projectId/scans/:scanId/findings`
- `GET /api/v1/projects/:projectId/scans/:scanId/findings/:findingId`

The page route accepts only `severity`, `scanner`, `page`, and `pageSize`. Each query key may appear once. Severity and scanner use the closed shared vocabularies; `page` is 1–10,000; `pageSize` is 1–100 (default 20). Results are filtered on the server, sorted by the shared deterministic finding comparator, and sliced after filtering. The scan's existing maximum of 200 persisted findings bounds the full result set. Unsupported, repeated, malformed, or out-of-range query inputs fail closed.

Newly persisted findings carry an explicit project ID (the store attaches server-authoritative context for source findings); legacy source rows remain linked through their scan for backward-compatible reads. DAST findings include mandatory project/target context and observation time. Finding detail is nested under its project and scan. The response cross-checks project ID, scan ID, finding ID, and scanner family. Evidence remains bounded and redacted where applicable, and the web UI renders it as text. SCA dependency advisories remain part of the SCA result and are not converted into common Finding records.

## Persisted, single-scan report

Reports derive only from a persisted `COMPLETED` scan and its stored result. They include project and scan context, single-scan scanner coverage, severity/scanner finding counts, persisted findings, an honest dependency-intelligence state, and the actual dependency inventory/SBOM when the source scan is SCA. DAST reports include bounded observed response metadata; raw response bodies, cookie values, credentials, and arbitrary response headers are not exported.

Routes:

- `POST /api/v1/projects/:projectId/scans/:scanId/report` with an empty JSON object creates a report, or returns the already-persisted report for that scan. New reports return 201; idempotent replays return 200.
- `GET /api/v1/projects/:projectId/scans/:scanId/report` retrieves an existing report without generating one.
- `GET /api/v1/projects/:projectId/scans/:scanId/report/download?format=json|markdown|sarif|pdf` downloads the persisted report. JSON is canonical; Markdown is a human-readable escaped representation; SARIF 2.1.0 is a machine-readable rendering for CI/code-scanning importers (rule-fixed severities mapped to SARIF levels, DROBON stable fingerprints carried as `drobon/v1` fingerprints, DAST observations as logical locations; dependency-intelligence status is carried verbatim and remains honest when `NOT_ASSESSED`). PDF is a bounded human-readable summary of the saved report, with caps and omissions disclosed. Filenames are generated from validated report IDs.
- `GET /api/v1/projects/:projectId/reports/portfolio/download` creates an owner-only project PDF on demand. It uses the latest attempted scan of each type, not an older success when a newer attempt failed. If latest request timestamps tie, it states `ORDER_UNCERTAIN` instead of guessing. Scans may use different snapshots or scopes, findings are not deduplicated, and PDF detail caps are disclosed. The export does not create a persisted multi-scan report.
- `GET /api/v1/projects/:projectId/scans/:scanId/report/sbom` downloads the persisted CycloneDX SBOM subset of an SCA scan as a standalone JSON document. It is a re-serialization of the exact persisted `inventory.sca.sbom` — never regenerated and never enriched with external data; when the source scan produced no dependency inventory the route answers `422` with an explicit "no dependency inventory" validation message. The SBOM is an inventory, not a vulnerability verdict.

One report record per completed scan is stored in the existing durable scan JSON document. Pump 13 adds an optional point-in-time workflow snapshot to new reports; legacy Pump 12 reports without it remain valid. The store validates schema, digests, scan linkage, and size on startup; corrupt or detached report data fails startup rather than being silently served. Older scan documents without a `reports` array load as an empty report set. The store permits at most 100 reports and each canonical JSON report is capped at 512 KiB. Export bodies are separately bounded; the web client validates media type, generated filename, and streamed byte size before creating a download.

`GET .../report` returns the saved snapshot as-is. `POST .../report` rebuilds a snapshot from current persisted findings/workflows and replaces that scan's report only when the content digest changes; the report ID is derived from the new content and may therefore change. Regeneration does not consume scan quota. A workflow mutation does not silently alter an already-persisted report; explicitly regenerate it to capture the new point-in-time state.

Canonical JSON sorts object keys recursively while preserving array order. SHA-256 `contentDigest` covers the report's source/result material; `reportId` is derived from that digest. `integrityDigest` is an actual SHA-256 over the persisted report fields, including its generation timestamp. These digests detect content changes; **they are not signatures and do not prove who produced a report**. Report creation/retrieval does not consume scan quota.

## Coverage and vulnerability-data honesty

**Current coverage ledger:** New reports include a deterministic SAC section describing the single scan, known metrics, recorded SAST effective-rule provenance when available (otherwise unknown), limitations, and `UNKNOWN` residual risk / `NOT_ASSESSED` compliance. JSON, Markdown, SARIF, and the report UI surface it. Older reports without it remain valid. See [`SECURITY_OPERATIONS_COVERAGE.md`](SECURITY_OPERATIONS_COVERAGE.md).

**AST coverage:** Current SAST summaries record bounded JS/TS/JSX/TSX, Python, PHP and Java parser counts and file statuses, missing flow categories, effective-rule metadata/hash, parser versions and limited JS/TS project flow. DAST additionally inspects only already-observed baseline response scripts without fetching or executing them; Secrets adds context to existing redacted matches; SCA counts package.json syntax declarations without making advisory claims. The optional `astSupplement` and `astContext` record counts, incomplete inputs and attribution. JSON and Markdown carry these fields; SARIF uses `drobon/astParser`, `drobon/astCoverage`, `drobon/astFlow`, `drobon/astSupplement` and `drobon/astContext`. Older reports without fields remain valid and do not imply coverage. SAC marks a partial AST supplement as partial; SOC may produce a saved-scan partial-coverage alert. Category-selected reporters are not proof the exact rule matched, hashes are not signatures, and coverage is not a completeness claim. See [`AST_ANALYSIS.md`](AST_ANALYSIS.md).


Each report states which scanner ran for the source scan and labels other scanner types `NOT_RUN`; it is not a project-wide or cross-scan roll-up. SCA inventory and CycloneDX-subset SBOM data are included only when present in the persisted SCA result. With `VULN_INTEL_PROVIDER=none`, the result retains `NO_DATA_LOADED` and `NOT_ASSESSED`; an empty advisory collection is not described as zero vulnerabilities or as a clean bill of health. The app does not bundle or automatically update vulnerability catalogs. An operator-configured external dataset or advisory pack may be loaded; its availability, scope and freshness must be checked separately.

Reports do not synthesize findings, dependency versions, advisories, CWE/CVSS scores, or assessment coverage that the scan did not produce. Unsupported scanner behavior remains explicit and unchanged.

## Limits

Persisted reports cover one completed scan at a time; the on-demand project PDF is a bounded, non-deduplicated summary across the latest attempts and is not persisted. The bounded finding lifecycle and note history are persisted in the existing scan store and summarized in point-in-time reports; the full audit history is not embedded in reports. Digital signatures, report scheduling, and a database-backed report repository are not implemented. PDF renders Bengali/Latin where supported; unsupported glyphs are replaced, and exact Unicode text should be obtained from JSON.
