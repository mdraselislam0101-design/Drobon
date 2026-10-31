# Finding lifecycle and remediation (Pump 13)

Pump 13 adds server-authoritative remediation workflow to the existing finding and scan stores. It does not create findings, change scanner evidence, modify source code, alter project ownership, or introduce another authorization/quota system.

## API and authorization

All endpoints require an authenticated account and resolve the project with the existing owner-only project resolver before touching a scan or finding:

- `GET /api/v1/projects/:projectId/scans/:scanId/findings/:findingId` returns the existing project/scan/finding detail plus its persisted workflow and deterministic rule-based guidance.
- `PATCH /api/v1/projects/:projectId/scans/:scanId/findings/:findingId/lifecycle` accepts exactly `{ "state": "..." }`.
- `POST /api/v1/projects/:projectId/scans/:scanId/findings/:findingId/notes` accepts exactly `{ "note": "..." }`.
- `GET /api/v1/projects/:projectId/scans/:scanId/findings/:findingId/history?page=1&pageSize=20` returns a bounded newest-first audit page.

The server derives the project, finding, actor, role and account from existing authenticated records. Client-supplied ownership, role, plan, scanner identity, fingerprint, evidence, or scan context is never accepted. Cross-account/project requests follow existing project/finding 403/404 behavior. Archived projects remain readable, but lifecycle and note mutations fail with `409 PROJECT_ARCHIVED`. Workflow changes consume no scan quota; a verification scan remains a real scan under the existing FREE/PRO quota policy.

## Lifecycle and verification semantics

States are `OPEN`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE`, and `REOPENED`. Only these transitions are accepted:

| Current | Allowed next state |
| --- | --- |
| `OPEN` | `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE` |
| `ACKNOWLEDGED` | `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE` |
| `IN_PROGRESS` | `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE` |
| `RESOLVED` | none manually |
| `FALSE_POSITIVE` | none manually |
| `REOPENED` | `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `FALSE_POSITIVE` |

Transitions are checked and recorded by the server. The original scanner finding—including scanner identity, rule, deterministic fingerprint, scan context, location, evidence and remediation—is immutable. A user selecting `RESOLVED` is a workflow decision, **not** a claim that the scanner verified a fix.

The existing deterministic project/fingerprint identity connects later completed findings. A matching finding in a completed same-scanner scan whose persisted finding count matches its summary updates the observation snapshot; a previously `RESOLVED` or `FALSE_POSITIVE` finding becomes `REOPENED` (reclassification by evidence, automatic and audited). An authoritative empty result records only `NOT_OBSERVED_IN_LATEST_SCAN`; it is not evidence of remediation, credential revocation, or removal from every copy. Completed results with missing/inconsistent finding details do not update verification or produce new reports. Failed, interrupted, queued and running scans do not update verification.

Every initial observation, user state change, note, reobservation, and eligible not-observed update is represented in a bounded audit history. There are at most 200 retained events per workflow, 20 notes per workflow (each at most 1,000 normalized characters), 50 events per history page, and 2,000 workflows per scan-store document. A reserved audit slot prevents a user transition from silently blocking a later automatic reopen.

## Notes, guidance, and data safety

Notes are NFC-normalized plain text. HTML tags and unsupported control characters are rejected. Credential-shaped assignments, private-key blocks, and long opaque token-like values are redacted before persistence; raw note input is not echoed in validation errors or logs. This is a heuristic, not a guarantee that arbitrary or unlabelled secrets are detected: do not put secrets in notes. The note limit and retained note count are enforced server-side. Rendered notes and evidence are inert text, never HTML. Source snippets in SAST and Secrets findings are withheld, but uploaded source and historical data can remain on disk and require appropriate access and retention controls.

Guidance is closed-rule-based and read-only:

- Rule-specific guidance is resolved from the configured, process-cached Dataset; absent or malformed entries receive an explicit `UNAVAILABLE` fallback. Secret values are not intentionally interpolated, but free-form Dataset text is filtered heuristically, not provably secret-free.
- DAST guidance describes observations and future authorized checks, not exploit validation.
- SCA includes only advisory data actually returned by the configured provider; without it, vulnerability intelligence is `NOT ASSESSED`, not a safety verdict.
- Examples are illustrative, separately reviewed, and available only for a small exact-match allowlist; they are not verified project patches.

Drobon does not execute uploaded source, browser code, shell commands, credential checks, external AI, or automatic source edits. An explicitly consented `ACTIVE_SAFE` DAST mode performs limited network probes; see `DAST.md` for scope and limitations.

## Persistence and reports

Workflow records and event histories are written atomically in the existing durable scan JSON document. Scan completion and fingerprint observation changes share the scan's existing serialized durable write. Older Pump 12 documents without workflow rows deterministically migrate workflows from their completed scan findings; scanner records are not rewritten. Corrupt workflow records fail startup rather than being silently repaired. The JSON store remains single-process/single-writer foundation storage.

Reports can contain a bounded point-in-time workflow snapshot (state, observation/verification identifiers and timestamps, and notes). The snapshot is covered by the content digest. `POST .../report` normally refreshes the one persisted report for that scan when lifecycle content changed; it does not consume quota. `GET .../report` retrieves its safe view. A historical report containing source snippets is projected to a safe view with a new digest and ID; its original bytes are not rewritten. If regeneration would replace a different unsafe historical snapshot, it returns 409 instead; a migration/retention policy is still needed. Markdown escapes notes and explicitly states that a user-selected resolved state or a missing finding is not proof of a fix. Reports do not include the full audit history.

The default saved report and JSON/Markdown/SARIF/PDF downloads remain compatible and contain the snapshot's existing remediation. To include current Dataset guidance explicitly, use `GET .../report/download?format=json|markdown|sarif|pdf&guidance=1` or `GET .../reports/portfolio/download?guidance=1`; the existing web download controls offer an unchecked option. In JSON this produces a versioned bundle `{ bundleVersion: "1.0", report, guidance, notice }`, rather than a bare report. Each guidance entry is associated with a finding ID and rule ID; unavailable entries are labelled. Guidance comes from the currently loaded, process-cached Dataset at export time, can differ from scan-time data, and **is not covered by the saved report digest**. Review and test suggestions; Drobon neither applies nor verifies fixes. PDF has existing bounded finding limits and explicitly reports omitted details. SBOM export is unchanged.

## Verification coverage

`apps/api/test/findingWorkflow.test.ts` covers legal/illegal transitions, notes and redaction, deterministic legacy migration, restart persistence, history ordering, evidence immutability, fingerprint reobservation/reopening, report snapshot digest updates, and SAST/Secrets/passive-DAST/SCA guidance. `apps/api/test/findingLifecycleApi.test.ts` exercises real authenticated local HTTP routes, ownership/IDOR, archived-project mutation, strict request shapes, note/Markdown injection resistance, quota neutrality, report output, and a real second SAST scan. `apps/web/test/findingsReportsUi.test.tsx` covers detail guidance/workflow, state changes, notes, history, and report snapshots. This is controlled local fixture coverage only, not a public-target or active security test.
