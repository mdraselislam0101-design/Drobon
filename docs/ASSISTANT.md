# AI Security Assistant (Pump 14)

Pump 14 adds a **read-only, evidence-grounded assistant foundation** to each existing project. It reuses the authenticated account, project ownership, scan store, findings, workflow/history, reports, SBOM/SCA, and passive DAST records from Pumps 1–13. It creates no parallel account, project, scan, finding, report, quota, or persistence system.

## Current provider state: NONE

No generative provider is configured or active. The API does not read provider credentials, call a model, make assistant-related network requests, or fabricate model output. `GET /api/v1/assistant/status` reports `providerState: NONE`, `providerId: null`, `toolsEnabled: false`, and `conversationPersistence: NOT_IMPLEMENTED`.

Closed deterministic handlers can answer a bounded set of questions from persisted records (for example: top findings, explain a selected finding, existing rule guidance, scanner identity, workflow/verification state, completed-scan comparison, dependency inventory/assessment state, latest scan observations, and a persisted report summary). The intent recognizer is closed and only examines the user's question. It does not execute, obey, or classify text from findings, notes, project descriptions, packages, reports, or DAST evidence as instructions.

Open-ended or unsupported questions return `state: UNAVAILABLE` and explicitly say generation is unavailable; they do not receive a made-up answer. A future provider must be configured server-side, pass a security review, and be genuinely available before any provider-backed mode can be exposed. Client input cannot select a provider.

## API and authorization

- `GET /api/v1/assistant/status` requires an authenticated session.
- `POST /api/v1/projects/:projectId/assistant/ask` requires an authenticated session and the existing own-project resolver. A foreign project returns the application's uniform 403.
- The request accepts only `question` (required, up to 1,200 characters), optional `scanId`, optional `findingId` (only with `scanId`), and optional `compareScanId` (only with `scanId`). Unknown authority, provider, role, plan, account, and ownership fields are rejected.
- Scan IDs are resolved in the authorized project. Findings are resolved only within the selected persisted completed scan. Reports are resolved from that scan through the existing store. No client-provided account/project/finding/report/scan ownership is trusted.
- Assistant operations are reads only. They do not mutate sources, findings, lifecycle state, reports, scan state, or verification state; they do not invoke scanner tools, arbitrary shell/filesystem/browser/code execution, or arbitrary URL/network access.
- Assistant use is not a scan and never calls the usage/quota consumption service. FREE remains three scans per UTC month; the existing PRO exemption and verification-scan rules are unchanged.

## Evidence and limitations

Context is assembled only from server-owned records, preserving source type, source ID, project ID, and applicable scan ID. The builder reuses existing store methods for completed scans, findings, finding workflow and history, and persisted reports. It can include project metadata, scan summaries, finding records, bounded DAST observation metadata, SCA/SBOM inventory metadata, lifecycle state/history/notes, existing remediation guidance, and a point-in-time report summary. It never fetches a user-supplied URL or includes raw DAST response bodies.

Every response separates:

- **Facts** — values directly present in persisted application evidence;
- **Interpretations** — narrow explanation of what those records mean;
- **Recommendations** — existing deterministic guidance or safe next steps;
- **Limitations** — scope, partial-result, missing-data, and verification caveats;
- **Evidence references** — bounded provenance IDs, not a claim that the source is complete.

Scan summary/detail mismatches, partial results, truncation, absent records, and scanner-specific scope are surfaced rather than treated as clean results. Finding absence in one scan is not proof of remediation. `RESOLVED` remains user-managed workflow state; guidance is not a code change or verification. Only a subsequent authorized scan can update observation status.

Dependency inventory does not imply vulnerable/safe status, exploitability, or license status. No CVE, CVSS, CWE, advisory, vulnerability catalogue, or threat-intelligence claim is invented. Without applicable vulnerability intelligence the response preserves `NOT ASSESSED` / `NO_DATA_LOADED`.

## Security and bounds

- All project, finding, report, source, package, URL, note, and DAST-derived text is treated as untrusted data. Current deterministic code does not interpret evidence as instructions.
- A second redaction pass covers private-key blocks, credential assignments, auth headers, cookies, JWTs, known token formats, URL credentials, and long opaque values. Ambiguous auth/cookie/private-key material fails closed. Response strings are redacted as well, so untrusted finding titles/descriptions are not exempt.
- The provider request contract keeps policy, user request, and untrusted evidence in separate typed fields. **No provider call exists in this release.** Any future provider must receive only bounded, redacted context and must fail closed if the context is not safe; it must not gain tools or network access.
- Request body is capped at the smaller of 8 KiB and the existing API body limit. Question: 1,200 characters. Context: at most 40 items, 1,800 characters per item, and 12,000 characters total. Answers: 4,000 characters. Each fact/interpretation/recommendation/limitation: 500 characters and at most 10 entries. Evidence references: at most 30.
- Context selection is further bounded (at most four latest completed scans—one per supported scanner type—ten findings, three DAST observations per scan, ten SBOM components, five lifecycle events per included history, and five recent notes per workflow) before the global context bounds apply.
- Logs contain request/user/project IDs, response state/mode and bounded item/redaction counts only. Raw questions, source evidence, notes, tokens, and generated answer text are not logged.
- Conversation history is **not implemented or persisted**. The project page keeps only its current response in component memory; navigation/reload clears it.

## Verification

The local API integration tests use ephemeral loopback servers, synthetic accounts/projects, and a local synthetic SAST fixture. They do not contact public targets or load vulnerability datasets. The assistant redaction tests use synthetic credential-shaped markers only. The full repository boundary gate remains `npm run check:boundaries`; the cumulative release gate is `npm run verify`.
