# Secrets Detection (Pump 10 — the third real engine)

`SECRETS` scans detect **hardcoded secrets** in a project's uploaded
source snapshot: private-key PEM headers, known-prefix service
credentials, bearer tokens, credential URLs, API-key-shaped
assignments and strong password literals. The engine is REAL —
deterministic pattern analysis of actual snapshot content, with
**mandatory evidence redaction enforced at every layer**.

Like SAST (Pump 8) and SCA (Pump 9), the engine reuses the Pump 8
snapshot architecture only: there is no second storage, discovery or
upload path.

## The core honesty contract

- **DETECTED_SECRET ≠ VERIFIED_LIVE_CREDENTIAL.** A finding proves the
  *string* has a credential's shape — nothing more. No rule, title,
  description, remediation or UI text may claim the credential is
  *valid*, *active*, *compromised* or *revoked*.
- **No verification, no network.** The engine never contacts any
  service, never validates a credential, never parses or uses key
  material. It reads text and matches patterns. That is all.
- **No match = no finding.** A finding exists only when a real rule
  matched real snapshot content at a real line/column. "Unknown" is
  reported as unknown, never as safe.
- **Severity and confidence are rule-defined constants** — never
  runtime-guessed, never client- or UI-influenced.

## The rule set (`apps/api/src/scans/secrets/rules.ts`)

| Rule | Category | Severity | Confidence | Fires on |
| --- | --- | --- | --- | --- |
| `DG-SEC-001` | private-key | HIGH | HIGH | `-----BEGIN … PRIVATE KEY-----` PEM header lines |
| `DG-SEC-002` | known-prefix | HIGH | HIGH | AWS `AKIA…`, GitHub `ghp_…`, Stripe `sk_live_…`, Slack `xoxb-…`, Google `AIza…` shapes |
| `DG-SEC-003` | bearer-token | HIGH | MEDIUM | `Authorization: Bearer <20+ mixed-class token>` and `bearer_token` assignments |
| `DG-SEC-004` | credential-url | HIGH | MEDIUM | `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis(s)://`, `amqp(s)://`, `ftp(s)://` URLs with an inline `user:password@` |
| `DG-SEC-005` | api-key | HIGH | MEDIUM | `apiKey`/`api_key`/`x-api-key`-named settings assigned a 20+ character mixed-class literal |
| `DG-SEC-006` | generic-secret | MEDIUM | LOW | `password`/`passwd`/`pwd`/`client_secret`/`secret` assignments with a 12+ character, ≥2-class, ≥3.5-entropy literal |

All rules map to **CWE-798** (Use of Hard-coded Credentials).

Severity policy (documented, deterministic): **no CRITICAL** in v1 —
even a private-key match does not prove the key is real, current or
authorized for anything. HIGH = credential-shaped material is present
in source; MEDIUM = heuristic rules where shape alone is weaker
evidence.

Confidence (`HIGH`/`MEDIUM`/`LOW`, closed vocabulary) is the RULE's
detection certainty — HIGH for structural/known formats, MEDIUM for
shape heuristics, LOW for the generic password rule. It is never a
liveness or exploitability claim.

## Redaction (the hard invariant)

**The raw secret value never appears in any externally visible
representation** — API responses, UI, logs, errors, audit records,
exports or stores. The enforcement is layered and adversarially
tested:

1. **Positional span blanking.** Each rule declares the span of the
   secret *inside* its match (`valueSpan`). The engine blanks that
   span positionally — by position, never by string search — so a
   value cut by the evidence window can never leak partially.
2. **Neighbour redaction.** A line can carry several secrets; the
   engine blanks every value span *any* rule resolved on the line,
   so one finding's evidence cannot leak another secret beside it.
3. **Defensive re-scan.** The finished evidence must itself match no
   rule; if it does (e.g. a second, different AWS key on the same
   line), the whole evidence fails closed to `[DG-SEC-###] <redacted>`.
4. **Header-only matches.** `DG-SEC-001`'s evidence is exactly the
   matched PEM header — the key body never enters the finding, is
   never parsed and never leaves the store.
5. **Deterministic fingerprints that exclude the secret.** A finding's
   id/fingerprint derive from `ruleId`, file, line and the
   **redacted** evidence — the same location and redacted evidence
   always produce the same identity, and the value itself is never
   fingerprint input.

Evidence is bounded (≤200 characters), control-character-free and
keeps enough context (variable name, scheme, quotes) to understand the
finding without the value.

## False-positive defenses (tested)

- **Placeholder/template denylist** (substring, case-insensitive):
  `changeme`, `example`, `dummy`, `sample`, `your`, `placeholder`,
  `<YOUR_API_KEY>`, `${…}`, `{{…}}`, plus the self-referential docs
  values `password`/`secret`/`token` as *values*.
- **Known documentation values**: the AWS docs example key
  `AKIAIOSFODNN7EXAMPLE`, Stripe *test-mode* keys (`sk_test_…`), etc.
- **Structure gates**: minimum length, ≥2 character classes, entropy
  ≥ 3.5 (one input among several — "high entropy = secret" alone is
  never a rule), UUID-shape exclusion, plain-hex-digest exclusion
  (MD5/SHA-1/SHA-256/… checksums and commit ids are not credentials).
- **Not suppressed merely because a file is named "test"** — content
  and context decide, per the spec.
- **Non-literal values are not matched**: `process.env.API_KEY`,
  interpolations, function calls.

Note the deliberate asymmetry: an `sk_live_…`-shaped 20-character
value *fires* even in a file named `docs.md`, because the shape is the
evidence; a value containing placeholder markers does not fire even in
`prod.ts`, because documentation intent is the evidence.

## Scope and limits (the engine's honest boundaries)

- **Supported formats**: `.js .ts .jsx .tsx .mjs .cjs .py .java .go
  .rs .php .rb .cs .json .yaml .yml .toml .ini .cfg .conf
  .properties .sh .bash .zsh` (and `.env`-style paths, which the
  upload path in fact refuses — see below). Unsupported extensions are
  skipped and counted (`filesSkipped`), never interpreted.
- **Credential-material files never enter a snapshot**: the Pump 8
  upload policy already blocks `.pem .key .p12 .pfx .jks .kdbx
  .keystore .env` — uploading a private key would move the secret
  *into* the application's stores. Consequently `DG-SEC-001` fires on
  PEM headers pasted **into code/config files**, the realistic case.
- **Ignored directories**: `node_modules`, `dist`, `build`, `out`,
  `coverage`, `vendor`, `target`, `cache` (dependency trees, build
  output, caches — out of scope, not partial).
- **Snapshot only**: the engine inspects the uploaded snapshot — never
  git history, remotes or branches.
- **Never executes** snapshot content; binaries cannot enter a
  snapshot at all (text-only upload validation).
- **Per-rule one match per line**: the first matching pattern wins;
  duplicates on the same line collapse into one finding per
  (rule, file, line). Different rules on the same line stay distinct.

## Limits and failure semantics

Defaults (`DEFAULT_SECRETS_LIMITS`): 200 files, 256 KiB per file,
1 MiB total, `MAX_FINDINGS_PER_SCAN` (200) findings, 10 s deadline.
Deterministic file order (path ASC). Duplicate control via
`(ruleId, file, line)`.

Failure codes (closed set, tested): `SECRETS_TARGET_NOT_FOUND`,
`SECRETS_INPUT_INVALID` (owner mismatch, corrupt path — fail closed),
`SECRETS_FILE_LIMIT_EXCEEDED`, `SECRETS_TARGET_TOO_LARGE`,
`SECRETS_SCAN_TIMEOUT` (deadline or cancellation).

**PARTIAL honesty:** files skipped for size are reported with
`partial: true` and a bounded `partialReason`; reaching the findings
cap sets `truncated: true` plus partial. **A partial scan with 0
findings is "nothing found in what was inspected", never "no
secrets"** — the UI renders the reason inline. A FAILED scan never
reports findings at all.

## API and UI

- Pre-flight (quota protection): requesting a SECRETS scan without an
  uploaded snapshot → `409 CONFLICT`, nothing consumed.
- Findings ride the existing detail route and contract (`findings`
  array; `resultSummary` counts) — no second format. SECRETS findings
  additionally carry the rule-defined `confidence`.
- The web findings view is shared with SAST and renders rule id,
  severity, the **detection-confidence badge**, location (`file:line`
  + CWE), redacted evidence and remediation — all as text. The raw
  value never reaches the browser in any field, attribute, tooltip,
  URL or client state (tested by whole-DOM sweeps).
- DAST remains unregistered and fails honestly with
  `SCAN_ENGINE_NOT_IMPLEMENTED`.

## Remediation wording

Generic, actionable, honest: move the secret to the environment or a
secret manager, rotate the exposed value, invalidate where relevant.
The system **never** claims "this credential has been revoked" — it
cannot know that.

## Tests

- `apps/api/test/secretsRules.test.ts` — registry integrity, per-rule
  positive/false-positive matrices, pattern linearity (ReDoS bound),
  cross-rule honesty, concatenated-PEM fixtures.
- `apps/api/test/secretsEngine.test.ts` — redaction (long lines, tabs,
  neighbours, fail-closed), determinism, dedupe, partial/truncation,
  ignored dirs, all failure modes, no-execution invariant.
- `apps/api/test/secretsApi.test.ts` — §29 adversarial file and §30
  no-fake snapshot over real HTTP, three-layer redaction sweep
  (response/store/logs), findings cap, cross-account isolation,
  restart determinism, tamper fail-fast, SAST/SCA regression.
- `apps/web/test/secretsUi.test.tsx` — findings surface, confidence
  badge, partial rendering, whole-DOM no-leak sweep, DAST honesty.
