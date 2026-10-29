# SCA Declaration Engine — মেইন অ্যাপে নতুন ইঞ্জিন

> **বর্তমান সংশোধন (2026-10-28):** আগের ৪৩২/১,০০০ reachability সংখ্যা পূর্ণ scan coverage নয়। dotfile upload সীমা, subset readers এবং অসম্পূর্ণ document বোঝার ঝুঁকি এখনও আছে; non-JSON declaration analysis এখন `PARTIAL`। বর্তমান সীমা: [`SECURITY_OPERATIONS_COVERAGE.md`](SECURITY_OPERATIONS_COVERAGE.md)।


**তারিখ:** 2026-10-26 · **Branch:** `arena/5bb07bd8-drobon` · **Scope:** শুধুমাত্র `Drobon` (main app) — পুরনো কোডের উপর additive update। `Drobon-Dataset` বা `Drobon-Database` repo-তে **কোনো পরিবর্তন করা হয়নি**, কোনো database/migration কাজ হয়নি।

> **সংক্ষিপ্ত (বাংলা):** আগে SCA declaration pack-এর ১,০০০টি rule অ্যাপে load ও validate হত, কিন্তু কোনো scan-এ evaluate হত না — ৪,০০১টি declared test `skippedTests` হিসেবে গোনা হত এবং status দেখাত `NOT_IMPLEMENTED`। এখন অ্যাপের নিজস্ব **declaration-document evaluator** আছে: ৪,০০১/৪,০০১ declared test load-time-এ execute হয় (0 failure, 0 skipped), আর বাস্তব SCA scan-এ JSON artifact-এর ৪৩২টি rule চলে এবং সত্যিকারের persisted `scanner: "SCA"` finding তৈরি করে। বাকি parser-গুলোর জন্য bounded reader আছে, তবে সম্পূর্ণ format coverage নয়; এসব স্ক্যান partial হিসেবে দেখানো হয়।

---

## ১) নতুন/বদলা ফাইল (সবই মেইন অ্যাপে)

| ফাইল | পরিবর্তন | কাজ |
|---|---|---|
| `apps/api/src/external/scaDeclaration.ts` | **নতুন** | ৬টি closed predicate-এর pure evaluator, bounded path/name walk, regex একবার compile, rule validator |
| `apps/api/src/scans/sca/declarationScan.ts` | **নতুন** | snapshot → parsed document → finding; coverage counters; hard caps |
| `apps/api/src/external/conformance.ts` | update | SCA declared tests execute (আর skip নয়); closed check-field validation |
| `apps/api/src/external/service.ts`, `types.ts` | update | `AVAILABLE` + scan parser/reachable-rule counters status surface-এ |
| `apps/api/src/scans/sca/engine.ts` | update | `dataset?` option (additive) → declaration findings; inventory/SBOM/advisory অপরিবর্তিত |
| `apps/api/src/app.ts` | update | `createScaEngine({ ..., dataset: datasetService })` |
| `apps/api/src/scans/remediationGuidance.ts` | update | SCA finding-এর জন্য scanner-specific fallback |
| `packages/shared/src/scans.ts` | update | `SourceFinding.scanner`-এ `'SCA'`, `DPK-SCA-####` rule-id pattern, ২টি নতুন summary counter |
| `apps/api/test/scaDeclaration.test.ts` | **নতুন** | ১১টি নতুন unit/integration test |
| `apps/api/test/datasetConformance.test.ts`, `datasetService.test.ts` | update | পুরনো "skipped" expectation → "executed" |
| `scripts/verify-dataset.mjs` | update | স্বাধীন SCA parity check (সব ৪,০০১ test), skip/availability assertions |
| `docs/DATASET_CONNECTION.md`, `docs/SCA_DECLARATION_ENGINE.md` | update/নতুন | operator guide + এই ডক |

---

## ২) ইঞ্জিনটি আসলে কী করে

```
packs/sca/v1/rules/*.json  (external dataset — read-only, runtime)
        │
        ▼
external/conformance.ts ──► compileScaDeclarationRule() ──► ৪,০০১ declared test execute
        │                                                      (POSITIVE + NEGATIVE, fail-closed)
        ▼
createDatasetService().scaPacks()   (conformance-validated rules only)
        │
        ▼  SCA scan request
scans/sca/engine.ts  ──► evaluateScaDeclarations({
                            files: snapshot.files,      // virtual content tree, never filesystem
                            rawRules, record, shouldStop
                          })
        │
        ├──► JSON.parse(artifact text) ──► findScaMatch(rule, document)
        │                                     │
        │                                     └──► Finding { scanner:'SCA', ruleId:'DPK-SCA-…',
        │                                                    file, line, column, evidence, fingerprint }
        └──► counters: declarationRulesEvaluated / declarationRulesNotEvaluated
```

**ছয়টি predicate** (dataset-এর `scripts/sca-rule-engine.mjs` semantics-এর সঠিক port — `verify:dataset` parity 0 mismatch দিয়ে প্রমাণিত):

| Check type | সংখ্যা | অর্থ |
|---|---:|---|
| `sca-name-distance` | ৫৩৩ | bounded Levenshtein (limit 1–2) দিয়ে typosquatting নাম |
| `sca-field-matches` | ৩৮৭ | কোনো resolved node-এর scalar value pattern-এ মেলে |
| `sca-field-absent` | ৩৯ | path-এ কোনো node নেই |
| `sca-entry-missing-field` | ২৭ | lockfile/map entry-তে নির্দিষ্ট field নেই |
| `sca-key-matches` | ১১ | object key pattern-এ মেলে |
| `sca-field-not-matches` | ৩ | node আছে কিন্তু কোনোটিই pattern-এ মেলে না |

Path grammar: `a.b`, `a.*`, `a[]`, `a.*[]` — সর্বোচ্চ ১২ segment, ৫১২ node, ৫১২ key, ২৫৬-char নাম। কোনো recursion/fixpoint নেই।

---

## ৩) Scan-time coverage — সৎ হিসাব (Pump 18 আপডেট)

**Pump 18 আপডেট:** এখন **৯টি parser kind-এরই** bounded reader আছে (`docs/SCA_READERS.md`)। আগে শুধু `json` পড়া যেত (৪৩২ rule); বাকি ৮টি reader যোগ হয়েছে, তবে সব rule কার্যত reachable নয়। JSON parser-এর artifact ছিল ১১টি:

```
Package.resolved, auth.json, composer.json, composer.lock, conan.lock,
package-lock.json, package.json, packages.lock.json, renv.lock,
vcpkg-configuration.json, vcpkg.json
```

বাকি ৮ parser-এর reader যোগ হয়েছে; তবে সেগুলো **bounded subset parser** — dataset-এর সব declared document shape ঠিকমতো reproduce করে না (historical round-trip parity parse failure-সহ প্রায় ৯৩.৪৯%)। কিছু unsupported shape `not evaluated` হয়; অন্য কিছু ভুলভাবে পড়াও হতে পারে, তাই scan `partial` চিহ্নিত হয়। এছাড়া dotfile artifact (`.npmrc`, `.yarnrc.yml` …) source-path policy-তে upload-ই করা যায় না — ৪১টি rule এই কারণে structurally unreachable; evidence JSON-এ আলাদা করে দেখানো হয়।

আগের dataset-এর উদাহরণ (বর্তমান count কনফিগার করা pack অনুযায়ী বদলায়; পুনরায় পরীক্ষা প্রয়োজন):

```json
{
  "sca": { "declaredTests": 4001, "executedTests": 4001, "skippedTests": 0,
           "failedTests": 0, "accepted": 1000 },
  "scaDeclarationEvaluator": "AVAILABLE",
  "scaDeclarationScanParsers": ["json","toml","yaml","xml","ini","properties","requirements","gradle","lockfile-text"],
  "scaDeclarationScanReachableRules": 959
}
```

Scan summary-তে প্রতি scan-এর হিসাব:

```json
{
  "findingsTotal": 5,
  "findingsBySeverity": {"CRITICAL":0,"HIGH":0,"MEDIUM":1,"LOW":4,"INFO":0},
  "declarationRulesEvaluated": 288,
  "declarationRulesNotEvaluated": 712,
  "truncated": false
}
```

(একটি `package.json`-only snapshot-এ ২৮৮টি `package.json` rule evaluate হয়; বাকি JSON artifactগুলো snapshot-এ নেই → not evaluated।)

---

## ৪) নিরাপত্তা সীমা (আগের guarantee অটুট)

- **কোনো declared VALUE finding-এ যায় না।** `.npmrc`/`auth.json`-এ token থাকতে পারে — evidence-এ শুধু rule id, artifact নাম, check type, matched path/key আর `(values withheld)` থাকে। Secret redaction এখানে design-by-construction।
- **Read-only, no execution.** Snapshot একটি virtual content tree; কোনো filesystem access, `npm install`, lifecycle script বা network call নেই।
- **Bounded:** সর্বোচ্চ ৫০ document, ১০,০০০ evaluation, ২০০ finding (`MAX_FINDINGS_PER_SCAN`); cap ছোঁয়া মানে `truncated: true`। ১০ সেকেন্ড engine deadline ও abort signal loop-এর ভেতরে check হয়।
- **Fail closed:** invalid regex / unknown check type / খারাপ `maxDistance` / মালformed artifact → rule বাদ বা not-evaluated, কখনো fabricated match নয়।
- **Finding contract:** `scanner: 'SCA'` ও `DPK-SCA-####` rule id shared guard-এ যোগ করা হয়েছে; ফলে finding workflow, reports, assistant, Web UI — সব জায়গায় এটি সাধারণ finding হিসেবেই কাজ করে (নতুন UI প্রয়োজন হয়নি)।
- **Additive:** `DATASET_PATH` configure না থাকলে আগের মতোই ০ declaration finding, `declarationRulesEvaluated: 0` — কোনো পুরনো SCA behaviour বদলায়নি।

---

## ৫) যাচাই (বাস্তব ফলাফল)

| চেক | ফল |
|---|---|
| `npm run verify:dataset -- --path ../Drobon-Dataset` | **PASS** — SCA ৪,০০১/৪,০০১ executed, 0 skipped, 0 failed, parity 0 mismatch, 0 rejected |
| `npm test` | **PASS** — ১,৩১৯ tests (shared + api ৮৪২ + worker ২৮ + web ২৬৬); নতুন ১৪টি test |
| `npm run typecheck` / `npm run lint` | PASS / 0 error |
| `check:boundaries` / `check:repo-integrity` / `check:secrets` | PASS / PASS / PASS |
| `npm run verify` | **PASS — ১১/১১** |
| **Live e2e** (dataset-enabled preview) | SCA scan → `COMPLETED`, ৫টি persisted `SCA` finding, `eval 288 / notEval 712`, evidence-এ কোনো value নেই |

Live e2e-এর একটি finding:

```json
{
  "ruleId": "DPK-SCA-0001",
  "scanner": "SCA",
  "severity": "MEDIUM",
  "file": "package.json",
  "line": 4,
  "evidence": "DPK-SCA-0001 package.json sca-field-matches dependencies.lodash (values withheld)",
  "remediation": "Pin the dependency to an exact version or to the narrowest range the project tests."
}
```

---

## ৬) এখনো যা করা হয়নি (open, সৎভাবে)

1. ✅ **৮টি বাকি document reader** — **সম্পন্ন** (Pump 18)। বিস্তারিত [`SCA_READERS.md`](SCA_READERS.md)।
2. **Per-finding `packId@version` stamping** — shared contract পরিবর্তন, fingerprint/report সব জায়গায় প্রভাব; আগের থেকেই open।
3. **Active DAST boundary (GAP-045, P0)** — এটা owner-এর লিখিত সিদ্ধান্ত, engineering নয়; এই কাজে ছোঁয়া হয়নি।
4. **Database/Postgres** — এই কাজে ইচ্ছাকৃতভাবেই কিছু করা হয়নি (আপনার নির্দেশ: ডেটাবেসের কাজ হবে না)।
5. SAST-এ AST/parser, browser engine, fuzzing, exploit, auto-remediation, generative AI — আলাদা roadmap; এই increment-এ নেই।

---

## ৭) পরবর্তী ধাপ (মেইন অ্যাপেই)

আগের প্রস্তাবিত ক্রম এখন এমন:

1. ✅ **SCA declaration evaluator** — সম্পন্ন (conformance + JSON scan-time)।
2. বাকি document readers যোগ করে ৫৬৮ rule-কেও scan-reachable করা।
3. Assistant provider (advisory, read-only) / suggested-diff remediation।
4. Deep SAST (JS/TS, opt-in) — নতুন dependency ও rule format প্রয়োজন।
5. Browser / fuzz / exploit / DB — owner decision বা আলাদা প্রজেক্ট।
