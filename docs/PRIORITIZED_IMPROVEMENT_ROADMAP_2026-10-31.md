# পরবর্তী উন্নয়ন roadmap — ৩১ অক্টোবর ২০২৬

এটি অনুমোদনের জন্য প্রস্তাব; এই পর্যায়ে autonomous attack engine, customer-system mutation, auto-deployment, নতুন plan/user type বা নতুন architecture তৈরি করা হয়নি। কোনো customer fix suggestion মানব review ও পৃথক test ছাড়া verified fix নয়। Material release blocker বন্ধ না হওয়া পর্যন্ত production NO-GO। **সর্বশেষ অবস্থা:** bounded Secrets literal join, XML reference/malformed handling, DAST duplicate-header evaluator এবং SAST heuristic wording-এর সীমিত কাজ হয়েছে; নিচে অবশিষ্ট validation ও gaps-কে অগ্রাধিকার দেওয়া হয়েছে।

## আগে release safety

| ক্রম | কাজ | শুরু করার শর্ত ও যাচাই |
|---:|---|---|
| ১ | JSON storage-এ বাস্তব single-writer enforcement বা অনুমোদিত transactional বিকল্প; Partner activation ও quota recovery-র provenance/atomicity পরিকল্পনা। | User-approved scope; multi-host/namespace, concurrent writer, partial write, process kill, recovery ও restore rehearsal। Database/migration এই পর্যায়ে বদলানো নয়। |
| ২ | Raw source ও historical evidence-এর lifecycle, encrypted storage/backup, key/access/retention এবং অনুমোদিত migration/rollback। | Data owner অনুমোদন; কোনো blind delete/rewrite নয়; restore, permission/ACL ও privacy fault tests। |
| ৩ | DAST-এর production authorization, explicit owner-approved scope, safe defaults, queued scans ও custom-engine enforcement। | Written authorization, side-effect/egress controls, fail-closed regression ও বাস্তব deployment rehearsal। |
| ৪ | Read-only mounted Dataset দিয়ে versioned API/worker/report E2E; freshness, incomplete/error এবং rollback evidence। | Dataset কেবল read-only; rule বা file তৈরি/পরিবর্তন আলাদা অনুমতি ছাড়া নয়। |

## মাপা scanner gap — প্রথমে পুনরুৎপাদন, পরে সীমিত fix

| ক্রম | পরিমাপ ও প্রস্তাব | নিরাপত্তা/গ্রহণযোগ্যতা gate |
|---:|---|---|
| ৫ | `SAST-04`-এ shell-less `execFile` category AST FP; `SAST-02` test lexical constant-concatenation FP। Review warning যোগ হয়েছে, classification হয়নি। আরও context-aware AST/argument ও rule-attribution যাচাই প্রয়োজন। | `shell:true`, shell/interpreter command, dynamic executable, shadowed import, argument injection, multiline ও unknown options-এ detection হারানো যাবে না। Production Dataset rule-কে test fixture ধরে বদলানো নয়। Privacy ও সময়সীমা বজায়। |
| ৬ | `SECRET-02`-এর bounded, non-executing JS/TS literal join এখন synthetic ও in-memory Dataset probe-এ মেলে। Escapes, multiline, Python, dynamic expressions এবং বড়/অসম্পূর্ণ input এখনও সীমার বাইরে। | কোনো customer source execute নয়; source/secret logs/evidence-এ না আনা, work caps, placeholder ও mixed expressions-এর FP/FN review, supplement coverage প্রকাশ। Live validity দাবি নয়। |
| ৭ | `SCA-03` ও `DAST-02` test-rule scope mismatch; pinned Dataset-এর applicable `DPK-SCA-0718` ও `DPK-DAST-073` in-memory probe-এ মেলে। Mounted-Dataset E2E এখনও প্রয়োজন। | এগুলো production-rule failure প্রমাণিত নয়। Dataset-owner approval, rule-scope/metadata consistency ও authorized E2E দরকার; existing check বা source-path security অন্ধভাবে বদলানো যাবে না। |
| ৮ | ১৬৪ dotfile case blocked এবং আট inconsistent NuGet fixture — সিদ্ধান্তসমূহ [reliability রিপোর্টে](SCANNER_RELIABILITY_REPORT_2026-10-31.md)। | Diagnostic-কে scan pass বলা নয়; নিরাপদ ingestion design ও Dataset মালিকের পৃথক review ছাড়া policy/data পরিবর্তন নয়। |
| ৯ | SAST/DAST evidence utility, severity consistency, report projection এবং line-sensitive finding identity। | Privacy না কমিয়ে human-reviewable evidence; regression-এ raw secret/adjacent value, legacy compatibility, digest, exports ও 409 behavior বজায়। Severity আলাদা reviewer যাচাই। |

| ১০ | XML/requirements/অন্যান্য declaration reader-এর supported subset, external-entity denial, malformed detection এবং partial propagation-এ স্বাধীন differential fixture বাড়ানো; DAST case-variant/repeated header ও transport edge আরও যাচাই। | Parser replacement বা Dataset/policy edit অনুমতি ছাড়া নয়; unsupported input-কে clean বলা নয়। ১৬৪+৮ হিসাব [SCA রিপোর্টে](SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md)। |
| ১১ | নতুন ৬২-case corpus blind independent human adjudication ও untouched holdout; version-specific vendor config, coverage, evidence, severity ও unmapped alerts আলাদা। | [ছয় readiness package](BENCHMARK_PREPARATION_REPORT_2026-10-31.md) NOT RUN; অজানা access বা অসম্পূর্ণ negative কখনো pass নয়। |

প্রতিটি পরিবর্তনের আগে failing regression, পরে targeted + full tests, preexisting কাজের integrity check এবং নতুন provisional case-level হিসাব প্রকাশ করতে হবে। Test-set-এ কেবল score বাড়াতে case বা label বদলানো নয়; পরিবর্তন হলে frozen holdout দরকার।

## স্বাধীন benchmark ও ভবিষ্যৎ validation ধারণা

১. **প্রথমে ground truth:** synthetic corpus version/hash freeze; অন্তত দুই স্বাধীন reviewer case ও evidence blind review করবেন; মতপার্থক্য নথিভুক্ত করে adjudication। DAST/SAST/SCA/Secrets আলাদা; একই source, rule scope, transport ও resource budget ছাড়া তুলনা নয়। Vendor access বা license না থাকলে NOT RUN-ই থাকবে।

২. **পরে local lab:** পূর্ণ অনুমোদিত disposable multi-host/step graph, known valid ও invalid paths, bounded capabilities, egress deny, isolated credentials, operation allowlist, cleanup ও rollback rehearsal। Autonomous validation এবং attack-path discovery-র metrics আলাদা; partial, failure, out-of-scope, side effect ও unmapped alert আলাদা গণনা। বিদ্যমান ২১-case HTTP/source lab এই কাজের বিকল্প নয়।

৩. **ভবিষ্যৎ ধারণা, implementation নয়:** publicly discussed security-validation ও path-analysis product category থেকে অনুপ্রাণিত হয়ে evidence-backed hypothesis, human-approved scope, bounded verification, path graph explanation এবং reviewed remediation suggestions বিবেচনা করা যেতে পারে। Reference entry points: [XBOW](https://xbow.com/), [Horizon3.ai](https://www.horizon3.ai/), [Pentera](https://pentera.io/)। এই session-এ এই vendor-গুলোর proprietary capability, বর্তমান সংস্করণ, license বা performance স্বাধীনভাবে যাচাই করা হয়নি; নামগুলো design inspiration মাত্র, parity দাবি নয়।

৪. **Mandatory control:** মানুষের স্পষ্ট অনুমোদন ছাড়া কোনো exploit, lateral movement, customer code/system modification, deployment বা secret validation নয়। কোনো AI-generated proposal-কে tested fix বলা যাবে না। Policy, data protection ও monitoring review শেষে আলাদা অনুমোদন ছাড়া development শুরু নয়।
