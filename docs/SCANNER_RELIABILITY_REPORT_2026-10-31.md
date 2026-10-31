# Scanner reliability ও fixture reconciliation — ৩১ অক্টোবর ২০২৬

> **সর্বশেষ accuracy পর্যায়:** নিচের পুরোনো ২১-case প্রাথমিক মাপের পরে প্রতিটি case পুনরায় reproduce এবং সীমিত engine fix করা হয়েছে। একই ২১-case-এ শুধু `SECRET-02` FN → TP; দুই SAST FP, SCA ও DAST-এর test-rule scope FN, দুটি DAST unassessed এবং SCA unknown রয়ে গেছে। এই নথির শেষে বর্তমান ফল; পূর্ণ ৬২-case ফল [synthetic corpus রিপোর্টে](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md), ১৬৪+৮ case [আলাদা SCA রিপোর্টে](SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md)। Production এখনও **NO-GO**।

## সীমা ও সিদ্ধান্ত

এটি সীমিত, লেখক-নির্ধারিত synthetic case-এর ফল; স্বাধীন মানব-পর্যালোচিত ground truth বা বাস্তব গ্রাহক-পরিবেশের accuracy নয়। Production Dataset-এর সব rule দিয়ে এই ২১-case মাপা হয়নি। কোনো সংখ্যাই সাধারণ scanner accuracy, exploitability, ১০০% নিরাপত্তা বা ছয়টি পণ্যের তুলনা নয়। Details ও executable fixtures: [`../benchmarks/local/`](../benchmarks/local/); পদ্ধতি ও পুনরাবৃত্তি: [benchmark প্রস্তুতি](BENCHMARK_PREPARATION_REPORT_2026-10-31.md)।

## এই পর্যায়ে ঠিক করা বাস্তব ত্রুটি

1. `requirements.txt` declaration reader আগে স্পষ্ট খালি pip option যেমন `--trusted-host=` বা `--no-binary=` প্রত্যাখ্যান করত। আলাদা offline pip 23.0.1 dry-run-এ চারটি long option-এর `=`-সহ খালি মান এবং `-i=` গ্রহণ, কিন্তু argument-বিহীন option প্রত্যাখ্যান দেখা গেছে। Reader এখন একই সীমিত পার্থক্য রাখে; অজানা directive এখনও প্রত্যাখ্যাত। পরিবর্তনের আগে চারটি regression ব্যর্থ; পরে লক্ষ্যভিত্তিক SCA/security suite ৮ ফাইল / ১৫৪ test পাস।
2. Dependency-inventory parser আগে include (`-r`), constraint, editable, bare URL বা malformed লাইন বাদ দিয়েও `ANALYZED` দেখাতে পারত। এখন পরিচিত dependency অক্ষত রেখে গণনাসহ `PARTIAL` দেখায়; include বা network নিজে থেকে অনুসরণ করে না। আগে পাঁচটি regression ব্যর্থ / ২৭ পাস; পরে SCA/engine/API/report/security ১০ ফাইল / ১৭০ test পাস। `scaEngine.test.ts` যাচাই করে যে অসম্পূর্ণতা report summary-তে পৌঁছায় এবং নির্দেশিত দ্বিতীয় ফাইলের নাম/বস্তু ফাঁস হয় না।
3. পুরোনো SAST/Secrets/report নথির প্রমাণ, সংরক্ষিত source ও legacy report নিয়ে অতিরঞ্জিত বিবরণ সংশোধন করা হয়েছে। নতুন source-finding evidence পুরো snippet গোপন করে; raw source এবং কিছু পুরোনো evidence এখনও disk-এ থাকতে পারে। এটি ঐতিহাসিক তথ্য encryption বা মুছে ফেলা নয়।

বিদ্যমান API, scan pipeline, Dataset এবং database পরিবর্তন করা হয়নি।

## Pinned Dataset: প্রতিটি SCA fixture-এর হিসাব

Read-only RAM audit: Dataset commit `3986082b22007b47930da3bc99be9c2f2b036080`, archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। ৮,২৩৪ নির্বাচিত JSON ফাইল (১১,০১৬,২৮০ bytes); ৪,০০৭ rule ও ১৬,৩৭৭ declared test গণনায় এসেছে; duplicate-key/JSON parse failure ০। Dataset checkout clone, extract বা write করা হয়নি। এটি mounted-filesystem বা সম্পূর্ণ HTTP end-to-end পরীক্ষা নয়।

| SCA raw-fixture ফল | case |
|---|---:|
| বাস্তব reader → declaration scan → expected ফল মিলেছে | ৩,৮২৯ |
| নিরাপদ source-path policy-তে blocked | ১৬৪ |
| বাস্তব ফাইলে বিশ্বস্তভাবে রূপ দেওয়া যায়নি | ৮ |
| parse failure / evaluated FP / evaluated FN | ০ / ০ / ০ |
| **মোট** | **৪,০০১** |

আগের ২টি pip parse failure আর নেই। **Blocked ও unrenderable ১৭২টি pass নয়**; সামগ্রিক reader coverage `PARTIAL`। ০ mismatch হলো এই self-declared synthetic fixture-এর সঙ্গে মিল, স্বাধীন vulnerability-detection precision নয়। Object-level evaluator-এ ৪,০০১ declared case মেলাও বাস্তব ফাইলের scan reachability প্রমাণ করে না।

### ১৬৪ blocked case-এর সম্পূর্ণ তালিকা

নিচের প্রতিটি rule-এর **zero-based test index `0,1,2,3`**, অর্থাৎ ৪টি করে case। Range-এর প্রতিটি rule অন্তর্ভুক্ত। ৪১ × ৪ = ১৬৪। একই production reader ও evaluator-কে upload gate-এর বাইরে শুধু memory-তে চালিয়ে ১৬৪/১৬৪ diagnostic expectation মিলে; FP/FN/parse failure ০। এটি production upload বা end-to-end scan নয়; নিচের path-গুলো এখনও blocked।

| Blocked artifact | সব rule ID |
|---|---|
| `.npmrc` | `DPK-SCA-0073`–`0088`, `0789`–`0791`, `0793`–`0794` |
| `.yarnrc.yml` | `DPK-SCA-0089`–`0094`, `0107`, `0795`–`0797` |
| `.pypirc` | `DPK-SCA-0142`, `0143` |
| `.cargo/config.toml` | `DPK-SCA-0691`, `0760`, `0788` |
| `.condarc` | `DPK-SCA-0778`, `0779`, `0978` |
| `.Rprofile` | `DPK-SCA-0777` |
| `.yarnrc` | `DPK-SCA-0651` |

সব সংক্ষিপ্ত সংখ্যার prefix `DPK-SCA-`। Path restriction দুর্বল করা হয়নি; `scaReaderFixtures.test.ts`-এ `.npmrc` এখনও প্রত্যাখ্যাত। Diagnostic কখনো বাস্তব scan pass হিসেবে গণ্য নয়।

### ৮ unrenderable case-এর সম্পূর্ণ তালিকা

সবগুলো `nuget.config`-এর normalized aliases। বাস্তব reader একই উৎস থেকে `sources` ও `packageSources.add` তৈরি করে। নিচের authored documents সেই সম্পর্ক ভঙ্গ করে; মিথ্যা fixture বানিয়ে match দেখানো হয়নি।

| Rule | zero-based index | কারণ |
|---|---|---|
| `DPK-SCA-0679` | 1, 3 | `sources` আছে, `packageSources.add` স্পষ্ট খালি |
| `DPK-SCA-0689` | 0, 1, 3 | দুই alias-এ একেকটি উৎস কিন্তু key/value ভিন্ন |
| `DPK-SCA-0753` | 0, 1 | `sources` আছে, `packageSources.add` অনুপস্থিত |
| `DPK-SCA-0753` | 3 | দুই alias-এর উৎস ভিন্ন |

Dataset-এর কোনো ফাইল সংশোধন বা সৃষ্টি করা হয়নি। নিরাপদ পথ হলো Dataset মালিকের পৃথক অনুমোদিত পর্যালোচনা; এই Main App কাজের মধ্যে সংশোধিত বলে দেখানো নয়।

## স্থানীয় ২১-case প্রাথমিক মাপ

এখানে SAST/Secrets-এ Main App-এর বিদ্যমান **test-only** rules, SCA-তে একটি synthetic runtime-dependency wildcard rule, DAST-এ একটি test-only passive header rule ব্যবহৃত। SCA ফল শুধু declaration hygiene, advisory/CVE detection নয়। DAST resolver ও transport mock; উৎপাদনের localhost নিষেধ অক্ষত। `benchmarks/local/results/drobon-provisional.json`-এ case ID ও normalized ফল আছে, source/credential value নেই। Mechanical oracle একই লেখকের তৈরি; স্বাধীন reviewer নয়।

| বিভাগ | মোট | TP | FP | TN | FN | unassessed | ground truth unknown | precision TP/(TP+FP) | recall TP/(TP+FN) |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| SAST | ৮ | ৪ | ২ | ২ | ০ | ০ | ০ | ৪/৬ | ৪/৪ |
| Secrets | ৪ | ১ | ০ | ২ | ১ | ০ | ০ | ১/১ | ১/২ |
| SCA declaration | ৪ | ১ | ০ | ১ | ১ | ০ | ১ | ১/১ | ১/২ |
| DAST passive header | ৫ | ১ | ০ | ১ | ১ | ২ | ০ | ১/১ | ১/২ |

১৮ assessed + ২ unassessed + ১ unknown = ২১। শূন্য denominator হলে score `null`; অনুপস্থিত বা অসম্পূর্ণ পরীক্ষা negative নয়। এগুলো **case-level** সংখ্যা: একই case-এ একাধিক alert একটি detection; alert-level precision এবং এক product-এর সঙ্গে অন্য product-এর ranking মাপা হয়নি।

| case | ফল | ব্যাখ্যা |
|---|---|---|
| `SAST-01` | TP | shell command-এ request input |
| `SAST-02` | FP | দুই constant যুক্ত command-এ test lexical rule |
| `SAST-03` | TP | আলাদা variable দিয়ে request থেকে command flow |
| `SAST-04` | FP | shell ছাড়া নির্দিষ্ট `execFile` argument-array case-এ category AST heuristic; অন্য executable/option-এ argument বা command ঝুঁকি থাকতে পারে |
| `SAST-05` / `06` | TP / TN | concatenated SQL / parameterized SQL |
| `SAST-07` / `08` | TP / TN | raw HTML-এ input / কেবল comment |
| `SECRET-01` / `02` | TP / FN | এক literal-এর synthetic credential shape / দুই literal থেকে runtime-এ পুনর্গঠিত একই shape |
| `SECRET-03` / `04` | TN / TN | placeholder / কেবল environment lookup |
| `SCA-01` / `02` / `03` | TP / TN / FN | runtime wildcard / fixed version / devDependency wildcard; test rule কেবল runtime path দেখে |
| `SCA-04` | UNKNOWN_TRUTH | malformed JSON; scan incomplete |
| `DAST-01` / `02` / `03` | TP / FN / TN | header অনুপস্থিত / ভুল মান / `nosniff`; নির্বাচিত test rule কেবল উপস্থিতি দেখে |
| `DAST-04` / `05` | UNASSESSED | unsafe/safe reflection-এর জন্য active query পরীক্ষা এই passive run-এ হয়নি |

`SAST-02`, `SCA-03` ও `DAST-02`-র ফল নির্বাচিত test-rule scope-এরও সীমা; এগুলোকে অপরীক্ষিত production Dataset rule-এর defect বলা যাবে না। `SAST-04`-এর heuristic over-report প্রাসঙ্গিক উন্নয়ন-প্রার্থী, তবে নিরীহ দেখানো সব `execFile` suppress করলে shell option, interpreter বা user-controlled executable-এর বাস্তব ঝুঁকি হারাতে পারে; নিরাপদ dataflow/argument regression ছাড়া অন্ধ suppression করা হয়নি। `SECRET-02`-এর constant reconstruction বাস্তব secret validity প্রমাণ করে না।

### Evidence, severity ও report

১৩টি mapped alert-এর ১৩টিতে nonempty evidence metadata; source alert-এর ১২/১২ location এবং DAST-এর ১/১ endpoint case-এর সঙ্গে মেলে। ১৯টি completed engine outcome থেকে সরাসরি `buildSecurityReport`-এ ১৯/১৯ integrity digest ও finding-count মিলেছে; নির্বাচিত সম্পূর্ণ source string ও synthetic key report-এ পাওয়া যায়নি। এই পরীক্ষা API/persistence/export end-to-end নয় এবং সব অজানা secret বা prose-র গোপনীয়তা প্রমাণ করে না। এই run-এ অন্য/unmapped alert ০। Severity rule থেকে উত্তরাধিকারসূত্রে এসেছে; স্বাধীন severity correctness যাচাই হয়নি। Fingerprint line move-এ বদলাতে পারে; digest signature নয়।

দুটি একই-environment run-এর ফল byte-identical (SHA-256 `1bd0099e5725c17a15dc522c3d38833a65dfad35ebfd0d51d07c08ff2137268c`); এটি portability বা runtime stability প্রমাণ নয়।

## সর্বশেষ accuracy পুনরুৎপাদন ও বাস্তব পরিবর্তন

পূর্বে প্রতিটি case আলাদা process-এ reproduce ও root cause চিহ্নিত: [পরিবর্তনের আগের evidence](SCANNER_ACCURACY_BASELINE_2026-10-31.md)। একই frozen ২১-case manifest দিয়ে পরে আবার ২১টি পৃথক process: [`before`](../benchmarks/local/results/accuracy-before-isolated.json), [`after`](../benchmarks/local/results/accuracy-after-isolated.json)।

| Family | আগে TP/FP/TN/FN/U/? | পরে TP/FP/TN/FN/U/? | পরিবর্তন |
|---|---|---|---|
| SAST | 4/2/2/0/0/0 | 4/2/2/0/0/0 | দুইটি FP রয়ে গেছে |
| Secrets | 1/0/2/1/0/0 | 2/0/2/0/0/0 | শুধু `SECRET-02` FN → TP |
| SCA declaration | 1/0/1/1/0/1 | 1/0/1/1/0/1 | নির্বাচিত rule-scope FN ও unknown রয়ে গেছে |
| DAST passive | 1/0/1/1/2/0 | 1/0/1/1/2/0 | নির্বাচিত rule-scope FN ও ২ unassessed রয়ে গেছে |

### মূল ২১টির প্রত্যেকটির আগে/পরে verdict

| Case | আগে | পরে |
|---|---|---|
| `SAST-01` | TP | TP |
| `SAST-02` | FP | FP |
| `SAST-03` | TP | TP |
| `SAST-04` | FP | FP |
| `SAST-05` | TP | TP |
| `SAST-06` | TN | TN |
| `SAST-07` | TP | TP |
| `SAST-08` | TN | TN |
| `SECRET-01` | TP | TP |
| `SECRET-02` | FN | TP |
| `SECRET-03` | TN | TN |
| `SECRET-04` | TN | TN |
| `SCA-01` | TP | TP |
| `SCA-02` | TN | TN |
| `SCA-03` | FN | FN |
| `SCA-04` | UNKNOWN_TRUTH | UNKNOWN_TRUTH |
| `DAST-01` | TP | TP |
| `DAST-02` | FN | FN |
| `DAST-03` | TN | TN |
| `DAST-04` | UNASSESSED | UNASSESSED |
| `DAST-05` | UNASSESSED | UNASSESSED |

এখানে U = unassessed, ? = unknown ground truth; case-level table [corpus রিপোর্টে](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md)। ২১টির মধ্যে বাকি ২০টির verdict অপরিবর্তিত; এটি general accuracy বৃদ্ধি মাপে না। ১৯টি report-producing observation-এর selected report integrity/count/privacy checks ১৯/১৯ মেলে।

1. **Secrets:** বিদ্যমান syntax worker ও engine-এ bounded, non-executing static literal-join detection যোগ হয়েছে; worker শুধু coordinates ফেরত দেয়, main engine transient join করে বিদ্যমান rule/denylist চালায়। একই rule/file/line dedupe, fingerprint, evidence withholding এবং finding cap বজায়। এটি ২–১৬টি সীমিত ASCII/সহজ literal, একই লাইন ও JS/TS family-তে সীমিত; escaping, dynamic input, multiline, Python ইত্যাদি unsupported। Optional supplement coverage `astSupplement`-এ, base scan-এর `partial` semantics অপরিবর্তিত। [`SECRETS.md`](SECRETS.md), [`secretStaticConcat.test.ts`](../apps/api/test/secretStaticConcat.test.ts)। Synthetic credential shape ধরা মানে live credential যাচাই নয়।
2. **SCA XML:** পূর্বে `&#58;` decode না হওয়া এবং trailing অসমাপ্ত tag গ্রহণ independent Python XML parser দিয়ে reproducible ছিল। Bounded numeric/predefined entity decode, malformed reference/trailing markup/duplicate attribute প্রত্যাখ্যান যোগ; DTD/CDATA/external entity unsupported ও fail-closed। Numeric HTTP/HTTPS, invalid code point, injection, nested references ও malformed controls-এর লক্ষ্যভিত্তিক test আছে। এটি general XML compliance নয়। আট alias-conflict fixture এখনও unrenderable।
3. **DAST:** case-insensitive একই header-এর পৃথক নাম-ভ্যারিয়েন্ট আর একে অন্যকে overwrite করে না; values আলাদা রেখে presence, directive ও value check হয়; cross-value regex নয়। এটি observation evaluator bug, `DAST-02`-এর নির্বাচিত presence-only rule-কে value rule বানানো নয়; target/authorization policy বদলায়নি।
4. **SAST:** command-category AST description এখন argument-vector বনাম shell ও inherited severity-র সতর্কতা জানায়; কোনো blanket `execFile` suppression বা privilege-changing fix নেই। `SAST-02` test lexical rule-এর FP, pinned Dataset-এ এই input-এ finding পাওয়া যায়নি। `SAST-04`-এ pinned Dataset category reporter `DPK-SAST-044` HIGH দেয়, কিন্তু exact rule pattern match প্রমাণ নয়। Dynamic executable, shell/interpreter এবং argument-level ঝুঁকি আলাদাভাবে গুরুত্বপূর্ণ।

`SCA-03`-এ test rule শুধু runtime `dependencies.*`, কিন্তু pinned pack-এ `DPK-SCA-0718` dev field-এ মেলে; `DAST-02`-এ presence-only test rule ভুল value ধরে না, pinned pack-এর পৃথক `DPK-DAST-073` ধরে। এটি mock/in-memory synthetic engine probe, mounted Dataset E2E নয়; প্রথম দুটিকে production Dataset defect বলে গণনা করা হয়নি। Scope ফল: [`before`](../benchmarks/local/results/dataset-scope-before.json), [`after`](../benchmarks/local/results/dataset-scope-after.json)।

## অপরিবর্তিত release blockers

Local single-host lease সব writer বা multi-host রক্ষা করে না; Partner-এর বহু-file activation atomic নয়; raw source/legacy evidence at rest; default legacy DAST authorization, পুঙ্খানুপুঙ্খ scanner coverage, স্বাধীন ground-truth/vendor benchmark, read-only mounted Dataset E2E এবং deployment/restore rehearsal অসম্পূর্ণ। Prioritized কাজ [roadmap](PRIORITIZED_IMPROVEMENT_ROADMAP_2026-10-31.md)-এ। Tests পাস মানে **production GO নয়**।

## সর্বশেষ offline regression

Node `v22.22.3`-এ `npm test`: **১৬৬ test file / ১,৭১৭ test পাস**। Shared ১৯/১৮৮, API ১১৩/১,২১৪, Worker ৩/৩২, Web ৩১/২৮৩। পূর্ববর্তী baseline ১৬৪ file / ১,৭০৩ test; পার্থক্য **+২ file / +১৪ test**। লক্ষ্যভিত্তিক accuracy v1/v2 ২ file / ১৩ test, scanner fix suite ৭৮/৭৮ ও Secrets suite ৪৩/৪৩ পাস।

Root typecheck, lint, সব workspace build, boundary, repository-integrity, secret matcher self-test ও ৮৫১-file secret scan, release-evidence self-test এবং `git diff --check` পাস। Web build-এ পুরোনো 508.37 kB chunk-এর >500 kB warning আছে; build pass হলেও performance review বাকি। Networked `npm audit` এই সীমাবদ্ধতার মধ্যে চালানো হয়নি; dependency vulnerability audit সম্পন্ন দাবি নয়। Dataset ফল আলাদা read-only RAM audit, offline full suite বা mounted-Dataset E2E-এর অংশ নয়।

## Workspace ও preview

এই পর্যায় শুরুর ১৮২টি পরিবর্তিত/নতুন path-এর snapshot-এ ১৮২/১৮২ original hash মেলে। বর্তমানে ১৬৬টি অপরিবর্তিত, ১৬টি এই কাজের নির্দিষ্ট engine/test/diagnostic/documentation প্রয়োজনে পরিবর্তিত, কোনোটি অনুপস্থিত নয়। Snapshot `/tmp`-এ সাময়িক; এটি durable backup নয়। Branch `arena/0056e643-drobon`; কিছু stage/commit/push/merge করা হয়নি। Preview web `39683` ও API `3001` চালু; local frontend এবং `/livez` proxy 200, বাইরের অজানা Host 403। Preview-তে Dataset configured নয়, তাই সেখানে production Dataset rule coverage দাবি নয়।
