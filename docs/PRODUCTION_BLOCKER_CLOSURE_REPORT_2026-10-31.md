# Drobon Main App — production blocker closure ও যাচাই

**তারিখ:** ৩১ অক্টোবর ২০২৬ · **শাখা:** `arena/0056e643-drobon` · **ভিত্তি HEAD:** `e763eb938d67d4163dca817716231794bb45e372`

## ১. সিদ্ধান্ত

**NO-GO।** নিচে বন্ধ বলা বিষয়গুলো কেবল চিহ্নিত সীমিত reproduction-এর জন্য বন্ধ; পুরো scanner, authorization বা storage-কে production-safe ঘোষণা নয়। JSON store-এর distributed/data-integrity নিশ্চয়তা, default DAST authorization, ঐতিহাসিক সংবেদনশীল data এবং বাস্তব deployment যাচাই এখনও যথেষ্ট নয়। Tests pass করলেই deployment নিরাপদ হয় না।

এই রিপোর্টে **১৩টি পৃথক blocker/work item** গণনা করা হয়েছে: **CLOSED ৩, PARTIALLY CLOSED ৫, OPEN ৩, NOT VERIFIED ২**। একটি ব্যাপক সমস্যার local ও distributed অংশ আলাদা সারিতে আছে, যাতে local mitigation-কে distributed নিশ্চয়তা মনে না হয়।

| ID | বিষয় | অবস্থা | বর্তমান প্রমাণ ও অবশিষ্ট কাজ |
|---|---|---|---|
| C1 | DAST matrix-parameter dot-segment scope bypass-এর নির্দিষ্ট reproduction | **CLOSED** | `/api/..;v=1`, encoded semicolon এবং `.;` ধরনের ambiguous path target, authorization, redirect ও crawl-এ আটকানো হয়। ১৩টি নতুন boundary test pass। সাধারণ non-dot matrix path অনুমোদিত। এটি সব proxy/framework-এর নিরাপত্তা প্রমাণ নয়। |
| C2 | Strict DAST mode-এ target save করতে engagement-এর আগে DNS | **CLOSED** | Strict mode-এ syntax ও literal IP locally যাচাই; authorized scan preflight-এর আগে DNS নয়। Private IPv4/IPv6 reject এবং অননুমোদিত scan-এ DNS/কোটা শূন্য—mock integration-এ যাচাই। Compatibility mode-এর পুরোনো আচরণ অপরিবর্তিত। |
| C3 | পূর্বে পুনরুৎপাদিত bounded XML ও shell-argument checker defect | **CLOSED** | Malformed XML/entity/trailing markup-এর নির্বাচিত regression এবং positional shell argument-কে unknown রাখার checker test বর্তমান regression-এ pass। এটি পূর্ণ XML parser বা general shell analysis নয়। |
| P1 | একক-process JSON persistence, quota ও crash recovery | **PARTIALLY CLOSED** | Serialized mutations, private temp+rename, intent/reconciliation ও সীমিত local writer lease আছে; ৩৩টি targeted test pass। Multi-file atomicity, power-loss durability এবং অন্য host/namespace এতে নিশ্চিত নয়; O1-ও দেখুন। |
| P2 | Partner activation/payment provenance | **PARTIALLY CLOSED** | একই millisecond-এ পরবর্তী APPROVED/APPROVING payment-কে Partner grant মনে করার দুইটি reproduction আটকানো হয়েছে; ambiguous intent quarantine ও matching operator retry পরীক্ষিত। Cross-file transaction বা timestamp থেকে নিঃসন্দেহ causal provenance এখনও নেই। |
| P3 | Historical finding/evidence এবং sensitive data | **PARTIALLY CLOSED** | Synthetic পুরোনো finding-এর title/description/remediation-এ পরিচিত credential-এর read-time exposure আটকানো হয়েছে; original file অপরিবর্তিত থাকে। Heuristic সব secret চেনে না, অনেক metadata/location ক্ষেত্র বাকি, পুরোনো source/backup at rest encrypted নয়। অনুমোদিত migration হয়নি। |
| P4 | Mounted Dataset থেকে scanner এবং সম্পূর্ণ SCA coverage | **PARTIALLY CLOSED** | Read-only mounted pinned mirror-এ চার scanner-এর sample finding/evidence/report/export pass; SCA-র ৩,৮২৯ matched, ১৬৪ path-blocked, ৮ unrenderable আলাদাভাবে রাখা হয়েছে। সব fixture-কে পূর্ণ HTTP E2E বা বাস্তব deployment coverage বলা যায় না। |
| P5 | ৬২-case synthetic benchmark reproducibility | **PARTIALLY CLOSED** | দুই run একই output; ২ FP, ২ test-rule-scope FN, ৯ unassessed ও ৬ unknown অপরিবর্তিত। SAST-04 বাস্তব mounted pack-এও over-report করে। এটি real-world accuracy বা মানব-পর্যালোচনা নয়। |
| O1 | Multi-process/multi-host JSON data integrity | **OPEN** | Linux lease কেবল একই network namespace-এর cooperating standard server-এর জন্য; সরাসরি/injected store, ভিন্ন namespace/host, hard-link alias, non-Linux এবং fsync/multi-file transaction নিরাপদ প্রমাণিত নয়। Production multi-writer নিষিদ্ধ। |
| O2 | Default legacy DAST authorization | **OPEN** | `DAST_REQUIRE_ENGAGEMENT` default `false`; unlinked legacy flow permission-verified নয়, compatibility target save-এ DNS হয়। Strict mode opt-in, user attestation স্বাধীন permission proof নয়; external egress control ও বাস্তব deployment enforcement যাচাই বাকি। |
| O3 | `SAST-04` shell-label false positive | **OPEN** | স্থির executable-এ shell ছাড়া argv-এর input-কে AST command-category reporter flag করে; mounted Dataset-এ `DPK-SAST-044`, `PROJECT`/`CATEGORY_REPORTER` finding পাওয়া গেছে। Blanket suppression shell option/interpreter/dynamic executable-এর সত্যিকারের ঝুঁকি হারাতে পারে। |
| N1 | স্বাধীন মানব benchmark adjudication ও vendor তুলনা | **NOT VERIFIED** | একই agent-এর scanner-free mechanical check স্বাধীন মানব review নয়; human review ০/৬২। ছয় vendor run করা হয়নি; parity/উৎকর্ষ দাবি নেই। |
| N2 | বাস্তব production deployment, historical inventory ও recovery rehearsal | **NOT VERIFIED** | বাস্তব customer data, backup, storage topology, legal authorization, egress, load, power loss ও restore পরীক্ষা করা হয়নি। নিচের পরিকল্পনা অনুমোদিত operational execution নয়। |

## ২. শুরুর অবস্থা ও সংরক্ষণ

এই কাজের শুরুতে Main App-এ ২৩০টি পূর্ববর্তী modified/untracked path ছিল; staged বা deleted path ছিল না। শেষে baseline archive-এর ২৩০/২৩০ hash যাচাই হয়েছে: ২২২টি path byte-identical, ৮টি এই task-এ ইচ্ছাকৃতভাবে এগিয়ে নেওয়া; একটিও missing বা status থেকে হারায়নি। আরও ৭টি path নতুন বা আগে clean ছিল। সর্বমোট working-tree status ২৩৭ path, staged/deleted ০। কোনো reset, branch change, staging, commit, push বা merge করা হয়নি। Shared workspace-ই স্থায়ী উৎস; `/tmp`-এর অস্থায়ী logs/baseline পুনরুদ্ধারের পর হারিয়ে যেতে পারে। কোনো বাস্তব historical store, Drobon-Database বা Dataset repository edit করা হয়নি।

পূর্ববর্তী স্বাধীন benchmark task-এর **১৬৮ file / ১,৭৩৭ test** ফল এখানে historical reference মাত্র; সেটিকে বর্তমান run বলে গণনা করা হয়নি। বর্তমান fresh run নিচে আলাদাভাবে দেওয়া।

## ৩. Root cause ও সংশোধন

### DAST scope ও network boundary

কিছু target framework dot-segment থেকে matrix parameter বাদ দিয়ে path normalize করে। ফলে দৃশ্যত `/api` prefix-এর ভেতরের `/api/..;v=1/outside` অন্যভাবে `/outside` হতে পারে। পূর্বে strict authorizer এবং redirect/crawler-এ সেই reference গ্রহণের reproduction-এ ১৩/১৩ নতুন test ব্যর্থ হয়েছিল। এখন shared ambiguous-path পরীক্ষা raw reference-এ URL normalization-এর **আগে** হয়; ambiguous historical scope prefix নতুন request authorize করে না। Ordinary `/api/item;v=1`, in-scope relative redirect ও একবার encoded space চালু আছে। Encoded dot/separator/percent, nested encoding, cross-host ও HTTPS downgrade policy শিথিল করা হয়নি।

Strict target-save আগে DNS করত, যদিও তখন engagement নাও থাকতে পারে। এখন strict mode-এ সেটি কেবল syntax ও literal-address পরীক্ষা করে; নতুন scan-এর assessment/engagement authorization-এর পরে public DNS preflight হয়, quota-এর আগে; request-এর আগে আবার scope ও DNS পরীক্ষা হয়। Legacy compatibility mode অপরিবর্তিত। পরীক্ষা প্রকৃত Internet target নয়: DNS ও DAST transport mock; transport unit test কেবল ephemeral loopback lab।

Audit অনুযায়ী owner-scoped project target scan request থেকে নেওয়া হয় না; strict mode-এ linked ACTIVE assessment, সঠিক host/path/type ও বর্তমান engagement দরকার। Built-in engine request-এর আগে gate পুনরায় দেখে; withdraw in-flight request ফেরাতে পারে না এবং injected custom engine এই নিশ্চয়তার বাইরে। All DNS answers public হতে হয়; vetted IP-তে socket pinning, Host/TLS hostname সংরক্ষণ, same-host redirect ও downgrade check আছে। DNS rebinding, routing ও target framework semantics-এর সব সম্ভাবনা প্রমাণিত নয়; egress policy দরকার। Query-bearing URL বর্তমানে আটকানো। PASSIVE সর্বোচ্চ ৩ attempt/২ redirect; ACTIVE_SAFE সর্বোচ্চ ২০ attempt, সীমিত crawl/marker; GET-ও side effect ঘটাতে পারে। Failed transport attempt cap-এ গণ্য, আংশিক response হলে result partial। Idempotent replay আবার DNS preflight করতে পারে এবং unsafe DNS-এ 409 দিলেও পুনরায় quota নেয় না। বিস্তারিত [`DAST.md`](DAST.md) ও [`SCANS.md`](SCANS.md)।

### Partner / paid ও complimentary PRO

একটি synthetic durable-store পরীক্ষায় Partner account write-এর পর final Partner write ব্যর্থ হয়ে compensation হয়েছিল; পরে একই timestamp-এ payment APPROVED বা APPROVING হয়ে account PRO করেছিল। পুরোনো recovery timestamp মিলিয়ে ভুল করে pending coupon সক্রিয় করত। Fix: pending intent থেকে নতুন grant অনুমান করার সময় ওই account-এর কোনো PRO APPROVING/APPROVED payment থাকলে auto-completion না করে quarantine করা হয়। দুইবার restart/recovery-তেও user/payment/partner bytes অপরিবর্তিত; explicit matching operator retry-এ coupon সক্রিয় এবং paid subscription অপরিবর্তিত থাকে। এটি কোনো বাস্তব payment তৈরি নয়; পরীক্ষা কেবল disposable synthetic files। পুরোনো approved payment থাকলেও সতর্কতার কারণে manual retry প্রয়োজন হতে পারে। Timestamp এখনও transaction ID নয়; একাধিক process/host, অন্য grant provenance এবং account/Partner file-এর atomic commit এখনও অমীমাংসিত।

### Historical privacy

Reproduction-এ synthetic legacy SAST finding-এর source evidence withheld হলেও title, description ও remediation-এ recognizer-চেনা credential scan detail দিয়ে দেখা যেত। একই issue পুরোনো immutable report-এও থাকতে পারত। এখন তিনটি free-text field recognizer-এ match করলে পুরো field bounded, idempotent redacted text হিসেবে project হয়; SAST/Secrets source evidence সম্পূর্ণ withheld, পুরোনো SCA/DAST evidence-এ পরিচিত credential ধরা পড়লে withheld। Safe field, fingerprint ও location রাখা হয়। Synthetic valid legacy report-এ scan API, report API, JSON/Markdown/SARIF export ও Assistant পরীক্ষা হয়েছে; projection-এর নতুন report ID/digest যাচাই হয় এবং মূল synthetic store-এর byte hash বদলায়নি। Re-hashed derived view পুরোনো report-এর original identity নয়।

এটি at-rest redaction বা encryption নয়। Source snapshot এবং পুরোনো JSON/report, backups, stale temp files, operator logs বা export-এ raw sensitive content থাকতে পারে। Recognizer অজানা/ছোট secret এবং সব path, DAST observation, project ও অন্যান্য free-text fields ধরার নিশ্চয়তা দেয় না। Owner-scoped API পরীক্ষা সফল হলেও বাস্তব historical corpus, log collection ও backup access যাচাই করা হয়নি। কোনো historical data মুছে বা overwrite করা হয়নি।

### JSON ও quota

বর্তমান code private same-directory temp file, rename, in-process queue, persist-before-observable এবং startup reservation reconciliation ব্যবহার করে। Synthetic write failure-এ পুরোনো file/অসংশ্লিষ্ট temp সংরক্ষণ, retry/restart, SIGKILL পর lease release এবং scan/quota recovery পরীক্ষিত। অন্য process একই namespace-এর default canonical paths নিয়ে শুরু হলে local abstract-socket lease বাধা দেয়। এটি journal বা distributed lock নয়: file ও directory fsync নেই, একাধিক JSON file transaction নয়, recovery সব real power-loss ordering প্রমাণ করে না, filesystem hard links/ভিন্ন namespace বা host/explicitly injected writers এর বাইরে। Orphan temp files-এর সম্ভাব্য content সংবেদনশীল; অনুমতি ছাড়া পরিষ্কার করবেন না।

**অপারেশনাল সীমা:** বর্তমান অবস্থায় replicas, shared-volume multi-writer, আলাদা namespace/host থেকে parallel API/worker বা সরাসরি store writer চালাবেন না। একটি নিয়ন্ত্রিত writer ও canonical path নিশ্চিত করাও পুরো production GO নয়; protected backup, tested restore, durability ও failure handling দরকার।

## ৪. Dataset: read-only mount ও end-to-end

Dataset commit `3986082b22007b47930da3bc99be9c2f2b036080`; archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। Pinned GitHub archive memory-তে পড়ে OS-level FUSE `ro,nosuid,nodev` **RAM mirror** হিসেবে expose করা হয়েছে; এটি বাস্তব Dataset file bytes-এর mounted view, কিন্তু কোনো checked-out `.git` working tree বা production filesystem নয়। কোনো Dataset file disk-এ extract, write, delete বা পরিবর্তন করা হয়নি। পরীক্ষার আগে ২১,৩৫৫ member/৪৫,৪৯৪,৬৮৭ bytes এবং পরে একই member-by-member bytes archive-এর সঙ্গে মেলে; composite manifest SHA-256 `ecaf9e4bc0de32e3eabd3564ad77aff41c28e017964f6646328c22a73d412738`। এটি archive origin-এর cryptographic signature নয়। চূড়ান্ত regression ও পুনরায় byte verification শেষে mount বন্ধ করা হয়েছে।

`npm run verify:dataset -- --path <read-only-mount>`: **PASS**। Filesystem discovery/load/schema/registration ও declared in-memory conformance:

| Pack | Accepted rules | Declared fixture tests | Conformance ফল |
|---|---:|---:|---|
| SAST | ১,০০০ | ৪,০৪৩ | সব passed, failure/skip ০ |
| Secrets | ১,০০০ | ৪,৬৬০ | সব passed, failure/skip ০ |
| DAST | ১,০০৭ | ৩,৬৭৩ | সব passed, failure/skip ০ |
| SCA | ১,০০০ | ৪,০০১ | সব passed, failure/skip ০ |
| মোট | **৪,০০৭** | **১৬,৩৭৭** | declared in-memory conformance, full API E2E নয় |

SCA-র পৃথক **render → production source-path policy → bounded reader → declaration evaluator** accounting: **৩,৮২৯ matched + ১৬৪ path-blocked + ৮ unrenderable = ৪,০০১**। Evaluated cases-এ FP/FN ও parser failure ০; ৯৫৯/১,০০০ rules scan-reachable; সম্পূর্ণ coverage **PARTIAL**। ১৬৪ blocked-কে pass বা path policy bypass বলা যাবে না। ৮টি NuGet alias/document conflict: `DPK-SCA-0679` indices 1,3; `DPK-SCA-0689` 0,1,3; `DPK-SCA-0753` 0,1,3। Conformance-এর in-memory document test এবং বাস্তব upload/reader reachability ভিন্ন পরিমাপ। বিস্তারিত [`SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md`](SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md)।

Opt-in [`mountedDatasetE2E.test.ts`](../apps/api/test/mountedDatasetE2E.test.ts) read-only filesystem service থেকে সব pack load/validate করে, তিনটি FREE synthetic account ব্যবহার করে আটটি Main App local HTTP scan/report/export flow চালিয়েছে; paid record তৈরি করে না। SAST `DPK-SAST-001` ১ finding; Secrets `DPK-SEC-001` ১; SCA `DPK-SCA-0001` ৫, **partial**; DAST `DPK-DAST-002` ২৪। প্রতিটিতে finding detail/evidence, report ও JSON export যাচাই। ওই এক SCA sample-এ ২৮৮ declaration rule evaluated/৭১২ not evaluated; advisory/version evidence এবং declared-vs-installed সীমার কারণে partial।

একই mounted flow-এ frozen `SAST-02`-এ ০ finding; `SAST-04`-এ `DPK-SAST-044` category reporter ১; `SCA-03` dev wildcard-এ `DPK-SCA-0718`; `DAST-02`-র frozen invalid-header response-এ `DPK-DAST-073` পাওয়া গেছে। পরের দুটি test-only selected rule-এর scope FN, সর্বজনীন Dataset FN নয়। DAST-এর দুটি transport attempt-ই strict engagement-সহ in-memory mock; **external target request ০**। SAST-04 finding rule-এর exact pattern match বা exploitability প্রমাণ নয়। Real deployment mount, বাস্তব customer data এবং প্রতিটি Dataset fixture-এর full HTTP/report E2E **NOT VERIFIED**।

## ৫. Benchmark ও অবশিষ্ট ব্যতিক্রম

Frozen ৬২ case (SAST ২১, Secrets ১৫, SCA ১৫, DAST ১১); manifest SHA-256 `8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6`, inherited SCA rule pin `b9ee26e96f5022c8e113cbd7430cde44321e7c78ecbc964d3f4cf84aecbd8e2b`। বর্তমান runner দুইবার byte-identical, SHA-256 `e2f43634f8e0500d28c2a0357237a472a2ef4ec06da2cb496f818b24fe0651bb`, ০ internal error; পুরোনো saved artifact-এর সঙ্গেও মেলে। Scanner-free checker দুইবার একই, ৬২/৬২ author-label agreement-এর মধ্যে ৬টি unknown; স্বাধীন মানব/blinded review **০/৬২**।

| Family | TP | FP | TN | FN | Unassessed | Unknown truth |
|---|---:|---:|---:|---:|---:|---:|
| SAST | ১০ | ২ | ৭ | ০ | ১ | ১ |
| Secrets | ৬ | ০ | ৪ | ০ | ৪ | ১ |
| SCA | ৪ | ০ | ৫ | ১ | ১ | ৪ |
| DAST | ৩ | ০ | ৪ | ১ | ৩ | ০ |
| মোট | **২৩** | **২** | **২০** | **২** | **৯** | **৬** |

৪৭ assessed synthetic case-এ micro precision/recall/F1 প্রতিটি ০.৯২; unassessed/unknown-কে pass/TN/FN-এ রূপান্তর করা হয়নি। `SAST-02` test-only lexical FP, `SAST-04` নির্দিষ্ট shell-label FP; `SCA-03` ও `DAST-02` selected test rule-এর scope FN। নয়টি unassessed: `DAST-04`, `DAST-05`, `AX-SAST-12`, `AX-SEC-05`, `AX-SEC-06`, `AX-SEC-09`, `AX-SEC-11`, `AX-SCA-06`, `AX-DAST-06`। ছয় unknown: `SCA-04`, `AX-SAST-13`, `AX-SEC-10`, `AX-SCA-05`, `AX-SCA-10`, `AX-SCA-11`। স্বাধীন fixture checker-এ positional shell data, এমনকি পরে `eval` হতে পারে, অজানা থাকে; সেটিকে safe বলে নয়।

বিস্তারিত root-cause, per-case evidence এবং semantic location/duplicate সীমা [`INDEPENDENT_BENCHMARK_VALIDATION_2026-10-31.md`](INDEPENDENT_BENCHMARK_VALIDATION_2026-10-31.md)। এটি synthetic test-only corpus; বাস্তব-world accuracy, exploitability বা কোনো vendor comparison নয়। Burp Suite Professional, Invicti, Snyk, XBOW, Horizon3 NodeZero, Pentera **NOT RUN**; valid access/licence বা authorized vendor execution এখানে প্রতিষ্ঠিত হয়নি।

## ৬. বর্তমান পরীক্ষার ফল

চূড়ান্ত পূর্ণ অফলাইন regression **PASS: ১৭২ files / ১,৭৫৫ tests; failed ০, skipped ০**। ভাগ: shared ১৯/১৮৮, API ১১৯/১,২৫২, worker ৩/৩২, web ৩১/২৮৩। Extended mounted E2E-ও এই run-এ ছিল। একই task-এর তার আগের fresh run-এও ১৭২/১,৭৫৫ pass হয়েছিল; সেটি আগের task-এর ১,৭৩৭ নয়।

| পরীক্ষা | বর্তমান ফল / সীমা |
|---|---|
| Mounted Dataset verifier | **PASS** — উপরের ১৬,৩৭৭ conformance; SCA scan-parser accounting partial |
| Extended mounted Dataset E2E | **PASS** — ১ Vitest test, ৮ synthetic scan/export flow; mock DAST, কোনো external target নয় |
| DAST/engagement/HTTP/target | **PASS**, ৮ files / ১২৭ tests |
| Storage, quota, crash, writer lease, permission rehearsal | **PASS**, ৮ files / ৩৩ tests |
| Partner/subscription/concurrency/recovery | **PASS**, ৫ files / ৫৮ tests |
| Historical/privacy/report/Assistant ও failure | **PASS**, ১০ files / ৩৬ tests; পরে অতিরিক্ত bounded/idempotence case-ও pass |
| Typecheck / lint | **PASS** / **PASS**, সব workspace |
| Build | **PASS**, সব workspace; web ৫০৮.৩৭ kB chunk warning, build failure নয় |
| Boundary, repo integrity, release-evidence self-test, secrets matcher self-test, source/build secret scan, `git diff --check` | **PASS**; synthetic test literals আগে checker-এ flag হয়েছিল, স্পষ্ট test annotation যোগ; checker দুর্বল করা হয়নি |
| Benchmark / scanner-free fixture checker | প্রতিটি **দুইবার PASS/reproducible**, ফলের FP/FN/unknown পৃথক, উপরোক্ত |
| `npm audit` / পুরো `npm run verify` wrapper | **NOT RUN** — wrapper networked dependency audit করে; এই task-এ অনুমোদনহীন external security service ব্যবহার হয়নি। Offline অংশগুলি আলাদাভাবে চালানো হয়েছে। |
| Real targets, real historic stores, multi-host/power-loss lab, independent human/vendor review | **NOT RUN / NOT VERIFIED** |

Pre-fix failure-গুলি deliberate reproduction: DAST ১৩/১৩, Partner ২/২ এবং historical metadata exposure ১/১। প্রাথমিক নতুন test-এ TypeScript/lint এবং synthetic-secret annotation-এর সমস্যা ধরা পড়ে, সংশোধনের পর আলাদা checks pass; এসবকে আড়াল করা হয়নি।

## ৭. Historical backup, dry-run, migration ও rollback পরিকল্পনা — **করা হয়নি**

বাস্তব historical content বদলাতে আগে ব্যবহারকারীর স্পষ্ট অনুমোদন প্রয়োজন। এই পরিকল্পনা চালু করার নির্দেশ বা encryption-implemented দাবি নয়।

1. **Inventory ও maintenance:** অনুমোদিত operator সব API/worker/অন্যান্য writer থামিয়ে storage topology ও canonical paths যাচাই করবেন; store, source snapshots, reports/exports, backups, orphan temp, logs, access control ও retention তালিকাভুক্ত করবেন। Content console-এ বা রিপোর্টে প্রকাশ নয়। বাস্তব inventory এখনও হয়নি।
2. **Protected backup:** কোনো mutation-এর আগে প্রতিটি সম্পর্কিত store-এর byte-exact backup একটি access-controlled, অনুমোদিত অবস্থানে নিন; encryption চাইলে আলাদা প্রতিষ্ঠিত key-management ব্যবস্থা দরকার। Size/hash, owner, permissions ও প্রয়োজনীয় ACL-এর metadata নিরাপদে সংরক্ষণ; backup ও original hash মিলিয়ে verify করুন। আলাদা disposable location-এ restore করে schema, scan↔quota, account↔Partner/payment ও report integrity যাচাই করুন। এই repository নিজে backup encryption দেয় না।
3. **Read-only dry run:** snapshot digest pin করে অনুমোদিত offline tool-এ সম্ভাব্য sensitive fields, report identity/reference পরিবর্তন, unknown values, counts, rejected/unsupported records ও সম্ভাব্য data loss-এর metadata-only plan তৈরি করুন। Tool/coverage এখনও তৈরি বা বাস্তবে যাচাই হয়নি; কোনো live file overwrite হবে না। Unknown secret সম্পূর্ণ শনাক্ত হয়েছে এমন দাবি নয়।
4. **অনুমোদন ও copy-on-write rehearsal:** পর্যালোচিত scope, retention, secret handling, mapping, write plan, downtime ও rollback-এর জন্য স্পষ্ট অনুমোদন নিন। Verified backup থেকে আলাদা copy-তে transform করুন; report digest/ID ও workflow references, schema, record counts, quota/subscription এবং পুনরায় চালালে idempotency পরীক্ষা করুন। কোনো discrepancy হলে থামুন। Multi-file atomic/durable cutover বিদ্যমান code নিশ্চিত করে না; বাস্তব cutover পদ্ধতি আলাদাভাবে তৈরি ও পরীক্ষা করতে হবে।
5. **Rollback:** writers বন্ধ রাখুন; approved byte-exact backup আলাদা স্থানে restore ও hash/integrity যাচাই করুন, পরে নিয়ন্ত্রিত cutover। Post-cutover নতুন writes থাকলে সরাসরি পুরোনো backup বসিয়ে সেগুলি হারাবেন না—আগে reconciliation plan ও অনুমোদন নিন। ACL/permissions এবং cross-file relationship পুনরায় যাচাই করুন; audit-এ values নয়, কেবল প্রয়োজনীয় identifiers/counts রাখুন।

বিদ্যমান `scripts/restrict-json-file.mjs` কেবল explicit opt-in POSIX permission change; plan/apply/rollback synthetic test আছে, এটি secret removal বা encryption নয়। বাস্তব store-এ এটি চালানো হয়নি।

## ৮. পরিবর্তিত Main App paths — এই task

পূর্ববর্তী ২৩০টি পরিবর্তনের মধ্যে ৮টি সংশ্লিষ্ট path সতর্কভাবে এগিয়ে নেওয়া হয়েছে এবং আরও ৭টি path এই task-এ নতুন বা আগে clean ছিল; মোট **১৫টি**। এটি পুরো cumulative working tree-এর সংখ্যা নয়।

- `apps/api/src/partners/service.ts`
- `apps/api/src/routes/projects.ts`
- `apps/api/src/scans/dast/authorization.ts`
- `apps/api/src/scans/dast/reference.ts`
- `apps/api/src/scans/dast/target.ts`
- `apps/api/src/scans/findingIdentity.ts`
- `packages/shared/src/dast.ts`
- `packages/shared/src/assessments.ts`
- `apps/api/test/productionDastBoundaries.test.ts`
- `apps/api/test/productionPartnerProvenance.test.ts`
- `apps/api/test/productionHistoricalProjection.test.ts`
- `apps/api/test/mountedDatasetE2E.test.ts`
- `docs/DAST.md`
- `docs/SCANS.md`
- `docs/PRODUCTION_BLOCKER_CLOSURE_REPORT_2026-10-31.md` (এই রিপোর্ট)

## ৯. Production-এর আগে প্রয়োজন

Distributed/transactional persistence ও failover নিরাপদ নকশা/বাস্তব rehearsal; strict DAST এবং egress/বাস্তব permission enforcement; অনুমোদিত historical data inventory, protected restore ও migration decision; Partner causal provenance ও cross-file reconciliation; SAST-04-এর binding/shell/argument-aware positive-negative regression; SCA blocked/unrenderable coverage review; স্বাধীন মানব adjudication এবং authorized deployment/load/crash/restore/security tests সম্পূর্ণ না হওয়া পর্যন্ত **NO-GO** বজায় থাকবে। কোনো automatic fix, customer code change বা deployment চালানো হয়নি।
