# Drobon Main App: পোস্ট-ইমপ্লিমেন্টেশন কোড রিভিউ ও রিলায়েবিলিটি যাচাই

**তারিখ:** ৩১ অক্টোবর ২০২৬, এশিয়া/ঢাকা  
**ব্রাঞ্চ:** `arena/0056e643-drobon`  
**ভিত্তি commit:** `e763eb938d67d4163dca817716231794bb45e372`  
**পরিধি:** বর্তমান working tree-এর রিভিউ; সমাধান বাস্তবায়ন নয়।

## ১. সংক্ষিপ্ত সিদ্ধান্ত

**বর্তমান অবস্থায় বাস্তব customer data বা বহির্মুখী production ব্যবহারের জন্য প্রস্তুত বলা যাচ্ছে না।** পুরো automated suite পাস করলেও synthetic যাচাইয়ে sensitive evidence প্রকাশ, quota crash-consistency, Student progress, finding-এর পুরোনো পরিচয় এবং Partner activation-এর গুরুত্বপূর্ণ সমস্যা পাওয়া গেছে। নিচে প্রতিটির প্রমাণ ও সম্ভাব্য সমাধান দেওয়া হলো; কোনো সংশোধন করা হয়নি।

এই রিভিউতে **P0 হিসেবে নিশ্চিত করার মতো প্রমাণ পাওয়া যায়নি**: অন্য tenant বা অননুমোদিত বহিরাগত ব্যক্তি বাস্তব secret পেয়েছেন—এমন পরীক্ষা বা দাবি নেই। তবে P1 নিরাপত্তা সমস্যাগুলো বাস্তব secret থাকলে অনুমোদিত finding/report গ্রাহকের কাছে অনিচ্ছাকৃতভাবে চলে যেতে পারে। P1-গুলো production-এর আগে সমাধান ও পুনঃপরীক্ষার যোগ্য; P2-গুলো কার্যকারিতা, সীমাবদ্ধতা বা শর্তসাপেক্ষ ঝুঁকি।

| আইডি | অগ্রাধিকার | ফল |
|---|---|---|
| P1-01 | P1, নতুন regression | Dataset Secrets denylist-এর কারণে একই লাইনের দ্বিতীয় synthetic value finding ও report-এ অসংশোধিত রয়ে গেছে। |
| P1-02 | P1, বিদ্যমান/অবশিষ্ট ঝুঁকি | SAST evidence ও finding note-এর generic redaction কিছু credential-আকৃতি চেনে না; synthetic SAST value deterministic Assistant-এর উত্তরেও এসেছে। |
| P1-03 | P1 | quota লেখা ও scan লেখা পৃথক; মাঝখানে process বন্ধ হলে quota কাটা থেকেছে, scan নেই। |
| P1-04 | P1, বিদ্যমান সমস্যা | ছয়টি Dataset lesson provider গ্রহণ করলেও Student progress store সেগুলোতে read, quiz বা practice সংরক্ষণ করে না; valid-আকৃতির progress file-ও reload প্রত্যাখ্যান করে। |
| P1-05 | P1, নতুন compatibility regression | পরিবর্তিত SAST evidence পুরোনো fingerprint বদলায়; একই finding তুলনায় `NEW` ও `RESOLVED` হয়েছে, পুরোনো workflow reopen হয়নি। |
| P1-06 | P1, বিদ্যমান failure path | Partner record লেখা হয়ে account PRO লেখা ব্যর্থ হলে ACTIVE partner/coupon থেকে যায়, account FREE থাকে এবং retry প্রত্যাখ্যাত হয়। |
| P1-07 | শর্তসাপেক্ষ P1 | JSON store স্পষ্টভাবে single-writer; দুটি স্বতন্ত্র writer ব্যবহার করলে quota update হারায়। Multi-instance production এ অবস্থায় নিরাপদ নয়। |
| P1-08 | P1 production-policy সিদ্ধান্ত | DAST-এর legacy unlinked/engagement-ছাড়া পথ `UNVERIFIED` হয়েও চালু; consent/owner declaration স্বাধীন অনুমতির যাচাই নয়। এটি বিদ্যমান design, নতুন করে bypass প্রমাণ নয়। |
| P2-01 | P2 | DAST route অনুমতি অস্বীকারের আগে DNS করে; cross-host redirect-ও host যাচাইয়ের আগে DNS করতে পারে। সফল request-এর replay অস্থায়ী DNS ব্যর্থতায় 409 হতে পারে। |
| P2-02 | P2, অসম্পূর্ণ চাহিদা | নতুন Dataset guidance finding detail/Assistant-এ আছে, কিন্তু report snapshot ও export-এ নেই; আগের remediation text রয়ে গেছে। |
| P2-03 | শর্তসাপেক্ষ P2 | পৃথক `apps/worker` timeout-এর পরে abort উপেক্ষাকারী পুরোনো attempt retry-এর পাশাপাশি চলতে পারে। API scan processor এই package ব্যবহার করে না। |
| P2-04 | P2/coverage | Active DAST query probe পাঠায় না, পাঁচ payload category-র মধ্যে বর্তমান budget প্রথমটিই নেয়; SCA hidden path ও version/parser সীমা রয়ে গেছে। |

**নিরাপদ সাময়িক অবস্থান:** P1-01 ও P1-02 সমাধান এবং export/Assistant পর্যন্ত regression test না হওয়া পর্যন্ত বাস্তব secret থাকতে পারে এমন source দিয়ে scan করা বা তার finding/report বিতরণ ঝুঁকিপূর্ণ। ইতোমধ্যে তৈরি report-এ বাস্তব secret আছে কি না এ রিভিউ পরীক্ষা করেনি; প্রয়োজন হলে অনুমোদিত ব্যক্তি নিয়ম মেনে পরীক্ষা করবেন। কোনো secret স্বয়ংক্রিয়ভাবে পরিবর্তন, অপসারণ বা rotate করা হয়নি।

## ২. পরিধি, সংরক্ষণ ও প্রমাণের ধরন

- রিভিউ শুরুর working tree: **৫৭টি tracked modified, ৯টি untracked, staged ০**। এগুলোর তালিকা ১১ নম্বর অংশে। এই নতুন প্রতিবেদনটি আলাদা untracked deliverable।
- রিভিউ চলাকালে application source, test, configuration বা আগের দুটি untracked report সম্পাদনা করা হয়নি; commit, push, merge, reset বা revert করা হয়নি। Build/test-এর স্বাভাবিক ignored output তৈরি হয়েছে।
- Original ৬৬টি path-এর `status`, path, mode, byte-size ও প্রতিটি file-এর SHA-256 দিয়ে path-ক্রমে সাজানো compact JSON-এর SHA-256: `b1c80d87ee9416d418afb3a7cfc752ec06c875ed50c4616b35cafe3f244b88a6`। প্রতিবেদন তৈরির পর একই তালিকা ও পদ্ধতিতে আবার যাচাই করা হয়েছে; নতুন প্রতিবেদন গণনার বাইরে।
- প্রমাণে synthetic/disposable value, in-memory store, সাময়িক JSON store ও local mock resolver/transport ব্যবহার করা হয়েছে। কোনো বাস্তব secret বা বাহ্যিক target scan ব্যবহার করা হয়নি। PDF-এর ক্ষেত্রে উৎস কোডে evidence ব্যবহারের পথ দেখা হয়েছে; PDF text extraction এখানে চালানো যায়নি।
- পূর্ণ suite-এর সফলতা ও নিচের পৃথক reproduction একে অপরের বিপরীত নয়: suite মূলত নির্দিষ্ট fixture ও code path পরীক্ষা করে; ফাঁকগুলো ৮ নম্বর অংশে দেখানো হয়েছে।

## ৩. P1 বিস্তারিত: প্রমাণ, প্রভাব ও প্রস্তাব

### P1-01 — Secrets finding-এর পাশের sensitive value থেকে যাওয়া

**প্রমাণ:** pinned Dataset archive থেকে RAM-এ লোড করা সব **১,০০০টি প্রকৃত Secrets rule** দিয়ে synthetic একই-লাইনের fixture চালানো হয়েছে। `DPK-SEC-001` একটি finding দেয়; প্রতিবেশী `DPK-SEC-003`-এর ম্যাচ সম্পূর্ণ লাইনে থাকা placeholder marker-এর জন্য deny হয়। ফল: প্রথম synthetic value redacted, দ্বিতীয়টি `evidence`-এ রয়ে যায়। এই finding বাস্তব scan store ও report store-এর shared guard পেরিয়েছে। synthetic value scan-store finding, report JSON এবং Markdown-এ পাওয়া গেছে; SARIF-এ পাওয়া যায়নি। PDF renderer সরাসরি `finding.evidence` লেখে, তবে PDF text আলাদাভাবে extract করা হয়নি।

**আগে/পরে:** working-tree diff-এ denylist validation matched substring থেকে সম্পূর্ণ লাইনে বদলেছে। বর্তমান engine-এর মধ্যে কেবল আগের substring-validation আচরণ অনুকরণ করে একই fixture চালালে দুই rule match করে এবং দ্বিতীয় value evidence-এ থাকে না। এটি সম্পূর্ণ পুরোনো HEAD চালানোর পরীক্ষা নয়। সম্পূর্ণ লাইনের denylist Dataset-এর প্রত্যাশিত detection semantics-এর অংশ—তাই শুধু ওই পরিবর্তন উল্টে দেওয়া সমাধান ধরে নেওয়া যাবে না।

**কেন:** finding eligibility, neighbouring evidence scrub এবং শেষের defensive re-scan একই denylist-aware matcher ব্যবহার করে। Finding হিসাবে কোনো rule দমন করা মানে তার মতো দেখতে প্রতিবেশী value দেখানো নিরাপদ—এমন নয়।

**কোড:** `apps/api/src/external/packProvider.ts:107-117`, `apps/api/src/scans/secrets/rules.ts:29-45`, `apps/api/src/scans/secrets/engine.ts:180-277,459-491`, `apps/api/src/reports/build.ts:93-100,311`, `apps/api/src/reports/pdf.ts:127`।

**প্রস্তাব:** Dataset-এর detection/denylist semantics বজায় রেখে evidence scrub-কে finding eligibility থেকে আলাদা করা; সন্দেহ থাকলে bare redacted marker-এ fail closed করা। একই লাইনে denylisted ও non-denylisted একাধিক synthetic value, দীর্ঘ লাইন, scan persistence, JSON/Markdown/PDF এবং Assistant-এর জন্য regression test দরকার। পুরোনো evidence/report-এর দায়িত্বশীল পর্যালোচনা ও সংরক্ষণনীতি আলাদা অনুমোদনের বিষয়।

### P1-02 — SAST, note ও Assistant redaction সর্বজনীন নয়

**প্রমাণ:** প্রকৃত pinned `DPK-SAST-001` rule ও synthetic source চালিয়ে একই লাইনে `dbPass` নামের একটি ছোট credential-আকৃতির value SAST finding evidence-এ পাওয়া গেছে। একই finding scan store-এ রেখে `AssistantService.answer` চালালে সেই synthetic value response-এও ছিল; provider state ছিল `NONE`, কোনো external AI বা API ব্যবহৃত হয়নি। আলাদা synthetic note-এ ছোট `api_key`-আকৃতির value `prepareFindingNote` থেকে `redacted: false` এবং মূল value-সহ ফেরত এসেছে। Note সংরক্ষণ ও Markdown export সেই text ব্যবহার করে।

**কারণ/প্রেক্ষাপট:** বর্তমান SAST পরিবর্তন সম্পূর্ণ লাইন আগে scrub করে, যা উন্নতি; কিন্তু generic শব্দ/দৈর্ঘ্য heuristic সর্বপ্রকার নাম ও format চিনতে পারে না। Note scrubber খালি embedded `SECRETS_RULES` ও `SAST_RULES` catalog-এর ওপর আংশিক নির্ভর করে; বাকি long-value heuristic এই ছোট fixture ধরেনি। UI-তে note-এর জন্য secrets redacted বলা আছে, যা সর্বজনীন নিশ্চয়তা হিসেবে নির্ভরযোগ্য নয়। Raw source snapshot আলাদাভাবে server-side সংরক্ষিত হয়—evidence redaction সেটিকে মুছে দেয় না।

**কোড:** `apps/api/src/scans/sast/engine.ts:150-180`, `apps/api/src/assistant/redaction.ts:7-47`, `apps/api/src/scans/findingWorkflow.ts:225-254`, `apps/api/src/scans/secrets/rules.ts:95-101`, `apps/api/src/scans/sast/rules.ts:44-51`, `apps/api/src/reports/build.ts:311-326`, `apps/web/src/pages/ProjectDetailPage.tsx:1900`।

**প্রস্তাব:** প্রতিটি surface-এ স্পষ্ট privacy contract ও shared fail-closed sanitization বিবেচনা করা; পর্যাপ্ত নিশ্চয়তা না থাকলে raw source line/notes-এর বদলে সীমিত safe summary বা omission। সংরক্ষণের আগেই এবং export-এ প্রতিরক্ষামূলক পরীক্ষা, short/alias/mixed-neighbour synthetic fixtures ও আগের data compatibility পরীক্ষা দরকার। যেকোনো heuristic-কে সব secret ধরার নিশ্চয়তা বলা যাবে না।

### P1-03 — quota ও scan-এর crash-atomicity নেই

**প্রমাণ:** সাময়িক বাস্তব usage/scan JSON store-এ FREE quota persist হওয়ার ঠিক পরে ও scan persist-এর আগে child process-কে `SIGKILL` করা হয়েছে। পুনরায় store খুললে account usage **১**, device usage **১**, scan **০**। এটি process-kill পরীক্ষা, power-loss/fsync পরীক্ষা নয়।

**আগে/পরে:** এখন সাধারণ scan-file rename failure-এ সফল compensation এবং persist-before-publish আছে; আগের চেয়ে ভালো। কিন্তু দুটি আলাদা JSON document-এ একক durable transaction বা startup reconciliation নেই। `scanQuotaFailure.test.ts`-এর double-failure test নিজে `grant` ধরে পরে rollback করে; সাধারণ route failure-এর পরে production caller-এর কাছে ওই closure ধরে পুনরায় চালানোর durable ব্যবস্থা নেই। Error দেখানো আর পরে হিসাব ঠিক হওয়া এক জিনিস নয়।

**কোড:** `apps/api/src/usage/service.ts:147-175`, `apps/api/src/usage/store.ts:234-260`, `apps/api/src/scans/store.ts:956-1031`।

**প্রস্তাব:** বিদ্যমান Main App architecture-এর ভেতরে durable reservation/journal ও idempotent reconciliation, অথবা প্রকৃত atomic persistence boundary-এর নকশা অনুমোদনের জন্য দেখানো। Account/device/PRO quota, idempotency replay, দ্বিতীয়বার crash, failed compensation ও restart—সবগুলো পরীক্ষা চাই। পৃথক database repository বা migration পরিবর্তন এ রিভিউতে প্রস্তাব বাস্তবায়ন নয়।

### P1-04 — Dataset Student lesson progress ও পুরোনো data গ্রহণ

**প্রমাণ:** pinned Dataset-এর **৬/৬ lesson** in-memory `getMergedLessons` provider গ্রহণ করেছে। সেই accepted ID দিয়ে `acknowledgeRead`, `recordQuiz` ও `recordIdentify`—তিনটিই প্রত্যাখ্যাত হয়েছে। Shared `isStudentLessonProgress`-এ valid একটি synthetic progress entry দিয়ে সাময়িক JSON document বানিয়ে reopen করলে student store সেটিও প্রত্যাখ্যান করেছে। অর্থাৎ lesson দেখা সম্ভব হলেও progress সফল হওয়ার নিশ্চয়তা নেই; এমন valid-আকৃতির document থাকলে store initialization-ও থামতে পারে। বাস্তব ব্যবহারকারীর কোনো data পরীক্ষা করা হয়নি।

**কারণ:** route Dataset lesson খোঁজে; `student/store.ts`-এর write ও reload validation শুধুই `findStudentLesson`-এর খালি embedded catalog দেখে। `readDocument` read error-ও সাধারণভাবে empty document ধরে—storage-error আচরণ আলাদাভাবে পরীক্ষা দরকার।

**কোড:** `apps/api/src/routes/student.ts:96-110,141-150,166-177,188-203,224-249`, `apps/api/src/student/lessons.ts`, `apps/api/src/student/store.ts:44-50,78-84,115-116`।

**প্রস্তাব:** route ও store-এ একই অনুমোদিত Dataset catalog/identity ব্যবহার এবং পুরোনো বৈধ progress-কে fail-safe ও backward-compatible উপায়ে গ্রহণের নকশা করা; read/quiz/IDENTIFY/FIX, attempt limit, restart, unavailable/changed Dataset এবং অন্য account-এর isolation সত্যিকারের Dataset-backed E2E দিয়ে যাচাই করা। পুরোনো file মুছে বা স্বয়ংক্রিয়ভাবে rewrite না করে migration পরিকল্পনা আগে দেখাতে হবে।

### P1-05 — SAST fingerprint বদলে workflow ও comparison বিভক্ত

**প্রমাণ:** pinned `DPK-SAST-001` এবং একই synthetic source/location-এ পুরোনো HEAD-এর short raw evidence আচরণ নিয়ন্ত্রিতভাবে অনুকরণ করে প্রথম scan তৈরি, পরে বর্তমান engine দিয়ে দ্বিতীয় scan চালানো হয়েছে। পুরোনো ও নতুন fingerprint আলাদা। Store-এ পুরোনো user-marked workflow `RESOLVED` রয়ে গেছে, নতুনটি `OPEN` হয়েছে; পুরোনোটি `REOPENED` হয়নি। বর্তমান প্রকৃত HTTP comparison route একই rule-এর জন্য **NEW=১, RESOLVED=১, UNCHANGED=০** দেখিয়েছে। দ্বিতীয় scan `partial` ছিল। এটি একটি controlled old-evidence simulation; সম্পূর্ণ পুরোনো application চালানোর দাবি নয়।

**অতিরিক্ত সমস্যা:** `canVerifyAbsence` lifecycle-এ partial/truncated scan থেকে absence verification আটকায়, কিন্তু comparison route সম্পূর্ণতা না দেখে হারানো fingerprint-কে `RESOLVED` নাম দেয়। UI এই শব্দকে “not observed, not proof of repair” বলে ব্যাখ্যা করে, তবুও অসম্পূর্ণ scan থেকে পাওয়া ফল বিভ্রান্তিকর হতে পারে।

**কোড:** `apps/api/src/scans/sast/engine.ts:150-180,399`, `apps/api/src/scans/findingIdentity.ts:19-32`, `apps/api/src/scans/store.ts:1343-1363`, `apps/api/src/routes/scans.ts:443-470`, `apps/web/src/pages/ProjectDetailPage.tsx:1428-1435,1513-1519`।

**প্রস্তাব:** secret প্রকাশ না করে versioned stable identity/alias বা সংরক্ষিত ইতিহাসের নিরাপদ reconciliation নকশা করা; পুরোনো workflow, audit notes, report digest ও SARIF `drobon/v1` contract রক্ষা করে actual old-to-new upgrade test চালানো। Partial comparison-এ uncertainty স্পষ্ট দেখানোর backward-compatible API/UI সিদ্ধান্ত প্রয়োজন; closed enum আচমকা বদলে পুরোনো client ভাঙা উচিত নয়।

### P1-06 — Partner activation split state

**প্রমাণ:** সাময়িক বাস্তব Partner JSON store-এ partner creation সফল হওয়ার পরে synthetic user-store activation failure বসানো হয়েছে। Partner store পুনরায় খুলে commission recovery চালানোর পরও partner `ACTIVE`, coupon ব্যবহারযোগ্য, account `FREE`; একই activation retry প্রত্যাখ্যাত। Record-এ complimentary PRO granted timestamp ছিল। এটি store reopen ও recovery-র synthetic পরীক্ষা, সম্পূর্ণ OS/process restart-এর পরীক্ষা নয়।

**কারণ:** `activatePartner` আগে partner/coupon persist করে পরে account-এ `activatePro` করে। `NOT_FOUND`-এর একটি compensation আছে; সাধারণ storage exception বা মধ্যবর্তী process failure-এর জন্য durable recovery দেখা যায়নি। এই অংশটি বর্তমান পরিবর্তনের আগের code path।

**কোড:** `apps/api/src/partners/service.ts:160-190`; payment approval-এর আলাদা recoverable saga `apps/api/src/payments/service.ts:174-203`।

**প্রস্তাব:** Partner entitlement activation-এর জন্য recoverable intent/state, নিরাপদ পুনরায় প্রয়োগ বা fail-closed compensation নিয়ে অনুমোদনসাপেক্ষ নকশা; প্রথম ও দ্বিতীয় store write failure, process death, repeat/restart, coupon usability এবং ভুল granted timestamp-এর regression পরীক্ষা।

### P1-07 — Single-writer সীমা ভাঙলে quota হারানো

**প্রমাণ:** একই সাময়িক usage JSON file-এর ওপর দুটি পৃথক store instance তৈরি করে দুটির FREE consumption সফল করা হয়েছে। তৃতীয় instance-এ reload করলে প্রথম account usage **০**, দ্বিতীয় account usage **১**, shared-device count **১**—প্রথম update হারিয়েছে। এটি stale independent instances-এর synthetic পরীক্ষা; আলাদা machine বা distributed filesystem পরীক্ষা নয়।

**প্রেক্ষাপট:** এটি code-এর নথিভুক্ত **single-process/single-writer** সীমা, নতুন regression নয়। In-process queue অন্য process-এর জন্য lock নয়। তাই একাধিক API writer/shared JSON store চালালে quota ও অন্য data consistency দাবি করা যাবে না।

**প্রস্তাব:** অবিলম্বে deployment boundary হিসেবে একক writer বজায় রাখা; multi-instance প্রয়োজন হলে পৃথক অনুমোদিত design, locking/transaction ও বহু-process recovery test ছাড়া চালু না করা। কোনো database বা migration এখানে বদলানো হয়নি।

### P1-08 — DAST অনুমতি একটি production policy gate

**পর্যবেক্ষণ:** `ACTIVE_SAFE`-এ explicit boolean consent লাগে; linked active engagement থাকলে host/path/type/window যাচাই হয় এবং withdraw-এর পরে engine আবার যাচাই করে। তবে no-assessment এবং engagement-ছাড়া legacy পথে scan অনুমোদিত/`UNVERIFIED`; owner-এর assertion প্রকৃত target owner-এর স্বাধীন verification নয়। GET-ও side effect তৈরি করতে পারে। এটি বিদ্যমান backward-compatible design; এই রিভিউতে বাস্তব অননুমোদিত target request দেখানো হয়নি।

**প্রস্তাব:** বাহির্মুখী DAST চালুর আগে product owner-কে অনুমতি, scope, retention ও operational policy নির্ধারণ করতে হবে। প্রয়োজন হলে কোনো network action-এর আগে authoritative authorization ও opt-in enforcement-এর compatible পথ ডিজাইন করে পরীক্ষা করতে হবে; legacy client-এর পরিবর্তন আলাদা অনুমোদনসাপেক্ষ।

## ৪. P2 ও অন্য গুরুত্বপূর্ণ সীমা

### P2-01 — DAST authorization-এর আগে DNS এবং replay

- বাস্তব local HTTP route, mock DNS ও mock transport ব্যবহার করে linked engagement-এ DAST নিষিদ্ধ থাকলে response **409**, কিন্তু ওই request-এ resolver **১ বার**, target transport **০ বার** ডাকা হয়েছে। `dastAuthorization.test.ts`-এর শূন্য-DNS assertion সরাসরি engine পরীক্ষা করে; HTTP creation route নয়।
- আরেক mock-এ passive unlinked target-এর cross-host redirect অনুসরণ করা হয়নি, কিন্তু `resolveRedirect` host তুলনা করার আগে অন্য host-এর resolver ডেকেছে। Cross-host target HTTP **০ বার**।
- এক সফল DAST request-এর একই idempotency key আবার পাঠিয়ে mock DNS ব্যর্থ করলে প্রথম response **201**, replay **409**, সংরক্ষিত scan **১**; নতুন target HTTP হয়নি। Store-level replay test নিজে সঠিক হলেও route preflight আগে DNS করে।
- **প্রস্তাব:** অনাকাঙ্ক্ষিত DNS-এর আগে syntax, ownership ও scope/redirect host/scheme যাচাই; নিরাপদ authorized replay-কে নতুন execution না ভেবে মূল রেকর্ড ফেরত দেওয়ার নীতি মূল্যায়ন। তবে target policy, DNS rebinding ও execution-time reauthorization দুর্বল করা যাবে না। Revoked assessment-এর replay semantics-ও স্পষ্ট করতে হবে।
- **কোড:** `apps/api/src/routes/scans.ts:224-276,279-325`, `apps/api/src/scans/dast/target.ts:258-280`, `apps/api/src/scans/dast/authorization.ts`।

### P2-02 — Dataset guidance report export-এ নেই

Finding detail route ও Assistant `RULE_SPECIFIC` Dataset guidance resolve করে। কিন্তু `buildSecurityReport` scan-এর মূল finding ও workflow snapshot নেয়; ওই নতুন `whyItMatters`, actions, verification এবং reviewed example snapshot-এ যোগ করে না। Synthetic `RULE_SPECIFIC` marker report JSON, Markdown ও SARIF-এ অনুপস্থিত ছিল। PDF একই snapshot থেকে তৈরি; PDF text extract করা হয়নি। পুরোনো `finding.remediation` JSON/Markdown/PDF এবং SARIF `help.text`-এ আছে—পুরোনো export পুরোপুরি ভেঙেছে এমন প্রমাণ নয়।

**প্রস্তাব:** যদি export চাহিদা অনুমোদিত হয়, report schema/version, size cap, digest এবং পুরোনো report পাঠযোগ্যতা রক্ষা করে bounded/redacted point-in-time guidance snapshot-এর পরিকল্পনা ও চার format-এর tests। এটি এ রিভিউতে বাস্তবায়িত হয়নি। **কোড:** `apps/api/src/routes/reports.ts:196-212`, `apps/api/src/reports/build.ts:93-154,311-312,414-430`, `apps/api/src/reports/pdf.ts:124-134`।

### P2-03 — Worker timeout-এর পরে late side effect

পৃথক `apps/worker`-এর synthetic noncooperative handler abort উপেক্ষা করলে runner **attempt ২-এ succeeded** দেখিয়েছে; তখন effect ছিল `[2]`, পুরোনো attempt শেষ হওয়ার পরে `[2,1]`। Runner নিজেই at-most-once guarantee নেই বলে নথিভুক্ত করে। Cancellation/backoff-এর নতুন tests পাস, কিন্তু এই late-side-effect পথ প্রমাণ করে না। **এটি API scan processor দিয়ে duplicate Main App scan হয়েছে এমন প্রমাণ নয়।** API নিজস্ব `apps/api/src/scans/processor.ts` ব্যবহার করে; সেটিও noncooperative engine-কে জোর করে থামাতে পারে না, তবে timeout-এর পরে স্বয়ংক্রিয়ভাবে একই scan retry করে না।

**প্রস্তাব:** ভবিষ্যতে worker-এ side-effecting handler ব্যবহার করলে cooperative abort, idempotency/fencing, stale attempt isolation ও cancellation-এর পরে কোনো effect না হওয়ার contract পরীক্ষা করা; প্রয়োজন হলে process isolation আলাদা নকশা। **কোড:** `apps/worker/src/runner.ts:102-117,248-270`, `apps/api/src/scans/processor.ts:96-127`।

### P2-04 — Active DAST, SCA এবং documentation coverage

- Mock active scan-এ ৫টি request-এর মধ্যে ২টি path XSS marker ছিল, query-bearing request **০**, অন্য catalog marker **০**; result `PARTIAL` ছিল। কারণ target policy query নিষিদ্ধ করে এবং `payloadsForBudget(1)` প্রথম marker বেছে নেয়। `docs/DAST.md` ও UI path-marker সীমা স্বীকার করে। এটিকে সব পাঁচ active category বা পূর্ণ vulnerability test বলা যাবে না।
- SCA-তে npm/PyPI unsupported বা ambiguous range `unknown/partial` হতে পারে; Dataset-এর ৪১টি declaration rule-এর artifact hidden-path policy-র কারণে upload-eligible নয়। `.npmrc`, `.env` বা key-material জোর করে অনুমোদন করলে source storage-এ credential exposure বাড়তে পারে। Gradle reader সীমিত DSL, transitive graph সর্বত্র পাওয়া যায় না।
- SCA provider static symlink, size/depth ও byte cap-এর fixture পাস করেছে; hostile concurrent replacement, অন্য OS ও সব বাস্তব manifest নিশ্চিত নয়।
- `docs/FINDINGS.md:46` এখনো active DAST নেই বলছে, অথচ code ও `docs/DAST.md`-এ opt-in active পথ আছে। Documentation consistency সংশোধনের প্রস্তাব, এখন কোনো edit নয়।

## ৫. গুরুত্বপূর্ণ আগে/পরে ও compatibility পর্যবেক্ষণ

| ক্ষেত্র | বর্তমান পরিবর্তনের গুরুত্বপূর্ণ আচরণ | সীমা/compatibility |
|---|---|---|
| Dataset loader | Pack validation, language alias, rejected-rule/partial reporting ও reader coverage উন্নত হয়েছে। | Dataset না থাকলে SAST/Secrets/passive DAST rule শূন্য হতে পারে, SCA `NOT_ASSESSED`; এটি clean bill of health নয়। |
| Usage/scan | File persist-before-publish, সাধারণ write failure compensation, সফল replay-তে quota পুনরায় না কাটা। | দুই file-এর crash-atomicity নেই; পুরোনো JSON document ও প্রতিটি failure path-এর migration এখনও পূর্ণ যাচাই নয়। |
| DAST identity | Mode ও consent idempotency identity-তে ধরা হয়; পুরোনো mode-হীন record PASSIVE হিসেবে replay test পাস। | Route DNS/authorization preflight replay-এর আগে; active consent বাস্তব স্বাধীন অনুমতি যাচাই নয়। |
| Worker | Retry backoff-এ fresh cancel signal, backoff চলাকালে cancellation ও failure finalization পরীক্ষা পাস। | পৃথক worker runner; noncooperative timeout attempt চলতে পারে। |
| SCA | npm/PyPI prerelease, epoch/ordering ক্ষেত্রে অনিশ্চয়তা গোপন না করে partial; bounded no-follow file reads। | Hidden files/unsupported syntax/OS ও concurrency সীমিত। |
| SAST/Secrets | সম্পূর্ণ line redaction, comment masking, Dataset denylist semantics ও অন্যান্য coverage উন্নয়ন। | P1-01/02 privacy এবং P1-05 old finding identity regression সমাধান হয়নি; comment masking সব language-এর পূর্ণ parser নয়। |
| Findings/Assistant | Detail/Assistant-এ bounded Dataset guidance; ৩টি hash-pinned compatible illustrative example দেখানো যায়। | ৫টি অনিরাপদ example withheld, rule text নয়; example কোনো verified patch নয়, code কখনো auto-apply হয় না। Export-এ নতুন guidance নেই। |
| Subscription/Partner/Admin/Account | Server-side paid-source evidence ছাড়া complimentary partner PRO-কে `PAID` না দেখানোর নতুন tests পাস। | Payment approval-এর recovery test আছে; Partner failure path-এ P1-06। পুরোনো historical provenance/সময়ের সব edge প্রমাণিত নয়। |
| Student | Dataset lesson catalog পড়া যায়। | Store অন্য catalog যাচাই করে; P1-04। UI mock পাস বাস্তব backend progress প্রমাণ নয়। |
| Report/API | পুরোনো finding remediation ও report integrity digest থেকে যায়; SARIF evidence দেয় না। | নতুন guidance absent; fingerprint পরিবর্তনে history/compare/SARIF correlation প্রভাবিত হতে পারে। SHA-256 report digest signature নয়। |

Assistant বর্তমান অবস্থায় deterministic, `createNoAssistantProvider()` ব্যবহার করে; generative model বা নতুন external AI service নয়। Guidance মানুষকে পর্যালোচনায় সাহায্য করে; বাস্তব exploitability বা code fix যাচাই করে না।

## ৬. DAST ও scan আচরণে যা পাস করেছে

- Passive এবং active engine-এ linked scope refusal, withdrawal ও transport-এর ঠিক আগে recheck-এর mock পরীক্ষা পাস; DNS policy public address যাচাই ও transport resolved address pin করে। Passive-এ সর্বোচ্চ ৩, active-এ সর্বোচ্চ ২০ bounded request এবং অন্যান্য response/deadline cap রয়েছে। এগুলো configured maximum, প্রতিটি scan ওই সংখ্যক request চালায়—এমন নয়।
- `scanApi.test.ts`-এ একই key-র দশটি সমান্তরাল request-এ একটি scan/একবার quota, FREE quota concurrency, shared device এবং restart recovery test পাস। API processor boot-এ আগে RUNNING scan-কে `SCAN_INTERRUPTED` করে এবং QUEUED drain করে; এটি quota/scan-এর মধ্যবর্তী crash reconciliation নয়।
- Payment approval test `APPROVING` state থেকে simulated restart recovery চালায়; Partner activation একই saga নয়। Role/user type নিজেরা plan বা cross-account authority দেয় না—সংশ্লিষ্ট automated tests পাস।
- এগুলো synthetic ও local-mock ভিত্তিক। প্রকৃত target অনুমতি, নিরাপত্তা, exploitability, network infrastructure বা সম্পূর্ণ coverage নিশ্চিত করে না।

## ৭. Dataset অপরিবর্তন ও coverage-এর প্রমাণ

রিভিউতে ব্যবহার করা user-owned Dataset pinned commit `3986082b22007b47930da3bc99be9c2f2b036080`-এর archive read-only ভাবে RAM-এ পড়া হয়েছে। আগে নথিভুক্ত এবং পুনরায় আনা archive-এর SHA-256 এক: `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। Dataset repository clone/extract, file create, edit বা delete করা হয়নি। এই hash **ওই pinned archive-এর bytes একই** প্রমাণ করে; remote repository-এর সব branch/বর্তমান HEAD পুরোপুরি অপরিবর্তিত—তা স্বাধীনভাবে প্রমাণ করে না। পৃথক Drobon-Database repository, database বা migration-ও পরিবর্তন করা হয়নি।

পূর্ববর্তী একই working tree-র integration যাচাইয়ের সারাংশ, এই রিভিউতে প্রতিটি সংখ্যা নতুন করে পুনরায় চালানো নয়:

- Pack: SAST ১,০০০, Secrets ১,০০০, DAST ১,০০৭, SCA ১,০০০; মোট **৪,০০৭** rule। Conformance-এ ৪,০০৭ গ্রহণ এবং ঘোষিত evaluator fixture **১৬,৩৭৭/১৬,৩৭৭** পাস। Mock positive fixture hit বাস্তব-world accuracy নয়। এই রিভিউতে Secrets-এর ১,০০০ rule ও ছয় Student lesson পৃথকভাবে RAM-এ ব্যবহার করা হয়েছে।
- SCA ৪,০০১ rendered case-এর আগের final হিসাব: ৩,৮৩৩ নির্ণেয় সঠিক, ১৬৪ blocked, ২ unrenderable, ২ unparsed; নির্ণেয় subset-এ ০ FP/FN। Fixture renderer-ও পরিবর্তিত হয়েছে—এটি স্বাধীন benchmark নয়, এবং unavailable case বাদ দিয়ে সব rule বাস্তবে কাজ করে বলা যাবে না।
- ৪১টি hidden artifact-সম্পর্কিত SCA rule path policy-র কারণে upload-eligible নয়; প্রকল্পভেদে বাস্তব coverage আরও কম হতে পারে। SAST comment-mask simulation-এ ১৯৫টি inactive-comment expected positive দমন হয়েছে; প্রতিটি rule-এর অন্তত একটি positive fixture ছিল।
- আগের local version matrix: npm ৫২৮ case-এ ৪৫২ definitive agreement, ৭৬ unknown; PyPI ১,৯৫৩ case-এ ১,৬৭৯ agreement, ২৭৪ unknown। এটি exhaustive ecosystem parity নয়।
- ৪,০০৭ guidance entry resolver-এ valid পাওয়া এবং ৮টির মধ্যে ৩ example দেখানোর আগের in-memory পরীক্ষা export completeness নয়; P2-02 তা আলাদা করে দেখায়।

## ৮. Automated tests ও প্রাসঙ্গিক সীমা

### এই রিভিউতে নতুন করে চালানো

| কমান্ড / suite | ফল |
|---|---|
| `npm test` | **১,৫৭৭/১,৫৭৭**, **১৪৬/১৪৬ file**: shared ১৮৮/১৯, API ১,০৭৫/৯৩, worker ৩২/৩, web ২৮২/৩১। |
| `npm run typecheck` | PASS — shared, API, worker, web। |
| `npm run build` | PASS — সব workspace; Vite minified web chunk **৫০৭.৩৯ kB**, ৫০০ kB warning। |
| `npm run lint` | PASS। |
| `npm run check:secrets`, `check:repo-integrity`, `check:boundaries`, `check:release-evidence` | PASS। Static secret matcher-এর PASS runtime evidence redaction-এর নিশ্চয়তা নয়। |
| `git diff --check` | PASS। |

`npm audit`/network-dependent পূর্ণ `npm run verify` এই রিভিউতে চালানো হয়নি; উপরোক্ত সফল কমান্ডগুলোকে পূর্ণ verify বা বর্তমান dependency-vulnerability clearance বলা যাবে না। বাস্তব customer code, বাস্তব credentials, external scanning service বা বাহ্যিক target ব্যবহার করা হয়নি।

### নির্বাচিত নামযুক্ত suite এবং আসল coverage

- `scanApi.test.ts` **৩৬**: `10 simultaneous requests with the SAME idempotency key`, FREE/account/device quota, `startup recovery: interrupted RUNNING scans...` পাস। Process death ঠিক quota ও scan file-এর মাঝখানে এই test নয়।
- `scanQuotaFailure.test.ts` **৪**, `usageStorePersistence.test.ts` **৩**, `scanIdentity.test.ts` **১**: সাধারণ rename failure/compensation, persistence এবং legacy PASSIVE replay পাস; double-failure test manually captured closure পরে চালায়। P1-03 আলাদা `SIGKILL` reproduction।
- `dastAuthorization.test.ts` **৭**, `dastTarget.test.ts` **৫৭**, `dastEngine.test.ts` **৯**, `dastApi.test.ts` **৫**, `engineStrengthening.test.ts` **২২**: scope/withdrawal/bounds ও mock response path পাস। Engine-only `denied initial scope ... neither DNS ...` পুরো HTTP route নয়; P2-01 route পরীক্ষা ভিন্ন ফল দেখায়।
- `secretsEngine.test.ts` **১৯**, `secretsRules.test.ts` **১৩**, `sastEngine.test.ts` **২৩**: সাধারণ neighbour redaction, long-line ও stable repeat পাস। Secrets fixture ইচ্ছাকৃতভাবে placeholder denylist এড়িয়ে যায়; suppressed neighbour + emitted finding একসাথে পরীক্ষা নয়। SAST stable repeat নতুন code একইভাবে চালানো; old-to-new identity migration নয়।
- `scaVersionRanges.test.ts` **৯**, `scaFilesystemSafety.test.ts` **৪**, `scaReaderFixtures.test.ts` **২**: prerelease/unknown, static symlink ও bounded reader fixture পাস; সব real manifest/OS-এ সমতা প্রমাণ নয়।
- `datasetGuidance.test.ts` **১৪**, `assistantService.test.ts` **৫**, `reportsApi.test.ts` **৫**, `findingWorkflow.test.ts` **৮**: guidance validation, deterministic answer, report ownership/digest এবং partial lifecycle পাস। Report export-এ নতুন Dataset guidance assertion নেই; P1-02 ও P1-05-এর cross-surface case-ও আলাদা।
- `partnerApi.test.ts` **২৩**, `paymentApi.test.ts` **২৪**, `entitlementApi.test.ts` **১০**, `adminApi.test.ts` **৯**, web `subscriptionUi.test.tsx` **৮**, `partnerDashboardUi.test.tsx` **১১**: সফল path, paid/complimentary distinction, অনুমতি ও restart-এর নির্বাচিত path পাস। P1-06-এর Partner user-store write failure নেই।
- `studentApi.test.ts` **৩** পাস হলেও নামগুলো বিভ্রান্তিকর: `progress persists across a restart...` কোনো সফল progress persist/reload করে না, unknown lesson reject ও corrupt file দেখে; `quiz attempt limit...` প্রকৃত attempt limit পর্যন্ত quiz চালায় না। `catalog, progress, quiz integrity...` নামের test-ও Dataset-backed সফল progress/quiz/practice করে না। Web `studentLearnUi.test.tsx` **৩** mocked client-এ success দেখায়; বাস্তব Student store E2E নয়।
- `apps/worker/test/runner.test.ts` **১৯** সহ মোট worker **৩২**: retry, timeout ও cancellation পাস; abort উপেক্ষাকারী handler-এর late side effect না হওয়ার প্রমাণ দেয় না।

## ৯. দ্বৈত ব্যবস্থা, operational সীমা ও বাস্তব readiness

1. API scan processor এবং `apps/worker` দুটি আলাদা orchestration ব্যবস্থা। প্রথমটি scan JSON store দিয়ে কাজ করে; দ্বিতীয়টি in-memory generic queue/retry। একটির test/promise অন্যটিতে আরোপ করা যাবে না।
2. Student route-এর Dataset catalog এবং progress store-এর embedded catalog কার্যত দুই উৎস; P1-04। Finding detail/Assistant-এর live guidance এবং report snapshot-এর পুরোনো remediation-ও পৃথক surface; P2-02।
3. JSON store ও process-local session/rate limit single-instance foundation। Distributed queue/database, multi-writer consistency, operational backup/restore ও production load/failover প্রমাণিত নয়। Auth-এ email verification, password reset ও MFA-ও সম্পূর্ণ production capability হিসেবে দাবি করা যাচ্ছে না।
4. Raw uploaded source server-side সংরক্ষিত হয়; access, retention, backup ও incident-response ব্যবস্থা deployment-এর দায়িত্ব। Manual payment record নিজে অর্থ স্থানান্তর verify করে না। SOC/SAC saved-scan view/coverage ledger, live monitoring বা certification নয়।
5. এই ফল paid-tool parity, সব vulnerability শনাক্তকরণ, পূর্ণ security, production traffic বা স্বাধীন certification নয়। কোনো বাস্তব target নিরাপদ/অসুরক্ষিত ঘোষণা করা হয়নি।

**প্রস্তাবিত ক্রম:** প্রথমে P1-01/02 privacy ও P1-03 quota recovery, তারপর Student ও compatibility/Partner failure paths সমাধানের নকশা ও পরীক্ষার অনুমোদন; বহির্মুখী DAST-এর policy এবং deployment single-writer boundary স্পষ্ট করা। এরপর P2 export/replay/worker/coverage মোকাবিলা ও পূর্ণ regression, historical-data upgrade, security review ও কার্যকর operational rehearsal দরকার। এগুলো সুপারিশ, সম্পন্ন কাজ নয়।

## ১০. Git status ও file-integrity নোট

রিভিউর শুরু ও শেষে মূল branch/HEAD অপরিবর্তিত; original ৬৬ path-এর status/content/mode অপরিবর্তিত, staged file নেই। নিচের তালিকায় `M` মানে পূর্ববর্তী unstaged tracked পরিবর্তন এবং `??` মানে পূর্ববর্তী untracked। এই প্রতিবেদন `docs/POST_IMPLEMENTATION_REVIEW_2026-10-31.md` একটি নতুন, আলাদা untracked file; নিচের original ৬৬-র মধ্যে গণনা করা হয়নি। আগের untracked প্রতিবেদন দুটি অক্ষত রাখা হয়েছে।

## ১১. রিভিউ শুরুর ৬৬টি পরিবর্তিত path-এর সম্পূর্ণ তালিকা

```text
 M apps/api/src/app.ts
 M apps/api/src/assistant/service.ts
 M apps/api/src/entitlements/service.ts
 M apps/api/src/external/conformance.ts
 M apps/api/src/external/knowledge.ts
 M apps/api/src/external/languageAliases.ts
 M apps/api/src/external/packIntegration.ts
 M apps/api/src/external/packProvider.ts
 M apps/api/src/external/scaDeclaration.ts
 M apps/api/src/external/service.ts
 M apps/api/src/external/types.ts
 M apps/api/src/payments/store.ts
 M apps/api/src/routes/admin.ts
 M apps/api/src/routes/subscription.ts
 M apps/api/src/scans/dast/activeEngine.ts
 M apps/api/src/scans/dast/engine.ts
 M apps/api/src/scans/remediationGuidance.ts
 M apps/api/src/scans/sast/engine.ts
 M apps/api/src/scans/sast/languages.ts
 M apps/api/src/scans/sast/semantic.ts
 M apps/api/src/scans/sca/declarationReaders.ts
 M apps/api/src/scans/sca/declarationScan.ts
 M apps/api/src/scans/sca/engine.ts
 M apps/api/src/scans/sca/filesystemProvider.ts
 M apps/api/src/scans/sca/range.ts
 M apps/api/src/scans/secrets/engine.ts
 M apps/api/src/scans/secrets/rules.ts
 M apps/api/src/scans/store.ts
 M apps/api/src/usage/service.ts
 M apps/api/src/usage/store.ts
 M apps/api/test/assistantService.test.ts
 M apps/api/test/dastAuthorization.test.ts
 M apps/api/test/datasetConformance.test.ts
 M apps/api/test/datasetGuidance.test.ts
 M apps/api/test/datasetLanguageAliases.test.ts
 M apps/api/test/datasetService.test.ts
 M apps/api/test/declarationReaders.test.ts
 M apps/api/test/engineStrengthening.test.ts
 M apps/api/test/partnerApi.test.ts
 M apps/api/test/paymentApi.test.ts
 M apps/api/test/sastEngine.test.ts
 M apps/api/test/sastSemantic.test.ts
 M apps/api/test/scaDeclaration.test.ts
?? apps/api/test/scaFilesystemSafety.test.ts
?? apps/api/test/scaReaderFixtures.test.ts
?? apps/api/test/scaVersionRanges.test.ts
 M apps/api/test/scanApi.test.ts
?? apps/api/test/scanIdentity.test.ts
?? apps/api/test/scanQuotaFailure.test.ts
 M apps/api/test/secretsRules.test.ts
?? apps/api/test/usageStorePersistence.test.ts
 M apps/web/src/pages/AccountPage.tsx
 M apps/web/src/pages/ProjectDetailPage.tsx
 M apps/web/test/subscriptionUi.test.tsx
 M apps/worker/src/runner.ts
 M apps/worker/test/runner.test.ts
 M docs/ADMIN.md
?? docs/DATASET_INTEGRATION_REPORT_2026-10-30.md
?? docs/MAIN_APP_RELIABILITY_REPORT_2026-10-31.md
 M docs/SCA.md
 M packages/shared/src/dast.ts
 M packages/shared/src/plans.ts
 M scripts/ci/runner.ts
 M scripts/sca-reader-fixtures.mjs
?? scripts/verify-dataset-runtime.mjs
 M scripts/verify-dataset.mjs
```
