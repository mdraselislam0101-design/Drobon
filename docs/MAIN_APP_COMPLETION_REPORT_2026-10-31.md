# Main App completion report — ৩১ অক্টোবর ২০২৬

> এটি পূর্ববর্তী benchmark পর্যায়ের completion record। পরবর্তী accuracy কাজের বর্তমান ফল, নতুন corpus এবং unresolved gap দেখতে [scanner reliability](SCANNER_RELIABILITY_REPORT_2026-10-31.md), [synthetic corpus](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md) ও [SCA unresolved](SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md) রিপোর্ট দেখুন। নিচের ১,৭০৩-test সংখ্যা পূর্ববর্তী baseline, সর্বশেষ run-এর সংখ্যা নয়। Production সিদ্ধান্ত অপরিবর্তিত: NO-GO।

## সংক্ষিপ্ত সিদ্ধান্ত

বিদ্যমান Main App-এর scanner reliability উন্নত করা হয়েছে; দুটি পুনরুৎপাদিত SCA সমস্যা সংশোধিত, সীমিত local benchmark ও reproducible scoring প্রস্তুত, এবং পূর্ণ regression পাস। **পুরো benchmarking বা production release সম্পন্ন নয়।** স্বাধীন ground truth, ছয়টি paid product-এর access/run, autonomous attack-path lab, production authorization/deployment rehearsal এবং গুরুত্বপূর্ণ storage/privacy/transaction blocker এখনও বাকি। Release: **NO-GO**।

| ধাপ | অবস্থা | প্রমাণ ও সীমা |
|---|---|---|
| ১. Existing app audit ও নিরাপদ fix | সীমিত বাস্তব fix ও regression সম্পন্ন | SCA requirements reader/inventory এবং scanner/report/privacy নথি সংশোধিত; অবশিষ্ট ঝুঁকি নিচে। |
| ২. Reliability/fixture হিসাব | সম্পূর্ণ case accounting; coverage অসম্পূর্ণ | ৪,০০১ SCA case: ৩,৮২৯ মিল, ১৬৪ blocked, ৮ unrenderable; ২১টি ছোট synthetic case-এ provisional TP/FP/TN/FN। |
| ৩. Benchmark প্রস্তুতি | আংশিক | Local source/dependency/synthetic-secret corpus ও loopback HTTP lab আছে; independent reviewer ও autonomous infrastructure lab নেই। |
| ৪. তুলনামূলক run | **অসম্পূর্ণ** | শুধু Drobon engine-এ test-only rules ও mocked DAST run। ছয় vendor-এর কোনো run হয়নি; ranking নেই। |
| ৫. পরবর্তী roadmap | নথিভুক্ত | নিরাপত্তা, বাস্তব মাপা gap, মানব-অনুমোদিত ভবিষ্যৎ validation; কোনো autonomous engine development নয়। |

## বিদ্যমান architecture ও audit

- Shared contract + Web/API/Worker monorepo অক্ষত। Source upload → owner-scoped snapshot → bounded SAST/SCA/Secrets engine → বিদ্যমান quota/idempotency/job processor → findings/report workflow পুনর্ব্যবহৃত; কোনো parallel scanner system, API format, নতুন page/plan/user type নয়।
- Authentication-এ server-side session, scrypt, cookie/CSRF/CORS/rate limit ও ownership checks রয়েছে; এসবের উপস্থিতি distributed session, MFA বা production security review-এর দাবি নয়। DAST passive default, সীমিত consent-based `ACTIVE_SAFE`; production private/loopback restriction অপরিবর্তিত। Strict engagement enforcement opt-in, default legacy authorization অনিশ্চিত।
- Dataset runtime integration read-only ও bounded; উৎপাদনের embedded SAST/Secrets/passive DAST rule catalog খালি। Dataset না থাকলে partial/`NOT_ASSESSED` হলো সীমা, clean verdict নয়। Pinned Dataset-এর ৪,০০৭ rules ও ১৬,৩৭৭ declared tests RAM-এ যাচাই; mounted Dataset দিয়ে পূর্ণ API E2E নয়।
- Reports completed scan ও persisted findings-ভিত্তিক; JSON/Markdown/SARIF/PDF-এ সীমা আছে, digest signature নয়। নতুন source-finding snippet withheld; historical raw source/evidence disk-এ থাকতে পারে। Legacy report safe projection-এর ID বদলাতে পারে এবং ভিন্ন regeneration 409 হতে পারে।

## এই পর্যায়ের বাস্তব পরিবর্তন

1. `apps/api/src/scans/sca/declarationReaders.ts`: pip-এর স্পষ্ট খালি option ও missing argument আলাদা করে; অজানা directive এখনও fail closed।
2. `apps/api/src/scans/sca/parsers.ts`: বাদ পড়া requirements include/constraint/editable/URL/malformed লাইন `PARTIAL` হিসেবে দেখায়, পরিচিত dependency রাখে, referenced file বা network খোলে না।
3. `scripts/sca-reader-fixtures.mjs` ও `scripts/verify-dataset-memory.mjs`: path-blocked case-এ **শুধু memory diagnostic**, production source path policy অপরিবর্তিত।
4. `benchmarks/local/`: ২১টি synthetic case, loopback-only lab, আলাদা mechanical oracle, case-level scorer, redacted vendor-observation validator ও sanitized ফল। Oracle স্বাধীন মানব review নয়।
5. Targeted regression এবং `docs/SCA.md`, `docs/SCA_READERS.md`, `docs/SAST.md`, `docs/SECRETS.md`, `docs/REPORTS.md`-এ current সীমা ও report আচরণ স্পষ্ট করা হয়েছে।

No Dataset repository file, separate database বা migration পরিবর্তন/সৃষ্টি করা হয়নি; কোনো external paid scanner, customer target বা real secret ব্যবহার হয়নি। Existing controls দুর্বল করা হয়নি।

## পরীক্ষা — এই পর্যায়ের final run

Node `v22.22.3`, npm `10.9.8`; পূর্ণ offline `npm test`: **১৬৪ file / ১,৭০৩ test পাস** — shared ১৯/১৮৮, API ১১১/১,২০০, worker ৩/৩২, web ৩১/২৮৩। পূর্ববর্তী ১,৬৮৫ ফল বর্তমান পরিবর্তনের প্রমাণ নয়।

- Root typecheck, lint এবং সব workspace build পাস। Vite-এর 508.37 kB JS chunk-এ >500 kB warning রয়ে গেছে; build failure নয়, performance review বাকি।
- Boundaries, repository integrity, secret-scan self-test ও scan, release-evidence self-test এবং `git diff --check` পাস। Networked `npm audit` চালানো হয়নি।
- নতুন lab/scoring ও SCA/DAST/report/privacy focused run: ৯ ফাইল / ১১৪ test পাস; এর মধ্যে lab ৭ test। আলাদা oracle ২১/২১ authored behavior মেলে।
- ১৯টি local completed engine outcome-এর ১৯ report digest/count মেলে; ১৩ mapped alert-এ evidence metadata আছে। স্বাধীন severity correctness বা production HTTP/persisted report end-to-end এই benchmark দিয়ে প্রমাণিত নয়।
- Full output: `/tmp/drobon-benchmark-final-regression-3.log` (সাময়িক workspace log); পুনরাবৃত্তির উপায় benchmark preparation report-এ আছে।

## আগে থেকে থাকা কাজ ও Git অবস্থা

পর্ব শুরুর ১৫৯ পরিবর্তিত path-এর নিরাপদ `/tmp/drobon-benchmark-phase-baseline.{json,patch,tar.gz}` snapshot-এর hash যাচাই হয়েছে: কোনো path অনুপস্থিত নয়, ১৫৩ অপরিবর্তিত এবং ৬টিতে এই পর্যায়ের নির্দিষ্ট reader/test/diagnostic/documentation সংযোজন বা প্রয়োজনীয় সংশোধন হয়েছে। Backup-এর ১৫৯/১৫৯ hash মিলে। আগে থাকা অন্য কাজ reset বা discard করা হয়নি। Snapshot সাময়িক; এটি স্থায়ী backup/production recovery নয়।

Branch `arena/0056e643-drobon`, base HEAD `e763eb938d67d4163dca817716231794bb45e372`; পরিবর্তনগুলো working tree-তে tracked unstaged ও untracked অবস্থায় আছে। কিছুই stage, commit, push, merge বা branch switch করা হয়নি। এই পর্যায়েও আলাদা database পরিবর্তন করা হয়নি।

## পাঁচটি deliverable

1. এই completion report।
2. [Scanner reliability report](SCANNER_RELIABILITY_REPORT_2026-10-31.md) — প্রতিটি SCA blocked/unrenderable case-এর তালিকা, provisional score ও evidence।
3. [Benchmark preparation report](BENCHMARK_PREPARATION_REPORT_2026-10-31.md) — local run, six-product procedure, safety ও scoring।
4. [Unresolved blocker register](UNRESOLVED_BLOCKERS_2026-10-31.md) — release gates ও প্রয়োজনে operation pause।
5. [Prioritized improvement roadmap](PRIORITIZED_IMPROVEMENT_ROADMAP_2026-10-31.md) — প্রথমে নিরাপত্তা, পরে independently measured উন্নয়ন।

পূর্ববর্তী বিস্তারিত readiness audit [`FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md`](FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md) সংরক্ষিত। কোনো test, local fixture বা report সম্পূর্ণ নিরাপত্তা, independent vendor parity বা production readiness প্রমাণ করে না।
