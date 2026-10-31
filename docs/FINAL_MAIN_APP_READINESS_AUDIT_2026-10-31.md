# Drobon Main App — উন্নয়ন ও বাস্তব প্রস্তুতি অডিট

**তারিখ:** ৩১ অক্টোবর ২০২৬, এশিয়া/ঢাকা
**পরিধি:** শুধু Main App-এর বর্তমান working tree; কোনো commit তৈরি করা হয়নি।
**শাখা:** `arena/0056e643-drobon`
**ভিত্তি commit:** `e763eb938d67d4163dca817716231794bb45e372`

> **সংস্করণ-সংক্রান্ত নোট:** ১–১২ নম্বর অংশ আগের hardening পর্যায়ের ঐতিহাসিক
> snapshot ও তার প্রমাণ সংরক্ষণ করে। সেখানে থাকা “বর্তমান”, test/file count
> বা inventory সেই সময়ের; সর্বশেষ pre-release ফল ও সম্পূর্ণ working-tree
> তালিকা ১৩–১৪ নম্বর অংশে।

## ১. সিদ্ধান্ত

Main App-এর বিদ্যমান কোডে গুরুত্বপূর্ণ privacy, quota recovery, Student progress, finding identity, Partner activation, report guidance, scanner ও logging সংশোধন করা হয়েছে। পূর্ববর্তী পর্যায়ের সম্পূর্ণ offline regression-এ **১,৬৪৯/১,৬৪৯টি test এবং ১৫৮/১৫৮টি test file পাস**। এটি পরীক্ষিত fixture ও code path-এর ফল, পূর্ণ নিরাপত্তা বা নির্ভুলতার প্রমাণ নয়।

**Production-এর জন্য শর্তহীন অনুমোদন দেওয়া যাচ্ছে না।** JSON store-এর single-writer সীমা, পুরোনো sensitive data ও source-এর at-rest সংরক্ষণ, Partner-এর দুই-file consistency, legacy DAST policy, bounded Dataset loader-এর অবশিষ্ট filesystem ও coverage সীমা এবং scanner coverage-এর সীমা রয়ে গেছে। এগুলোর সমাধান/অপারেশনাল সিদ্ধান্ত ও বাস্তব deployment rehearsal ছাড়া Part 1–8 পুরোপুরি verified নয়। তাই Part 9-এর autonomous engine implementation শুরু করা হয়নি।

এই পরীক্ষায় **P0 হিসেবে নিশ্চিত সমস্যা দেখানো হয়নি**; এর অর্থ P0 অসম্ভব বা অনুপস্থিত প্রমাণিত নয়। P1–P3-এর বিস্তারিত ৮ নম্বর অংশে। কোনো বাস্তব credential বা অনুমতিহীন target ব্যবহার করা হয়নি।

## ২. আগের কাজ ও repository সংরক্ষণ

- **পূর্ববর্তী baseline যাচাইয়ে** রিভিউ শুরুর মূল **৬৬টি পরিবর্তিত path-এর সবগুলো উপস্থিত ছিল**: ৫১টি byte-identical, ১৫টি সংশোধনের প্রয়োজনেই পরিবর্তিত; কোনোটি হারায়নি। তাদের আগের অবস্থার manifest-এর aggregate SHA-256: `b1c80d87ee9416d418afb3a7cfc752ec06c875ed50c4616b35cafe3f244b88a6`। আগের byte-identical থাকার দাবি সব ৬৬টির জন্য করা হচ্ছে না।
- **ঐতিহাসিক পরিমাপে** remediation শুরুর baseline-এ আগের review report-সহ **৬৭টি path** ছিল: ৫২টি byte-identical, ১৫টি ইচ্ছাকৃতভাবে update, ০টি missing। ওই ১৫টির pre-remediation bytes পূর্বে সংরক্ষিত patch থেকে RAM-এ পুনর্গঠন করে প্রতিটির baseline SHA-256 মিলেছে। আগের পরিবর্তনের ওপর কাজ করা হয়েছে; reset/revert করা হয়নি।
- আগের snapshot-এ এই রিপোর্টসহ inventory ছিল: **১১৪টি tracked unstaged modified, ২৯টি untracked, ০টি staged, ০টি deleted**। সম্পূর্ণ তৎকালীন নাম ১২ নম্বর অংশে; ১০৮ + ২১ = ১২৯ path-এর আগের snapshot ঐতিহাসিক হিসেবে ১১ নম্বর অংশে রাখা হয়েছে। আগের `POST_IMPLEMENTATION_REVIEW_2026-10-31.md` ও অন্য untracked report overwrite করা হয়নি।
- Continuation-এর আগের ১২৯টি path-ই আবার বর্তমান tree-তে পাওয়া গেছে; তার সঙ্গে ১৪টি নতুন path আছে। Session interruption-এর আগে পূর্ব-baseline hash comparison-এ ১০৪টি identical, ২৫টি changed ও ০টি missing পাওয়া হয়েছিল। ওই `/tmp` baseline পুনরায় পরিবেশ চালু হলে হারিয়েছে, তাই শেষ অবস্থায় ওই byte comparison নতুন করে করা সম্ভব হয়নি; শুধু সব ১২৯টি path-এর উপস্থিতি পুনরায় যাচাই হয়েছে।
- এই continuation-এ কোনো commit, push, merge বা branch পরিবর্তন করা হয়নি। আগের অনুমোদিত PR #6 merge এই statement-এর বাইরের ঐতিহাসিক কাজ। Build/test-এর ignored output ও dependency directory Git-এর পরিবর্তিত-file গণনায় নেই। পৃথক Database repository, database বা migration পরিবর্তন করা হয়নি।
- আগের ও বর্তমান `/tmp/drobon-*` baseline/test logs অস্থায়ী sandbox evidence; session পুনরারম্ভে আগের `/tmp` হারিয়েছে। এগুলো স্থায়ী archive নয়; পূর্বের সংখ্যা ঐতিহাসিক পরীক্ষার নথিভুক্ত ফল।

## ৩. রিভিউয়ের অগ্রাধিকারগুলোর আগে ও পরে

| বিষয় | আগে | এখন এবং সীমা |
|---|---|---|
| Secrets/SAST evidence | এক লাইনের অন্য synthetic sensitive value finding, report ও Assistant-এ যেতে পারত; detection denylist-এর সঙ্গে scrub জড়িত ছিল। | Detection semantics না বদলে source finding-এর raw snippet fail-closed withheld; নতুন ও legacy output projection, Assistant, API, JSON, Markdown, PDF ও SARIF synthetic marker দিয়ে পরীক্ষা। Raw source এবং পুরোনো evidence at rest মুছে ফেলা হয়নি; arbitrary note, filename, Dataset text বা ভবিষ্যৎ field সম্পূর্ণ secret-free প্রমাণিত নয়। |
| Logs ও error | request path/client ID, exception ও কিছু loader path/error-এ অচেনা sensitive text প্রকাশের পথ ছিল। | Request log-এ route template ও পৃথক server-generated `X-Log-Id`; exception message/stack withheld। Dataset/SCA/advisory loader-এর path, filename ও raw parse error বাদ; rejected count/valid rule ID বজায় আছে। সাধারণ heuristic logging-কে সর্বজনীন secret detector বলা যায় না। |
| Quota ও scan | quota persist-এর পরে process kill হলে quota কাটা থাকত, scan থাকত না; partial write-এ recovery অসম্পূর্ণ ছিল। | Existing stores-এ reservation, commit/release, idempotent reconciliation এবং audit evidence যুক্ত। FREE/PRO partial-write, restart ও `SIGKILL` fixture পাস। JSON file এখনও single-process/single-writer; pending finalization-এর retry startup-এ, ক্রমাগত background reconciliation নয়; audit capacity সীমিত। |
| Student lesson | বাস্তব Dataset ID catalog-এ এলেও progress store গ্রহণ করত না; পুরোনো valid progress পড়তে সমস্যা ছিল। | পরিচিত Dataset ID যাচাই, read/quiz/practice progress, invalid ID rejection ও durable restart path যুক্ত। HTTP test-এ pinned Dataset-এ দেখা `lsn_pack_shell_fix` ID ও **synthetic lesson content** ব্যবহার করা হয়েছে; বাস্তব mounted Dataset দিয়ে HTTP E2E এখানে চালানো হয়নি। |
| Finding identity | evidence বদলালে একই SAST finding `NEW`/`RESOLVED` হতে পারত। | SAST/Secrets v2-তে project, scanner, rule, normalized file ও line-ভিত্তিক evidence-independent identity; legacy matching রক্ষণশীল, ambiguous match merge করে না। Line সরলে split হতে পারে; DAST/SCA এখনও v1/evidence-dependent। |
| Partner/PRO | account update ব্যর্থ হলে ACTIVE Partner ও FREE account-এর split state থাকতে পারত। | Existing Partner/account/payment boundary-তে guarded mutation, durable saga, retry, compensation ও startup recovery; tested pending state-এ HTTP fail-closed। Complimentary ও paid provenance পৃথক রাখতে failure/restart/SIGKILL পরীক্ষা হয়েছে। দুটি file-এ একক atomic commit নেই, সব concurrent side effect বা একাধিক process-এর isolation প্রমাণিত নয়; পুরোনো paid provenance অস্পষ্ট হতে পারে। |
| Report guidance | finding/Assistant-এ guidance ছিল, export-এ অনুপস্থিত ছিল। | অপ্ট-ইন `?guidance=1` দিয়ে JSON, Markdown, PDF ও SARIF-এ rule-specific guidance; আগের remediation ও saved snapshot অপরিবর্তিত থাকে। Default export আগের মতো; guidance snapshot digest-এর বাইরে। তিনটি উদাহরণ অনুমোদিত, পাঁচটি নিরাপত্তার জন্য withheld; এগুলো verified patch নয়। |
| Legacy report | পুরোনো saved evidence নিরাপদ projection ছাড়া বের হতে পারত। | Safe projection output-এ redaction করে কিন্তু পুরোনো disk bytes পুনর্লিখন করে না। Projection-এ report ID/digest বদলাতে পারে; আলাদা regeneration-এ ঐতিহাসিক bytes নষ্ট করার বদলে 409 হতে পারে। Migration/retention নীতি এখনও দরকার। |
| DAST policy ও execution | linked scope denial বা cross-host redirect-এর আগেও DNS হতে পারত। | Linked-scan authorization এবং redirect host/downgrade denial DNS-এর আগে; request/time/response bounds ও mock পরীক্ষাগুলো পাস। Legacy unlinked scan `UNVERIFIED` রয়ে গেছে, declaration স্বাধীন অনুমতির প্রমাণ নয়; DNS না থাকলে replay এখনও 409 হতে পারে। |

**ইচ্ছাকৃত HTTP compatibility পরিবর্তন:** authenticated `/api/v1/dataset/status` response-এ পূর্বে থাকা optional `datasetPath` এখন বাদ যায়, কারণ path-এ arbitrary sensitive text থাকতে পারে। Internal Dataset service-এ property আগের মতো আছে; category counts, valid rule IDs ও status বজায় আছে। Invalid diagnostic names/keys আর verbatim প্রকাশ করা হয় না।

## ৪. Scanner ও Dataset coverage — বর্তমান কোডে RAM-only পরীক্ষা

User-owned Dataset-এর pinned commit `3986082b22007b47930da3bc99be9c2f2b036080`-এর archive শুধুমাত্র read-only RAM-এ আনা হয়েছে। SHA-256 পূর্বের সঙ্গে মিলেছে: `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। Dataset clone/extract বা repository-তে file create/edit/delete করা হয়নি। Hash শুধু এই pinned archive-এর bytes প্রমাণ করে, remote-এর সব branch অপরিবর্তিত প্রমাণ করে না।

Application-এর `validatePackRules` দিয়ে বর্তমান RAM-only conformance পুনঃযাচাই নিচে দেওয়া হলো। শেষ column-এর representative runtime positive হলো **পূর্ববর্তী পৃথক run**; সর্বশেষ DAST normalization/payload পরিবর্তনের পরে ওই পুরো runtime harness আবার চালানো হয়নি।

| Family | Rule গৃহীত/দেখা | Declared test executed/passed | Skipped | পূর্ববর্তী representative runtime positive |
|---|---:|---:|---:|---:|
| SAST | ১,০০০/১,০০০ | ৪,০৪৩/৪,০৪৩ | ০ | ১,০০০/১,০০০ |
| Secrets | ১,০০০/১,০০০ | ৪,৬৬০/৪,৬৬০ | ০ | ১,০০০/১,০০০ |
| DAST | ১,০০৭/১,০০৭ | ৩,৬৭৩/৩,৬৭৩ | ০ | ১,০০৭/১,০০৭ |
| SCA | ১,০০০/১,০০০ | ৪,০০১/৪,০০১ | ০ | নিচের reader হিসাব |
| **মোট** | **৪,০০৭/৪,০০৭** | **১৬,৩৭৭/১৬,৩৭৭** | **০** | প্রতি SAST/Secrets/DAST rule-এর একটি fixture |

ওই পূর্ববর্তী runtime positive পরীক্ষায় তখনকার App engines-এ প্রতিটি rule-এর একটি synthetic positive পাঠানো হয়; DAST-এর ১,১২০টি request **mock transport**, বাস্তব network target নয়। Schema-invalid summary/finding, truncated batch বা পরীক্ষিত SAST/Secrets evidence-এ অনিরাপদ raw snippet পাওয়া যায়নি। এটি প্রতিটি rule-এর সব প্রয়োগ, negative coverage, বাস্তব FP/FN, exploitability বা বাস্তব-world accuracy-এর দাবি নয়। RAM-only harness প্রকৃত filesystem-mounted Dataset loader-এর পূর্ণ integration test-ও নয়।

### SCA reader-এর সৎ হিসাব

৪,০০১টি declared case শ্রেণিবিন্যাস করা হয়েছে; যেগুলো নীতিমতে uploadযোগ্য ও render করা যায়, কেবল সেগুলোর synthetic file App-এর reader এবং declaration scan layer-এ পরীক্ষা করা হয়েছে:

| ফল | Case |
|---|---:|
| নির্ণেয় ও প্রত্যাশা অনুযায়ী | ৩,৮২৭ |
| Upload path policy-তে blocked | ১৬৪ |
| Fixture render করা যায়নি | ৮ |
| Parse করা যায়নি | ২ |
| নির্ণীত অংশে false positive / false negative | ০ / ০ |

এই ০/০ কেবল **৩,৮২৭ নির্ণীত synthetic case**-এ; অবশিষ্ট **১৭৪টি pass নয়** এবং renderer স্বাধীন বাস্তব benchmark নয়। ১,০০০ rule-এর মধ্যে **৯৫৪টির সব fixture** নির্ণীত হয়েছে; **৪৬টি rule আংশিক/অনুপলব্ধ**। ৪১টি rule-এর প্রতিটির চারটি (zero-based index ০–৩) hidden artifact source-path policy-তে blocked: মোট ১৬৪টি। আটটি বাস্তব NuGet XML-এ render অসম্ভব: `DPK-SCA-0679` index ১, ৩; `DPK-SCA-0689` index ০, ১, ৩; `DPK-SCA-0753` index ০, ১, ৩। দুইটি pip options-এর খালি representation parser বুঝতে পারেনি: `DPK-SCA-0729` ও `DPK-SCA-0730`, প্রতিটির index ৩। কোনোটি passing বলা হয়নি।

আগের ৩,৮৩৩/১৬৪/২/২ হিসাব এবং ৯৫৬/৪৪ rule হিসাব **সংশোধিত ও superseded**: NuGet-এর `packageSources.add` ও derived `sources` alias পরস্পর বিরোধী হলে আগের fixture renderer কয়েকটি value নীরবে ফেলে দিচ্ছিল। এখন সেগুলো render failure হিসেবে গণনা হয়; Dataset rule বদলানো হয়নি। শূন্য evaluator mismatch-ও ওই blocked/failed case-গুলো reader দিয়ে পাস করেছে—এমন নয়।

Blocked ৪১টি rule: `DPK-SCA-0073`–`0094`, `0107`, `0142`, `0143`, `0651`, `0691`, `0760`, `0777`–`0779`, `0788`–`0791`, `0793`–`0797`, `0978` (range inclusive; `0792` নেই)। বাকি পাঁচটি অনির্ণীত rule-এর index উপরে দেওয়া আছে।

যেসব ৪৬টি rule-এ অন্তত একটি fixture অনির্ণীত, সম্পূর্ণ তালিকা:

`DPK-SCA-0073`, `DPK-SCA-0074`, `DPK-SCA-0075`, `DPK-SCA-0076`, `DPK-SCA-0077`, `DPK-SCA-0078`, `DPK-SCA-0079`, `DPK-SCA-0080`, `DPK-SCA-0081`, `DPK-SCA-0082`, `DPK-SCA-0083`, `DPK-SCA-0084`, `DPK-SCA-0085`, `DPK-SCA-0086`, `DPK-SCA-0087`, `DPK-SCA-0088`, `DPK-SCA-0089`, `DPK-SCA-0090`, `DPK-SCA-0091`, `DPK-SCA-0092`, `DPK-SCA-0093`, `DPK-SCA-0094`, `DPK-SCA-0107`, `DPK-SCA-0142`, `DPK-SCA-0143`, `DPK-SCA-0651`, `DPK-SCA-0679`, `DPK-SCA-0689`, `DPK-SCA-0691`, `DPK-SCA-0729`, `DPK-SCA-0730`, `DPK-SCA-0753`, `DPK-SCA-0760`, `DPK-SCA-0777`, `DPK-SCA-0778`, `DPK-SCA-0779`, `DPK-SCA-0788`, `DPK-SCA-0789`, `DPK-SCA-0790`, `DPK-SCA-0791`, `DPK-SCA-0793`, `DPK-SCA-0794`, `DPK-SCA-0795`, `DPK-SCA-0796`, `DPK-SCA-0797`, `DPK-SCA-0978`।

| Parser | Declared | সঠিক | Blocked | Render/parse অনির্ণীত |
|---|---:|---:|---:|---:|
| JSON | ১,৭২৮ | ১,৭২৮ | ০ | ০ |
| TOML | ১,০১৬ | ১,০০৪ | ১২ | ০ |
| YAML | ৩৩২ | ২৭২ | ৬০ | ০ |
| requirements | ১০৯ | ১০৭ | ০ | ২ |
| XML | ২৫৬ | ২৪৮ | ০ | ৮ |
| Gradle | ১০০ | ১০০ | ০ | ০ |
| properties | ১২ | ১২ | ০ | ০ |
| INI | ২০৪ | ১১২ | ৯২ | ০ |
| lockfile-text | ২৪৪ | ২৪৪ | ০ | ০ |

Gradle ও অন্যান্য reader সীমিত syntax বোঝে; unsupported shape বা absent-field semantics ভুল হতে পারে। Hidden file নীতি শিথিল না করে এগুলো সমাধান করা যায় কি না আলাদা নিরাপত্তা/compatibility সিদ্ধান্ত প্রয়োজন। SCA advisory/version-এ অনিশ্চিত ফল clean/vulnerable বলে দাবি করা হয় না। আগের একই pinned Dataset provider-vector পরীক্ষা **১৬/১৬** ছিল; সেটি শেষ privacy-diagnostic পরিবর্তনের আগের run। আগের npm matrix ৫২৮ case-এ ৪৫২ agreement/৭৬ unknown, PyPI ১,৯৫৩ case-এ ১,৬৭৯ agreement/২৭৪ unknown; ecosystem-wide equivalence নয়।

SAST comment-mask-এর আগের per-line simulation-এ Dataset-এর inactive-comment positive ১৯৫টি দমন হয়েছে; এটি production false-negative rate নয়, বরং lexer/context সীমার প্রমাণ। String, comment, dead code, সব ভাষার parser ও সব encoded secret পুরোপুরি বিশ্লেষণ হয় না। Secrets scanner বাস্তব credential যাচাই করে না এবং Git history scan সমর্থিত বলে দাবি করা হয়নি। Passive DAST pack ছাড়া ফাঁকা থাকতে পারে; active DAST-এ কিছু bounded built-in probe আছে, কিন্তু বহির্মুখী ব্যবহার policy ও explicit authorization সাপেক্ষ। Dataset অনুপস্থিত হলে SAST/Secrets/passive DAST pack ফাঁকা ও SCA `NOT_ASSESSED` হতে পারে।

## ৫. বিদ্যমান module ও AI assessment

| Module | পরীক্ষিত অবস্থা ও সীমা |
|---|---|
| Auth, authorization, accounts | বিদ্যমান session, scrypt, role/ownership, origin/CORS, unauthorized/cross-account regression full suite-এ পাস। Session ও rate limiter process-local; MFA, email verification, password reset এবং distributed session production-ready বলে প্রমাণ নেই। |
| Admin, payment, subscription | Role-এর পাশাপাশি server allowlist ও existing payment/entitlement boundary পরীক্ষা হয়েছে। Payment manual; request বা `APPROVED` status একা bank transfer-এর স্বাধীন প্রমাণ নয়। Production reviewer IDs ও নির্দেশনা operator-কে নিরাপদভাবে সেট করতে হবে। |
| Partner, Student, usage | উপরের fault/restart tests পাস; multi-writer ও দুই-file সীমা বজায় আছে। Student বাস্তব ID-সহ synthetic data-তে পরীক্ষা, mount E2E অনিরীক্ষিত। |
| Scans, findings, reports, UI | বর্তমান API এবং React workflow-এর automated tests পাস; identity ও report history compatibility সীমা উপরে বর্ণিত। Saved report-এর SHA-256 integrity hash, ডিজিটাল signature নয়। |
| Dataset, guidance | Read-only provider ও বৈধ rule/declared-test acceptance RAM-এ যাচাই। আলাদা Dataset বা database পরিবর্তন নয়; arbitrary Dataset guidance/text সম্পূর্ণ secret-free বা কোনো fix নিজে verified—এমন দাবি নেই। |
| Assistant | Default provider `NONE`; বিদ্যমান scan/finding/report নিয়ে deterministic সীমিত intent উত্তর দেয়। Open-ended generation বাস্তবায়িত নয়; কোনো local model, local inference engine বা প্রকৃত generative agent দেখানো যায়নি। Tool-calling/autonomous orchestration-এর production capability প্রমাণিত নয়। |
| Worker / orchestration | API-র durable scan processor ও আলাদা in-memory worker একই ব্যবস্থা নয়। Retry/cancellation পরীক্ষিত; abort অমান্যকারী handler timeout-এর পর চলতে এবং retry-এর সঙ্গে overlap করতে পারে। |
| SOC/SAC | বর্তমান implementation-এ saved scan-এর view/coverage; এটি live security monitoring, certification বা স্বয়ংক্রিয় attack validation নয়। |

## ৬. Automated verification ও পূর্ববর্তী failure

### সর্বশেষ সম্পূর্ণ offline regression

| Workspace | Test files পাস/মোট | Tests পাস/মোট |
|---|---:|---:|
| shared | ১৯/১৯ | ১৮৮/১৮৮ |
| API | ১০৫/১০৫ | ১,১৪৬/১,১৪৬ |
| worker | ৩/৩ | ৩২/৩২ |
| web | ৩১/৩১ | ২৮৩/২৮৩ |
| **মোট** | **১৫৮/১৫৮** | **১,৬৪৯/১,৬৪৯** |

সর্বশেষ run-এ ০ failure এবং test runner কোনো skipped test রিপোর্ট করেনি। Dataset-এর ১৬,৩৭৭ conformance fixture ও SCA-র ১৭৪ অনির্ণীত reader case এই ১,৬৪৯ test-এর সঙ্গে যোগ করে এক সংখ্যা দেখানো হচ্ছে না। আগের সম্পূর্ণ run ছিল ১৫৪ file/১,৬১৪ test; সেটি ঐতিহাসিক, সর্বশেষ নয়।

পূর্বে নথিভুক্ত নির্বাচিত focused run (একই test একাধিক run-এ আছে, যোগ করা যাবে না): privacy/detection ১১৮/১১৮; quota ৫৫/৫৫ এবং FREE/PRO recovery ২২/২২; Student ৫/৫; identity v2 ৩/৩; Partner regression ৭৭/৭৭ ও recovery/HTTP ১০/১০; export privacy ৩৭/৩৭; guidance API ২৯/২৯ ও web ৫৯/৫৯; logging ৯০/৯০ ও request-log ৬৯/৬৯; DAST gates ১২৬/১২৬; processor concurrency ৪৮/৪৮; সর্বশেষ loader privacy, Dataset, advisory, SCA ও CI regression ৬৮/৬৮। Full suite-এ unit, integration, API/authorization, UI, worker retry/cancellation এবং existing feature regression অন্তর্ভুক্ত।

**লুকানো নয়:** আগের প্রথম full run-এ দুটি SAST assertion raw snippet আশা করায় fail করেছিল; privacy বজায় রেখে withheld evidence-এর পাশাপাশি rule/location/AST attribution স্পষ্ট assert করে সংশোধনের পরে focused ৪১/৪১ এবং পরবর্তী full run পাস। Secret scanner প্রথমে ছয়টি synthetic fixture line flag করেছিল; সেগুলো test-only হিসেবে চিহ্নিত করা হয়েছে, scanner দুর্বল করা হয়নি। নতুন loader privacy test প্রথমে ৫/৫ fail করে বাস্তব path/diagnostic leak দেখায়; সংশোধনের পর ৫/৫ এবং তার বৃহত্তর focused ৬৮/৬৮ পাস।

### অন্যান্য checks

- Root `npm run typecheck`, `npm run build`, `npm run lint`: **PASS**। Web production build-এ minified chunk **৫০৮.৩৭ kB (৫০৮,৩৭৩ bytes; gzip ১৩৮.০২ kB)**; ৫০০ kB threshold warning আছে।
- Secret scanner self-test ও scan: **PASS**; বর্তমান file count ও command ১০ নম্বর অংশে। আগের scan-এ ৭৭৯টি file ছিল। Repository integrity, boundary check, release-evidence **self-test**, `git diff --check`: **PASS**। এগুলো dependency vulnerability clearance বা স্বাধীন security audit নয়।
- `npm audit` এবং network-dependent পুরো `npm run verify` চালানো হয়নি; external security-service নিষেধ মানা হয়েছে। Dependency vulnerabilities তাই অনিরীক্ষিত। বাস্তব target scan, বাস্তব credentials, independent accuracy benchmark, production failover/load test ও mounted Dataset-এর full end-to-end run করা হয়নি।
- প্রধান logs: `/tmp/drobon-master-full-test-post-loader.log`, `/tmp/drobon-master-full-test-post-loader-metrics.json`, `/tmp/drobon-master-loader-privacy-before.log`, `/tmp/drobon-master-loader-privacy-focused.log`, `/tmp/drobon-master-typecheck-build-post-loader.log`, `/tmp/drobon-master-static-checks-after-audit.log`, `/tmp/drobon-master-dataset-memory-post-loader.log`, `/tmp/drobon-master-sca-memory-post-loader.log`। এগুলো অস্থায়ী sandbox evidence।

## ৭. Resource ও deployment মূল্যায়ন

- পরিমাপের sandbox: Node `v22.22.3`, npm `10.9.8`, ২ logical CPU, প্রায় ৩.৮৫ GiB RAM ও প্রায় ২০ GiB ফাঁকা disk। **পূর্ববর্তী ১,৬১৪-test run-এর** wall time **১৮৭.২৩ s**; child-process CPU user **২১৯.৭২ s**, system **২০.৫২ s**; Linux-এর বৃহত্তম child `ru_maxrss` **৪৪৯,১৪৮ KiB**। এটি পুরো process tree-এর সম্মিলিত peak memory নয় এবং production capacity বা প্রতি-scan benchmark নয়।
- DAST passive constants: সর্বোচ্চ ৩ request, ২ redirect, ৩২,৭৬৮-byte response, ৫ s request timeout ও ১৫ s scan deadline; active-এর upper ceiling ২০ request ও ৩০ s deadline, একই redirect/response/request-timeout সীমা (tier/config প্রয়োজনে কমাতে পারে)। Declaration reader-এ ২৬২,১৪৪ byte, ৮,০০০ line, depth ৬৪ ও ২,০০০ node সীমা; declaration evaluation ১০,০০০; finding cap ২০০। Bounds থাকা সব input বা সব timeout-এ process থামে—এমন প্রমাণ নয়।
- আগের code review-এ সাধারণ Dataset loader-এ bounds ও incompleteness reporting অনুপস্থিত ছিল। এখন bounded traversal/JSON reader, category ও manifest diagnostics যোগ হয়েছে; সর্বোচ্চ সংখ্যা, synthetic প্রমাণ ও ব্যতিক্রম ১০ নম্বর অংশে। এটি পুরোনো unbounded finding-এর সংশোধন, কিন্তু hostile concurrent filesystem replacement, সব OS বা বাস্তব mounted full-corpus production load প্রমাণিত নয়।
- Production-এ অন্তত `NODE_ENV=production`, TLS/secure cookies, নির্দিষ্ট CORS origin, অনুমোদিত DAST scope, নিরাপদ স্থায়ী store path, encrypted/permission-restricted storage, backup/restore rehearsal এবং **একটি মাত্র writer/API instance** দরকার। এটি কেবল অস্থায়ী operational constraint; high availability বা multiple writer নিরাপদ করার সমাধান নয়। Session, rate limiting ও JSON storage distributed নয়; raw source retention, storage growth ও incident response নীতিও প্রয়োজন। কোনো deployment বা live preview এখানে চালানো হয়নি।

## ৮. অবশিষ্ট অগ্রাধিকার

### P0

- পরীক্ষায় নির্দিষ্ট P0 প্রমাণিত হয়নি। এটি P0 নেই বা app আক্রমণ-অযোগ্য—এমন নিশ্চয়তা নয়।

### P1 — production-এর আগে সিদ্ধান্ত/সমাধান দরকার

1. **Single-writer integrity:** quota, scan, account ও অন্যান্য JSON store একাধিক process/replica থেকে atomic নয়। Transactional/single-writer enforcement এবং crash, power-loss, backup/restore ও multi-process পরীক্ষার নকশা দরকার; পৃথক Database repo/migration পরিবর্তনের অনুমতি এখানে নেই।
2. **Sensitive data at rest:** raw source এবং legacy report/evidence রয়ে গেছে; arbitrary notes, filenames, guidance বা অন্যান্য free text-এ সব ধরনের secret ধরা অসম্ভব। অনুমোদিত retention, access control, encryption, historical migration/incident policy দরকার। পরীক্ষিত redaction-কে সর্বজনীন বলে ধরে বাস্তব sensitive data বিতরণ করা যাবে না।
3. **Partner consistency:** saga ও fail-closed gate পরীক্ষিত হলেও দুটি file-এর সর্বাবস্থায় atomicity, ইতোমধ্যে চলমান concurrent side effect এবং পুরোনো paid/complimentary provenance প্রমাণিত নয়। সিদ্ধান্ত, failure-injection ও concurrency যাচাই দরকার।
4. **DAST authorization policy:** legacy unlinked scan `UNVERIFIED`; user declaration নিজের মধ্যে প্রকৃত অনুমতির স্বাধীন প্রমাণ নয়। Production active scan-এর explicit scope/consent, ownership ও legacy policy resolve করতে হবে; অনুমতি ছাড়া বাস্তব target চালানো যাবে না।
5. **Dataset trust ও residual filesystem risk:** সাধারণ loader-এ এখন bounded read/traversal ও observed incompleteness status আছে। তবু attacker-controlled concurrent parent replacement-এর বিরুদ্ধে race-free sandbox নয়; বড় ভবিষ্যৎ corpus limit-এ আংশিক হতে পারে, category status সম্পূর্ণ semantic validity প্রমাণ করে না। বিশ্বস্ত read-only mount, deployment-এর সম্পূর্ণ corpus পরীক্ষা ও compatibility decision প্রয়োজন।

### P2 — কার্যকারিতা/বিশ্বাসযোগ্যতা

- Abort অমান্যকারী API/worker handler timeout-এর পরে চলতে পারে; worker retry overlap ও side effect সম্পূর্ণ নিরোধ নয়। Process isolation, fencing/idempotency ও cancellation পরীক্ষা প্রয়োজন।
- SCA ৪৬ rule-এর কিছু fixture অনির্ণীত; hidden path, bounded parser, version semantics ও unsupported shape সীমা বজায় আছে। SAST line movement, comment/context এবং DAST/SCA identity এখনও incomplete; independent FP/FN benchmark নেই।
- Legacy DAST replay DNS failure-এ 409 হতে পারে। Active probes-এ সীমিত marker/payload budget, query-URL restriction ও প্রকৃত লক্ষ্য থেকে অনুমতির স্বয়ংক্রিয় যাচাই নেই।
- Safe legacy report projection ID/digest পরিবর্তন ও 409-এর migration policy দরকার। Guidance opt-in; পাঁচ example withheld এবং অন্যগুলিও tested patch নয়।
- General Dataset loader-এর বাস্তব mounted full-corpus test, hostile concurrent file replacement ও অন্যান্য OS পরীক্ষা হয়নি। Model inference, generative AI, task planning বা autonomous platform parity নেই।

### P3 — অপারেশনাল/রক্ষণাবেক্ষণ

- Web chunk warning: ৯৮টি module transform হয়ে ৮১টি module-সহ একটি ৫০৮.৩৭ kB minified JS chunk তৈরি হয়। `routes.tsx`-এ page import eager এবং `ProjectDetailPage.tsx` source ১,৩০,৯২৩ bytes। একই config-এর in-memory Rollup attribution-এ তার rendered length ১,৫৫,৪৯৫, React DOM ১,৩৩,৮৩৮, React Router ৮৬,৩০৯; এগুলো minification-পূর্ব module length, শেষ gzip/minified file-এ যোগযোগ্য সঠিক অংশ নয়। Route-level lazy loading loading/error behavior বদলাতে পারে; runtime UX ও performance benchmark ছাড়া cosmetic split করা হয়নি। কিছু পুরোনো documentation ও `.env.example`-এ ঐতিহাসিক count/বর্ণনা থাকতে পারে; সেগুলো authoritative current coverage নয়।
- Production observability, disk-growth/retention limits, distributed rate limits, disaster recovery ও independent security review অনিরীক্ষিত।

## ৯. পরবর্তী পর্যায়ের শুধু boundary assessment

Part 1–8 পূর্ণ verified হওয়ার আগে autonomous engine implementation শুরু করা হয়নি। ভবিষ্যতে নিজস্ব implementation বিবেচনার আগে: existing engagement/consent boundary-তে explicit scope ও expiry; deny-by-default target policy, DNS pinning ও bounded requests; existing scanner/processor পুনর্ব্যবহার; প্রতিটি correlation/attack path-এর প্রমাণ ও অনিশ্চয়তা; শুধু অনুমোদিত lab-এ validation; human-reviewed fix suggestion ও পরে অনুমোদিত retest প্রয়োজন। Customer system-এ স্বয়ংক্রিয় file write, code পরিবর্তন বা deployment নয়। Local model সত্যিই উপস্থিত ও যাচাই করা না গেলে AI ক্ষমতা দাবি করা যাবে না; নতুন external AI API বা paid scanner যোগ করা হয়নি। এসব প্রকাশ্য ধারণার নিরাপদ নিজস্ব assessment, proprietary implementation নকল বা paid-platform parity নয়।

**পরবর্তী কাজ শুরু করা নিরাপদ?** P1 ঝুঁকি সমাধান ও Part 1–8-এর অবশিষ্ট যাচাইয়ের আগে autonomous implementation বা production customer data-এর জন্য নিরাপদ বলা যাচ্ছে না। বর্তমান ফল সীমিত local/test hardening হিসেবে ব্যবহারযোগ্য; বড় storage/schema/loader policy পরিবর্তনে compatibility ও data-loss ঝুঁকি থাকলে আগে আলাদা অনুমোদন দরকার।


## ১০. Continuation audit — ফল, পুনরুৎপাদন ও বাকি সীমা

### ১০.১ অগ্রাধিকারভিত্তিক verdict

| ক্ষেত্র | অবস্থা | কী প্রমাণিত / কী নয় |
|---|---|---|
| সাধারণ Dataset traversal ও JSON bounds | **PARTIAL** | Synthetic limit, malformed/duplicate, privacy ও compatibility regression পাস; pinned archive RAM-এ limit-এর ভেতরে। বাস্তব mounted full-corpus E2E, hostile concurrent filesystem ও সব OS অনিরীক্ষিত। |
| Scan/quota/account/subscription recovery | **PARTIAL** | Tested write-failure, retry, compensation, restart এবং সীমিত SIGKILL পরিস্থিতি পাস; single-writer JSON ও দুই-file transaction সীমা রয়ে গেছে। |
| DAST entry point ও engagement | **PARTIAL** | Local mock-এ linked/unlinked, passive/active, redirect, DNS, withdrawal, replay ও request budget পরীক্ষা; legacy unverified ও প্রকৃত authorization স্বাধীনভাবে যাচাই হয় না। |
| পুরোনো report/finding/log privacy | **PARTIAL** | Synthetic পুরোনো evidence read/export পরীক্ষিত ও disk bytes অপরিবর্তিত; প্রকৃত deployment-এর historical data পরীক্ষা বা migration করা হয়নি। |
| SCA ৪,০০১ case accounting | **PASS** | সব case শ্রেণিবদ্ধ; reader coverage **PARTIAL**, কারণ ১৭৪টি blocked/failed—not pass। |
| Offline regression, typecheck, build, lint ও static checks | **PASS** | নিচের commands/results; এগুলো নিরাপত্তা certification বা সব execution path-এর প্রমাণ নয়। |
| Production, dependency audit ও বাস্তব target | **NOT VERIFIED** | Networked `npm audit`/`npm run verify`, বাস্তব customer/target, production failover/load ও independent accuracy benchmark চালানো হয়নি। |

### ১০.২ Dataset bounded loading ও read-only প্রমাণ

General `external/service.ts` loader এখন streaming directory enumeration ব্যবহার করে। একটি load-এর shared budget: **৫০,০০০ directory entries**, **২০,০০০ JSON files**, **directory depth ১৬**, **প্রতি file ২ MiB**, **মোট ৬৪ MiB**; JSON depth **৬৪**, lexical tokens **১,০০,০০০**। প্রতি rule-এর declared tests সর্বোচ্চ **২৫৬টি**, প্রতিটির serialized দৈর্ঘ্য সর্বোচ্চ **১৬,৩৮৪ characters**। Test override শুধু ceiling কমাতে পারে, বাড়াতে পারে না। Limits per-load, পুরো server বা একাধিক একসঙ্গে চলা process-এর global memory cap নয়।

JSON parser escaped-equivalent সহ duplicate object key প্রত্যাখ্যান করে; malformed JSON, oversize, গভীর nesting, token/file/entry/byte limit, unreadable file, static symlink, unexpected entry ও invalid knowledge/lesson shape synthetic fixtures-এ পরীক্ষা হয়েছে। File growth/read এবং concurrent budget reservation-এর পরীক্ষাও আছে। Category status-এ observed unreadable/invalid/duplicate/enumeration/resource counts ও `incomplete` দেওয়া হয়; manifest সমস্যা আলাদাভাবে দেখা যায়। Remediation/CWE/lesson-এর duplicate identity flag করা হলেও legacy raw record/order সংরক্ষিত—সব duplicate স্বয়ংক্রিয়ভাবে delete/reject করা হয় না; downstream map একই ID collapse করতে পারে। Status পুরো schema বা semantic correctness নিশ্চিত করে না এবং অদেখা directory-এর file count জানা যায় না।

Alternate path-এ SCA filesystem intelligence reader নিজস্ব bounded traversal এবং একই bounded JSON parser ব্যবহার করে। সরাসরি configured advisory file আগের **১ MiB** limit বজায় রাখে এবং compatibility-র জন্য তার final symlink অনুমোদিত; সাধারণ Dataset entry-র জন্য তা নয়। Static symlink refusal race-free OS sandbox নয়; parent directory concurrent replacement, non-Linux behavior, regex worst case ও operator-এর ভবিষ্যৎ বড় corpus পরীক্ষিত নয়। `samples` ancestor-এর কারণে বৈধ intelligence বাদ যাওয়ার synthetic failure সংশোধিত হয়েছে।

Pinned archive যাচাইয়ে নির্বাচিত **৮,২৩৪টি JSON**, **১১,০১৬,২৮০ bytes**, সর্ববৃহৎ **১৫,৮৯২ bytes**, parse/duplicate-key failure **০**; পূর্ববর্তী RAM পর্যবেক্ষণে JSON depth সর্বোচ্চ **১০**, lexical tokens **৮০৪**, category-relative directory depth **১**, declared tests/rule সর্বোচ্চ **১৬** এবং remediation/CWE/lesson duplicate identity **০** ছিল। এগুলো নির্বাচিত archive member, mounted-loader end-to-end বা ভবিষ্যৎ Dataset-এর নিশ্চয়তা নয়। কোনো Dataset file create/edit/delete, clone বা extract করা হয়নি। সীমা, parser ও conformance পরীক্ষা Main App-এ; disposable synthetic fixture ছাড়া অন্য কোনো Dataset লেখা হয়নি। SHA-256 ও commit ৪ নম্বর অংশে।

### ১০.৩ Crash, retry, compensation ও অস্থায়ী file

- Scan/quota-তে reserve → durable scan → commit/release ও restart reconciliation আছে। FREE/PRO synthetic failure ও SIGKILL পরীক্ষায় retry idempotent; PRO device quota কাটে না। Quota-finalization ব্যর্থ হলে durable scan ফিরতে পারে, pending reservation startup-এ reconcile হয়; অবিরাম background retry নিশ্চিত নয় এবং audit capacity সীমিত।
- Partner activation-এ account/partner write failure, compensating rollback, HTTP gate, restart, matching retry এবং নির্দিষ্ট SIGKILL point পরীক্ষা হয়েছে। `ACTIVE`/`FREE` legacy record quarantine হয়, bytes নিজে বদলায় না। দুই JSON file-এ একসঙ্গে atomic commit নেই; অন্য process, সব in-flight side effect বা legacy paid/complimentary provenance প্রমাণিত নয়। `APPROVED` payment একাই বাস্তব transfer বা current PRO-এর উৎস প্রমাণ করে না।
- Account ও source JSON writer-এর actual rename-failure fixture আগে **২/২ fail** করেছিল: synthetic sensitive `.tmp` পড়ে থাকত। এখন private, exclusive temp create এবং caught-failure-এ best-effort cleanup; পুরোনো destination/restart ও retry, আগের collision file এবং synthetic replacement-interleaving পরীক্ষা পাস। Replacement test প্রথমে **১ fail/১ pass** হয়েছিল; cleanup-এ device/inode যাচাই যোগের পরে পাস।
- এই যাচাই `lstat` ও `unlink` একক atomic operation করে না, multi-writer lock বা hostile replacement থেকে সম্পূর্ণ সুরক্ষা নয়। `fsync`, power-loss durability ও SIGKILL-এ temp cleanup প্রমাণিত নয়। Project, payment, payment-config, entitlement ও assessment-এর অন্য JSON stores-এ code inspection-এ আগের unguarded temp-write/rename রয়ে গেছে; তাদের failure cleanup আলাদা করে পরীক্ষা হয়নি। কোনো historical temp file সরানো হয়নি। কোনো একক rename-কে multi-file transaction বা universal atomicity বলা হচ্ছে না।

### ১০.৪ DAST authorization, replay ও compatibility

| Entry point | Local mock-এ যাচাই ও সীমা |
|---|---|
| Target configuration | Owner-only, syntax ও public-address/DNS policy। আলাদা configuration preflight-এ DNS হতে পারে; scan engagement gate-এর আগে DNS না করার দাবি ওই আলাদা endpoint-এ প্রযোজ্য নয়। |
| Scan create / quota | Authenticated owner, server-owned target, mode/consent ও linked assessment scope/engagement check; rejected scope DNS/transport ও quota-র আগে। Active-এর explicit consent লাগে। |
| Passive/active execution | Linked request-এর scope/engagement ও DNS policy প্রতি request-এ পুনরায় পরীক্ষা; DNS চলাকালে withdrawal, অনুপস্থিত/failed authorizer fail-closed। Legacy unlinked এবং engagement-বিহীন পুরোনো workflow এখনও `UNVERIFIED`। |
| Redirect / crawl | Linked same-host path scope এবং cross-host/HTTPS downgrade rejection পরীক্ষা; অগ্রহণযোগ্য redirect-এর DNS/transport হয় না। Active payload selection bounded; arbitrary target-এর পূর্ণ আচরণ যাচাই নয়। |
| Idempotency/replay | একই identity ও request-এ দ্বিতীয় quota charge নয়; ভিন্ন request একই key-তে conflict। Target safety/DNS preflight replay lookup-এর আগেই হওয়ায় DNS অনিরাপদ/ব্যর্থ হলে বিদ্যমান replay-ও 409 হতে পারে। |
| Limits/errors | Passive সর্বোচ্চ ৩ request/১৫ s, active সর্বোচ্চ ২০ request/৩০ s; failed transport attempt-ও active request budget-এ গোনা হয়। Timeout, response ও redirect bounds ৭ নম্বর অংশে; abort অমান্যকারী handler সবসময় থেমেছে—এমন প্রমাণ নেই। |

আগে nested encoding দিয়ে চারটি separator/traversal target normalization পেরোতে পারত এবং synthetic unlinked scan mock transport পর্যন্ত যেত। এখন path-এ `%25` পুরোপুরি প্রত্যাখ্যাত; linked engagement আগেই এই pattern আটকাত। **Compatibility:** নিরীহ double-encoded path-ও এখন reject হয় এবং আগের configured target ভবিষ্যৎ scan-এ reject হতে পারে; পুরোনো record rewrite হয়নি। Query URL আগের মতো সীমিত। Declaration বাস্তব owner consent-এর স্বাধীন প্রমাণ নয়; এমনকি GET-ও target-defined side effect ঘটাতে পারে। সব network/transport পরীক্ষা local mock ছিল; অনুমতিহীন বা বাস্তব target scan হয়নি।

### ১০.৫ Historical data বনাম নতুন output

Raw source snapshots ও আগে persist হওয়া report/finding evidence disk-এ থাকতে পারে; ঐতিহাসিক sensitive value মুছে ফেলা বা রূপান্তর করা হয়নি। Synthetic পুরোনো SAST/Secrets, SCA ও DAST record readable রেখে tested API, report projection, Assistant ও JSON/Markdown/PDF/SARIF export-এ স্বীকৃত credential-shaped evidence withheld/redacted করা হয়েছে। SCA/DAST synthetic evidence-এর নতুন দুইটি পরীক্ষা সংশোধনের আগে fail এবং পরে pass হয়েছিল; একই bytes disk-এ অপরিবর্তিত থাকার assertion আছে। Runtime secret scan প্রকৃত deployed historical logs পড়েনি।

Derived safe legacy projection-এ report ID/digest পরিবর্তন হতে পারে; আলাদা regeneration-এ পুরোনো record নষ্ট না করে 409 হতে পারে। Migration চাইলে প্রথমে অনুমোদিত retention, backup/restore, dry-run, rollback ও compatibility পরীক্ষা প্রয়োজন। Arbitrary filename, note, URL, Dataset prose বা অজানা secret pattern সম্পূর্ণ safe প্রমাণিত নয়; repeated generic redaction সব ক্ষেত্রে idempotent নয়।

### ১০.৬ বর্তমান reproducible checks ও failure history

```sh
# Main App root; dependency installation uses the lockfile, not npm audit.
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run typecheck
npm run build
npm run lint
npm run check:boundaries
npm run check:repo-integrity
npm run check:release-evidence
node scripts/check-no-secrets.mjs --self-test
npm run check:secrets
git diff --check

# Read-only pinned archive in RAM: needs the shared workspace build first.
npm run build --workspace @drobon/shared
python3 scripts/audit-dataset-archive.py > /tmp/drobon-priority5-memory-final.json 2> /tmp/drobon-priority5-memory-final.log
# Network-free alternative only if the exact pinned archive already exists:
# python3 scripts/audit-dataset-archive.py --archive /path/to/pinned-archive.tar.gz

# Inspect production bundle module lengths without writing a second build.
node --input-type=module <<'NODE'
import { build } from 'vite';
import { resolve } from 'node:path';
const result = await build({ root: resolve('apps/web'),
  configFile: resolve('apps/web/vite.config.ts'), logLevel: 'silent', build: { write: false } });
for (const r of Array.isArray(result) ? result : [result]) {
  for (const chunk of r.output.filter((item) => item.type === 'chunk')) {
    const modules = Object.entries(chunk.modules).map(([id, m]) => ({ id, rendered: m.renderedLength }));
    modules.sort((a, b) => b.rendered - a.rendered);
    console.log(chunk.fileName, Buffer.byteLength(chunk.code), modules.slice(0, 10));
  }
}
NODE
```

Focused regressions আবার চালানোর কমান্ড (full suite-এর সঙ্গে overlap আছে):

```sh
npm run test --workspace @drobon/api -- datasetCompleteness.test.ts datasetResourceBounds.test.ts datasetService.test.ts datasetConformance.test.ts scaFilesystemSafety.test.ts scaReaderFixtures.test.ts loaderPrivacy.test.ts advisory.test.ts
npm run test --workspace @drobon/api -- scanQuotaRecovery.test.ts partnerActivationRecovery.test.ts storageFailurePrivacy.test.ts privateJsonWrite.test.ts evidenceRedaction.test.ts reportsApi.test.ts
npm run test --workspace @drobon/api -- dastTarget.test.ts dastAuthorization.test.ts dastApi.test.ts dastEngine.test.ts dastHttp.test.ts dastSurface.test.ts dastRules.test.ts engagements.test.ts scanApi.test.ts
```

- `npm test`: **PASS**, shared ১৯ file/১৮৮ test, API ১০৫/১,১৪৬, worker ৩/৩২, web ৩১/২৮৩; মোট **১৫৮ file/১,৬৪৯ test**, reported failure বা skip ০। Static security tests অন্তর্ভুক্ত: API `security` ৪৬ ও `staticSafety` ৬, web `staticWeb` ৪।
- উপরের focused command তিনটির ফল যথাক্রমে **৮ file/৬২ test**, **৬ file/৩০ test**, **৯ file/১৪৫ test PASS**; full suite-এর সঙ্গে যোগ করা যাবে না।
- Root `npm run typecheck`, `npm run build`, `npm run lint`: **PASS**। Build warning ও in-memory bundle attribution ৭–৮ নম্বর অংশে; threshold বাড়িয়ে warning ঢেকে রাখা হয়নি।
- `npm run check:boundaries`, `npm run check:repo-integrity`, `npm run check:release-evidence` (self-test), `node scripts/check-no-secrets.mjs --self-test`: **PASS**। `npm run check:secrets`: **PASS**, ৭৯০ file; `git diff --check`: **PASS** (Git-এর tracked diff; untracked report-এর trailing whitespace আলাদাভাবে পরীক্ষা করা হয়েছে)।
- Pinned archive script: **PASS** for bounded parse, rule acceptance ও সম্পূর্ণ accounting; ফলের `readerCoverage` **PARTIAL**। Network কেবল ব্যবহারকারীর নিজস্ব pinned GitHub archive-এর read-only retrieval; অন্য কোনো Dataset বা external security service নয়। `scripts/sync-dataset.mjs --check` read-only; default `sync:dataset` clone/pull করে বলে এই পর্বে চালানো হয়নি এবং Dataset read-only constraint চলাকালে চালানো উচিত নয়।
- বর্তমান অস্থায়ী logs: `/tmp/drobon-priority6-test-final.log`, `/tmp/drobon-priority6-{dataset,recovery,dast}-focused.log`, `/tmp/drobon-priority6-{typecheck,build,lint,security}-final.log`, `/tmp/drobon-priority5-memory-final.{json,log}`, `/tmp/drobon-bundle-attribution.log`। এগুলো session restoration-এ হারাতে পারে।

Failure history গোপন নয়: loader completeness/privacy, Dataset `samples` ancestor, SCA conflicting aliases, account/source rename cleanup, cleanup replacement interleaving, legacy SCA/DAST evidence এবং DAST nested encoding-এর synthetic pre-fix failures সংশোধনের পরে পাস হয়েছে। আগের প্রথম full run-এর দুই SAST expectation ও six synthetic secret-scan flags ৬ নম্বর অংশে আছে। এই continuation-এ প্রথম `npm run lint` তিনটি অপ্রয়োজনীয় escape-এ fail করেছিল; string/regex semantics না বদলে ঠিক করার পরে পুনরায় PASS। Environment পুনরারম্ভে ignored `node_modules`/`dist` হারিয়ে `npx eslint` স্বয়ংক্রিয়ভাবে ESLint 10 আনতে চেষ্টা করে কিন্তু dependency missing-এ fail করে; একবার archive verifier-ও shared build missing-এ fail করে। এতে repository dependency/lockfile বদলায়নি। Lockfile থেকে reinstall ও shared build-এর পরে official lint ও archive verifier PASS। কোনো test/security control দুর্বল করা হয়নি।

### ১০.৭ এই continuation-এ সংশ্লিষ্ট প্রধান পরিবর্তিত file

- Dataset ও diagnostics: `apps/api/src/external/{boundedJson,service,types,conformance,advisory,packIntegration,knowledge,lessonProvider,routes}.ts`, `apps/api/src/scans/sca/{filesystemProvider,engine}.ts`, `apps/api/test/{datasetCompleteness,datasetResourceBounds,datasetService,datasetConformance,loaderPrivacy,scaFilesystemSafety,scaReaderFixtures}.test.ts`।
- SCA/read-only verification: `scripts/sca-reader-fixtures.mjs`, `scripts/{verify-dataset,verify-dataset-runtime,verify-dataset-memory,sync-dataset}.mjs`, `scripts/audit-dataset-archive.py`, `scripts/ci/{runner,datasetPreflight}.ts`।
- Storage/privacy: `apps/api/src/lib/writePrivateJson.ts`, `apps/api/src/auth/jsonFileUserRepository.ts`, `apps/api/src/scans/{sources,store,findingIdentity}.ts`, `apps/api/src/partners/store.ts`, `apps/api/test/{privateJsonWrite,storageFailurePrivacy,evidenceRedaction}.test.ts`।
- DAST: `apps/api/src/scans/dast/{target,activeEngine,payloads}.ts`, `apps/api/src/routes/scans.ts`, `apps/api/test/{dastTarget,dastAuthorization,dastApi}.test.ts`, `docs/DAST.md`।
- এই রিপোর্ট: `docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md`। নিচের ১২ নম্বর অংশে সেই পর্যায়ে থাকা সব path-এর status আছে; কোনোটি stage/commit করা হয়নি। সর্বশেষ inventory ১৪ নম্বর অংশে।


## ১১. ঐতিহাসিক পরিবর্তিত-file snapshot

নিচের তালিকা আগের audit লেখার পরের **ঐতিহাসিক** `git status --porcelain` snapshot; পরবর্তী snapshot ১২ নম্বর এবং সর্বশেষ তালিকা ১৪ নম্বর অংশে। ` M` = tracked unstaged, `??` = untracked; staged/deleted নেই। এতে শুরু থেকেই থাকা এবং এই remediation-তে নতুন পরিবর্তন দুটোই আছে। তালিকার অন্তর্ভুক্ত হওয়া মানে প্রতিটি file এই turn-এ নতুন করে তৈরি হয়েছে—তা নয়।

### Tracked unstaged — ১০৮টি

```text
 M apps/api/src/app.ts
 M apps/api/src/assistant/context.ts
 M apps/api/src/assistant/redaction.ts
 M apps/api/src/assistant/service.ts
 M apps/api/src/auth/jsonFileUserRepository.ts
 M apps/api/src/auth/memoryUserRepository.ts
 M apps/api/src/auth/repositories.ts
 M apps/api/src/config.ts
 M apps/api/src/entitlements/service.ts
 M apps/api/src/external/advisory.ts
 M apps/api/src/external/conformance.ts
 M apps/api/src/external/knowledge.ts
 M apps/api/src/external/languageAliases.ts
 M apps/api/src/external/packIntegration.ts
 M apps/api/src/external/packProvider.ts
 M apps/api/src/external/routes.ts
 M apps/api/src/external/scaDeclaration.ts
 M apps/api/src/external/service.ts
 M apps/api/src/external/types.ts
 M apps/api/src/http.ts
 M apps/api/src/index.ts
 M apps/api/src/logger.ts
 M apps/api/src/middleware/cors.ts
 M apps/api/src/middleware/originGuard.ts
 M apps/api/src/partners/service.ts
 M apps/api/src/partners/store.ts
 M apps/api/src/payments/service.ts
 M apps/api/src/payments/store.ts
 M apps/api/src/reports/build.ts
 M apps/api/src/reports/pdf.ts
 M apps/api/src/routes/admin.ts
 M apps/api/src/routes/assistant.ts
 M apps/api/src/routes/auth.ts
 M apps/api/src/routes/projects.ts
 M apps/api/src/routes/reports.ts
 M apps/api/src/routes/scans.ts
 M apps/api/src/routes/sources.ts
 M apps/api/src/routes/subscription.ts
 M apps/api/src/routes/usage.ts
 M apps/api/src/scans/dast/activeEngine.ts
 M apps/api/src/scans/dast/engine.ts
 M apps/api/src/scans/dast/target.ts
 M apps/api/src/scans/findingIdentity.ts
 M apps/api/src/scans/findingWorkflow.ts
 M apps/api/src/scans/processor.ts
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
 M apps/api/src/student/store.ts
 M apps/api/src/usage/service.ts
 M apps/api/src/usage/store.ts
 M apps/api/test/assistantService.test.ts
 M apps/api/test/config.test.ts
 M apps/api/test/dastAuthorization.test.ts
 M apps/api/test/dastTarget.test.ts
 M apps/api/test/datasetConformance.test.ts
 M apps/api/test/datasetGuidance.test.ts
 M apps/api/test/datasetLanguageAliases.test.ts
 M apps/api/test/datasetService.test.ts
 M apps/api/test/declarationReaders.test.ts
 M apps/api/test/deepSast.test.ts
 M apps/api/test/engagements.test.ts
 M apps/api/test/engineStrengthening.test.ts
 M apps/api/test/errorDisclosure.test.ts
 M apps/api/test/helpers.ts
 M apps/api/test/logger.test.ts
 M apps/api/test/partnerApi.test.ts
 M apps/api/test/paymentApi.test.ts
 M apps/api/test/pdfReports.test.ts
 M apps/api/test/reports.test.ts
 M apps/api/test/reportsApi.test.ts
 M apps/api/test/sastEngine.test.ts
 M apps/api/test/sastSemantic.test.ts
 M apps/api/test/scaDeclaration.test.ts
 M apps/api/test/scanApi.test.ts
 M apps/api/test/secretsEngine.test.ts
 M apps/api/test/secretsRules.test.ts
 M apps/api/test/studentApi.test.ts
 M apps/web/src/api/client.ts
 M apps/web/src/pages/AccountPage.tsx
 M apps/web/src/pages/ProjectDetailPage.tsx
 M apps/web/test/client.test.ts
 M apps/web/test/findingsReportsUi.test.tsx
 M apps/web/test/subscriptionUi.test.tsx
 M apps/worker/src/runner.ts
 M apps/worker/test/runner.test.ts
 M docs/ADMIN.md
 M docs/ARCHITECTURE.md
 M docs/AUTHORIZATION.md
 M docs/DAST.md
 M docs/DATASET_CONNECTION.md
 M docs/FINDINGS.md
 M docs/SCA.md
 M docs/SECURITY.md
 M packages/shared/src/dast.ts
 M packages/shared/src/plans.ts
 M scripts/ci/runner.ts
 M scripts/sca-reader-fixtures.mjs
 M scripts/verify-dataset.mjs
```

### Untracked — ২১টি

```text
?? apps/api/src/auth/accountMutationLock.ts
?? apps/api/test/evidenceRedaction.test.ts
?? apps/api/test/findingIdentityV2.test.ts
?? apps/api/test/loaderPrivacy.test.ts
?? apps/api/test/partnerActivationRecovery.test.ts
?? apps/api/test/pdfTextFixture.ts
?? apps/api/test/reportGuidanceExport.test.ts
?? apps/api/test/requestLogPrivacy.test.ts
?? apps/api/test/scaFilesystemSafety.test.ts
?? apps/api/test/scaReaderFixtures.test.ts
?? apps/api/test/scaVersionRanges.test.ts
?? apps/api/test/scanIdentity.test.ts
?? apps/api/test/scanProcessorConcurrency.test.ts
?? apps/api/test/scanQuotaFailure.test.ts
?? apps/api/test/scanQuotaRecovery.test.ts
?? apps/api/test/usageStorePersistence.test.ts
?? docs/DATASET_INTEGRATION_REPORT_2026-10-30.md
?? docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md
?? docs/MAIN_APP_RELIABILITY_REPORT_2026-10-31.md
?? docs/POST_IMPLEMENTATION_REVIEW_2026-10-31.md
?? scripts/verify-dataset-runtime.mjs
```

### আগের baseline-এর যে ১৫টি file ইচ্ছাকৃতভাবে update হয়েছে

এই তালিকা byte comparison; প্রতিটি file-এর ভেতরের সব পূর্ববর্তী পরিবর্তন অপরিবর্তিত—এমন দাবি নয়। নিরাপত্তা, compatibility বা recovery উন্নয়নের জন্য বিদ্যমান implementation-এর অংশ refactor হয়েছে।

- `apps/api/src/app.ts`
- `apps/api/src/assistant/service.ts`
- `apps/api/src/external/conformance.ts`
- `apps/api/src/external/service.ts`
- `apps/api/src/routes/admin.ts`
- `apps/api/src/scans/sast/engine.ts`
- `apps/api/src/scans/sca/filesystemProvider.ts`
- `apps/api/src/scans/secrets/engine.ts`
- `apps/api/src/scans/store.ts`
- `apps/api/src/usage/service.ts`
- `apps/api/src/usage/store.ts`
- `apps/api/test/dastAuthorization.test.ts`
- `apps/api/test/sastEngine.test.ts`
- `apps/api/test/sastSemantic.test.ts`
- `apps/web/src/pages/ProjectDetailPage.tsx`


## ১২. আগের পর্যায়ের working-tree inventory (ঐতিহাসিক)

সেই সময়ের `git status --porcelain=v1 -uall` snapshot: ১১৪টি tracked unstaged (` M`), ২৯টি untracked (`??`); staged ও deleted ০। সর্বশেষ তালিকা ১৪ নম্বর অংশে।

```text
 M apps/api/src/app.ts
 M apps/api/src/assistant/context.ts
 M apps/api/src/assistant/redaction.ts
 M apps/api/src/assistant/service.ts
 M apps/api/src/auth/jsonFileUserRepository.ts
 M apps/api/src/auth/memoryUserRepository.ts
 M apps/api/src/auth/repositories.ts
 M apps/api/src/config.ts
 M apps/api/src/entitlements/service.ts
 M apps/api/src/external/advisory.ts
 M apps/api/src/external/conformance.ts
 M apps/api/src/external/knowledge.ts
 M apps/api/src/external/languageAliases.ts
 M apps/api/src/external/lessonProvider.ts
 M apps/api/src/external/packIntegration.ts
 M apps/api/src/external/packProvider.ts
 M apps/api/src/external/routes.ts
 M apps/api/src/external/scaDeclaration.ts
 M apps/api/src/external/service.ts
 M apps/api/src/external/types.ts
 M apps/api/src/http.ts
 M apps/api/src/index.ts
 M apps/api/src/logger.ts
 M apps/api/src/middleware/cors.ts
 M apps/api/src/middleware/originGuard.ts
 M apps/api/src/partners/service.ts
 M apps/api/src/partners/store.ts
 M apps/api/src/payments/service.ts
 M apps/api/src/payments/store.ts
 M apps/api/src/reports/build.ts
 M apps/api/src/reports/pdf.ts
 M apps/api/src/routes/admin.ts
 M apps/api/src/routes/assistant.ts
 M apps/api/src/routes/auth.ts
 M apps/api/src/routes/projects.ts
 M apps/api/src/routes/reports.ts
 M apps/api/src/routes/scans.ts
 M apps/api/src/routes/sources.ts
 M apps/api/src/routes/subscription.ts
 M apps/api/src/routes/usage.ts
 M apps/api/src/scans/dast/activeEngine.ts
 M apps/api/src/scans/dast/engine.ts
 M apps/api/src/scans/dast/payloads.ts
 M apps/api/src/scans/dast/target.ts
 M apps/api/src/scans/findingIdentity.ts
 M apps/api/src/scans/findingWorkflow.ts
 M apps/api/src/scans/processor.ts
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
 M apps/api/src/scans/sources.ts
 M apps/api/src/scans/store.ts
 M apps/api/src/student/store.ts
 M apps/api/src/usage/service.ts
 M apps/api/src/usage/store.ts
 M apps/api/test/assistantService.test.ts
 M apps/api/test/config.test.ts
 M apps/api/test/dastApi.test.ts
 M apps/api/test/dastAuthorization.test.ts
 M apps/api/test/dastTarget.test.ts
 M apps/api/test/datasetConformance.test.ts
 M apps/api/test/datasetGuidance.test.ts
 M apps/api/test/datasetLanguageAliases.test.ts
 M apps/api/test/datasetService.test.ts
 M apps/api/test/declarationReaders.test.ts
 M apps/api/test/deepSast.test.ts
 M apps/api/test/engagements.test.ts
 M apps/api/test/engineStrengthening.test.ts
 M apps/api/test/errorDisclosure.test.ts
 M apps/api/test/helpers.ts
 M apps/api/test/logger.test.ts
 M apps/api/test/partnerApi.test.ts
 M apps/api/test/paymentApi.test.ts
 M apps/api/test/pdfReports.test.ts
 M apps/api/test/reports.test.ts
 M apps/api/test/reportsApi.test.ts
 M apps/api/test/sastEngine.test.ts
 M apps/api/test/sastSemantic.test.ts
 M apps/api/test/scaDeclaration.test.ts
 M apps/api/test/scanApi.test.ts
 M apps/api/test/secretsEngine.test.ts
 M apps/api/test/secretsRules.test.ts
 M apps/api/test/studentApi.test.ts
 M apps/web/src/api/client.ts
 M apps/web/src/pages/AccountPage.tsx
 M apps/web/src/pages/ProjectDetailPage.tsx
 M apps/web/test/client.test.ts
 M apps/web/test/findingsReportsUi.test.tsx
 M apps/web/test/subscriptionUi.test.tsx
 M apps/worker/src/runner.ts
 M apps/worker/test/runner.test.ts
 M docs/ADMIN.md
 M docs/ARCHITECTURE.md
 M docs/AUTHORIZATION.md
 M docs/DAST.md
 M docs/DATASET_CONNECTION.md
 M docs/FINDINGS.md
 M docs/SCA.md
 M docs/SECURITY.md
 M packages/shared/src/dast.ts
 M packages/shared/src/plans.ts
 M scripts/ci/datasetPreflight.ts
 M scripts/ci/runner.ts
 M scripts/sca-reader-fixtures.mjs
 M scripts/sync-dataset.mjs
 M scripts/verify-dataset.mjs
?? apps/api/src/auth/accountMutationLock.ts
?? apps/api/src/external/boundedJson.ts
?? apps/api/src/lib/writePrivateJson.ts
?? apps/api/test/datasetCompleteness.test.ts
?? apps/api/test/datasetResourceBounds.test.ts
?? apps/api/test/evidenceRedaction.test.ts
?? apps/api/test/findingIdentityV2.test.ts
?? apps/api/test/loaderPrivacy.test.ts
?? apps/api/test/partnerActivationRecovery.test.ts
?? apps/api/test/pdfTextFixture.ts
?? apps/api/test/privateJsonWrite.test.ts
?? apps/api/test/reportGuidanceExport.test.ts
?? apps/api/test/requestLogPrivacy.test.ts
?? apps/api/test/scaFilesystemSafety.test.ts
?? apps/api/test/scaReaderFixtures.test.ts
?? apps/api/test/scaVersionRanges.test.ts
?? apps/api/test/scanIdentity.test.ts
?? apps/api/test/scanProcessorConcurrency.test.ts
?? apps/api/test/scanQuotaFailure.test.ts
?? apps/api/test/scanQuotaRecovery.test.ts
?? apps/api/test/storageFailurePrivacy.test.ts
?? apps/api/test/usageStorePersistence.test.ts
?? docs/DATASET_INTEGRATION_REPORT_2026-10-30.md
?? docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md
?? docs/MAIN_APP_RELIABILITY_REPORT_2026-10-31.md
?? docs/POST_IMPLEMENTATION_REVIEW_2026-10-31.md
?? scripts/audit-dataset-archive.py
?? scripts/verify-dataset-memory.mjs
?? scripts/verify-dataset-runtime.mjs
```

## ১৩. Final pre-release hardening — সর্বশেষ পর্যায়

### ১৩.১ সিদ্ধান্ত ও অবস্থার সারাংশ

**Release recommendation: production-এর জন্য অনুমোদন নয়।** Synthetic local
fixtures-এ নিচের সংশোধন ও regression পাস হলেও বহুলেখক storage, historical
plaintext, Partner-এর cross-file provenance, default DAST authorization এবং
scanner/operational coverage-এর P1 সীমা এখনও release blocker। এটি সীমিত
local hardening; কোনো autonomous attack engine, customer code পরিবর্তন বা
unauthorized scan করা হয়নি। পূর্বের ১–১২ নম্বর অংশের ফল historical evidence;
এই অংশ তার সংশোধন/সংযোজন।

| পরীক্ষা/বিষয় | অবস্থা | কী প্রমাণিত, কী নয় |
|---|---|---|
| Offline tests, build, typecheck, lint ও repository controls | **PASS** | নিচের নির্দিষ্ট commands ও ফলের সীমায়। এটি independent audit বা dependency vulnerability clearance নয়। |
| JSON single-writer/crash | **PARTIAL** | Linux-এর একই network namespace-এ cooperating standard server-এর canonical-parent lease, duplicate-path refusal, startup failure cleanup ও process-kill/reacquisition পরীক্ষিত। Generic store, সব namespace/host/OS ও power failure নয়। |
| পুরোনো sensitive data | **PARTIAL** | New private temporary write এবং synthetic report/source bytes অক্ষত রেখে ঐচ্ছিক permission plan/apply/rollback পরীক্ষিত। পুরোনো plaintext স্বয়ংক্রিয়ভাবে মুছে বা encrypt করা হয়নি। |
| Partner/account | **PARTIAL** | fail-closed unreadable read-back, আগে/পরে write failure, retry, restart, SIGKILL এবং আলাদা সময়ের concurrent paid approval পরীক্ষিত। Timestamp transaction ID নয়; atomic multi-file বা সব concurrent history প্রমাণিত নয়। |
| DAST scope/legacy | **PARTIAL** | Raw encoded traversal/redirect/crawl আগেই deny; `%20` ও সাধারণ relative reference পরীক্ষিত। Strict engagement opt-in, legacy default অব্যাহত; attestation স্বাধীন authorization proof নয়। |
| Dataset/scanner completeness | **PARTIAL** | Local synthetic regressions পাস; আগের pinned archive-এর হিসাব ৪ নম্বর অংশে historical। এই পর্যায়ে mounted পূর্ণ Dataset E2E বা বাস্তব scanner accuracy benchmark হয়নি। |
| Networked dependency audit ও production rehearsal | **NOT VERIFIED** | `npm audit` ও পুরো `npm run verify` চালানো হয়নি; verify dependency audit-এ network ব্যবহার করে। বাস্তব infrastructure, ACL, encrypted backup restoration, load/failover ও independent security audit পরীক্ষা হয়নি। |
| Release acceptance | **FAIL** | P1 blockerগুলোর সিদ্ধান্ত, প্রয়োগ ও বাস্তব deployment evidence ছাড়া production ছাড়পত্র নয়; tests পাস মানেই নিরাপত্তা নিশ্চিত নয়। |

### ১৩.২ Reproduction, সংশোধন ও compatibility

1. **JSON concurrency ও crash:** একই synthetic project file-এর দুইটি আলাদা
   store instance খুলে A ও B লিখলে দুই project থাকার কথা থাকলেও শুধু B
   ছিল; আগের A update হারায় (`/tmp/drobon-release-stale-before.log`)। তাই
   সব default file-backed store-এর জন্য standard `startServer` এখন Linux
   abstract-socket lease নেয়, loading/recovery-এর আগেই। ব্যস্ত বা একই
   configured path startup-এ refuse করে; listen failure-এ release হয়। ভিন্ন
   process-এর আসল server collision, SIGKILL ও restart, path alias, partial
   acquisition, shutdown এবং অপেক্ষমাণ startup recovery-র local test আছে।
   `createApp`/direct store ও injected store এতে অন্তর্ভুক্ত নয়; অন্য host,
   container network namespace, hard-link alias, hostile path replacement ও
   non-Linux-এ external single-writer enforcement আবশ্যক। Kernel socket
   lease distributed transaction বা OS-ব্যাপী সব ধরনের lock নয়।
2. **Private temporary writes:** আগে পাঁচটি অন্য JSON writer-এ synthetic
   rename failure-এর পাঁচটিতেই private temp থেকে যেত
   (`/tmp/drobon-release-json-before.log`)। Projects, payments, payment
   config, entitlements, assessments, student, usage, scans ও partners-এর
   writer এখন বিদ্যমান `writePrivateJson` helper ব্যবহার করে; accounts ও
   sources আগেই এই helper ব্যবহার করত। Owned temp exclusive create ও 0600
   mode; caught failure-এ inode-মেলা temp best-effort cleanup। Partial write,
   একই-name অন্য file অক্ষত রাখা, retry ও restart পরীক্ষা আছে। `SIGKILL`
   before rename-এ পুরোনো source bytes ঠিক ছিল ও 0600 orphan ছিল; cleanup
   অবশ্যই হবে বা কোনো temp থাকবে না—এমন দাবি নয়। `stat`/`unlink` atomic
   নয়, fsync/power-loss durability, cross-file atomicity প্রমাণিত নয়।
3. **Historical at-rest data:** `scripts/restrict-json-file.mjs` কেবল
   selected file-এর POSIX permission bits-এর opt-in `plan`, `apply` ও
   `rollback`; plan নিজের জন্য একটি নতুন private metadata file তৈরি করে,
   source পরিবর্তন করে না। Synthetic source, backup ও saved report-এর bytes,
   report ID/digest এবং application read অপরিবর্তিত ছিল; local backup পৃথক
   synthetic path-এ restore করেও আবার পড়া হয়েছে। এই copy encrypted বা
   independent storage নয়। Stale inode/mode,
   final symlink, hardlink, special mode, overwrite ও confirmation checks
   পরীক্ষিত। এটি encryption, secret detection, deletion বা JSON rewrite নয়;
   পুরোনো evidence/source, backup ও orphan plaintext থাকতে পারে। প্রথমে
   সব writer বন্ধ, encrypted independent backup, restore rehearsal এবং ACL,
   owner/service-access ও parent-directory review জরুরি। Plan বিশ্বাসযোগ্য
   ও private রাখতে হবে; rollback access বাড়াতে পারে, আর পরবর্তী atomic
   write inode বদলালে plan অচল। ACL পুনর্গঠন, hostile race বা production
   backup এখানে যাচাই হয়নি। পূর্ণ runbook `docs/SECURITY.md`-এ।
4. **Partner saga:** account mutation ও partner finalization ব্যর্থতার পর
   outcome পড়া না গেলে অনুমান করে compensate না করে HTTP 503-সহ gate বন্ধ
   থাকে; restart recovery পরীক্ষা করা হয়েছে। Compensated failed Partner
   attempt-এর পরে প্রকৃত synthetic paid PRO approval হলে আগে restart ভুল
   করে Partner finalize করছিল (আগে ১ failed/১৩ passed); এখন attempt-এর
   timestamp বা আগের PRO snapshot না মিললে intent quarantine ও দুই file
   অক্ষত থাকে; matching explicit retry পরীক্ষিত। একই millisecond collision,
   unrelated timestamp match, cross-process concurrency এবং `APPROVED`
   payment থেকে বর্তমান subscription-এর provenance অনুমানযোগ্য নয়। এটি
   stable transaction ID বা atomic two-file commit-এর বিকল্প নয়।
5. **DAST compatibility ও authorization:** URL parser raw encoded-dot
   segment normalize করার আগেই redirect ও crawled reference validate হয়;
   nested `%25`, encoded separator/dot ও অন্য blocked reference fail closed।
   ordinary relative redirect এবং একবার encode করা `%20` এখনও কাজ করে;
   কিছু benign double-encoded URL সতর্কতামূলকভাবে নিষিদ্ধ। আগে চারটি raw
   encoded-dot case fail করেছিল (`/tmp/drobon-release-dast-before.log`)।
   Default `DAST_REQUIRE_ENGAGEMENT=false` legacy unlinked scan-কে আগের
   মতো `UNVERIFIED` রাখে। `true` কেবল linked, active, scoped, owner-attested
   engagement অনুমোদন করে; built-in engine প্রতি request-এ পুনঃযাচাই করে।
   Strict চালুর আগে queued unlinked scan restart-এর পর DNS-এর আগে blocked,
   আগের completed history পাঠযোগ্য থাকে। Custom injected engine-এর নিজস্ব
   execution-time enforcement থাকতে হবে; self-attestation স্বাধীনভাবে
   target ownership বা অনুমতি প্রমাণ করে না, এবং GET-এরও side effect থাকতে পারে।

### ১৩.৩ সর্বশেষ local verification

```sh
npm run test
npm run typecheck
npm run build
npm run lint
npm run check:boundaries
npm run check:repo-integrity
npm run check:release-evidence
node scripts/check-no-secrets.mjs --self-test
npm run check:secrets
git diff --check

# অতিরিক্ত focused checks; এগুলো full test-এর সঙ্গে overlap করে।
npm run test --workspace @drobon/api -- test/security.test.ts test/staticSafety.test.ts test/errorDisclosure.test.ts test/requestLogPrivacy.test.ts test/loaderPrivacy.test.ts test/allStoreFailurePrivacy.test.ts test/privateJsonWrite.test.ts test/privateJsonPartialWrite.test.ts test/privateJsonCrash.test.ts test/storageFailurePrivacy.test.ts test/jsonStoreLease.test.ts test/scanProcessorConcurrency.test.ts test/restrictJsonFile.test.ts test/evidenceRedaction.test.ts
npm run test --workspace @drobon/api -- test/partnerActivationRecovery.test.ts test/partnerApi.test.ts test/paymentApi.test.ts test/scanQuotaRecovery.test.ts
npm run test --workspace @drobon/api -- test/dastTarget.test.ts test/dastAuthorization.test.ts test/dastApi.test.ts test/dastEngine.test.ts test/dastHttp.test.ts test/dastSurface.test.ts test/dastRules.test.ts test/engagements.test.ts test/scanApi.test.ts

# Compiled API smoke; synthetic temp project only; no real store is touched.
node --input-type=module <<'NODE'
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServer } from './apps/api/dist/server.js';
import { loadConfig } from './apps/api/dist/config.js';
import { createLogger } from './apps/api/dist/logger.js';
const dir = mkdtempSync(join(tmpdir(), 'drobon-compiled-smoke-'));
const logger = createLogger({out: () => {}});
const config = {...loadConfig({NODE_ENV:'test'}), host:'0.0.0.0', port:0,
  authStorePath:':memory:', usageStorePath:':memory:', entitlementStorePath:':memory:',
  paymentStorePath:':memory:', paymentConfigStorePath:':memory:', partnerStorePath:':memory:',
  assessmentStorePath:':memory:', studentStorePath:':memory:', sourceStorePath:':memory:',
  scanStorePath:':memory:', projectStorePath:join(dir, 'projects.json')};
let first;
try {
  first = await startServer({config, logger, scanProcessorAutoStart:false});
  if (process.platform !== 'linux') throw new Error('This collision smoke requires Linux');
  await assert.rejects(startServer({config, logger, scanProcessorAutoStart:false}), /already owned/);
  await first.stop(); first = undefined;
  const next = await startServer({config, logger, scanProcessorAutoStart:false});
  await next.stop();
  console.log('compiled API startup, Linux collision, clean restart: PASS');
} finally { if (first) await first.stop(); rmSync(dir, {recursive:true, force:true}); }
NODE

# Same built crawler, no network requests.
node --input-type=module <<'NODE'
import assert from 'node:assert/strict';
import { extractCrawlCandidates } from './apps/api/dist/scans/dast/crawler.js';
const links = extractCrawlCandidates('<a href="./docs/quick%20start">ok</a><a href="./%2e%2e/admin">unsafe</a>', 'https://app.example.org/api/');
assert.deepEqual(links, ['https://app.example.org/api/docs/quick%20start']);
console.log('compiled crawler: relative %20 kept; encoded traversal rejected: PASS');
NODE
```

- `npm run test`: **PASS**, shared ১৯ file/১৮৮ test, API ১১০/১,১৮২,
  worker ৩/৩২, web ৩১/২৮৩; সর্বমোট **১৬৩ file/১,৬৮৫ test**,
  reported failed বা skipped ০। Permission test-এ synthetic protected backup
  পৃথক local path-এ restore/read-সহ শেষ সংস্করণ চলেছে।
- উপরের তিন focused group যথাক্রমে **১৪ file/৯১ test**, **৪ file/৬৮ test**
  এবং **৯ file/১৫৮ test PASS**; এগুলো full suite-এর সঙ্গে overlap করে,
  আলাদাভাবে যোগ করা যাবে না। প্রথম group-এ ৪৬ security, ৬ static-safety,
  private-write/lease/SIGKILL, logging, loader ও evidence privacy tests আছে।
- Root `npm run typecheck`, `npm run build`, `npm run lint`: **PASS**। Web
  build-এ `index-52LrLfq2.js` ৫০৮,৩৭৩ bytes (gzip ১৩৮.০২ kB) এবং >৫০০ kB
  chunk warning রয়ে গেছে; warning লুকানো হয়নি। Compiled API startup,
  same-path collision/restart এবং compiled crawler compatibility smoke: **PASS**।
- Boundary, repository integrity, release-evidence self-test এবং secret
  matcher self-test: **PASS**। Build-সহ `npm run check:secrets`: **PASS**,
  ৮০২ file; `git diff --check`: **PASS**। Node `v22.22.3`, Linux।
- আগে Partner unreadable read-back-এর ২টি synthetic test এবং পাঁচটি legacy
  store rename-cleanup case fail করেছিল; সংশোধিত tests পাস। Partner paid-PRO
  restart race আগে ১ failed/১৩ passed, এখন focused Partner group পাস। DAST
  raw encoded-reference-এর আগে চারটি failure ছিল; বর্তমান focused group পাস।

Final test output `/tmp/drobon-release-full-test-final.log`, typecheck/lint
`/tmp/drobon-release-full-{typecheck,lint}-final.log`, build
`/tmp/drobon-release-full-build.log`, focused ও boundary/privacy logs
`/tmp/drobon-release-*.log`; এগুলো sandbox-এর
অস্থায়ী evidence, চিরস্থায়ী archive নয়। `npm run check:release-evidence` শুধু
নিজস্ব self-test, সম্পূর্ণ release attestation নয়। `git diff --check` শুধু
tracked diff-এর whitespace দেখে; untracked audit আলাদা করে পরীক্ষা করা হয়েছে।

### ১৩.৪ অবশিষ্ট risk ও release blocker

- **P0:** নির্দিষ্ট P0 এই local পরীক্ষায় প্রমাণিত হয়নি; P0 অনুপস্থিত বা ১০০%
  নিরাপত্তা প্রমাণিত—কোনোটিই বলা হচ্ছে না।
- **P1 — release-এর আগে সমাধান বা অনুমোদিত operational control:** (ক) সব
  JSON writer-এর জন্য বাস্তব deployment-এ exclusive single-writer ব্যবস্থা,
  অথবা আলাদা অনুমোদিত transactional storage design ও multi-host পরীক্ষা;
  (খ) historical raw source/evidence, backup ও temp-এর encryption, access,
  retention ও verified restore পরিকল্পনা; (গ) Partner/payment-এর stable
  provenance, transaction/atomicity ও multi-process race resolution; (ঘ)
  DAST strict policy নির্বাচন, যথাযথ বাস্তব consent ও execution-time
  enforcement; (ঙ) scanner false-positive/negative, partial SCA parsing,
  Dataset trust ও mounted corpus-সহ coverage/accuracy-এর স্বাধীন validation;
  (চ) production networked dependency audit, security review, deployment
  failure/load/failover এবং backup restore rehearsal। কোনো একটি omission
  লুকিয়ে release-ready দাবি করা যাবে না।
- **P2:** SIGKILL orphan, no-fsync power loss, concurrent hostile parent/ACL
  race, non-Linux/namespace behavior, quota reconciliation কেবল startup-এ ও
  finite audit capacity, legacy report projection-এ নতুন digest/409, SAST
  lexer/line-based identity ও DAST/SCA evidence-dependent identity সীমা।
  Timeout-এ abort অমান্যকারী engine/worker code কাজ চালিয়ে যেতে পারে;
  processor shutdown সেই arbitrary কাজ থামানোর নিশ্চয়তা নয়। Strict DAST
  mode legacy unlinked queued scan বন্ধ করে—enable করার আগে workflow
  migration/communication প্রয়োজন।
- **P3:** Vite-এর >500 kB chunk warning এখনও আছে; route splitting-এর আগে
  runtime UX/performance যাচাই দরকার। Temporary test logs/baselines হারাতে
  পারে। Error/log redaction সব ভবিষ্যৎ arbitrary field secret-free হওয়ার
  প্রমাণ নয়।

### ১৩.৫ Existing কাজ সংরক্ষণ

এই পর্যায় শুরুর ১৪৩ path baseline `/tmp/drobon-release-baseline.{json,patch,tar.gz}`
mode 0600; aggregate baseline SHA-256
`00ed37323f4ac94addb4c494ac05d919ae48af984f3706c6d0e3b470e4e927ec`
(parsed manifest-কে Python `json.dumps(..., sort_keys=True, separators=(',', ':'))`
দিয়ে UTF-8 serialization-এর SHA-256)। শেষ comparison-এ 119টি byte-identical,
24টি ইচ্ছাকৃতভাবে পরিবর্তিত, 0টি missing; baseline archive-এর সব 143টি
file-এর SHA-256 manifest-এর সঙ্গে মিলে **PASS**। Changed মানে পুরোনো file-এর সব
byte অপরিবর্তিত নয়; এই পর্যায়ে নিরাপত্তা/compatibility/recovery-এর জন্য
ইচ্ছাকৃত update। কোনো baseline path missing নয়। আগের historical audit,
untracked report ও অন্যান্য কাজ রাখা হয়েছে; পৃথক Dataset repository,
Database repository বা migration পরিবর্তন হয়নি। Network থেকে কোনো নতুন
Dataset বা external AI/scanner service ব্যবহার করা হয়নি। Build output ও
`node_modules` ignored; এগুলো source inventory নয়।

Baseline manifest sandbox-এ থাকলে তুলনা পুনরায় করতে:

```sh
python3 - <<'PYBASE'
import hashlib, json, pathlib
rows = json.loads(pathlib.Path('/tmp/drobon-release-baseline.json').read_text())
canonical = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
print('baseline manifest SHA-256:', hashlib.sha256(canonical).hexdigest())
same = changed = missing = 0
for item in rows:
    path = pathlib.Path(item['path'])
    if not path.is_file(): missing += 1; continue
    if hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']: same += 1
    else: changed += 1
print('baseline paths:', len(rows), 'identical:', same, 'changed:', changed, 'missing:', missing)
PYBASE
python3 - <<'PYARCHIVE'
import hashlib, json, tarfile
rows = json.load(open('/tmp/drobon-release-baseline.json'))
expected = {row['path']: row['sha256'] for row in rows}
with tarfile.open('/tmp/drobon-release-baseline.tar.gz', 'r:gz') as archive:
    files = {m.name.removeprefix('./'): m for m in archive.getmembers() if m.isfile()}
    assert set(files) == set(expected)
    for name, digest in expected.items():
        assert hashlib.sha256(archive.extractfile(files[name]).read()).hexdigest() == digest
print('baseline archive: PASS', len(files), 'files')
PYARCHIVE
git status --porcelain=v1 -uall
```

### এই পর্যায়ে সংশ্লিষ্ট নির্ভুল path তালিকা

Baseline-এর আগে থেকেই থাকা কিন্তু এই পর্যায়ে bytes পরিবর্তিত **24টি path**:

```text
 M apps/api/src/app.ts
 M apps/api/src/config.ts
 M apps/api/src/partners/service.ts
 M apps/api/src/partners/store.ts
 M apps/api/src/payments/store.ts
 M apps/api/src/routes/scans.ts
 M apps/api/src/scans/dast/target.ts
 M apps/api/src/scans/processor.ts
 M apps/api/src/scans/store.ts
 M apps/api/src/student/store.ts
 M apps/api/src/usage/store.ts
 M apps/api/test/config.test.ts
 M apps/api/test/dastApi.test.ts
 M apps/api/test/dastAuthorization.test.ts
 M apps/api/test/dastTarget.test.ts
 M apps/api/test/engagements.test.ts
 M apps/api/test/helpers.ts
 M docs/ARCHITECTURE.md
 M docs/AUTHORIZATION.md
 M docs/DAST.md
 M docs/SECURITY.md
?? apps/api/test/partnerActivationRecovery.test.ts
?? apps/api/test/scanProcessorConcurrency.test.ts
?? docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md
```

Baseline-এ ছিল না, এখন পরিবর্তিত/untracked **16টি path**:

```text
 M .env.example
 M apps/api/src/assessments/store.ts
 M apps/api/src/entitlements/store.ts
 M apps/api/src/payments/configStore.ts
 M apps/api/src/projects/store.ts
 M apps/api/src/scans/dast/authorization.ts
 M apps/api/src/scans/dast/crawler.ts
 M apps/api/src/server.ts
?? apps/api/src/lib/jsonStoreLease.ts
?? apps/api/src/scans/dast/reference.ts
?? apps/api/test/allStoreFailurePrivacy.test.ts
?? apps/api/test/jsonStoreLease.test.ts
?? apps/api/test/privateJsonCrash.test.ts
?? apps/api/test/privateJsonPartialWrite.test.ts
?? apps/api/test/restrictJsonFile.test.ts
?? scripts/restrict-json-file.mjs
```

## ১৪. সর্বশেষ সম্পূর্ণ working-tree inventory

`git status --porcelain=v1 -uall`: **122টি tracked unstaged, 37টি untracked, মোট 159টি path; ০টি staged ও ০টি deleted**। ` M` tracked, `??` untracked। তালিকায় আগের কাজও আছে; কোনোটি stage, commit, push বা merge করা হয়নি।

```text
 M .env.example
 M apps/api/src/app.ts
 M apps/api/src/assessments/store.ts
 M apps/api/src/assistant/context.ts
 M apps/api/src/assistant/redaction.ts
 M apps/api/src/assistant/service.ts
 M apps/api/src/auth/jsonFileUserRepository.ts
 M apps/api/src/auth/memoryUserRepository.ts
 M apps/api/src/auth/repositories.ts
 M apps/api/src/config.ts
 M apps/api/src/entitlements/service.ts
 M apps/api/src/entitlements/store.ts
 M apps/api/src/external/advisory.ts
 M apps/api/src/external/conformance.ts
 M apps/api/src/external/knowledge.ts
 M apps/api/src/external/languageAliases.ts
 M apps/api/src/external/lessonProvider.ts
 M apps/api/src/external/packIntegration.ts
 M apps/api/src/external/packProvider.ts
 M apps/api/src/external/routes.ts
 M apps/api/src/external/scaDeclaration.ts
 M apps/api/src/external/service.ts
 M apps/api/src/external/types.ts
 M apps/api/src/http.ts
 M apps/api/src/index.ts
 M apps/api/src/logger.ts
 M apps/api/src/middleware/cors.ts
 M apps/api/src/middleware/originGuard.ts
 M apps/api/src/partners/service.ts
 M apps/api/src/partners/store.ts
 M apps/api/src/payments/configStore.ts
 M apps/api/src/payments/service.ts
 M apps/api/src/payments/store.ts
 M apps/api/src/projects/store.ts
 M apps/api/src/reports/build.ts
 M apps/api/src/reports/pdf.ts
 M apps/api/src/routes/admin.ts
 M apps/api/src/routes/assistant.ts
 M apps/api/src/routes/auth.ts
 M apps/api/src/routes/projects.ts
 M apps/api/src/routes/reports.ts
 M apps/api/src/routes/scans.ts
 M apps/api/src/routes/sources.ts
 M apps/api/src/routes/subscription.ts
 M apps/api/src/routes/usage.ts
 M apps/api/src/scans/dast/activeEngine.ts
 M apps/api/src/scans/dast/authorization.ts
 M apps/api/src/scans/dast/crawler.ts
 M apps/api/src/scans/dast/engine.ts
 M apps/api/src/scans/dast/payloads.ts
 M apps/api/src/scans/dast/target.ts
 M apps/api/src/scans/findingIdentity.ts
 M apps/api/src/scans/findingWorkflow.ts
 M apps/api/src/scans/processor.ts
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
 M apps/api/src/scans/sources.ts
 M apps/api/src/scans/store.ts
 M apps/api/src/server.ts
 M apps/api/src/student/store.ts
 M apps/api/src/usage/service.ts
 M apps/api/src/usage/store.ts
 M apps/api/test/assistantService.test.ts
 M apps/api/test/config.test.ts
 M apps/api/test/dastApi.test.ts
 M apps/api/test/dastAuthorization.test.ts
 M apps/api/test/dastTarget.test.ts
 M apps/api/test/datasetConformance.test.ts
 M apps/api/test/datasetGuidance.test.ts
 M apps/api/test/datasetLanguageAliases.test.ts
 M apps/api/test/datasetService.test.ts
 M apps/api/test/declarationReaders.test.ts
 M apps/api/test/deepSast.test.ts
 M apps/api/test/engagements.test.ts
 M apps/api/test/engineStrengthening.test.ts
 M apps/api/test/errorDisclosure.test.ts
 M apps/api/test/helpers.ts
 M apps/api/test/logger.test.ts
 M apps/api/test/partnerApi.test.ts
 M apps/api/test/paymentApi.test.ts
 M apps/api/test/pdfReports.test.ts
 M apps/api/test/reports.test.ts
 M apps/api/test/reportsApi.test.ts
 M apps/api/test/sastEngine.test.ts
 M apps/api/test/sastSemantic.test.ts
 M apps/api/test/scaDeclaration.test.ts
 M apps/api/test/scanApi.test.ts
 M apps/api/test/secretsEngine.test.ts
 M apps/api/test/secretsRules.test.ts
 M apps/api/test/studentApi.test.ts
 M apps/web/src/api/client.ts
 M apps/web/src/pages/AccountPage.tsx
 M apps/web/src/pages/ProjectDetailPage.tsx
 M apps/web/test/client.test.ts
 M apps/web/test/findingsReportsUi.test.tsx
 M apps/web/test/subscriptionUi.test.tsx
 M apps/worker/src/runner.ts
 M apps/worker/test/runner.test.ts
 M docs/ADMIN.md
 M docs/ARCHITECTURE.md
 M docs/AUTHORIZATION.md
 M docs/DAST.md
 M docs/DATASET_CONNECTION.md
 M docs/FINDINGS.md
 M docs/SCA.md
 M docs/SECURITY.md
 M packages/shared/src/dast.ts
 M packages/shared/src/plans.ts
 M scripts/ci/datasetPreflight.ts
 M scripts/ci/runner.ts
 M scripts/sca-reader-fixtures.mjs
 M scripts/sync-dataset.mjs
 M scripts/verify-dataset.mjs
?? apps/api/src/auth/accountMutationLock.ts
?? apps/api/src/external/boundedJson.ts
?? apps/api/src/lib/jsonStoreLease.ts
?? apps/api/src/lib/writePrivateJson.ts
?? apps/api/src/scans/dast/reference.ts
?? apps/api/test/allStoreFailurePrivacy.test.ts
?? apps/api/test/datasetCompleteness.test.ts
?? apps/api/test/datasetResourceBounds.test.ts
?? apps/api/test/evidenceRedaction.test.ts
?? apps/api/test/findingIdentityV2.test.ts
?? apps/api/test/jsonStoreLease.test.ts
?? apps/api/test/loaderPrivacy.test.ts
?? apps/api/test/partnerActivationRecovery.test.ts
?? apps/api/test/pdfTextFixture.ts
?? apps/api/test/privateJsonCrash.test.ts
?? apps/api/test/privateJsonPartialWrite.test.ts
?? apps/api/test/privateJsonWrite.test.ts
?? apps/api/test/reportGuidanceExport.test.ts
?? apps/api/test/requestLogPrivacy.test.ts
?? apps/api/test/restrictJsonFile.test.ts
?? apps/api/test/scaFilesystemSafety.test.ts
?? apps/api/test/scaReaderFixtures.test.ts
?? apps/api/test/scaVersionRanges.test.ts
?? apps/api/test/scanIdentity.test.ts
?? apps/api/test/scanProcessorConcurrency.test.ts
?? apps/api/test/scanQuotaFailure.test.ts
?? apps/api/test/scanQuotaRecovery.test.ts
?? apps/api/test/storageFailurePrivacy.test.ts
?? apps/api/test/usageStorePersistence.test.ts
?? docs/DATASET_INTEGRATION_REPORT_2026-10-30.md
?? docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md
?? docs/MAIN_APP_RELIABILITY_REPORT_2026-10-31.md
?? docs/POST_IMPLEMENTATION_REVIEW_2026-10-31.md
?? scripts/audit-dataset-archive.py
?? scripts/restrict-json-file.mjs
?? scripts/verify-dataset-memory.mjs
?? scripts/verify-dataset-runtime.mjs
```
