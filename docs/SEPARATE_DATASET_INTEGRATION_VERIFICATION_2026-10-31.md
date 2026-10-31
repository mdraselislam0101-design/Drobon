# Drobon Main App — পৃথক Dataset integration যাচাই

**তারিখ:** ২০২৬-১০-৩১  
**সামগ্রিক সিদ্ধান্ত: PARTIALLY VERIFIED**

Main App সত্যিকারের পৃথক Drobon-Dataset থেকে চার ধরনের নিয়ম পড়েছে, যাচাই করেছে এবং নির্বাচিত নিরাপদ fixture-এ চালিয়ে finding ও রিপোর্ট তৈরি করেছে। পরীক্ষিত commit-এ মোট **৪,০০৭টি নিয়ম** পাওয়া, parse, গ্রহণ ও scanner-ready করা গেছে। তবে এটি অস্থায়ী read-only RAM mirror-এর পরীক্ষা; production deployment বা সব নিয়মের বাস্তব কার্যকারিতার নিশ্চয়তা নয়। SCA-র কিছু case path policy-তে blocked বা পরীক্ষার renderer-এ unrenderable।

| বিষয় | সিদ্ধান্ত | অর্থ |
|---|---|---|
| পৃথক GitHub repository, নির্দিষ্ট commit ও read-only mirror | **VERIFIED** | API ও archive পাওয়া গেছে; Main App mirror পড়েছে; পূর্ণ byte তুলনা মিলেছে। |
| ৪,০০৭টি নিয়ম discovery, parse, validation ও scanner-ready conversion | **VERIFIED** | নিচের সংখ্যা কেবল পরীক্ষিত commit ও এই runtime-এর। |
| চার scanner-এ নির্বাচিত বাস্তব নিয়মের positive/negative, finding ও export | **VERIFIED** | অল্পসংখ্যক synthetic fixture ও local HTTP mock; সব নিয়মের end-to-end পরীক্ষা নয়। |
| SCA বাস্তব scan-path reachability | **PARTIALLY VERIFIED** | ৩,৮২৯টি case মিলেছে; ১৬৪ blocked ও ৮ unrenderable case pass নয়। |
| ত্রুটিপূর্ণ/অনুপস্থিত Dataset এবং schema/identity আচরণ | **PARTIALLY VERIFIED** | ত্রুটি দৃশ্যমান; process cache, optional manifest ও trusted identity-র সীমা রয়ে গেছে। |
| production mount, deployment, বাস্তব লক্ষ্য, নিরাপত্তা বা accuracy | **NOT VERIFIED** | এই পরীক্ষায় সেগুলো পরীক্ষা করা হয়নি। |

## ১. উৎস ও read-only প্রমাণ

- Repository: [mdraselislam0101-design/Drobon-Dataset](https://github.com/mdraselislam0101-design/Drobon-Dataset)। যাচাইয়ের সময়ে GitHub API-তে default branch `main`-এর commit ছিল `3986082b22007b47930da3bc99be9c2f2b036080`।
- একই commit-এর GitHub codeload archive RAM-এ পড়া হয়েছে: archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। এটি local digest comparison, publisher signature যাচাই নয়।
- archive extract বা Dataset-এ লেখা হয়নি। FUSE RAM mirror `/tmp/drobon-dataset-readonly`-এ `ro,nosuid,nodev` ছিল। Main App-এর `DATASET_PATH` এই পৃথক root নির্দেশ করেছে। পরীক্ষার পর mirror বন্ধ ও unmount করা হয়েছে।
- শুরুর ও শেষের তুলনায় archive-এর প্রতিটি member-এর byte-এর সঙ্গে mirror মিলে: **২১,৩৫৫টি file**, **৪৫,৪৯৪,৬৮৭ bytes**, অতিরিক্ত file **০**। সাজানো `path\0size\0sha256\n` তালিকার SHA-256 উভয়বার `05075238809ae389b59b3d0a76dac18f43efcb4775e6eb4772842e3553e33ec9`। mirror-এ ৫৩টি directory ছিল। Dataset-এর কোনো file পরিবর্তন বা Main App-এ copy করা হয়নি।
- এই mirror Git checkout, স্থায়ী filesystem mount, access-control deployment বা production rehearsal নয়। GitHub-এর branch পরবর্তীতে বদলাতে পারে; App নিজে এই commit বা digest pin/verify করে না।

## ২. Loader থেকে scanner পর্যন্ত প্রকৃত পথ

1. `apps/api/src/config.ts`: `VULN_INTEL_PROVIDER=filesystem` হলে `DATASET_PATH` আবশ্যক; provider `none` হলে path দেওয়া যায় না। Path অস্তিত্ব startup-এ নিশ্চিত করা হয় না। Relative path process-এর working directory অনুযায়ী resolve হয়।
2. `apps/api/src/app.ts`: production composition `createDatasetService` তৈরি করে এবং একই service SAST, Secrets, passive DAST ও SCA engine-এ দেয়। SCA advisory matching-এর জন্য আলাদা `scans/sca/filesystemProvider.ts` একই root থেকে `vuln-intel` পড়ে।
3. `apps/api/src/external/service.ts` ও `boundedJson.ts`: প্রথম status/rule/guidance access-এ lazy load; `packs/{sast,secrets,dast,sca}/v1/rules`-এর JSON bounded enumeration ও parsing; symlink, unreadable file এবং resource limit হিসাব করে। সফল বা ব্যর্থ প্রথম load process-এ cache হয়; প্রতিটি scan-এ source পুনরায় যাচাই হয় না।
4. `external/conformance.ts`: প্রতিটি rule-এর family-specific `schemaVersion`, closed fields, ID, severity, check/pattern, ReDoS lint এবং নিজস্ব positive/negative declared test যাচাই করে। অকার্যকর rule বাদ দেয়; অজানা সংখ্যক অদেখা file-কে enumeration failure হিসেবে আলাদা রাখে।
5. `external/packProvider.ts` ও `packIntegration.ts`: SAST/Secrets/DAST rule scanner-এ map করে; duplicate/unmappable rule silently বাদ না দিয়ে scan partial করে। SCA-তে `external/scaDeclaration.ts` compile এবং `scans/sca/declarationScan.ts` artifact path/reader অনুযায়ী evaluate করে। Registration এখানে scanner-ready conversion/compilation; সব rule প্রতিটি scan-এ চালানো বোঝায় না।
6. Authenticated `GET /api/v1/dataset/status` ও `GET /api/v1/dataset/packs/:kind` সংখ্যা/identity দেখায়; HTTP status-এ operator-এর filesystem path withheld। Finding/detail এবং `reports/build.ts`, `reports/pdf.ts`, `routes/reports.ts` থেকে JSON, Markdown, SARIF ও PDF export হয়।

Passive SAST ও Secrets-এর embedded rule array খালি; passive DAST-এর embedded observation rule-ও খালি। Dataset `none` অবস্থায় চারটি পরীক্ষিত DPK finding হারিয়েছে এবং scan partial হয়েছে; SCA advisory state `NOT_ASSESSED`। Test helper-এর synthetic default catalog এই পরীক্ষার production registry-তে inject করা হয়নি। Active DAST-এর আলাদা built-in probe আছে; এখানে সেটি চালানো বা পরিবর্তন করা হয়নি।

### Identity/version-এর সীমা

পরীক্ষিত চার manifest যথাক্রমে `drobon-sast-starter`, `drobon-secrets-starter`, `drobon-dast-starter`, `drobon-sca-dependency-hygiene`; প্রতিটির content version `1.0.0` এবং নিজের family-এর `drobon.pack.<family>/v1` schema। সংশোধনের পর উপস্থিত manifest-এর family/schema ও `packId`/version shape পরীক্ষা হয়। Content version-এর জন্য কোনো নির্ধারিত compatibility range বা নির্দিষ্ট pack ID, Git commit, provenance বা signature যাচাই নেই: syntactically valid `999.0.0` content version-ও গ্রহণযোগ্য identity হিসেবে দেখা গেছে; এটিকে সমর্থিত schema version বলে দাবি করা যায় না।

অনুপস্থিত `pack.json` আগের চুক্তি অনুযায়ী optional: বৈধ নিয়ম চলতে পারে, কিন্তু pack identity অনুপস্থিত থাকে এবং শুধু এই কারণে `incomplete` সেট হয় না। Rule ID ও একই সময়ে দেখা status ব্যবহার করে এই পরীক্ষায় উৎস correlate করা হয়েছে; প্রতিটি finding-এ commit/pack identity cryptographically stamp করা নেই। SAST scan summary-তে effective rule-set hash/pack identity থাকতে পারে; সেটি signature নয়।

## ৩. প্রকৃত Dataset-এর গণনা

নিচে discovered file count filesystem enumeration, parsed count আলাদা JSON parse, accepted/rejected loader conformance, এবং registered scanner conversion/compilation থেকে এসেছে। চার family-তেই enumeration failure ও manifest issue ছিল **০**। `rejected` হলো জানা discovered file থেকে accepted বাদ দিলে যত; bounded diagnostic তালিকার দৈর্ঘ্য নয়।

| Family | Discovered | Parsed | Validated ও accepted | Rejected | Scanner-ready | Declared / executed tests | Failed / skipped |
|---|---:|---:|---:|---:|---:|---:|---:|
| SAST | ১,০০০ | ১,০০০ | ১,০০০ | ০ | ১,০০০ | ৪,০৪৩ / ৪,০৪৩ | ০ / ০ |
| Secrets | ১,০০০ | ১,০০০ | ১,০০০ | ০ | ১,০০০ | ৪,৬৬০ / ৪,৬৬০ | ০ / ০ |
| DAST | ১,০০৭ | ১,০০৭ | ১,০০৭ | ০ | ১,০০৭ | ৩,৬৭৩ / ৩,৬৭৩ | ০ / ০ |
| SCA declaration | ১,০০০ | ১,০০০ | ১,০০০ | ০ | ১,০০০ compiled | ৪,০০১ / ৪,০০১ | ০ / ০ |
| **মোট** | **৪,০০৭** | **৪,০০৭** | **৪,০০৭** | **০** | **৪,০০৭** | **১৬,৩৭৭ / ১৬,৩৭৭** | **০ / ০** |

এগুলো load-time evaluator-এর Dataset-authored declared tests; পুরো project-এর scanner accuracy নয়। অতিরিক্ত SAST line/comment simulation-এ ৪,০৪৩টির মধ্যে ৩,৮৪৮ expectation মিলেছে, **১৯৫টি expected positive comment masking-এ suppressed**, negative matched ০। এটি প্রথম resolved language family ব্যবহার করা simulation, পুরো-project scan বা স্বয়ংক্রিয়ভাবে ১৯৫টি বাস্তব false negative নয়।

SCA advisory data-এর status-এ ১০০টি file, ৮৪ identity item ও ৭৮ পৃথক advisory ID দেখা গেছে—১০০টি পৃথক advisory নয়। Dataset-এর ১৬টি provider vector App-এর filesystem provider-এ ১৬/১৬ মিলেছে। এটি provider-level পরীক্ষা; নিচের HTTP SCA উদাহরণগুলো declaration rule, advisory-to-HTTP end-to-end proof নয়।

## ৪. বাস্তব Dataset rule-এর HTTP end-to-end পরীক্ষা

`scripts/verify-separate-dataset-http.mjs` চালিয়ে App-এর নিজস্ব service ও scanner registry ব্যবহার করা হয়েছে; service বা scan engine inject করা হয়নি। Source ও account store in-memory। ইতিবাচক ও নেতিবাচক synthetic input সংশ্লিষ্ট বাস্তব Dataset rule-এর declared fixture থেকে runtime-এ নেওয়া; কোনো fixture value বা secret এখানে প্রকাশ করা হয়নি। DAST-এ strict assessment/engagement enabled, DNS test resolver ও test-only transport সব request loopback HTTP mock-এ পাঠিয়েছে: **৩টি loopback GET, ০টি বাহ্যিক target request**।

| Scanner ও প্রত্যক্ষ rule | Positive → negative: নির্বাচিত rule | মোট finding positive → negative | মন্তব্য |
|---|---|---|---|
| SAST `DPK-SAST-001` | পাওয়া গেছে → পাওয়া যায়নি | ১ → ০ | effective rules `DATASET`, ১,০০০ |
| Secrets `DPK-SEC-001` | পাওয়া গেছে → পাওয়া যায়নি | ১ → ০ | confidence ও source withholding যাচাই |
| SCA `DPK-SCA-0001`, `package.json` | পাওয়া গেছে → পাওয়া যায়নি | ৫ → ৪ | দুই scan-ই partial; ২৮৮ evaluated / ৭১২ not evaluated |
| SCA `DPK-SCA-0043`, `package-lock.json` | পাওয়া গেছে → পাওয়া যায়নি | ৪ → ৩ | দুই scan-ই partial; ২৫ evaluated / ৯৭৫ not evaluated |
| DAST `DPK-DAST-002` | পাওয়া গেছে → পাওয়া যায়নি | ২৪ → ২২ | mock response-এ নির্দিষ্ট header absent/present; অন্যান্য নিয়মের finding থাকতে পারে |

Negative কলামে কেবল **ওই rule-এর** absence প্রত্যাশিত; SCA/DAST-এ অন্য findings থাকা ভুল হিসেবে গণ্য হয়নি। SCA partial-এর কারণের মধ্যে advisory/version evidence-র সীমা আছে; manifest-এ ঘোষিত dependency আসলে install ছিল কি না এটি প্রমাণ করে না।

### উৎসের trace ও metadata

পরীক্ষিত rule file-এর SHA-256 (Dataset থেকে read-only গণনা):

| Rule ID | Severity / CWE | Rule file SHA-256 |
|---|---|---|
| `DPK-SAST-001` | MEDIUM / CWE-95 | `5f464532bd8293a2217baaf177caff02f40de14d5d4ad1a53aba158dab3ca3c6` |
| `DPK-SEC-001` | MEDIUM / CWE-798 | `82f55ba22a1d343e43c5c47e738f18520c53b962b951a71d6c4bfaaae232899d` |
| `DPK-DAST-002` | MEDIUM / CWE-693 | `760224ea51d849b895c242e0b12ac51d3eba3058f4c89428e70519c755dd0878` |
| `DPK-SCA-0001` | MEDIUM / CWE-1104 | `76536379fc02034af066af54c1db387d19a5d2e1705e77b9fa62cfc56ee9a7c3` |
| `DPK-SCA-0043` | MEDIUM / CWE-494 | `53358ab1816f818ee466646fc43c67007b6785a790f22412f8b00b62b833a370` |

প্রতিটি positive finding-এর rule ID, title, severity, CWE, location এবং scanner পরীক্ষা করা হয়েছে; Secrets confidence-ও মিলেছে। SAST/Secrets evidence নির্দিষ্ট withheld-source text; SCA evidence-এ শুধু rule ID ও values withheld; DAST evidence-এ endpoint ও check type, response value নয়। Synthetic marker source, SCA document এবং DAST mock cookie/body-তে দেওয়া হলেও পরীক্ষিত finding/detail, report, export ও logs-এ তা পাওয়া যায়নি। এটি সীমিত fixture-level redaction প্রমাণ, সব ধরনের secret শনাক্ত হওয়ার নিশ্চয়তা নয়।

- **JSON:** positive ও negative report-এর rule উপস্থিতি/অনুপস্থিতি, content digest এবং positive evidence/severity যাচাই।
- **Markdown:** পাঁচটি positive report-এ ID ও escaped evidence যাচাই।
- **PDF:** পাঁচটি positive report-এ PDF header, text-extracted ID, severity ও evidence যাচাই; bundled test decoder ব্যবহৃত, স্বাধীন PDF reader পরীক্ষা নয়। PDF-এ finding detail cap আছে।
- **SARIF:** পাঁচটি positive report-এ rule ID, severity-to-level ও title যাচাই; এই exporter finding-এর evidence field অন্তর্ভুক্ত করে না। তাই SARIF evidence preservation দাবি করা হচ্ছে না।

বিদ্যমান `mountedDatasetE2E.test.ts`-ও চালানো হয়েছে: উপরোক্ত চার ধরনের পাশাপাশি `DPK-SAST-044`, `DPK-SCA-0718`, `DPK-DAST-073` এবং একটি SAST negative উদাহরণ দেখেছে। `DPK-SAST-044`-এর AST `CATEGORY_REPORTER` attribution তার সুনির্দিষ্ট regex match-এর প্রমাণ নয়।

## ৫. SCA declared-test বনাম scan-path হিসাব

| Reader | Declared | Scan-path-এ matched expectation | Path-blocked | Renderer-এ unrenderable |
|---|---:|---:|---:|---:|
| JSON | ১,৭২৮ | ১,৭২৮ | ০ | ০ |
| TOML | ১,০১৬ | ১,০০৪ | ১২ | ০ |
| YAML | ৩৩২ | ২৭২ | ৬০ | ০ |
| Requirements | ১০৯ | ১০৯ | ০ | ০ |
| XML | ২৫৬ | ২৪৮ | ০ | ৮ |
| Gradle | ১০০ | ১০০ | ০ | ০ |
| Properties | ১২ | ১২ | ০ | ০ |
| INI | ২০৪ | ১১২ | ৯২ | ০ |
| Lockfile text | ২৪৪ | ২৪৪ | ০ | ০ |
| **মোট** | **৪,০০১** | **৩,৮২৯** | **১৬৪** | **৮** |

পরীক্ষায় verdict mismatch, reader parse failure ও unsupported-reader case ০; তবে **১৬৪ + ৮ = ১৭২ case pass হিসেবে ধরা হয়নি**। ৪১টি rule-এর artifact বর্তমান নিরাপত্তা path policy-তে uploadযোগ্য নয়; ফলে ১,০০০ compiled-এর মধ্যে সর্বোচ্চ **৯৫৯ potentially scan-reachable**। আটটি XML case (`DPK-SCA-0679`: ২, `DPK-SCA-0689`: ৩, `DPK-SCA-0753`: ৩) পরীক্ষার renderer-এর সীমায় unrenderable—বাস্তব সব XML অসম্ভব, এমন দাবি নয়। Reader-গুলো bounded subset; সব ভুল ব্যাখ্যা শনাক্ত নাও হতে পারে। Hidden-path বা upload policy শিথিল করা হয়নি।

## ৬. Negative পরীক্ষা এবং সংশোধিত integration defect

নিচের malformed/incompatible catalog-গুলো **শুধু আলাদা synthetic test fixture**, বাস্তব Dataset নয়। কোনো synthetic catalog-কে প্রকৃত Dataset হিসেবে গণনা করা হয়নি।

| অবস্থা | পর্যবেক্ষণ |
|---|---|
| Provider `none` | চার status `NOT_CONFIGURED`, startup warning; চার নির্বাচিত positive fixture-এ DPK finding অনুপস্থিত, চার scan partial; SCA `NOT_ASSESSED`। |
| `filesystem` কিন্তু path নেই / অজানা provider | Config validation প্রত্যাখ্যান করেছে। |
| ভুল path / permission-denied directory | Fresh service `UNAVAILABLE`, enumeration failure; ভুল path-এর HTTP SAST scan partial, rule count ০। `configured: true` কেবল configuration আছে বোঝায়। |
| Malformed JSON, unknown rule schema, unknown field, ভুল declared test, duplicate ID, symlink | Synthetic SAST-এ ৯ discovered file-এর ৪ accepted, ৫ rejected, ১ অতিরিক্ত enumeration failure; ২ declared test failed; accepted ৪ registered, scan partial। বাদ পড়া rule পাস নয়। |
| অনুপস্থিত family directory | `UNAVAILABLE`; ০ discovered এবং ১ enumeration failure—লুকানো file সংখ্যা অজানা। |
| Invalid manifest semver, wrong family, missing/unknown manifest schema | `manifestIssue`, pack `incomplete: true` ও identity withheld। Unknown schema-র পৃথক synthetic পরীক্ষায় চার scanner-ই partial; পৃথকভাবে বৈধ rule চলতে পারে। `AVAILABLE` অর্থ কিছু rule আছে, সম্পূর্ণ pack নয়। |
| Manifest সম্পূর্ণ অনুপস্থিত | বিদ্যমান compatibility অনুযায়ী optional; valid rule চালু থাকে, identity অনুপস্থিত। এটি trusted provenance নয়। |

**মূল কারণ ও fix:** আগে `parsePackManifest` শুধু `packId` এবং version-এর shape দেখত, manifest-এর family বা `schemaVersion` দেখত না। Synthetic `drobon.pack.sast/v9` manifest-সহ চারটি v1 rule থাকলে status `AVAILABLE`, manifest issue অনুপস্থিত এবং SAST scan non-partial ছিল। নতুন regression প্রথমে **৪ failed / ১ passed** দিয়ে সমস্যাটি reproduce করে। ন্যূনতম সংশোধনে service বর্তমান family অনুযায়ী manifest schema যাচাই করে; invalid identity প্রকাশ করে না, বিদ্যমান `manifestIssue` ও scanner partial ব্যবহার করে এবং pack status-এ বিদ্যমান `incomplete` flag দেখায়। প্রত্যাখ্যাত/অগণনীয় rule থাকলেও এই flag দেখায়। পুরোনো এক-argument identity helper এবং optional-absent manifest-এর আচরণ সংরক্ষিত; content version `1.0.0`-এ জোর করে pin করা হয়নি। **আচরণগত পরিবর্তন:** আগে গৃহীত, উপস্থিত কিন্তু schema-বিহীন manifest-এর identity এখন withheld ও pack partial; তার পৃথকভাবে বৈধ rule এখনও চলে। পরে সংশ্লিষ্ট ছয়টি নতুন regression test pass করেছে।

**Cache সীমা:** বাস্তব mirror unmount করার পর আগের service তার cache-এ ১,০০০ SAST rule ও পুরোনো `loadedAt` ধরে `AVAILABLE` দেখিয়েছে এবং cached rule দিয়েই synthetic finding তৈরি করেছে। একই path-এ নতুন service `UNAVAILABLE`, `incomplete: true`, enumeration failure দেখিয়েছে। অর্থাৎ status বর্তমানে mount পৌঁছানো যায় কি না তার live health check নয়; restart বা আলাদা পর্যবেক্ষণ প্রয়োজন। এ আচরণ গোপন না করতে এখানে খোলাখুলি জানানো হলো; cache architecture বদলানো হয়নি।

## ৭. পরীক্ষা, ব্যর্থতা ও সংরক্ষণ

- `npm run verify:dataset -- --path /tmp/drobon-dataset-readonly`: **PASS**, fix-এর পর পুনরায়।
- `node --import tsx scripts/verify-separate-dataset-http.mjs --path /tmp/drobon-dataset-readonly`: **PASS**, উপরের ১৫টি scan case; নির্বাচিত পাঁচ positive-এ চার format export।
- Mounted targeted API regression: **৬ file / ৪৩ test PASS**, mounted integration test-সহ।
- `DROBON_MOUNTED_DATASET_TEST_PATH=/tmp/drobon-dataset-readonly npm test`: **১৭৩ file / ১,৭৬১ test PASS**, failed/skipped ০। Shared ১৯/১৮৮; API ১২০/১,২৫৮; worker ৩/৩২; web ৩১/২৮৩।
- `npm run typecheck`, `npm run lint`, `npm run build`: **PASS**। Build-এ বিদ্যমান Vite chunk-size warning: ৫০৮.৩৭ kB। `check:secrets` ও তার self-test, `check:boundaries`, `check:repo-integrity`, release-evidence self-test এবং `git diff --check`: **PASS**।
- প্রথম DAST scratch mock Dataset-এর mixed-case header সরাসরি দিয়েছিল, কিন্তু production Node transport lowercase `IncomingHttpHeaders` দেয়; initial negative assertion ব্যর্থ হয়। Final পরীক্ষায় প্রকৃত loopback HTTP response/Node transport ব্যবহার করে সঠিক normalization যাচাই হয়েছে; production control দুর্বল করা হয়নি। প্রথম cache scratch-এ unsettled top-level await ও ভুল wrapper PID-এর কারণে পুনরায় চালাতে হয়েছে; সর্বশেষ বাস্তব unmount/cache check exit ০। একটি অস্থায়ী test-account literal প্রথম secrets check-এ flag হয়েছিল; সেটিকে স্পষ্ট synthetic test value হিসেবে চিহ্নিত করে পুনরায় pass করা হয়েছে, checker বদলানো হয়নি।
- `npm audit`, production mount/deploy, বাস্তব external target scan, paid/vendor scanner এবং independent human accuracy review **চালানো হয়নি**।
- শুরুর ২৩৭টি modified/untracked path-এর backup ও hash নেওয়া ছিল: ২৩৫ অপরিবর্তিত, কেবল প্রমাণিত fix-এর জন্য `external/conformance.ts` ও `external/service.ts` ইচ্ছাকৃতভাবে সম্পাদিত, কোনোটি হারায়নি। নতুন regression test, এই report এবং reproducible HTTP verification script যোগ হয়েছে। কোনো branch change, stage, commit বা push করা হয়নি।

## ৮. পুনরায় চালানো ও বাকি কাজ

প্রথমে operator-নিয়ন্ত্রিত, Main App-এর বাইরে থাকা read-only Dataset root প্রস্তুত করে স্বাধীনভাবে তার source/commit যাচাই করুন। নিচের script root-এ লেখে না, তবে নিজে mount `ro` কিনা নিশ্চিত করে না। এটি বর্তমানে উপরের নির্দিষ্ট ৪,০০৭-rule catalog-এর expectation নিয়ে চলে।

```sh
npm run verify:dataset -- --path /path/to/read-only/Drobon-Dataset
node --import tsx scripts/verify-separate-dataset-http.mjs --path /path/to/read-only/Drobon-Dataset
DROBON_MOUNTED_DATASET_TEST_PATH=/path/to/read-only/Drobon-Dataset \
  npm run test --workspace @drobon/api -- test/mountedDatasetE2E.test.ts test/datasetManifestSchemaIntegration.test.ts
```

Production চালুর আগে আলাদা production mount/permissions ও restart rehearsal, বিশ্বস্ত commit/identity verification এবং cache freshness monitoring যাচাই প্রয়োজন। SCA-র blocked/unrenderable case-এর নিরাপদ সমাধান ও bounded reader-এর coverage আলাদাভাবে মূল্যায়ন প্রয়োজন; নিরাপত্তা policy শিথিল করে সংখ্যা বাড়ানো উচিত নয়। এই report পূর্ণ নিরাপত্তা, বাস্তব-বিশ্ব accuracy বা production readiness-এর ঘোষণা নয়।
