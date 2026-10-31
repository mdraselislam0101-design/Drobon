# Drobon Dataset ইন্টিগ্রেশন: উন্নয়ন ও যাচাই রিপোর্ট

**তারিখ:** ৩০ অক্টোবর ২০২৬  
**Main App:** `arena/0056e643-drobon`, ভিত্তি commit `e763eb938d67d4163dca817716231794bb45e372`  
**Dataset:** `Drobon-Dataset`, নির্দিষ্ট commit `3986082b22007b47930da3bc99be9c2f2b036080`  
**অবস্থা:** Main App-এর পরিবর্তনগুলো uncommitted। Dataset ও Database repository পরিবর্তন করা হয়নি।

## সংক্ষিপ্ত ফল

Dataset-এ চার ধরনের মোট **৪,০০৭টি নিয়ম** পাওয়া গেছে। Loader-এর schema, mapping ও ঘোষিত পরীক্ষায় সব ৪,০০৭টি গ্রহণযোগ্য হয়েছে। এটি সব নিয়ম প্রতিটি বাস্তব প্রকল্পে চলবে বা সব vulnerability ধরবে—এমন প্রমাণ নয়।

| স্ক্যানার | নিয়ম | Loader গ্রহণ করেছে | বাস্তব engine/scan-layer পরীক্ষায় অবস্থা | বিশেষ সীমা |
|---|---:|---:|---|---|
| SAST | ১,০০০ | ১,০০০ | প্রতিটি নিয়মের একটি করে positive fixture-এ ১,০০০টি নিয়মই finding দিয়েছে | ঘোষিত comment-positive-এর একটি অংশ ইচ্ছাকৃতভাবে suppression; ভাষা ও syntax আংশিক বোঝে |
| Secrets | ১,০০০ | ১,০০০ | প্রতিটি নিয়মের একটি করে positive fixture-এ ১,০০০টি নিয়মই finding দিয়েছে | ৯৯৯ নিয়মের denylist আছে; placeholder ও অন্যান্য সীমা বাস্তব ফলকে প্রভাবিত করতে পারে |
| DAST | ১,০০৭ | ১,০০৭ | প্রতিটি নিয়মের একটি করে positive response fixture-এ ১,০০৭টি নিয়মই finding দিয়েছে | সব response ছিল mock; body/header/target সীমাবদ্ধ |
| SCA | ১,০০০ | ১,০০০ | ৯৫৯টি uploadযোগ্য artifact-এর নিয়ম; এর মধ্যে ৯৫৬টির সব raw-rendered fixture পাস | ৪১টি নিয়মের artifact path নিষিদ্ধ; আরও ৩টির অন্তত একটি fixture অবাস্তব/অপাঠ্য |

SCA-এর ৯৫৯ হলো **সম্ভাব্য scan-eligible** নিয়মের সংখ্যা, একই প্রকল্পে একসঙ্গে বাস্তবে চালানো নিয়মের সংখ্যা নয়। উল্লিখিত ৯৫৬ ও ৪৪-এর হিসাব: ৯৫৬টির সব fixture পাস; ৪৪টির অন্তত একটি fixture অসম্পূর্ণ—৪১টি পথের কারণে এবং অন্য ৩টি fixture উপস্থাপন/পড়ার কারণে। পরীক্ষায় অন্য fixture পাস করা অসম্পূর্ণ নিয়মও আছে।

## পরীক্ষার ধরন ও ফল

### ১. ঘোষিত document/line/response পরীক্ষা

| স্ক্যানার | ঘোষিত পরীক্ষা | Loader/evaluator-এ পাস | পার্থক্য |
|---|---:|---:|---:|
| SAST | ৪,০৪৩ | ৪,০৪৩ | ০ |
| Secrets | ৪,৬৬০ | ৪,৬৬০ | ০ |
| DAST | ৩,৬৭৩ | ৩,৬৭৩ | ০ |
| SCA | ৪,০০১ | ৪,০০১ | ০ |
| **মোট** | **১৬,৩৭৭** | **১৬,৩৭৭** | **০** |

এগুলো dataset-এর ঘোষিত line, parsed document ও response উদাহরণের সঙ্গে evaluator-এর মিল। এখানে SCA-র ৪,০০১টি আগে থেকেই parsed document; raw manifest পড়ার পরীক্ষা নয়। সুতরাং এই টেবিলকে বাস্তব detection accuracy বা শূন্য false positive/negative-এর দাবি হিসেবে ব্যবহার করা যাবে না।

### ২. Engine-এ প্রতি নিয়মের একটি positive উদাহরণ

Main App-এর আসল SAST, Secrets ও Active DAST engine ব্যবহার করে আলাদা ব্যাচে প্রতি নিয়মের একটি নির্বাচিত positive উদাহরণ চালানো হয়েছে:

- **SAST:** ১০০ ব্যাচে ১,০০০/১,০০০ নিয়মের নিজের representative source file-এ finding পাওয়া গেছে।
- **Secrets:** ১০০ ব্যাচে ১,০০০/১,০০০ নিয়মের নিজের representative source file-এ finding পাওয়া গেছে।
- **DAST:** ১১৩টি mock scan ও ১,১২০টি mock transport call-এ ১,০০৭/১,০০৭ নিয়মের নিজের representative response-এ finding পাওয়া গেছে। DNS resolver ও transport ছিল test double; কোনো বাহ্যিক target-এ request যায়নি।
- তিন ক্ষেত্রেই তৈরি finding/summary-এর shared guard-এ কোনো ব্যর্থতা বা পরীক্ষার ব্যাচে truncation পাওয়া যায়নি।

এই পরীক্ষা প্রতি নিয়মে **একটি positive fixture** পরীক্ষা করে। এটি সব negative fixture-এর engine-level পরীক্ষা, বাস্তব প্রকল্পে সফলতার হার বা exploitability নিশ্চিত করে না। আবার চালানোর read-only script: `node --import tsx scripts/verify-dataset-runtime.mjs --path /path/to/Drobon-Dataset`।

### ৩. SAST comment-context পার্থক্য

লাইন-ম্যাচার একা dataset-এর ৪,০৪৩টি পরীক্ষার সবগুলোর সঙ্গে মিলে। কিন্তু স্ক্যানের comment-mask অনুকরণ করলে ৩,৮৪৮টি মেলে এবং dataset-এর expected positive **১৯৫টি comment fixture** ইচ্ছাকৃতভাবে suppress হয়; এগুলো ১৯৫টি নিয়মে ছড়ানো। পরীক্ষায় অন্য কোনো expected-negative ভুল করে positive হয়নি। সক্রিয় কোডের vulnerability বোঝাতে comment-এর উদাহরণকে finding না করার জন্য এই পার্থক্য রাখা হয়েছে। Credential-সংক্রান্ত নিয়ম comment-এও চালানো হয়, কারণ সেখানে secret থাকলে সেটি গুরুত্বপূ্র্ণ। প্রতিটি SAST নিয়মের অন্তত একটি positive উদাহরণ উপরের engine পরীক্ষায় কাজ করেছে। Bounded comment lexer সব ভাষার পূর্ণ parser নয়।

### ৪. SCA raw-file pipeline

প্রতিটি ঘোষিত SCA document-কে সম্ভব হলে raw file-এ render করে source-path policy, আসল reader ও declaration scan-layer দিয়ে চালানো হয়েছে। Renderer ও reader—দুই অংশের সীমা ফলকে প্রভাবিত করে।

| ৪,০০১ fixture-এর অবস্থা | উন্নয়নের আগে | বর্তমান |
|---|---:|---:|
| প্রত্যাশিত verdict মিলেছে | ৩,৬৫৯ | ৩,৮৩৩ |
| Positive বেশি পাওয়া (fixture FP) | ১৮ | ০ |
| Positive পাওয়া যায়নি (fixture FN) | ১২৩ | ০ |
| Source-path policy-তে আটকে | ১৬৪ | ১৬৪ |
| বাস্তবসম্মত raw fixture তৈরি করা যায়নি | ১২ | ২ |
| তৈরি fixture parser পড়তে পারেনি | ২৫ | ২ |

বর্তমান ০ FP/FN শুধু **মূল্যায়িত fixture-গুলোর** verdict; ১৬৮টি অনির্ণীত/blocked fixture এর বাইরে। আগের তুলনায় renderer-ও সংশোধিত হয়েছে, তাই এটিকে স্বাধীন এক-এক accuracy benchmark বলা যাবে না।

- `DPK-SCA-0729` ও `DPK-SCA-0730`: একটি করে fixture-এ খালি pip option value; এই raw syntax গ্রহণযোগ্য ধরে নেওয়া হয়নি।
- `DPK-SCA-0753`: দুটি fixture-এ NuGet-এর normalized `sources` ও `packageSources.add` পরস্পর অসঙ্গত; মিথ্যা সমতুল্য XML বানানোর বদলে unrenderable গণনা করা হয়েছে।
- JSON, TOML, YAML, XML, INI, requirements, Gradle, properties ও lockfile-text reader আছে; JSON ছাড়া বাকিগুলো সম্পূর্ণ grammar parser নয়। অসমর্থিত syntax-এ under-detection বা ভুল absence judgement এখনও সম্ভব।
- Advisory provider-এর dataset-প্রদত্ত ১৬টি vector-এর ১৬টি মিলে; এটি বিশ্বব্যাপী advisory completeness প্রমাণ করে না।

### ৫. স্থায়ী regression ও offline যাচাই

- `npm test`: Shared **১৮৮**, API **১,০৩৯**, Worker **২৮**, Web **২৮২**—মোট **১,৫৩৭টি পাস**। এরপর যোগ করা fixture-renderer-এর আরও **২টি test** আলাদাভাবে পাস হয়েছে; নতুন পূর্ণ-suite count আলাদাভাবে অনুমান করা হয়নি।
- সম্পূর্ণ `npm run typecheck`, `npm run build`, এবং পরবর্তী `npm run lint` পাস। Web build-এ ৫০০ kB-এর বড় chunk নিয়ে warning আছে।
- মালফর্মড ফাইল, duplicate ID, অজানা ভাষা/DAST header, denylist, path containment, আংশিক coverage, Gradle/requirements syntax, DAST request cap, baseline ও authorization-সংক্রান্ত synthetic regression tests পাস।
- `scripts/verify-dataset.mjs` নির্দিষ্ট dataset-কে শুধু RAM-এ virtual filesystem হিসেবে পড়িয়ে চালানো হয়েছে: checks `PASS`, তবে SCA raw coverage **`PARTIAL`**। এই PASS সীমিত regression checks-এর, পূর্ণ coverage-এর নয়। Script-এ JSON fixture, blocked path, FP/FN, parse/render failure এবং বর্তমান branch এখন আলাদা দেখানো হয়।
- `npm audit`, কোনো paid security tool, third-party engine, external scanning service বা বাস্তব অননুমোদিত target scan চালানো হয়নি।

## এই পর্যায়ে করা পরিবর্তন

1. **Loader ও validator:** malformed JSON, duplicate ID, অজানা ভাষা, অচল DAST header/check, ভুল flag/regex এবং mapper-এ না যাওয়া নিয়ম হিসাব ও প্রত্যাখ্যান করা হয়। Directory enumeration ব্যর্থ হলে লুকানো ফাইলের অজানা সংখ্যা বানিয়ে না বলে আলাদা failure দেখায়। Symlink অনুসরণ করা হয় না। একসঙ্গে চলা load একই promise ব্যবহার করে।
2. **Partial coverage:** SAST, Secrets, DAST ও SCA-তে rejected বা load-অসম্পূর্ণ নিয়মকে partial হিসেবে দেখানো হয়; বাকি গ্রহণযোগ্য নিয়ম এখনও চলতে পারে। CI-তেও ব্যর্থতা স্পষ্ট থাকে।
3. **SAST ও Secrets:** নিষ্ক্রিয় code-comment-এর কিছু false positive কমানো, credential comment-এর detection রাখা, পুরো evidence crop করার আগে redaction, এবং Secrets denylist পুরো লাইনে প্রয়োগ করা হয়েছে। কয়েকটি template filename ও Blade ভাষা mapping উন্নত। সাধারণ redaction সর্বপ্রকার অজানা secret নিশ্চিতভাবে শনাক্ত করতে পারে না।
4. **DAST:** ব্যর্থ request-সহ transport attempt গণনা করে cap মানা, ব্যর্থ probe-কে partial দেখানো, অনুমোদন DNS/transport-এর আগে পরীক্ষা, বাস্তবে অনুসৃত redirect গণনা, bounded response ও একই endpoint-এর baseline-এর সঙ্গে active reflection তুলনা করা হয়েছে।
5. **SCA:** path-qualified artifact suffix matching-এর সঙ্গে বিদ্যমান hidden-path নিষেধ বজায় রাখা হয়েছে। TOML, YAML, requirements, NuGet/XML, Gradle, Go, Yarn, CocoaPods, Swift ও আরও কিছু bounded reader/fixture উন্নত করা হয়েছে। অসামঞ্জস্যপূর্ণ বা unsupported fixture-কে সাফল্য হিসেবে গণনা করা হয় না।

## ৪১টি path-নিষিদ্ধ SCA নিয়ম

Raw source server-এ সংরক্ষিত হয়; credential-bearing hidden file খুলে দিয়ে এই সংখ্যাকে কৃত্রিমভাবে কমানো হয়নি।

- `.npmrc` — ২১টি: `DPK-SCA-0073`–`DPK-SCA-0088`, `DPK-SCA-0789`, `DPK-SCA-0790`, `DPK-SCA-0791`, `DPK-SCA-0793`, `DPK-SCA-0794`।
- `.yarnrc.yml` — ১০টি: `DPK-SCA-0089`–`DPK-SCA-0094`, `DPK-SCA-0107`, `DPK-SCA-0795`, `DPK-SCA-0796`, `DPK-SCA-0797`।
- `.pypirc` — ২টি: `DPK-SCA-0142`, `DPK-SCA-0143`।
- `.yarnrc` — ১টি: `DPK-SCA-0651`।
- `.cargo/config.toml` — ৩টি: `DPK-SCA-0691`, `DPK-SCA-0760`, `DPK-SCA-0788`।
- `.Rprofile` — ১টি: `DPK-SCA-0777`।
- `.condarc` — ৩টি: `DPK-SCA-0778`, `DPK-SCA-0779`, `DPK-SCA-0978`।

## অবশিষ্ট সীমা ও প্রয়োজনীয় সিদ্ধান্ত

- কোনো dataset configure না করলে SAST/Secrets ও passive DAST-এর dataset rules ফাঁকা থাকে; SCA advisory assessment-ও `NOT_ASSESSED` হতে পারে। Operator-কে নিজস্ব read-only dataset path দিয়ে `VULN_INTEL_PROVIDER=filesystem` এবং `DATASET_PATH` configure করতে হবে। এই সেশনে কোনো dataset checkout তৈরি করা হয়নি।
- Active DAST-এ query-bearing URL বর্তমান target নিরাপত্তা policy-তে নিষিদ্ধ; default payload budget প্রথম marker-এ সীমিত। Authenticated crawling, সম্পূর্ণ browser/JS execution এবং পূর্ণ payload coverage নেই।
- SAST language aliases-এর একটি অংশ shared config family-তে পড়ে; ভাষাভিত্তিক scope মোটা হতে পারে। Regex ও bounded AST গভীর interprocedural analysis বা সম্পূর্ণ syntax বোঝে না। Secrets denylist পূর্ণ লাইনে প্রয়োগ হওয়ায় ওই লাইনে সত্যিকারের secret থাকলেও placeholder শব্দের কারণে সেটি চাপা পড়তে পারে।
- SCA reader-গুলো partial; hidden/credential path-এর নিরাপদ সমাধানের আগে upload বা persistence policy পরিবর্তন করা উচিত নয়। Dependency graph ও vulnerability intelligence সব ecosystem/version-এর পূর্ণ বাস্তব অবস্থা নয়।
- Dataset-এর ১০০টি non-fixture npm/PyPI advisory file-এ GHSA provenance আছে—৮৪টি deduplicated identity ও ৭৮টি advisory ID। এগুলো ব্যবহারকারীর নিজস্ব dataset-এর ভেতরেই পড়া হয়েছে; GHSA endpoint বা অন্য dataset আনা হয়নি। বাইরের উৎস-উৎপন্ন তথ্যও নিষিদ্ধ হলে এই advisory ব্যবহার সম্পর্কে আলাদা সিদ্ধান্ত প্রয়োজন।
- Dataset-এ ৪,০০৭ remediation, ১০২ CWE, ৬ lesson, ৩ assessment ও ২ engagement template পাওয়া গেছে; চারটি remediation নমুনা UI guidance lookup-এ যাচাই হয়েছে। সব knowledge category-র production ব্যবহার বা সব lesson workflow এই কাজ দিয়ে সম্পূর্ণ প্রমাণিত নয়।

**Git:** কোনো commit, push, merge, reset বা revert করা হয়নি। স্টেজ করা পরিবর্তন নেই; Main App-এর পরিবর্তন ও এই রিপোর্ট working tree-তে আছে।
