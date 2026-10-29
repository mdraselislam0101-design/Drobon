# Drobon অ্যাপ: ইঞ্জিন, ব্যবহার ও বর্তমান সীমার বিস্তারিত বাংলা গাইড

**কোড যাচাইয়ের তারিখ:** ২৮ অক্টোবর ২০২৬  
**কোন সংস্করণ সম্পর্কে:** মেইন অ্যাপ `Drobon`-এর এই ব্রাঞ্চে বর্তমানে থাকা কোড, আগের অসম্পন্ন-কমিটসহ। কোনো চালু সার্ভার বা অন্য কারও ওয়েবসাইট এই রিপোর্ট তৈরির জন্য স্ক্যান করা হয়নি। বাস্তবে ডিপ্লয় করা সংস্করণ, সেটিংস ও ডেটাসেট আলাদা হলে ফলও আলাদা হতে পারে।

> **প্রথমে সবচেয়ে জরুরি কথা:** Drobon সম্ভাব্য নিরাপত্তা সমস্যা খুঁজে দেখার ও তার প্রমাণ গুছিয়ে রাখার টুল। কোনো স্বয়ংক্রিয় টুল সব বাগ খুঁজতে পারে না। `0 findings`, `COMPLETED` বা কোনো স্ক্যান রিপোর্ট দিয়ে কোনো অ্যাপ বা ওয়েবসাইটকে ১০০% নিরাপদ বলা যায় না। অন্যের সাইটে পরীক্ষা করার আগে প্রকৃত মালিকের লিখিত অনুমতি ও নির্দিষ্ট scope নিতে হবে।

---

## ১. এক নজরে: অ্যাপটি কী করে?

সহজ ভাষায় কাজের ধাপটি হলো:

```text
অ্যাকাউন্ট → নিজের Project → প্রয়োজনীয় ফাইল অথবা অনুমতিপ্রাপ্ত URL
           → একটি স্ক্যানের ধরন বাছাই → স্ক্যান সম্পন্ন হওয়ার অপেক্ষা
           → Findings ও সীমা দেখা → প্রয়োজনীয় সংশোধন → একই ধরনে আবার স্ক্যান
           → রিপোর্ট তৈরি ও প্রয়োজনে শেয়ার
```

অ্যাপে **চারটি মূল স্ক্যান ইঞ্জিন** আছে। প্রতিবার একটি স্ক্যান শুরু করলে এদের মধ্যে একটি ধরন চলে; চারটি একসঙ্গে একটি স্ক্যান হিসেবে চলে না।

| মূল ইঞ্জিন | ইনপুট | সহজ কাজ | কী পাওয়া যেতে পারে |
|---|---|---|---|
| **SAST** | আপলোড করা source code | অ্যাপ না চালিয়ে কোডের সন্দেহজনক প্যাটার্ন ও সীমিত তথ্যপ্রবাহ দেখা | নিয়ম-সমর্থিত code finding, অবস্থান, evidence, remediation |
| **SCA** | আপলোড করা dependency manifest ও lockfile | কোন কোন library/package ঘোষণা আছে তার inventory ও সীমিত নিয়ম/অ্যাডভাইজরি মিলানো | dependency তালিকা, সীমিত SBOM, প্রযোজ্য নিয়ম বা advisory |
| **SECRETS** | আপলোড করা সমর্থিত text/code ফাইল | কোডে key, token বা password-এর মতো দেখতে তথ্য খোঁজা | masked/redacted finding ও তার অবস্থান |
| **DAST** | অনুমতিপ্রাপ্ত ও নিরাপত্তা-নীতিতে গ্রহণযোগ্য HTTP(S) URL | সীমিত HTTP request-এর response পরীক্ষা | response observation ও প্রয়োগযোগ্য rule-এর finding |

এর পাশাপাশি আছে কয়েকটি সহায়ক ব্যবস্থা:

| সহায়ক ব্যবস্থা | এর কাজ | আলাদা পঞ্চম স্ক্যান কি? |
|---|---|---|
| **AST analysis** | কোডের গঠন ও কিছু সীমিত source-to-sink প্রবাহ বুঝতে scanner-কে সাহায্য করে | না |
| **Advisory matching** | কনফিগার করা advisory pack-এর সঙ্গে দৃশ্যমান version সংকেত মেলাতে পারে | না |
| **SOC-style overview** | সেভ করা স্ক্যান ও coverage gap দেখে অগ্রাধিকারের সংকেত দেখায় | না |
| **SAC coverage ledger** | একটি রিপোর্টে কী চলেছে/আংশিক হয়েছে/চলেনি তা জানায় | না |
| **Security Assistant** | নিজের সংরক্ষিত evidence থেকে নির্দিষ্ট প্রশ্নের সীমিত উত্তর দেয় | না |
| **Report ও SBOM** | সম্পন্ন স্ক্যানের ফল নির্দিষ্ট ফরম্যাটে সাজায় | না |

**ইঞ্জিন বনাম ডেটাসেট:** ইঞ্জিন হলো কাজ করার পদ্ধতি; ডেটাসেট হলো ইঞ্জিনের ব্যবহারযোগ্য rules, knowledge বা advisory-এর বাহ্যিক উৎস। ইঞ্জিন থাকা মানেই সব rules, সর্বশেষ CVE বা সব ভাষার coverage স্বয়ংক্রিয়ভাবে উপস্থিত নয়।

---

## ২. SAST — সোর্স কোডে সম্ভাব্য সমস্যা খোঁজা

### SAST কীভাবে কাজ করে?

SAST মানে **Static Application Security Testing**। আপনি যে অনুমতিপ্রাপ্ত text source files আপলোড করবেন, Drobon সেগুলো না চালিয়েই পড়বে। কনফিগার করা প্রযোজ্য rules এবং সীমিত AST বিশ্লেষণ দিয়ে কিছু সন্দেহজনক গঠন বা তথ্যপ্রবাহ শনাক্ত করার চেষ্টা করবে।

উদাহরণ হিসেবে, উপযুক্ত rule থাকলে অ্যাপ নিম্ন ধরনের বিষয় review-এর জন্য দেখাতে পারে:

- ব্যবহারকারীর ইনপুট থেকে তৈরি সন্দেহজনক SQL query বা command-এর গঠন;
- অনিরাপদ code evaluation বা HTML output-এর কিছু প্যাটার্ন;
- নির্দিষ্ট configuration বা অন্যান্য rule-এ বর্ণিত দুর্বলতার ইঙ্গিত।

এগুলো **উদাহরণ**, গ্যারান্টিযুক্ত শনাক্তকরণের তালিকা নয়। কোন বিষয় পাওয়া যাবে তা আপলোড করা ফাইল, সমর্থিত বিশ্লেষণ, কার্যকর rule pack এবং code shape-এর ওপর নির্ভর করে।

### কী ফল দেখতে পাবেন?

Finding তৈরি হলে সাধারণত rule ID, শিরোনাম, severity, file/line/column, সংক্ষিপ্ত evidence, scanner-provided remediation এবং থাকলে CWE দেখতে পাবেন। কিছু finding-এ AST source-to-sink context-ও থাকবে।

### সীমা

1. যে ফাইল আপলোড করেননি, SAST সেটি নিজে GitHub বা সার্ভার থেকে নিয়ে পড়ে না।
2. আপলোড করা কোড **চালানো বা install করা হয় না**। ফলে runtime behaviour, সব environment ও business logic বোঝা যায় না।
3. সমর্থিত গঠনেও ভুল সতর্কতা বা বাদ পড়া সমস্যা থাকতে পারে। কিছু legacy lexical matching comment/string-এও মিল পেতে পারে।
4. ডিফল্টে মেইন অ্যাপের embedded SAST rule list খালি; প্রযোজ্য বহিরাগত dataset না থাকলে SAST-এর ফল `0 findings` হওয়া বাস্তব সম্ভাবনা—এটি নিরাপত্তার প্রমাণ নয়।

---

## ৩. SECRETS — কোডে ফাঁস হওয়া গোপন তথ্যের ইঙ্গিত

এই ইঞ্জিন আপলোড করা সমর্থিত text/code ফাইলের মধ্যে configured rules অনুযায়ী token, API key, password বা অন্য credential-এর মতো প্যাটার্ন খোঁজে।

**উদাহরণ:** আপনার নিজের একটি JavaScript ফাইলে ভুল করে একটি API key লেখা থাকলে উপযুক্ত rule তার অবস্থান ও masked evidence দেখাতে পারে। এটি কেবল উদাহরণ; সব ধরনের key যে পাওয়া যাবে তার নিশ্চয়তা নেই।

- Finding-এর প্রমাণে শনাক্ত secret value mask/redact করার ব্যবস্থা আছে।
- ইঞ্জিন secret নিয়ে কোনো provider-এ লগইন করে দেখে না; key বাস্তবে চালু কি না তাও যাচাই করে না।
- `.env`, অন্যান্য dotfile ও `.pem`, `.key`-সহ নিষিদ্ধ key-file ধরনের ফাইল source snapshot হিসেবে আপলোড করা যায় না।
- ডিফল্ট embedded Secrets rules খালি। বহিরাগত উপযুক্ত rule pack ছাড়া `0 findings` দেখে কিছুই ফাঁস হয়নি বলা যাবে না।
- সত্যি secret প্রকাশিত হয়ে থাকলে মালিককে জানিয়ে সেটি revoke/rotate, access review এবং প্রয়োজনমতো source/history পরিষ্কারের ব্যবস্থা করতে হবে। শুধু finding-এর status বদলালেই secret নিরাপদ হয়ে যায় না।

**খুব গুরুত্বপূর্ণ গোপনীয়তার সীমা:** finding-এর evidence masked হলেও আপলোড করা **মূল source snapshot সার্ভারের source store-এ text content হিসেবে থাকে**। কোডের ভেতরে প্রকৃত secret থাকলে সেটিও সেই snapshot-এ থাকতে পারে। তাই তৃতীয় পক্ষের কোড/secret আপলোডের আগে অনুমতি নিন, সার্ভার ও backup-এর access সুরক্ষিত রাখুন, এবং redacted finding-কে পুরো সংরক্ষিত source encrypted বা secret-free হওয়ার নিশ্চয়তা ভাববেন না। API থেকে snapshot পড়লে সাধারণত content নয়, metadata ফেরত আসে—তবু সার্ভারে content সংরক্ষিত থাকে।

---

## ৪. SCA — dependency, SBOM ও advisory

SCA মানে **Software Composition Analysis**। এটি আপনার source snapshot-এ থাকা package declaration/manifest পড়ে। প্যাকেজ ইনস্টল করে না এবং manifest-এর script চালায় না।

### ৪.১ Dependency inventory কী?

অ্যাপ কোন package কোথায় ঘোষণা হয়েছে, version declaration কী, এবং যথেষ্ট lockfile তথ্য থাকলে কোথায় resolved version বা transitive dependency আছে—তার একটি সীমিত তালিকা তৈরি করে। প্রধান inventory parser-গুলোর ফাইল:

- `package.json` ও `package-lock.json` — npm;
- `requirements.txt` ও `pyproject.toml` — Python/PyPI।

সব manifest, lockfile, ecosystem বা version syntax একই গভীরতায় বোঝে না। বিশেষত lockfile evidence ছাড়া পুরো transitive dependency graph আছে বলে দাবি করা যায় না। একটি স্ক্যানে সর্বোচ্চ ৫০টি manifest ও সর্বোচ্চ ২০০টি persisted dependency-এর মতো সীমা আছে; truncation/status দেখুন।

### ৪.২ SBOM কী?

**Software Bill of Materials** হলো ব্যবহৃত সফটওয়্যার উপাদানের তালিকা। SCA স্ক্যান থেকে Drobon **CycloneDX 1.5 JSON-এর একটি সীমিত subset** তৈরি ও ডাউনলোড করতে পারে। এতে snapshot-এ প্রমাণিত উপাদান থাকে; পুরো deployment, সব image, license, supplier বা সব transitive dependency আছে—এমন নিশ্চয়তা নয়।

### ৪.৩ Vulnerability advisory আর declaration rule এক জিনিস নয়

- **Inventory:** কী কী package/declaration দেখা গেছে।
- **Vulnerability-intelligence provider:** বাহ্যিক dataset-এ উপস্থিত তথ্যের সঙ্গে সমর্থিত npm/PyPI package/version মেলানোর চেষ্টা।
- **Declaration rules:** কনফিগার করা rules দিয়ে কিছু manifest/config declaration-এর শর্ত পরীক্ষা। নয়টি bounded reader kind আছে—JSON, TOML, YAML, XML, INI, properties, requirements, Gradle ও lockfile text। এগুলো সংশ্লিষ্ট format-এর পূর্ণ grammar বোঝে না; non-JSON reader-ভিত্তিক পরীক্ষা partial হতে পারে এবং ভুল verdict-ও সম্ভব। Dotfile upload নিষিদ্ধ হওয়ায় কিছু artifact এই পথে পৌঁছায়ই না।
- **স্বতন্ত্র generic advisory pack:** আলাদা `ADVISORY_PATH` দিয়ে কিছু দৃশ্যমান version signal মেলানো যায়। এটি নিচের dependency-intelligence status-এর সমতুল্য নয়।

SCA-তে `NOT_ASSESSED` মানে **দুর্বলতা নেই নয়**। Provider data অনুপস্থিত, অপ্রাপ্য বা কোনো যাচাইকৃত মিল না থাকলেও বর্তমান কোড `NOT_ASSESSED` দেখাতে পারে। আলাদা generic advisory finding থাকলেও dependency-intelligence status স্বয়ংক্রিয়ভাবে `ASSESSED` হয় না। পুরোনো UI বার্তা কখনো কারণটিকে শুধু dataset unavailable বলে সরল করতে পারে; প্রকৃত provider ও dataset status-ও দেখুন।

**বাস্তব ব্যবহার:** package ও version দেখে সংশ্লিষ্ট নির্মাতা/official advisory যাচাই করুন, পরীক্ষিত compatible সংস্করণে পরিবর্তন করুন, প্রয়োজনীয় lockfile আপডেট করে source snapshot আবার আপলোড করুন এবং SCA পুনরায় চালান। Inventory বা SBOM নিজে দুর্বলতা আছে/নেই তার রায় নয়।

---

## ৫. DAST — অনুমতিপ্রাপ্ত ওয়েবসাইটের সীমিত HTTP পর্যবেক্ষণ

DAST মানে **Dynamic Application Security Testing**। Source code না থাকলেও নির্দিষ্ট public HTTP(S) target থেকে পাওয়া সীমিত response পরীক্ষা করা যায়। একটি project-এ একটি configured target URL থাকে।

### ৫.১ দুইটি mode

| Mode | বর্তমান আচরণ | সীমা |
|---|---|---|
| **PASSIVE** | বাছাই করা URL-এ bounded GET request, response/header পর্যবেক্ষণ এবং configured rule প্রয়োগ | মোট সর্বোচ্চ ৩ request, redirect-সহ; crawl বা injection নয় |
| **ACTIVE_SAFE** | সম্মতি নিয়ে সীমিত same-host static link crawl ও bounded path-based marker probe চেষ্টা | মোট সর্বোচ্চ ২০ request; সর্বোচ্চ ১০টি link ও ১০টি probe চেষ্টা, ২০০ ms throttle; বাস্তবে কম হতে পারে |

দুই ক্ষেত্রেই ফল response/প্রমাণভিত্তিক পর্যবেক্ষণ; reflection দেখা মানেই ব্যবহারযোগ্য exploit প্রমাণ নয়, আর reflection না দেখাও নিরাপত্তার প্রমাণ নয়। `ACTIVE_SAFE` নাম থাকলেও **GET request-এরও বাস্তব সিস্টেমে side effect থাকতে পারে**। তাই এটি কেবল স্পষ্ট লিখিত অনুমতি, সম্মত scope ও সময়ের মধ্যে ব্যবহার করুন।

### ৫.২ URL ও coverage-এর সীমা

- কেবল নিরাপত্তা-নীতিতে গ্রহণযোগ্য public HTTP(S) destination; local/private/reserved ঠিকানা এবং অনিরাপদ DNS/redirect প্রতিরোধ করা হয়।
- URL-এ credentials, query string, fragment বা custom port গ্রহণ করা হয় না।
- বর্তমান target policy query-যুক্ত crawl link ও query-parameter probe-ও ব্লক করে। বাদ পড়লে ফল `PARTIAL` হতে পারে। অনুমোদিত same-host path marker probe সম্ভব হলেও পূর্ণ active testing নয়।
- Browser চালানো, JavaScript execute করা, লগইন করা, authenticated pages পরীক্ষা, broad fuzzing, সব API বা business logic দেখা, এবং exploitability প্রমাণ করা এই ব্যবস্থার কাজ নয়।
- Baseline-এ আগেই পাওয়া inline script/direct JavaScript-এর কিছু static AST analysis হতে পারে; এটি নতুন external script fetch বা browser execution করে না।
- Passive observation-এর সাধারণ DAST rules বাহ্যিক pack-এর ওপর নির্ভরশীল; generic advisory matching কনফিগার থাকলে passive response-এ কাজ করতে পারে। Active mode-এ সীমিত marker-observation কোডও আছে, কিন্তু generic advisory matching-এর একই পথ সেখানে ধরে নেওয়া যাবে না।

### ৫.৩ অনুমতি সম্পর্কে সর্বাধিক গুরুত্বপূর্ণ কথা

Project নিজের হওয়া মানে target website আপনার নয়। Drobon URL-এর কারিগরি নিরাপত্তা এবং কিছু declaration/scope পরীক্ষা করলেও **সাইটের মালিক সত্যিই অনুমতি দিয়েছেন কি না স্বাধীনভাবে আইনগতভাবে যাচাই করে না**। অনুমতি ছাড়া passive বা active কোনো request পাঠানো উচিত নয়। বিস্তারিত assessment/engagement ব্যবস্থা ১১ নম্বর অংশে আছে।

---

## ৬. AST — সহায়ক বিশ্লেষণ, আলাদা scanner নয়

AST মানে **Abstract Syntax Tree**: প্রোগ্রামের লেখা নিয়মমাফিক ভাগ করলে যে গঠন পাওয়া যায়। খুব সহজ উদাহরণ:

```text
ব্যবহারকারীর ইনপুট → কোনো variable/function → database, command বা HTML sink
```

সন্দেহজনক flow পাওয়া গেলে এটি মানুষকে কোথায় যাচাই করতে হবে তা বুঝতে সাহায্য করে। গঠন বা flow পাওয়া মানেই ব্যবহারযোগ্য vulnerability নিশ্চিত নয়।

### বর্তমানে কোন জায়গায় AST ব্যবহার হচ্ছে?

1. **SAST:** JavaScript/TypeScript/JSX/TSX, Python, PHP ও Java-তে সীমিত structured parsing। JS/TS-এ local named function ও relative named import-এর কিছু cross-file flow দেখা হয়। Python/PHP/Java flow প্রধানত intra-file। সব ভাষা, dynamic import, arbitrary call graph, type/control flow বা sanitizer পূর্ণভাবে বিশ্লেষণ করা হয় না। অন্য কিছু ভাষায় কেবল rule/pattern বা অগভীর বিশ্লেষণ থাকতে পারে।
2. **DAST:** ইতোমধ্যে পাওয়া baseline HTML-এর inline script বা সরাসরি পাওয়া JavaScript-এর সীমিত static বিশ্লেষণ। Browser বা নতুন external fetch নেই।
3. **SECRETS:** আগে থেকেই পাওয়া redacted finding-এর literal context ব্যাখ্যা করার সীমিত সহায়তা; এটি নিজে অতিরিক্ত secret-discovery engine নয়।
4. **SCA:** `package.json`-এর syntactic dependency entry গোনার সীমিত সহায়তা; এটি dependency নিরাপদ কি না তার সিদ্ধান্ত নয়।

AST-এ `RAN`, `PARTIAL`, `NOT_APPLICABLE` বা কোথাও coverage অজানা থাকতে পারে। `RAN` মানে সীমিত অংশটি চলেছে; পুরো অ্যাপ বা সব rule পরীক্ষা হয়েছে—তা নয়। কিছু SAST AST finding একটি সম্ভাব্য flow-কে rule-এর **category** অনুযায়ী যুক্ত করে; rule-এর আসল pattern হুবহু মিলেছে বা exploit প্রমাণ হয়েছে—এমন নয়। Missing rule, skipped file, parse error ও partial coverage খেয়াল করুন।

---

## ৭. ডেটাসেট ও Advisory: কাজ করার জন্য কী কনফিগার করতে হয়?

### ৭.১ কেন এটি গুরুত্বপূর্ণ?

বর্তমান মূল অ্যাপে ডিফল্ট `VULN_INTEL_PROVIDER=none`। Production SAST ও Secrets-এর embedded rule list এবং পুরোনো passive DAST rule list খালি। External dataset না থাকলে এসব rule-নির্ভর শনাক্তকরণ সীমিত বা অনুপস্থিত হতে পারে। SCA তবুও inventory/SBOM তৈরি করতে পারে, কিন্তু vulnerability intelligence `NOT_ASSESSED` হতে পারে। Learning lessons-ও dataset ছাড়া খালি।

**শুধু engine আছে বলে ১,০০০টি rule, সব CVE বা বর্তমান data চালু আছে ধরে নেবেন না।** গ্রহণযোগ্য rule-এর সংখ্যা pack, schema, validation, পাঠযোগ্য ফাইল, version ও কনফিগারেশনের ওপর নির্ভর করে। আগে করা historical fixture পরীক্ষা বর্তমান production dataset-এর প্রমাণ নয়।

### ৭.২ Operator-এর জন্য কনফিগার করার উদাহরণ

আপনার সার্ভার/ডেভেলপমেন্ট পরিবেশে আগে থেকেই নিরাপদ ও উপযুক্ত dataset থাকলে, তার আসল filesystem path দিয়ে API process শুরু করতে হবে। নিচের path কেবল placeholder:

```bash
VULN_INTEL_PROVIDER=filesystem \
DATASET_PATH=/absolute/path/to/existing/verified-dataset \
npm run dev
```

আলাদা generic advisory pack ব্যবহার করলে operator `ADVISORY_PATH`-এ বিদ্যমান, উপযুক্ত JSON pack-এর বাস্তব path সেট করেন। সেটি dataset provider থেকে স্বতন্ত্র। ভুল path/schema, rejected rules বা পুরোনো data থাকলে coverage কমে। অ্যাপ নিজে internet থেকে নতুন advisory feed সংগ্রহ/refresh করে না; operator-কে উৎস যাচাই ও update করতে হয়। Version signal match মানেই সেই সফটওয়্যার সত্যিই ইনস্টল বা exploitable—এমন নয়।

**কনফিগ নোট:** `npm run dev` child process-এ shell environment পাঠায়; শুধু `.env` নামে ফাইল তৈরি করলেই API সেটি স্বয়ংক্রিয়ভাবে পড়বে—এমন ধরে নেবেন না। ডেভ সার্ভার production deployment নয়। প্রয়োজন হলে operator নিরাপদ server environment দিয়ে process restart করবেন।

### ৭.৩ কিভাবে status দেখবেন?

লগইন থাকা অবস্থায় একই অ্যাপ-origin-এ বা authenticated API client দিয়ে:

- `GET /api/v1/dataset/status` — dataset ও বিভিন্ন category-এর availability, count এবং conformance তথ্য;
- `GET /api/v1/advisory/status` — আলাদা advisory pack-এর অবস্থা ও stale কি না;
- Project-এর **Security operations overview → Load operations snapshot** — বর্তমান dataset/advisory status-এর সংক্ষিপ্ত দৃশ্য।

Status-এ `NOT_CONFIGURED`, `UNAVAILABLE` বা `STALE` এলে সংশ্লিষ্ট অপারেটরকে জানান। `AVAILABLE` দেখালেও সেটি সব প্রয়োজনীয় rule, সর্বশেষ advisory বা পূর্ণ coverage নিশ্চিত করে না।

---

## ৮. Source snapshot: কীভাবে ফাইল দেবেন এবং কী সীমা আছে?

Project page-এর **Source snapshot** অংশে SAST, SCA ও SECRETS-এর জন্য text file দেওয়া হয়।

### বর্তমান সীমা

- এক snapshot-এ সর্বোচ্চ **২০০টি ফাইল**;
- প্রতি ফাইল সর্বোচ্চ **২৫৬ KiB**;
- সব ফাইল মিলিয়ে সর্বোচ্চ **৭৬৮ KiB**;
- শুধু বৈধ text content এবং নিরাপদ relative path; binary, path traversal, dotfile segment ও key-file extension নিষিদ্ধ;
- প্রতিটি scan সর্বোচ্চ **২০০ finding** সংরক্ষণ করতে পারে; limit/timeout-এর কারণে ফল partial/truncated হতে পারে।

### নতুন ব্যবহারকারীর জন্য সবচেয়ে জরুরি বিষয়

1. File picker-এ একসঙ্গে প্রয়োজনীয় ফাইল বাছুন। একটি নতুন upload **আগের পুরো snapshot বদলে দেয়**, আগের ফাইলের সঙ্গে যোগ করে না।
2. বর্তমান browser file picker কেবল ফাইলের **নাম** ব্যবহার করে, আসল directory structure ধরে রাখে না। একই নামের দুই ফাইল সমস্যা করতে পারে; relative import-নির্ভর cross-file AST analysis-ও সীমিত হয়ে যেতে পারে।
3. **Or paste a text file (relative path)** দিয়ে একটি ফাইল path/content দেওয়া যায়, কিন্তু সেটিও পুরো snapshot বদলায়। একের পর এক paste করলে সব ফাইল জমা হয় না।
4. Authenticated source API এক অনুরোধে একাধিক valid relative path/content নিতে পারে; hierarchy ধরে রাখতে প্রযুক্তিগত ব্যবহারকারী এটিই ব্যবহার করতে পারেন। API/নিরাপত্তা নীতি বদলানো ছাড়াই কাজ করতে হবে।
5. বর্তমান UI-তে পুরো Git repository, folder tree বা ZIP auto-import করার সুবিধা ধরে নেওয়া যাবে না।

অনুমতিপ্রাপ্ত প্রয়োজনীয় অংশ বেছে দিন। বড় application-এর সব code এক snapshot-এ না ধরলে কী বাদ গেছে তা রিপোর্টে লিখুন; আলাদা স্ক্যানে আলাদা snapshot ব্যবহার করলে প্রতিটির সীমা ও তুলনার অর্থ সতর্কভাবে বুঝুন।

---

## ৯. প্রথমবার ব্যবহার: ধাপে ধাপে

### ধাপ ১ — অ্যাকাউন্ট তৈরি বা লগইন

1. **Create your account / Register** থেকে email ও password দিয়ে অ্যাকাউন্ট খুলুন অথবা লগইন করুন।
2. চাইলে Developer, Student, Security Professional বা Pentester classification বাছুন। পরে **Your account → Workspace classification → Save classification** থেকে বদলানো যায়।
3. এটি শুধু dashboard ও নির্দেশনার ধরন বদলায়; অ্যাডমিন ক্ষমতা, অন্যের project access, plan বা quota দেয় না।

### ধাপ ২ — Rules/data আছে কি না দেখুন

Operator-এর মাধ্যমে ৭ নম্বর অংশের dataset/advisory status যাচাই করুন। ডেটা অনুপস্থিত থাকলে প্রথমে সেটি বুঝে নিন; নইলে rule-dependent scan-এ `0 findings` দেখে ভুল ধারণা হতে পারে।

### ধাপ ৩ — Project তৈরি

1. **Projects** খুলুন।
2. Project name লিখুন; চাইলে description দিন।
3. **Create project** করুন এবং তালিকা থেকে নিজের project খুলুন।
4. Project `ACTIVE` থাকতে হবে। Archived project-এ নতুন source বা scan শুরু করা যায় না; প্রয়োজনে unarchive করতে হবে।

### ধাপ ৪ — প্রয়োজনে scope/assessment নথিভুক্ত করুন

আপনি Security Professional বা Pentester workspace-এ থাকলে project-এর **Structured security assessments** অংশে উদ্দেশ্য, নির্দিষ্ট in-scope hostname, out-of-scope hostname ও boundary লিখে assessment তৈরি ও শুরু করতে পারেন। এটি অনুমতির প্রমাণ নয়; বাস্তব লিখিত অনুমতি আলাদা রাখতে হবে। Engagement-এর সীমা ১১ নম্বর অংশে দেখুন।

### ধাপ ৫ — Source দিন

**Source snapshot → Source files (text only)** থেকে প্রয়োজনীয় ফাইল একসঙ্গে নির্বাচন করুন, অথবা একটি text file paste করুন। আপলোডের পর metadata-তে কত ফাইল/কত byte আছে দেখুন। নতুন আপলোড পুরোনো snapshot পুরো বদলায়—এটি আবার মনে রাখুন।

### ধাপ ৬ — একটি scan চালান

1. **Security scans → Scan type** থেকে `SAST`, `SCA` অথবা `SECRETS` নির্বাচন করুন।
2. প্রয়োজন হলে active assessment link নির্বাচন করুন, শর্ত প্রযোজ্য হলে।
3. **Request scan** চাপুন।
4. `QUEUED`/`RUNNING` হলে অপেক্ষা করে **Refresh scans** চাপুন।
5. `COMPLETED` হলে summary, finding, `PARTIAL`/`truncated`, skipped files এবং coverage দেখুন। `FAILED`/`TIMED_OUT` হলে failure message দেখুন; সেটি সফল assessment নয়।
6. অন্য ধরন পরীক্ষা করতে আবার আলাদা স্ক্যান শুরু করতে হবে। প্রতিটি স্ক্যান প্রচলিত plan quota-এর আওতায় পড়ে।

### ধাপ ৭ — অনুমতি থাকলে DAST

1. আগে target মালিকের সঙ্গে লিখিত অনুমতি, নির্দিষ্ট host/path, সময় ও permitted mode ঠিক করুন।
2. Project-এর **Passive DAST target → Project target URL**-এ বাস্তবে অনুমতিপ্রাপ্ত URL লিখে **Save target** করুন। `https://example.org/`-এর মতো UI placeholder প্রকৃত অনুমতি নয়; নিজের বাস্তব অনুমতিপ্রাপ্ত target দিন।
3. **Security scans → Scan type → DAST** বাছুন। প্রথমে সীমিত **Passive** mode বোঝা সহজ।
4. Active testing চুক্তিতে অনুমোদিত হলে এবং ঝুঁকি বুঝলে তবেই **Active Safe** নির্বাচন করে consent checkbox দিন।
5. **Request scan** চাপুন। ফলের request/response, coverage ও partial reason দেখুন। Query URLs, লগইন বা browser পরীক্ষা হয়েছে ধরে নেবেন না।

### ধাপ ৮ — Findings বুঝুন ও কাজ করুন

1. সম্পন্ন scan-এর **Finding details** খুলুন। Severity, rule, file/endpoint, evidence, guidance ও সীমা পড়ুন।
2. প্রাসঙ্গিক ব্যক্তির মাধ্যমে finding সত্যি কি না যাচাই করুন; প্রয়োজনমতো `ACKNOWLEDGED` বা `IN_PROGRESS` দিন এবং নিরাপদ সংক্ষিপ্ত note লিখুন। Note-এ password/key লিখবেন না।
3. বাস্তব পরিবর্তন নিজের code বা target system-এ করুন; Drobon স্বয়ংক্রিয়ভাবে code পরিবর্তন বা deploy করে না।
4. ফাইলভিত্তিক scan হলে সংশোধিত **সম্পূর্ণ প্রয়োজনীয় snapshot** আবার আপলোড করুন; পরে একই scanner দিয়ে নতুন scan চালান।
5. একই project-এর একই scan type-এর দুইটি completed scan থাকলে **Regression compare → Baseline scan → Compare** দিয়ে তুলনা করুন। Result-এর `RESOLVED` মানে তুলনায় fingerprint আর দেখা যায়নি, শতভাগ fix প্রমাণ নয়।
6. উপযুক্ত হলে workflow-এ `RESOLVED` বা `FALSE_POSITIVE` দিন; প্রয়োজন হলে `REOPENED` করা যায়। User-selected status নিজে প্রযুক্তিগত verification নয়। `NOT_OBSERVED_IN_LATEST_SCAN` মানেও কেবল সর্বশেষ উপযুক্ত same-scanner ফলের সীমার মধ্যে আর দেখা যায়নি।

### ধাপ ৯ — Report তৈরি ও শেয়ার

সম্পন্ন scan-এর **Security assessment report → Generate / retrieve report** চাপুন। পরে প্রয়োজন অনুযায়ী **Download JSON**, **Download Markdown**, **Download SARIF**, **Download PDF**, আর SCA-তে inventory থাকলে **Download SBOM (CycloneDX)** ব্যবহার করুন। Project overview-তে একাধিক scanner-এর সর্বশেষ চেষ্টার সীমিত সারাংশ **Download project summary PDF** থেকেও পাওয়া যায়। Findings/status বদলের পর নতুন single-scan snapshot দরকার হলে **Regenerate current snapshot** ব্যবহার করুন। শেয়ারের আগে scope, সংবেদনশীল তথ্য ও সীমা যাচাই করুন।

---

## ১০. Finding, comparison ও report-এর অর্থ

### Severity

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` হলো গুরুত্ব সাজানোর লেবেল। Severity rule/পর্যবেক্ষণ থেকে আসতে পারে; এটি নির্ভুল ব্যবসায়িক ক্ষতি, exploitability বা বাস্তব incident-এর নিশ্চয়তা নয়। প্রথমে high/critical review করা সুবিধাজনক, তবে asset ও প্রমাণ অনুযায়ী মানুষকে সিদ্ধান্ত নিতে হবে।

### Finding-এর অবস্থা

| অবস্থা | সহজ অর্থ |
|---|---|
| `OPEN` | finding-এর কাজ এখনো খোলা |
| `ACKNOWLEDGED` | কেউ বিষয়টি দেখেছেন/স্বীকার করেছেন |
| `IN_PROGRESS` | সংশোধন বা যাচাইয়ের কাজ চলছে |
| `RESOLVED` | ব্যবহারকারী সমাধান হয়েছে বলে চিহ্নিত করেছেন; নিজে প্রমাণ নয় |
| `FALSE_POSITIVE` | ব্যবহারকারী ফলটিকে ভুল সতর্কতা হিসেবে চিহ্নিত করেছেন |
| `REOPENED` | আগের বিষয় আবার খোলা হয়েছে |

### Report সম্পর্কে জেনে রাখুন

- সংরক্ষিত single-scan report হলো **একটি completed scan-এর point-in-time snapshot**। বিস্তারিত মূল রিপোর্ট চারটি scanner-এর জন্য পৃথক; আলাদা project summary PDF সর্বশেষ চেষ্টাগুলোর সীমিত সারাংশ, মূল রিপোর্টের বিকল্প নয়।
- JSON machine-readable, Markdown সহজে পড়া/সম্পাদনার উপযোগী, SARIF tool-compatible findings-এর ফরম্যাট, আর SBOM dependency inventory-এর ফরম্যাট।
- Report-এ scan scope, findings, coverage, workflow snapshot ও সীমা থাকতে পারে; পুরোনো report-এ কিছু field নাও থাকতে পারে।
- SHA-256 digest content-এর সারাংশ/অখণ্ডতা পরীক্ষা করার কাজে লাগে; এটি digital signature বা তৃতীয় পক্ষের certification নয়।
- Project summary PDF সর্বশেষ scan-চেষ্টা দেখায়; বিভিন্ন scope এবং duplicate finding থাকতে পারে, আর বিস্তারিত সীমাবদ্ধ হলে তা লেখা থাকে। PDF ও combined summary certification নয়। Scheduled report বা digital signing এখনও নেই। বাংলা conjunct copy/paste নির্ভুল নাও হতে পারে; exact text-এর জন্য JSON ব্যবহার করুন। আরও দেখুন [নতুন paid-style কাজের সীমা](./PAID_WORKFLOWS_BN.md)।
- Project overview-এ একাধিক scan-এর finding যোগ করলে একই issue বারবার গণনা হতে পারে; সেটি deduplicated unique vulnerability count নয়।

---

## ১১. অন্যের ওয়েবসাইট: assessment, declaration ও engagement

অন্যের কাজ করার ক্ষেত্রে একটি ব্যবহারযোগ্য নিরাপদ চেকলিস্ট:

1. মালিক/অনুমোদিত প্রতিনিধির **লিখিত অনুমতি** নিন। কে অনুমতি দিচ্ছেন তা মানুষের মাধ্যমে যাচাই করুন।
2. নির্দিষ্ট exact hostname, path, test type, অনুমোদিত সময়, দায়িত্বপ্রাপ্ত যোগাযোগ এবং কী বাদ থাকবে লিখুন। একটি subdomain অনুমোদিত মানেই অন্য subdomain অনুমোদিত নয়।
3. Project-এ assessment তৈরি করে objectives ও `In-scope`/`Out-of-scope` লিখুন, প্রয়োজনে শুরু করুন।
4. UI-তে configured target-এর জন্য `USER_DECLARED` বা `UNVERIFIED` declaration দেখা/রেকর্ড করা যায়। এটি আপনার নিজের বক্তব্য; স্বাধীন যাচাই নয়।
5. আরও বিস্তারিত engagement-এ client, exact host, allowed scan types, সময়সীমা ও path scope নথিভুক্ত করার owner-scoped API আছে। বর্তমান project UI ওই engagement-এর **তথ্য দেখায়**, তবে এটি তৈরি/withdraw করার পূর্ণ ফর্ম দেয় না; প্রযুক্তিগত operator-এর API ব্যবহার প্রয়োজন।
6. Assessment-linked scan-এ engagement থাকলে type/scope/validity gate করা হয়; linked DAST-এর ক্ষেত্রে প্রতিটি পরবর্তী request-এর আগেও বর্তমান scope পুনরায় পরীক্ষা হয়। Withdraw/expiry হলে পরবর্তী request/scan বন্ধ হতে পারে, কিন্তু ইতোমধ্যে পাঠানো request ফিরিয়ে নেওয়া যায় না।
7. **গুরুত্বপূর্ণ gap:** engagement না থাকলে পুরোনো `UNVERIFIED` path এখনও চালু। ফলে অ্যাপ সব scan-এর আগে লিখিত অনুমতি বাধ্যতামূলক করে না। এই gap-কে অনুমতি হিসেবে ব্যবহার করবেন না।

সবশেষে client-কে জানাবেন কী পরীক্ষা করেছেন, কী পরীক্ষা করেননি, কতটুকু partial, এবং কোন বিষয় মানুষ দিয়ে আরও পরীক্ষা প্রয়োজন।

---

## ১২. SOC ও SAC আসলে কী?

### SOC-style overview

Project-এর **Security operations overview → Load operations snapshot** সর্বশেষ সর্বোচ্চ **১০০টি saved scan** থেকে তথ্য সাজায়। যেমন: উচ্চ severity finding, অসম্পূর্ণ/ব্যর্থ scan, সাম্প্রতিক scan অনুপস্থিতি, অথবা dataset/advisory source unavailable/stale। Recent বলতে বর্তমান কোডে ৩০ দিনের window ব্যবহার হয়। বেশি history/alert হলে overview truncated হতে পারে।

এটি **live SIEM, ২৪/৭ attack monitoring, firewall/EDR integration, email/SMS alerting বা automatic incident response নয়**। এখানে alert মানেই attack হয়েছে—এমন নয়। এটি saved-scan triage view।

### SAC coverage ledger

আগের বাস্তবায়নে `SAC` নামটি **Security Assessment & Compliance** অর্থে ধরা হয়েছিল; আপনি এর অর্থ নির্দিষ্ট করেননি, তাই এটি কেবল বাস্তবায়নের নাম/অনুমান। রিপোর্টে এটি মূলত একটি scan-এর coverage ও সীমা নথিভুক্ত করে:

- `RAN` — সীমিত scanner চালানো হয়েছে;
- `PARTIAL` — ফল আংশিক, truncated বা supplement অসম্পূর্ণ;
- `NOT_RUN` — ওই single-scan report-এ scanner চালানো হয়নি;
- residual risk `UNKNOWN`; compliance `NOT_ASSESSED`।

এটি PCI DSS, ISO 27001, SOC 2 বা অন্য compliance certification নয়। `RAN` থাকলেও পুরো site/code/rule পরীক্ষা হয়েছে বলা যায় না। AST ও SOC/SAC চারটি scan type-এর ওপর সহায়ক স্তর, নতুন আলাদা scan নয়।

---

## ১৩. AI Security Assistant — বর্তমানে কী পারে?

Project-এর **AI Security Assistant** অংশটি project-এর অনুমোদিত saved scan/finding/report evidence থেকে কিছু পূর্বনির্ধারিত প্রশ্নের deterministic উত্তর দেয়। নামের মধ্যে AI থাকলেও বর্তমান provider state সাধারণত `NONE`: এটি external generative LLM বা স্বাধীন security agent নয়।

ব্যবহার:

1. অন্তত প্রাসঙ্গিক completed scan থাকলে project-এর assistant অংশে যান।
2. প্রয়োজনমতো **Scan context**, **Compare with** বা **Finding** নির্বাচন করুন।
3. বর্তমান recognizer ইংরেজি keyword-ভিত্তিক; উদাহরণ হিসেবে লিখতে পারেন:
   - `What are the top findings?`
   - `Summarize the assessment`
   - `What DAST observations were recorded?`
   - `How do I fix this finding?` — আগে finding নির্বাচন করুন।
   - `Compare scans` — দুইটি উপযুক্ত scan নির্বাচন করুন।
4. উত্তরের facts, evidence, limitations এবং `SUPPORTED`/`PARTIALLY_SUPPORTED`/`UNAVAILABLE` অবস্থা দেখুন।

এটি ইচ্ছামতো যেকোনো বাংলা প্রশ্ন বুঝবে, internet খুঁজবে, নতুন scan চালাবে, chat history রাখবে, code বদলাবে, fix deploy করবে বা সেই fix নিশ্চিত করবে—এমন সুবিধা বর্তমানে ধরে নেওয়া যাবে না। Unsupported প্রশ্নে `UNAVAILABLE` স্বাভাবিক।

---

## ১৪. চার ধরনের ব্যবহারকারী

| Classification | উপযোগী প্রদর্শন/কাজের ধারা | যা **বদলায় না** |
|---|---|---|
| **Developer** | source upload → SAST/SCA/Secrets → finding fix → rescan | ownership, role, quota, engine permissions |
| **Student** | নিজের project-এ শেখা, finding বোঝা ও learning page | কোনো বিশেষ admin ক্ষমতা বা আলাদা scanner নয় |
| **Security Professional** | scope, assessment, evidence, remediation ও report-ভিত্তিক কাজ | প্রকৃত মালিকের অনুমতি, ownership বা plan নিজে পাওয়া যায় না |
| **Pentester** | অনুমতিপ্রাপ্ত target, DAST observation, finding ও retest review | active testing-এর বাস্তব অনুমতি বা পূর্ণ pentest capability পাওয়া যায় না |

### Student learning-এর বর্তমান গুরুত্বপূর্ণ সমস্যা

External dataset-এ গ্রহণযোগ্য lesson থাকলে learning page-এ পাঠের তালিকা ও content দেখানো সম্ভব। কিন্তু বর্তমান source-এ progress store কেবল embedded lesson catalog দিয়ে ID যাচাই করে, আর embedded catalog এখন খালি। ফলে dataset থেকে আসা lesson-এর **read acknowledgement, quiz/progress বা practice verification সংরক্ষণ ব্যর্থ হতে পারে**। একটি synthetic in-memory পরীক্ষায় dataset-ধরনের lesson ID `Unknown student lesson id` বলে প্রত্যাখ্যাত হয়েছে।

অতএব এটি এখন **আংশিক/ত্রুটিপূর্ণ সুবিধা**—complete learning/progress system হিসেবে প্রতিশ্রুতি দেওয়া ঠিক হবে না। পৃথক সংশোধন ও পুনঃপরীক্ষা দরকার। Lesson content অনুপস্থিত হলে dataset status দেখুন। কোনো course certificate, শিক্ষক/শ্রেণিকক্ষ পরিচালনা, formal grade বা সম্পূর্ণ learning platform দাবি করা যাচ্ছে না।

---

## ১৫. Plan, payment, admin ও partner সুবিধা

### FREE ও PRO

- বর্তমান সাধারণ **FREE** allowance: প্রতি UTC মাসে account-wide **৩টি scan**; shared-device anti-abuse সীমাও প্রযোজ্য হতে পারে। মাস বাংলাদেশ সময় নয়, UTC অনুযায়ী বদলায়।
- প্রতিটি SAST/SCA/SECRETS/DAST request আলাদা scan; fix-এর পর rescan-ও quota ব্যবহার করে। তাই চার ধরনের প্রথম scan-ই সাধারণ FREE মাসিক ৩টির বেশি।
- Active **PRO**-এর মাসিক scan quota exemption আছে। এটিকে সব resource, request size, rate limit, file limit বা অন্য ব্যবস্থার সীমা ছাড়া অসীম ক্ষমতা ভাববেন না।
- Project, report, assistant বা comparison ব্যবহার নিজে নতুন scan নয়; report তৈরিতে scan quota লাগে না।
- **Account → Monthly scan usage / Plan & subscription**-এ নিজের বর্তমান অবস্থা দেখুন। User type বদলালে PRO পাওয়া যায় না।

### Payment ও admin

Manual payment request, reference জমা, নির্দিষ্ট অনুমোদিত reviewer-এর review/approve/reject এবং server-side entitlement-এর ভিত্তি আছে। Reference জমা মানেই টাকা যাচাই বা PRO সক্রিয় নয়। মূল্য/পদ্ধতি server configuration অনুযায়ী বদলাতে পারে; শুধু marketing screen-এর লেখা চূড়ান্ত ধরে নেওয়া ঠিক নয়। Online payment gateway, recurring billing, automatic refund বা নিজে নিজে payment verification ধরে নেওয়া যাবে না।

Admin operations ও payment review role/অতিরিক্ত allowlist-নির্ভর; শুধু Security Professional/Pentester classification বা PRO থাকলে admin ক্ষমতা মেলে না।

### Partner

Admin-provisioned partner coupon, discount ও commission record-এর ভিত্তি আছে। এটি self-service partner enrollment বা automatic payout নয়; payment approval ও commission status আলাদা প্রক্রিয়া।

---

## ১৬. একটি বাস্তবধর্মী উদাহরণ: অনুমতিপ্রাপ্ত ই-কমার্স অ্যাপ

ধরা যাক, একটি দোকান আপনাকে তাদের ওয়েব অ্যাপ review করার লিখিত অনুমতি দিয়েছে। নিচের কাজগুলো **সম্ভাব্য workflow**, বাস্তবে এ রিপোর্টের জন্য কোনো স্ক্যান করা হয়নি।

1. চুক্তিতে `shop`-এর সঠিক hostname, অনুমোদিত path, সময় এবং passive/active অনুমতি নির্ধারণ করুন। Payment, admin বা অন্য কোনো অংশ বাদ থাকলে সেটি স্পষ্ট লিখুন।
2. Drobon-এ project ও assessment খুলে scope লিখুন। প্রয়োজনে operator দিয়ে engagement record তৈরি করুন।
3. মালিকের অনুমতিপ্রাপ্ত source-এর প্রয়োজনীয় text files এক snapshot-এ দিন। বড় repo হলে কোন অংশ বাদ পড়ল নথিভুক্ত করুন।
4. Dataset status দেখে **SAST** চালিয়ে প্রাসঙ্গিক সন্দেহজনক code flow মানুষ দিয়ে যাচাই করুন।
5. একই snapshot-এ **SECRETS** চালান; প্রকৃত credential leak পেলে মালিকের সাহায্যে revoke/rotate করুন। মনে রাখবেন snapshot নিজেই সংবেদনশীল হতে পারে।
6. Manifest/lockfile থাকলে **SCA** চালিয়ে inventory ও SBOM দেখুন; advisory মিললে vendor-এর তথ্য দিয়ে version যাচাই করুন; `NOT_ASSESSED` হলে সেটি client-কে স্পষ্ট বলুন।
7. চুক্তি অনুযায়ী target URL-এ সীমিত **DAST** চালান। Active mode-এর জন্য আলাদা স্পষ্ট সম্মতি নিশ্চিত করুন। Observed header বা marker reflection vulnerability প্রমাণ নয়।
8. প্রাসঙ্গিক finding-এর remediation করুন, নতুন snapshot বা target অবস্থার উপর একই scanner-এ rescan করে comparison দেখুন।
9. প্রতিটি completed scan-এর আলাদা report তৈরি করুন। Client-কে report-এর পাশাপাশি পরীক্ষার সময়, scope, কোন rules/data ছিল, `PARTIAL`/`NOT_ASSESSED`, বাদ পড়া অংশ এবং মানুষের পরবর্তী review সুপারিশ দিন।

---

## ১৭. সাধারণ প্রশ্ন ও ভুল ধারণা

**প্রশ্ন: চারটি ইঞ্জিন থাকলে একটা বোতামেই চারটা পরীক্ষা হয়ে যায়?**  
না। বর্তমান UI-তে প্রতিবার একটি scan type নির্বাচন করতে হয়।

**প্রশ্ন: Source না থাকলে কি SAST/SCA/Secrets চলবে?**  
না; valid source snapshot দরকার। DAST-এর জন্য source নয়, অনুমতিপ্রাপ্ত গ্রহণযোগ্য target URL দরকার।

**প্রশ্ন: Dataset নেই, কিন্তু scan completed ও finding শূন্য। সাইট নিরাপদ?**  
না। বিশেষ করে rules অনুপস্থিত থাকলে গুরুত্বপূর্ণ পরীক্ষা হয়নি। Dataset/coverage status এবং মানুষের review প্রয়োজন।

**প্রশ্ন: SCA `NOT_ASSESSED` কেন?**  
প্রাসঙ্গিক provider data নেই/অপ্রাপ্য হতে পারে, অথবা বর্তমান assessment logic কোনো verified match না পেলেও এই status রাখে। এটি clean verdict নয়।

**প্রশ্ন: Active Safe কি যেকোনো সাইটে নিরাপদে চালানো যায়?**  
না। এটি network request ও path-based probe করতে পারে; প্রকৃত লিখিত অনুমতি, scope এবং ঝুঁকির বোঝাপড়া দরকার। Query-based testing-ও বর্তমান নীতিতে ব্লক করা।

**প্রশ্ন: `RESOLVED` মানে bug পুরো শেষ?**  
না। এটি ব্যবহারকারীর workflow status বা comparison-এ fingerprint না দেখা; উপযুক্ত retest ও মানুষের যাচাই প্রয়োজন।

**প্রশ্ন: Report-এ সব scanner `RAN` দেখায়?**  
না। প্রতিটি report একটি scan-এর; অন্য scanner সাধারণত `NOT_RUN`। চারটি scanner চাইলে চারটি scan ও পৃথক report প্রয়োজন।

**প্রশ্ন: Assistant কি ChatGPT-এর মতো ইন্টারনেট থেকে যেকোনো প্রশ্নের উত্তর দেয়?**  
না। বর্তমানটি নিজের সংরক্ষিত evidence-এর ওপর সীমিত নিয়মভিত্তিক উত্তর।

**প্রশ্ন: Secret finding masked, তাই source/server-এ কোনো secret নেই?**  
না। আপলোড করা source snapshot text হিসেবে সার্ভারে সংরক্ষিত থাকে। সিস্টেম ও backups সুরক্ষিত রাখতে হবে।

**প্রশ্ন: এই অ্যাপ কি এখনই বড় commercial multi-tenant production service হিসেবে সম্পূর্ণ প্রস্তুত?**  
এমন দাবি করা যায় না। JSON-file store মূলত single-process/single-writer foundation; নিরাপদ production deployment, scale, storage/backup, isolation, পর্যবেক্ষণ, legal consent enforcement ও আরও স্বাধীন security review প্রয়োজন।

---

## ১৮. পরীক্ষার অবস্থা ও জানা সীমা

- সর্বশেষ পূর্ববর্তী পূর্ণ `npm run verify` এই ব্রাঞ্চের কোডে **১১/১১ ধাপ PASS**, মোট **১,৪৮৭টি test**: shared ১৮৮, API ৯৯০, worker ২৮, web ২৮১। এটি স্বয়ংক্রিয় যাচাইয়ের ফল; সব বাগ নেই বা কোনো বাস্তব সাইট নিরাপদ—তার প্রমাণ নয়।
- রিপোর্ট প্রস্তুতির সময় lesson-progress সীমাটি একটি synthetic in-memory পরীক্ষায়ও দেখা হয়েছে; এটি নতুন করে কোনো বাস্তব target scan নয়।
- আগের যাচাইয়ে দুটি moderate development-dependency advisory এবং web bundle-size warning ছিল; high/critical audit gate pass করেছিল।
- SCA subset reader-এর আগের historical round-trip পরীক্ষায় mismatch/parse failure ছিল; বর্তমান production data ও সব বাস্তব manifest-এ শতভাগ parity প্রমাণিত নয়।
- Active DAST-এর query সীমা, dataset নির্ভরতা, Student progress সমস্যা, single-scan report, JSON-store deployment সীমা ও বাস্তব অনুমতি যাচাইয়ের gap commercial ব্যবহারের আগে গুরুত্ব দিয়ে দেখতে হবে।

### মূল কোড ও বিস্তারিত ডকুমেন্টের অবস্থান

- Scanner composition: `apps/api/src/app.ts`, `apps/api/src/scans/{sast,sca,secrets,dast}/`
- AST: `docs/AST_ANALYSIS.md`
- SOC/SAC: `docs/SECURITY_OPERATIONS_COVERAGE.md`, `apps/api/src/{soc,sac}/`
- Source policy: `packages/shared/src/sources.ts`, project UI `apps/web/src/pages/ProjectDetailPage.tsx`
- Dataset ও advisory: `docs/DATASET_CONNECTION.md`, `docs/ADVISORY_ENGINE.md`, `apps/api/src/external/`
- Reports: `docs/REPORTS.md`; assessments/engagement: `docs/ENGAGEMENTS.md`
- Assistant: `docs/ASSISTANT.md`, `apps/api/src/assistant/service.ts`
- Student lesson gap: `apps/api/src/student/lessons.ts`, `apps/api/src/student/store.ts`, `apps/api/src/routes/student.ts`
- আগের কাজ ও পূর্ণ যাচাইয়ের বাংলা সারাংশ: `docs/MAIN_APP_WORK_REPORT.md`

**নোট:** কিছু পুরোনো documentation ও marketing UI-তে ঐতিহাসিক rule count, passive-only DAST, embedded lesson বা পুরোনো plan-এর দাবি থাকতে পারে। এমন বিরোধে বর্তমান implementation, status ও উপরের সীমা প্রাধান্য দিন।
