# আপনার Drobon-Dataset: কী আছে, মেইন অ্যাপ কীভাবে ব্যবহার করে

**পরীক্ষার তারিখ:** ২৮ অক্টোবর ২০২৬  
**ডেটাসেট রিপোজিটরি:** [mdraselislam0101-design/Drobon-Dataset](https://github.com/mdraselislam0101-design/Drobon-Dataset)  
**যে সংস্করণ পরীক্ষা করা হয়েছে:** GitHub `main`-এর তৎকালীন commit [`3986082b22007b47930da3bc99be9c2f2b036080`](https://github.com/mdraselislam0101-design/Drobon-Dataset/tree/3986082b22007b47930da3bc99be9c2f2b036080), commit সময় ২৬ অক্টোবর ২০২৬, 07:38 UTC।  
**মেইন অ্যাপ:** `Drobon`-এর বর্তমান `arena/5bb07bd8-drobon` workspace, যার কিছু কাজ এখনো uncommitted। এই workspace আর আপনার বাস্তবে ডিপ্লয় করা সার্ভার একই সংস্করণ/কনফিগারেশনে আছে—এমন নিশ্চয়তা এই পরীক্ষা দেয় না।

> **এই রিপোর্টের সারকথা:** আপনার dataset-এ চারটি scanner-এর **৪,০০৭টি rule**, সীমিত dependency advisory data, remediation, CWE ও শিক্ষাসংক্রান্ত তথ্য আছে। বর্তমান মেইন অ্যাপের কোড সেগুলোর গুরুত্বপূর্ণ অংশ পড়তে পারে। আমরা একই commit-এর একটি অস্থায়ী read-only inspection copy দিয়ে সংযোগ পরীক্ষা করেছি। তবে কোনো বাস্তব ওয়েবসাইট বা ক্লায়েন্ট অ্যাপ scan করিনি, আর আপনার live deployment-এ dataset চালু আছে কি না পরীক্ষা করিনি।

ডেটাসেট বা ডেটাবেস রিপোজিটরিতে কোনো পরিবর্তন করা হয়নি। এই রিপোর্ট মেইন অ্যাপের `docs/`-এ রাখা হয়েছে।

---

## ১. প্রথমে বুঝি: মেইন অ্যাপ ও ডেটাসেট আলাদা কীভাবে?

একটি সহজ উদাহরণ:

- **Drobon মেইন অ্যাপ** হলো কাজ করার যন্ত্র: project, scan engine, upload, findings, report ও interface।
- **Drobon-Dataset** হলো যন্ত্রটি ব্যবহার করতে পারে এমন নিয়ম ও তথ্যের সংগ্রহ: কোন প্যাটার্ন খুঁজবে, তার বিবরণ, সংশোধনের নির্দেশনা ও সীমিত advisory।

```text
Drobon-Dataset-এর rules/তথ্য
             ↓ operator-এর কনফিগার করা DATASET_PATH
Drobon-এর dataset loader ও validation
             ↓
SAST / Secrets / DAST / SCA engine
             ↓
যে source বা response সত্যিই পরীক্ষা করা হয়েছে তার finding ও report
```

**ডেটাসেট নিজে scanner নয়।** আবার dataset-এ কোনো rule আছে বলেই সেটি আপনার live server-এ লোড হয়েছে, কোনো নির্দিষ্ট scan-এ ব্যবহার হয়েছে, বা নিশ্চিত vulnerability পাওয়া যাবে—এমন নয়।

---

## ২. পরীক্ষিত ডেটাসেটে কী কী আছে?

নিচের সংখ্যা **উপরের নির্দিষ্ট commit**-এর জন্য। ভবিষ্যৎ সংস্করণে এগুলো বদলাতে পারে।

| অংশ | পরীক্ষিত সংখ্যা | সাধারণ অর্থ |
|---|---:|---|
| SAST rule | ১,০০০ | Source code-এর সন্দেহজনক pattern সংক্রান্ত নিয়ম |
| Secrets rule | ১,০০০ | Credential-এর মতো দেখতে তথ্য শনাক্তের নিয়ম |
| DAST rule | ১,০০৭ | পর্যবেক্ষিত HTTP response, header বা body পরীক্ষার নিয়ম |
| SCA declaration rule | ১,০০০ | Manifest/dependency declaration-এর শর্ত পরীক্ষার নিয়ম |
| **চারটি pack-এ মোট rule** | **৪,০০৭** | চার scanner-এ ব্যবহারের জন্য প্রস্তুত data records |
| Remediation entry | ৪,০০৭ | Rule ID অনুযায়ী ব্যাখ্যা ও করণীয়ের data |
| CWE knowledge entry | ১০২ | কিছু weakness category-এর reference/summary |
| Learning lesson | ৬ | শিক্ষার জন্য পাঠ ও অনুশীলনের content |
| Assessment template | ৩ | Assessment planning-এর নমুনা content |
| Engagement template | ২ | Engagement planning-এর নমুনা content |
| Non-fixture advisory file | ১০০ | সীমিত npm/PyPI GHSA seed; নিচে আলাদা করে ব্যাখ্যা আছে |
| Synthetic advisory fixture | ৩ | পরীক্ষার নমুনা—বাস্তব advisory হিসেবে গণ্য নয় |

### ৪,০০৭ rule মানে কি ৪,০০৭টি আলাদা vulnerability?

**না।** Rule হলো চেক করার একটি শর্ত বা প্যাটার্ন। কিছু rule একই ধরনের বিষয়ের ভিন্ন রূপ পরীক্ষা করতে পারে। একটি rule কখনো না-ও মেলতে পারে, ভুল সতর্কতা দিতে পারে বা সীমার কারণে বাস্তব সমস্যা মিস করতে পারে। Rule count-কে vulnerability count বা detection accuracy বলা যাবে না।

ডেটাসেটে আলাদা `knowledge/patterns` ও `knowledge/records`-এও ৪,০০৭টি করে record আছে। এগুলোকে আরও ৮,০১৪টি স্বাধীন scanner বা vulnerability হিসেবে যোগ করা ঠিক নয়; বর্তমান app scanner ওই directory দুটিকে আলাদা scan-engine input হিসেবে ব্যবহারও করে না।

---

## ৩. SAST dataset মেইন অ্যাপে কী কাজে লাগে?

**অবস্থান:** `packs/sast/v1/rules/`  
**পরীক্ষিত সংখ্যা:** ১,০০০ rule।

SAST-এ ব্যবহারকারীর আপলোড করা source code-এর সঙ্গে উপযুক্ত rule-এর pattern মিলিয়ে review করার মতো সম্ভাব্য বিষয় বের করা হয়। Dataset-এ পাওয়া category-এর উদাহরণ:

- code বা command injection-এর কিছু প্যাটার্ন;
- SQL query ও HTML injection-এর কিছু গঠন;
- দুর্বল cryptography বা transport configuration-এর ইঙ্গিত;
- কিছু access-control, container, configuration ও deserialization-সংক্রান্ত প্যাটার্ন।

**নির্দিষ্ট উদাহরণ:** `DPK-SAST-001` হলো সরাসরি `eval()`-এর উপস্থিতি review করার rule। সেটি কোথাও মিললেও সত্যিই attacker-controlled input সেখানে পৌঁছেছে কি না rule একা নিশ্চিত করতে পারে না।

মেইন অ্যাপে বর্তমানে JS/TS/JSX/TSX, Python, PHP ও Java-র জন্য সীমিত structured AST সহায়তা আছে। অন্য বহু language/configuration-এ dataset pattern বা shallow analysis থাকতে পারে। Dataset-এ ১১৫টি language ID resolve হয়েছে বলেই ১১৫টি ভাষার পূর্ণ AST, পূর্ণ dataflow বা সব vulnerability শনাক্ত হয়—এমন নয়।

### আমাদের নিয়ন্ত্রিত পরীক্ষা

একটি **synthetic source fixture** দিয়ে SAST engine-এ `DPK-SAST-001` পাওয়ার পথ পরীক্ষা হয়েছে। এটি আসল website/application scan বা বাস্তব detection-rate benchmark নয়।

---

## ৪. Secrets dataset কী কাজে লাগে?

**অবস্থান:** `packs/secrets/v1/rules/`  
**পরীক্ষিত সংখ্যা:** ১,০০০ rule।

এসব rule source/text file-এ সম্ভাব্য API key, service token, cloud credential বা hardcoded credential-এর মতো আকৃতি শনাক্ত করতে সাহায্য করে।

- উদাহরণ `DPK-SEC-001`: AWS access-key-ID-এর মতো দেখতে একটি আকার review করা। শুধু ID মেললেই credential সক্রিয় বা ব্যবহারযোগ্য—এমন নয়।
- উপযুক্ত finding-এর evidence redaction-এর ব্যবস্থা আছে।
- টুলটি শনাক্ত value ব্যবহার করে কোনো provider-এ লগইন করে না।
- `.env`, dotfile ও নিষিদ্ধ key-file source snapshot-এ আপলোড করা যায় না।

**গোপনীয়তার সীমা:** Finding-এর evidence redacted হলেও আপলোড করা মূল source snapshot সার্ভারের store-এ text হিসেবে থাকে। তাই ক্লায়েন্টের source-এর access ও backup নিরাপদ রাখতে হবে।

একটি synthetic credential-shaped fixture ব্যবহার করে `DPK-SEC-001` finding এবং ওই পরীক্ষায় মূল synthetic value output-এ না থাকা যাচাই করা হয়েছে। এটি সব সম্ভাব্য secret বা সব redaction পরিস্থিতির পূর্ণ প্রমাণ নয়।

---

## ৫. DAST dataset কী কাজে লাগে?

**অবস্থান:** `packs/dast/v1/rules/`  
**পরীক্ষিত সংখ্যা:** ১,০০৭ rule।

এই pack ইতোমধ্যে পাওয়া response-এর URL, অনুমোদিত header ও সীমিত body-র ওপর পরীক্ষা করে। Dataset-এর উদাহরণ:

- `DPK-DAST-001`: পর্যবেক্ষিত target URL HTTP কি না;
- `DPK-DAST-002`: পর্যবেক্ষিত response-এ Content-Security-Policy header নেই কি না।

একটি response-এ header অনুপস্থিত মানেই exploit, compromised site বা পূর্ণ site-wide সমস্যা প্রমাণিত নয়। সংশ্লিষ্ট response ও deployment context যাচাই করতে হবে।

আমরা আসল network request না পাঠিয়ে **synthetic response ও mock transport** দিয়ে `DPK-DAST-002` engine পর্যন্ত পৌঁছায় কি না পরীক্ষা করেছি। ওই পরীক্ষায় একটি mock request ব্যবহৃত হয়েছে।

### বাস্তব ওয়েবসাইটে সীমা

- Passive default: সর্বোচ্চ ৩টি সীমিত GET request।
- Consent-gated Active Safe code path: সর্বোচ্চ ২০টি সীমিত request; এটি full pentest নয়।
- বর্তমান target policy query-যুক্ত URL ও query-parameter probe ব্লক করে; বাদ পড়লে scan `PARTIAL` হতে পারে।
- Browser, authenticated crawling বা JavaScript execution নেই।
- Dataset-এর লিখিত scope কিছু জায়গায় passive-only হলেও মেইন অ্যাপে consent-gated active path আছে। এই product/scope অমিলের বিষয়ে owner decision এখনো প্রয়োজন; এ রিপোর্ট সেটি অনুমোদন করছে না।

বাস্তব target owner-এর লিখিত অনুমতি ও নির্দিষ্ট scope ছাড়া কোনো mode ব্যবহার করবেন না। Drobon নিজে আইনগত অনুমতি স্বাধীনভাবে যাচাই করে না।

---

## ৬. SCA dataset: দুই ধরনের তথ্য আলাদা করে বুঝুন

### ৬.১ Declaration rules — ১,০০০টি

**অবস্থান:** `packs/sca/v1/rules/`

এই rules manifest/configuration-এ ঘোষিত তথ্যের কিছু গঠন পরীক্ষা করে। উদাহরণ, `DPK-SCA-0001` একটি `package.json` dependency-তে bare wildcard version declaration review করার rule। এটি কোনো CVE আছে বলে নিজে ঘোষণা করে না।

বর্তমান মেইন অ্যাপে নয় ধরনের **bounded subset reader** আছে: JSON, TOML, YAML, XML, INI, properties, requirements, Gradle ও lockfile text। এগুলো সব format-এর পূর্ণ grammar বোঝে না।

**এই নির্দিষ্ট dataset ও বর্তমান source-path policy অনুযায়ী:**

- ১,০০০টি declaration rule loader গ্রহণ করেছে।
- এর মধ্যে **৯৫৯টি** parser-kind ও upload করা যায় এমন artifact নামের ভিত্তিতে *সম্ভাব্য eligible*।
- **৪১টি** rule dotfile-জাতীয় artifact-এর সঙ্গে যুক্ত; বর্তমান upload policy-তে সেগুলো আপলোড করা যায় না। উদাহরণ `.npmrc`, `.yarnrc.yml`।
- ৯৫৯ eligible মানে নির্দিষ্ট snapshot-এ সব ৯৫৯টি চলেছে বা সঠিক ফল দিয়েছে নয়। ফাইল, format, rule condition ও scan সীমা মিলতে হবে।

### ৬.২ Vulnerability-intelligence records — সীমিত npm/PyPI seed

**অবস্থান:** `vuln-intel/npm/` ও `vuln-intel/pypi/`।

| গণনার ধরন | সংখ্যা | পার্থক্য |
|---|---:|---|
| Non-fixture JSON file | ১০০ | ৫০ npm ও ৫০ PyPI file |
| Advisory-package identity | ৮৪ | একই advisory/package-এর একাধিক file/shard একত্র ধরলে |
| আলাদা advisory ID | ৭৮ | Unique GHSA advisory identifier |
| পরীক্ষার fixture | ৩ | আলাদা; production advisory হিসেবে গণ্য নয় |

এই records-এ provenance হিসেবে `GHSA` ও retrieval date **১৪ অক্টোবর ২০২৬** উল্লেখ আছে। এগুলো একটি সীমিত seed; সব package, সব ecosystem বা সর্বশেষ সব CVE-এর তালিকা নয়। আমরা প্রতিটি upstream advisory-এর বর্তমান সত্যতা/লাইসেন্স আলাদাভাবে পুনরায় যাচাই করিনি।

মেইন অ্যাপের filesystem SCA provider সমর্থিত package নাম, ecosystem ও পাওয়া exact version-এর সঙ্গে dataset-এর শর্ত মেলাতে পারে। উপযুক্ত তথ্য না থাকলে বা match না হলে `NOT_ASSESSED` দেখা যেতে পারে—এর মানে dependency নিরাপদ নয়। Inventory/SBOM নিজেও vulnerability verdict নয়।

**আলাদা বিষয়:** `ADVISORY_PATH`-এর generic advisory pack মেইন অ্যাপের আরেকটি ঐচ্ছিক ব্যবস্থা; সেটি এই dataset-এর `vuln-intel` provider-এর মতো একই জিনিস নয় এবং নিজে নিজে কোনো live feed ডাউনলোড করে না।

---

## ৭. Remediation, CWE ও অন্যান্য content কতটা ব্যবহৃত হয়?

### Remediation — ৪,০০৭টি

`knowledge/remediation/`-এর entry rule ID দিয়ে পাওয়া গেলে মেইন অ্যাপ finding detail ও সীমিত Security Assistant-এ rule-specific ব্যাখ্যা/করণীয় দেখাতে পারে। চার ধরনের rule-এর একটি করে sample lookup আমাদের integration test-এ পাওয়া গেছে।

Scanner finding-এর নিজস্ব `remediation` text-ও rule pack থেকে আসে এবং report-এ থাকতে পারে। তবে আলাদা remediation knowledge entry-এর সম্পূর্ণ সব action স্বয়ংক্রিয়ভাবে standalone report-এ অন্তর্ভুক্ত হয়—এমন দাবি বর্তমান code থেকে করা যায় না। Guidance দেখালেই টুল নিজে code পরিবর্তন বা fix যাচাই করে না।

### CWE — ১০২টি

Dataset loader CWE records পড়তে পারে এবং status-এ সংখ্যা দেখাতে পারে। কোনো scan rule-এর `CWE-...` তথ্য finding/report-এ আসতে পারে। কিন্তু dataset-এর সব CWE entry থেকে পূর্ণ আলাদা CWE encyclopedia বা সম্পূর্ণ navigable learning feature বর্তমানে নিশ্চিত নয়; CWE map helper থাকলেও সাধারণ scanner workflow-এ তার সরাসরি ব্যবহার পাওয়া যায়নি।

### Lesson — ৬টি: একটি গুরুত্বপূর্ণ সমস্যা

Dataset-এর ছয়টি lesson মেইন অ্যাপের lesson provider-এ পৌঁছাতে পারে। কিন্তু বর্তমান progress store একটি খালি embedded catalog-এর সঙ্গে lesson ID যাচাই করে। তাই dataset lesson-এর **read acknowledgement, quiz বা practice progress সংরক্ষণ ব্যর্থ হতে পারে**।

এই পরীক্ষায় একটি বাস্তব dataset lesson ID দিয়ে synthetic in-memory progress update চেষ্টা করলে `Unknown student lesson id` পাওয়া গেছে। সমস্যাটি মেইন অ্যাপের integration-এ; এই রিপোর্ট তৈরিতে সেটি পরিবর্তন করা হয়নি।

### Assessment/engagement template ও user-type views

- Dataset-এ ৩টি assessment ও ২টি engagement template আছে; loader status-এ সংখ্যা দেখা যায়। বর্তমান project UI-তে dataset template থেকে স্বয়ংক্রিয়ভাবে assessment/engagement পূরণের পূর্ণ workflow পাওয়া যায়নি।
- `views/`-এ চারটি user-type lens আছে, প্রতিটিতে shared rules থেকে ১,০০০টি selection। এগুলো চার হাজার নতুন স্বাধীন rule নয়। বর্তমান মেইন অ্যাপ ওই `views/*-v1.json`-কে সরাসরি তার scan-engine input হিসেবে পড়ছে—এমন call site পাওয়া যায়নি।
- User type dashboard/guidance-এর classification; এগুলো নতুন scanner বা বাড়তি permission নয়।

---

## ৮. আমরা কীভাবে সংযোগ পরীক্ষা করেছি?

প্রথমে GitHub-এর `main` থেকে উপরে উল্লেখ করা exact commit শনাক্ত করে তার একটি **অস্থায়ী, read-only inspection copy** নিয়ে মেইন অ্যাপের বর্তমান module-গুলোর সঙ্গে পরীক্ষা করেছি। Dataset repo-তে commit, push বা অন্য কোনো পরিবর্তন করা হয়নি।

### ৮.১ Loader ও declared example tests

মেইন অ্যাপের `npm run verify:dataset -- --path ...` চালিয়ে ফল:

| Pack | Loader-এ গ্রহণ | Declared example test চালানো | Failed/skipped |
|---|---:|---:|---:|
| SAST | ১,০০০ / ১,০০০ | ৪,০৪৩ | ০ / ০ |
| Secrets | ১,০০০ / ১,০০০ | ৪,৬৬০ | ০ / ০ |
| DAST | ১,০০৭ / ১,০০৭ | ৩,৬৭৩ | ০ / ০ |
| SCA declaration | ১,০০০ / ১,০০০ | ৪,০০১ | ০ / ০ |
| **মোট** | **৪,০০৭ / ৪,০০৭** | **১৬,৩৭৭** | **০ / ০** |

Pack conversion-এর আলাদা পরীক্ষায় SAST ১,০০০, Secrets ১,০০০ ও DAST ১,০০৭টি engine-ready rule-এ রূপান্তর হয়েছে। SCA provider-এর dataset-এ থাকা ১৬টি pinned test vector-এর **১৬টি** মিলে গেছে। সামগ্রিক `verify:dataset` ফল **PASS**।

### ৮.২ PASS সত্ত্বেও SCA reader-এ কী সীমা পাওয়া গেছে?

নন-JSON declaration reader-এর **২,২৭৩টি synthetic round-trip case**-এ:

- **১১১টি verdict mismatch**;
- **৩৭টি render/parse failure**;
- একসঙ্গে **১৪৮টি** ব্যর্থ বা অমিল case;
- ওই নির্দিষ্ট fixture-সেটের হিসাবে প্রায় **৯৩.৪৯% parity**।

Verification script বর্তমানে নির্দিষ্ট residual budget-এর মধ্যে এই সংখ্যা থাকায় `PASS` দিয়েছে। এটি শূন্য ভুল, সব manifest-এর ৯৩.৪৯% accuracy বা production security guarantee নয়। কিছু parser ভুল document বুঝলেও সেটি সবসময় আলাদা `NOT_EVALUATED` হিসেবে ধরা নাও পড়তে পারে; non-JSON subset analysis-এ partial coverage গুরুত্ব দিয়ে দেখতে হবে।

### ৮.৩ চার scanner-এ controlled integration probe

| Engine | Synthetic fixture-এ প্রত্যাশিত rule |
|---|---|
| SAST | `DPK-SAST-001` পাওয়া গেছে |
| Secrets | `DPK-SEC-001` পাওয়া গেছে; পরীক্ষিত synthetic value redacted ছিল |
| SCA | `DPK-SCA-0001` পাওয়া গেছে; sample dependency intelligence ছিল `NOT_ASSESSED` |
| DAST | `DPK-DAST-002` পাওয়া গেছে; HTTP transport সম্পূর্ণ mock ছিল |

এগুলো **নিয়ন্ত্রিত ছোট পরীক্ষা**, কোনো বাস্তব গ্রাহকের code/site scan বা বাস্তব-বিশ্বে recall/precision পরীক্ষা নয়। Declared test ও synthetic probe pass করা মানে সব ধরনের সমস্যা পাওয়া যাবে—এমন নয়।

---

## ৯. নিজের চালু অ্যাপে dataset যুক্ত আছে কি না কীভাবে দেখবেন?

আমাদের অস্থায়ী test configuration আপনার production server-এর configuration বদলায়নি। আপনার প্রকৃত অ্যাপে যাচাই করতে:

1. অপারেটরকে নিশ্চিত করতে বলুন যে উপযুক্ত dataset-এর একটি নিরাপদ filesystem copy অ্যাপ সার্ভারে আছে। এই রিপোর্টের `/tmp` inspection copy স্থায়ী production path নয়।
2. API process-এর environment-এ `VULN_INTEL_PROVIDER=filesystem` এবং প্রকৃত directory-র absolute `DATASET_PATH` দিন।
3. Process চালু/প্রয়োজনে restart করুন। Loader প্রতি process-এ data cache করে; repository link দিলেই GitHub থেকে runtime-এ স্বয়ংক্রিয়ভাবে পড়া হয় না।
4. লগইন করে একই app-origin-এর `GET /api/v1/dataset/status` দেখুন। এতে configuration, pack count, conformance ও version-সংক্রান্ত তথ্য পাওয়া যায়।
5. বাস্তব scan-এর summary-তে rules/coverage, partial অবস্থা ও SCA provider state আলাদা করে দেখুন। শুধু category `AVAILABLE` হলেই প্রতিটি rule বা advisory ওই scan-এ কার্যকর হয়েছে—এমন নয়।

অপারেটরের জন্য উদাহরণ—পাথটি নিজস্ব বাস্তব পাথ দিয়ে বদলাতে হবে:

```bash
VULN_INTEL_PROVIDER=filesystem \
DATASET_PATH=/absolute/path/to/your/existing-dataset \
npm run dev
```

এটি development command, production deployment নির্দেশিকা নয়। শুধু `.env` ফাইল বানালেই API নিজে সেটি পড়ে নেবে—এমন ধরে নেবেন না; process environment নিশ্চিত করুন। পরিবেশে default `VULN_INTEL_PROVIDER=none` থাকলে embedded SAST/Secrets/passive DAST rule list খালি, lesson content অনুপস্থিত এবং SCA vulnerability intelligence `NOT_ASSESSED` হতে পারে।

আরও একটি read-only check:

```bash
npm run verify:dataset -- --path /absolute/path/to/your/existing-dataset
```

সেই command-এর `PASS` উপরের মতো bounded test-সীমার মধ্যে বুঝতে হবে। `--write` ব্যবহার করলে মেইন অ্যাপে evidence file লেখা হয়; এই রিপোর্টের পরীক্ষায় তা ব্যবহার করা হয়নি।

---

## ১০. লাইসেন্স, নতুন data ও production ব্যবহারের সতর্কতা

- Dataset-এর `README.md`-তে repository-wide license এখনো ঠিক করা হয়নি বলে লেখা; `NOTICE`-এ upstream data ব্যবহারের সিদ্ধান্ত ও per-record terms পর্যালোচনার কথা আছে। কোনো source link থাকলেই redistribution বা commercial use-এর অনুমতি পাওয়া যায় না। ব্যবসায়িক ব্যবহার বা data পুনর্বিতরণের আগে উপযুক্ত owner/legal review প্রয়োজন।
- Repository-তে advisory corpus expansion-এর জন্য data-lock/owner decision বর্ণিত। এই রিপোর্টে data যোগ, sync বা পরিবর্তন করা হয়নি।
- App বা dataset-এর এই integration **live, automatic vulnerability-feed refresh নয়**। পুরোনো seed থাকলে নতুন vulnerability মিস হতে পারে। প্রয়োজনে অনুমোদিত, রক্ষণাবেক্ষিত ও লাইসেন্স-পর্যালোচিত data এবং পৃথক advisory ব্যবস্থা বিবেচনা করতে হবে।
- DAST করার আগে সাইটের প্রকৃত মালিকের লিখিত অনুমতি ও exact scope প্রয়োজন। App-এর declaration permission-এর স্বাধীন প্রমাণ নয়।
- Dataset, scanner, AST বা report—কোনোটিই ১০০% নিরাপত্তার নিশ্চয়তা দেয় না।

---

## ১১. সহজ সিদ্ধান্ত

**আপনার dataset এবং main app-এর মধ্যে পড়ার ও কাজে লাগানোর integration আছে।** এই নির্দিষ্ট commit দিয়ে local controlled পরীক্ষায় চারটি rule pack লোড হয়েছে এবং চার ধরনের scanner-এ একটি করে প্রত্যাশিত rule পাওয়া গেছে।

কিন্তু একে সম্পূর্ণ production readiness বলতে এখনো বাধা আছে:

1. আপনার live server-এ dataset সত্যি কনফিগার করা আছে কি না অজানা।
2. SCA-র ৪১টি rule-এর artifact বর্তমান upload policy-তে নিষিদ্ধ; subset reader-এ পরীক্ষিত mismatch আছে।
3. Student lesson progress-এর বর্তমান integration-এ bug রয়েছে।
4. Dataset-এর passive scope ও app-এর Active Safe code path নিয়ে সিদ্ধান্ত প্রয়োজন।
5. Limited, সময়-বাঁধা advisory seed এবং licence/redistribution সিদ্ধান্ত আলাদাভাবে বিবেচনা করা দরকার।

**সবচেয়ে ব্যবহারিক পরবর্তী ধাপ:** আপনার প্রকৃত server-এর dataset status যাচাই করুন; তারপর চাইলে শুধু মেইন অ্যাপে Student progress ও উপরে চিহ্নিত integration সীমাগুলো আলাদাভাবে সংশোধনের পরিকল্পনা করা যায়।
