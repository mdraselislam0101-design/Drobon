# Drobon Main App: পৃথক benchmark যাচাই ও অবশিষ্ট defect — ৩১ অক্টোবর ২০২৬

> **সিদ্ধান্ত: production NO-GO।** নিচের ফল কেবল ছোট, synthetic, লেখক-নির্ধারিত corpus ও নির্বাচিত test rules-এর ক্ষেত্রে প্রযোজ্য। এটি বাস্তব গ্রাহক পরিবেশে scanner accuracy, exploitability বা কোনো vendor-এর তুলনা নয়।

## ১. কী স্বাধীনভাবে যাচাই হয়েছে, কী হয়নি

- ৬২টির প্রত্যেকটির fixture আলাদা, **scanner-output-বিহীন** mechanical পদ্ধতিতে পরীক্ষা: ৫৬টি true/false condition ও ৬টি malformed/unknown অবস্থা লেখকের label-এর সঙ্গে মিলে; মোট **৬২/৬২ agreement**। একই agent কোড ও এই checker লিখেছে, fixture-এর তথ্য আগে থেকেই জানা ছিল; এটি blinded বা পৃথক মানব review নয়। **স্বাধীন মানব review: ০/৬২।**
- নিচের ৬২টি case-এর প্রত্যেকটিই তাই **NOT INDEPENDENTLY VERIFIED (human/blinded review)**। এখানে “পৃথক check” মানে scanner engine বা scanner result ব্যবহার ছাড়া সীমিত যান্ত্রিক cross-check; পূর্ণ স্বাধীন মানব ground-truth adjudication নয়। Unknown অবস্থার সঙ্গে `null` মেলা মানে positive বা negative প্রমাণ নয়।
- এই checker-এর JavaScript অংশ Acorn দিয়ে অল্প কিছু expression/statement-এর static subset দেখে; fixture code execute করে না। JSON-এ Python JSON, XML-এ Python minidom, Python literal-এ Python AST, requirement-এ offline pip packaging এবং DAST-এ কেবল অনুমোদিত loopback lab response ব্যবহার করেছে। JS ৩৫, JSON ৯, HTTP ১১, Python AST ১, pip ১, XML ৫ = ৬২। এটি general-purpose security parser, sanitizer বা exploit proof নয়।
- `AX-SEC-05`-এর label কেবল **controlled empty environment**-এর জন্য। একই কৃত্রিম expression-এ nonempty environment দিলে ফল বদলায়; একে নির্বিচারে সব environment-এর সত্য বলা যাবে না। অজানা dynamic expression-এ এই checker `null` দেয়।
- Drobon test-only rule এবং নির্দিষ্ট condition-এর case-level verdict হিসাব করেছে। SCA শুধু declaration check, advisory feed নেই; DAST scanner transport mock, browser/real target scan নয়। পৃথক HTTP checker একটি ephemeral loopback lab-এ request করেছে, অন্য কোনো target-এ নয়। Test-only rule production Dataset rule নয়।
- Original authored oracle স্থানীয়, digest-pinned fixture-এর জন্য fake sink-সহ Node `vm` ব্যবহার করে; `vm` security boundary নয় এবং customer/downloaded code-এ ব্যবহার করা যাবে না। নতুন checker fixture execute করে না।

## ২. প্রত্যাশা বনাম ফল, সংখ্যা ও denominator

এক case এক verdict; দুটি finding থেকে দুটি TP হয় না। TP/FP/TN/FN-এ কেবল assessed ও non-unknown case। Unassessed এবং unknown বাদ। Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN); শূন্য denominator হলে metric undefined। শতাংশ কেবল এই সীমিত case-scoped corpus-এর।

| Scanner | মোট | TP | FP | TN | FN | Unassessed | Unknown | Assessed | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SAST | 21 | 10 | 2 | 7 | 0 | 1 | 1 | 19 | 83.33% | 100% | 90.91% |
| Secrets | 15 | 6 | 0 | 4 | 0 | 4 | 1 | 10 | 100% | 100% | 100% |
| SCA declaration | 15 | 4 | 0 | 5 | 1 | 1 | 4 | 10 | 100% | 80% | 88.89% |
| DAST passive/mock | 11 | 3 | 0 | 4 | 1 | 3 | 0 | 8 | 100% | 75% | 85.71% |
| **মোট / micro** | **62** | **23** | **2** | **20** | **2** | **9** | **6** | **47** | **92%** | **92%** | **92%** |

এই phase-এর আগে ও পরে উপরের প্রতিটি case verdict এবং তাই সব aggregate count অপরিবর্তিত: **৬২/৬২ একই**। আগে-পরে দুই ক্ষেত্রেই assessed positive denominator ২৫, assessed negative ২২, মোট ৪৭; বাদ ১৫। Corpus-এ নতুন malformed-XML counterexample যোগ করে score বাড়ানো হয়নি। Micro aggregate বিভিন্ন ধরনের ছোট test একত্র করে; এটিকে অন্য scanner বা production accuracy-এর সঙ্গে তুলনা করা অনুচিত। ১০০% দেখানো ছোট subset-ও সর্বব্যাপী নির্ভুলতা বা নিরাপত্তার দাবি নয়।

### Duplicate ও report/location audit

- ২৫টি detected case-এ মোট **২৯টি matching finding record**; বাকি ৩৭টিতে কোনো matching record নেই। `SAST-01`, `SAST-03`, `SAST-05`, `SAST-07`-এ প্রতিটিতে একই case/CWE ও line-এ ২টি করে ভিন্ন rule/fingerprint record। এগুলো overlapping সম্ভাব্য একই issue, কিন্তু পৃথক fingerprint বলে exact duplicate নয়; issue-level adjudication বা blanket deletion করা হয়নি। Binary scorer প্রত্যেকটিকে একবারই গণনা করে। অন্য unjudged finding এই run-এ ০।
- আগের `sourceLocationCorrect: true` কেবল একই file ও in-range line প্রমাণ করত; এটি সঠিক sink প্রমাণ নয়। সংশোধনের পরে ২৬/২৬ source-bearing record-এর `sourceLocationInFile=true`, কিন্তু **সঠিক sink independently adjudicated নয়**: `sourceLocationCorrect=null`। অন্য ৩টি DAST record-এ source location প্রযোজ্য নয়; তাদের mock target location ৩/৩ মিলে। False location হলে পুরোনো nullable field-এ `false` থাকে। নতুন `sourceLine` শুধু line number, source text নয়।
- রিপোর্ট তৈরি হওয়া ৫৯/৫৯ পর্যবেক্ষণে নির্বাচিত integrity/count ও source/synthetic-secret-absence check পাস। বাকি ৩টিতে reflection বা target rejection-এর কারণে report ছিল না; এগুলোকে report pass ধরা হয়নি। এই checks অন্যান্য সম্ভাব্য privacy leak বা সব finding-এর সত্যতা প্রমাণ করে না।
- Matching বর্তমানে rule ID **অথবা SAST-এ একই CWE** দিয়ে করা হয়। একই CWE হলেও সেটি ঠিক একই semantic issue কি না স্বয়ংক্রিয়ভাবে নিশ্চিত নয়; বাস্তব alert-level precision ও exact sink-এর জন্য স্বাধীন adjudication বাকি।

## ৩. সব ৬২ case

`+` = নির্দিষ্ট fixture condition উপস্থিত; `−` = অনুপস্থিত; `?` = অপর্যাপ্ত/ভাঙা input, তাই truth unknown। `JS/JSON/HTTP/PY/PIP/XML` উপরে বর্ণিত scanner-free method। প্রত্যেক সারিতে লেখক label ও পৃথক mechanical পর্যবেক্ষণ পাশাপাশি; **সব সারির human status: NOT INDEPENDENTLY VERIFIED**। `UNASSESSED` আর `UNKNOWN_TRUTH` কোনো pass বা TN নয়। প্রতিটি rule এখানে benchmark/test scope-এর; `নেই` মানে সংশ্লিষ্ট passive case-এর জন্য test rule নেই।

| Case | Scanner / test rule | Fixture-এর শর্ত | লেখক / পৃথক check | Drobon অবস্থা | Verdict | Matching records |
|---|---|---|---|---|---|---:|
| SAST-01 | SAST / DG-SAST-001 | request input shell command-এ যোগ | + / + (JS) | DETECTED | TP | 2 |
| SAST-02 | SAST / DG-SAST-001 | দুই স্থির string দিয়ে shell command | − / − (JS) | DETECTED | FP | 1 |
| SAST-03 | SAST / DG-SAST-001 | request থেকে variable হয়ে shell | + / + (JS) | DETECTED | TP | 2 |
| SAST-04 | SAST / DG-SAST-001 | স্থির echo executable; shell ছাড়া argv | − / − (JS) | DETECTED | FP | 1 |
| SAST-05 | SAST / DG-SAST-003 | request SQL text-এ যোগ | + / + (JS) | DETECTED | TP | 2 |
| SAST-06 | SAST / DG-SAST-003 | SQL placeholder ও পৃথক parameter | − / − (JS) | NOT_DETECTED | TN | 0 |
| SAST-07 | SAST / DG-SAST-004 | request থেকে innerHTML | + / + (JS) | DETECTED | TP | 2 |
| SAST-08 | SAST / DG-SAST-001 | shell sink শুধু comment-এ | − / − (JS) | NOT_DETECTED | TN | 0 |
| SECRET-01 | SECRETS / DG-SEC-002 | একটি synthetic key-shaped literal | + / + (JS) | DETECTED | TP | 1 |
| SECRET-02 | SECRETS / DG-SEC-002 | দুই literal-এ synthetic key shape | + / + (JS) | DETECTED | TP | 1 |
| SECRET-03 | SECRETS / DG-SEC-005 | explicit example placeholder | − / − (JS) | NOT_DETECTED | TN | 0 |
| SECRET-04 | SECRETS / DG-SEC-002 | শুধু environment lookup | − / − (JS) | NOT_DETECTED | TN | 0 |
| SCA-01 | SCA / DPK-SCA-9001 | runtime dependency wildcard | + / + (JSON) | DETECTED | TP | 1 |
| SCA-02 | SCA / DPK-SCA-9001 | নির্দিষ্ট runtime version | − / − (JSON) | NOT_DETECTED | TN | 0 |
| SCA-03 | SCA / DPK-SCA-9001 | dev dependency wildcard; test rule runtime-only | + / + (JSON) | NOT_DETECTED | FN | 0 |
| SCA-04 | SCA / DPK-SCA-9001 | ভাঙা JSON, তথ্য অনির্ণেয় | ? / ? (JSON) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| DAST-01 | DAST / DG-DAST-003 | nosniff header অনুপস্থিত | + / + (HTTP) | DETECTED | TP | 1 |
| DAST-02 | DAST / DG-DAST-003 | nosniff header-এর মান ভুল | + / + (HTTP) | NOT_DETECTED | FN | 0 |
| DAST-03 | DAST / DG-DAST-003 | nosniff মান সঠিক | − / − (HTTP) | NOT_DETECTED | TN | 0 |
| DAST-04 | DAST / নেই | unescaped reflection; active দরকার | + / + (HTTP) | UNASSESSED | UNASSESSED | 0 |
| DAST-05 | DAST / নেই | escaped reflection; active দরকার | − / − (HTTP) | UNASSESSED | UNASSESSED | 0 |
| AX-SAST-01 | SAST / DG-SAST-001 | request interpolation exec-এ | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-02 | SAST / DG-SAST-001 | request-controlled executable | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-03 | SAST / DG-SAST-001 | shell:true সঙ্গে user input | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-04 | SAST / DG-SAST-001 | shell interpreter-এ গঠিত command | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-05 | SAST / DG-SAST-001 | স্থির program ও argument | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SAST-06 | SAST / DG-SAST-001 | স্থির shell text | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SAST-07 | SAST / DG-SAST-001 | source শুধু comment-এ | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SAST-08 | SAST / DG-SAST-003 | SQL text-এ request interpolation | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-09 | SAST / DG-SAST-003 | পৃথক parameter-এ SQL input | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SAST-10 | SAST / DG-SAST-004 | HTML sink-এ unescaped input | + / + (JS) | DETECTED | TP | 1 |
| AX-SAST-11 | SAST / DG-SAST-004 | text sink, HTML sink নয় | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SAST-12 | SAST / DG-SAST-001 | unsupported text extension-এ command flow | + / + (JS) | UNASSESSED | UNASSESSED | 0 |
| AX-SAST-13 | SAST / DG-SAST-001 | ভাঙা JavaScript, তথ্য অনির্ণেয় | ? / ? (JS) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| AX-SEC-01 | SECRETS / DG-SEC-002 | একটি synthetic key-shaped literal | + / + (JS) | DETECTED | TP | 1 |
| AX-SEC-02 | SECRETS / DG-SEC-002 | দুই unescaped literal জোড়া | + / + (JS) | DETECTED | TP | 1 |
| AX-SEC-03 | SECRETS / DG-SEC-002 | বন্ধনীসহ তিন literal জোড়া | + / + (JS) | DETECTED | TP | 1 |
| AX-SEC-04 | SECRETS / DG-SEC-002 | literal fragments শুধু comment-এ | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SEC-05 | SECRETS / DG-SEC-002 | খালি environment-নির্ভর synthetic shape | + / + (JS) | UNASSESSED | UNASSESSED | 0 |
| AX-SEC-06 | SECRETS / DG-SEC-002 | escape decode করলে synthetic shape | + / + (JS) | UNASSESSED | UNASSESSED | 0 |
| AX-SEC-07 | SECRETS / DG-SEC-005 | example placeholder | − / − (JS) | NOT_DETECTED | TN | 0 |
| AX-SEC-08 | SECRETS / DG-SEC-002 | খালি string-সহ static fragments | + / + (JS) | DETECTED | TP | 1 |
| AX-SEC-09 | SECRETS / DG-SEC-002 | Python static literal folding | + / + (PY) | UNASSESSED | UNASSESSED | 0 |
| AX-SEC-10 | SECRETS / DG-SEC-002 | ভাঙা source, runtime value অনির্ণেয় | ? / ? (JS) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| AX-SEC-11 | SECRETS / DG-SEC-002 | ignored dependency directory-তে synthetic shape | + / + (JS) | UNASSESSED | UNASSESSED | 0 |
| AX-SCA-01 | SCA / DPK-SCA-9002 | dev wildcard; test dev rule | + / + (JSON) | DETECTED | TP | 1 |
| AX-SCA-02 | SCA / DPK-SCA-9002 | নির্দিষ্ট dev version | − / − (JSON) | NOT_DETECTED | TN | 0 |
| AX-SCA-03 | SCA / DPK-SCA-9001 | runtime dependency-তে wildcard | + / + (JSON) | DETECTED | TP | 1 |
| AX-SCA-04 | SCA / DPK-SCA-9001 | runtime wildcard নেই | − / − (JSON) | NOT_DETECTED | TN | 0 |
| AX-SCA-05 | SCA / DPK-SCA-9001 | ভাঙা JSON, তথ্য অনির্ণেয় | ? / ? (JSON) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| AX-SCA-06 | SCA / DPK-SCA-9001 | unrestricted requirement; npm rule-এর বাইরে | + / + (PIP) | UNASSESSED | UNASSESSED | 0 |
| AX-SCA-07 | SCA / DPK-SCA-9003 | numeric XML entity decode হলে HTTP source | + / + (XML) | DETECTED | TP | 1 |
| AX-SCA-08 | SCA / DPK-SCA-9003 | HTTPS source | − / − (XML) | NOT_DETECTED | TN | 0 |
| AX-SCA-09 | SCA / DPK-SCA-9003 | hex XML entity decode হলে HTTPS | − / − (XML) | NOT_DETECTED | TN | 0 |
| AX-SCA-10 | SCA / DPK-SCA-9003 | unknown XML entity, তথ্য অনির্ণেয় | ? / ? (XML) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| AX-SCA-11 | SCA / DPK-SCA-9003 | অসমাপ্ত XML, তথ্য অনির্ণেয় | ? / ? (XML) | UNASSESSED | UNKNOWN_TRUTH | 0 |
| AX-DAST-01 | DAST / DG-DAST-900 | ভুল nonempty header; value-aware test rule | + / + (HTTP) | DETECTED | TP | 1 |
| AX-DAST-02 | DAST / DG-DAST-900 | সঠিক header; value-aware rule | − / − (HTTP) | NOT_DETECTED | TN | 0 |
| AX-DAST-03 | DAST / DG-DAST-900 | header অনুপস্থিত; value-only rule-এর বাইরে | − / − (HTTP) | NOT_DETECTED | TN | 0 |
| AX-DAST-04 | DAST / DG-DAST-003 | header অনুপস্থিত; presence rule | + / + (HTTP) | DETECTED | TP | 1 |
| AX-DAST-05 | DAST / DG-DAST-003 | সঠিক header; presence rule | − / − (HTTP) | NOT_DETECTED | TN | 0 |
| AX-DAST-06 | DAST / DG-DAST-003 | query-সহ target block; lab header সঠিক | − / − (HTTP) | UNASSESSED | UNASSESSED | 0 |

## ৪. ১৯টি exception-এর কারণ, classification ও সিদ্ধান্ত

নিচের প্রতিটি পৃথক case পুনরুৎপাদন করতে `<ID>`-এর জায়গায় সারির ID বসান: `DROBON_BENCHMARK_CASE_ID=<ID> node --import tsx benchmarks/accuracy-v2/run.mjs`। এটি কেবল স্থানীয় synthetic case, test rules ও mock transport চালায়। পৃথক fixture observation-এর জন্য `node benchmarks/independent-validation/fixture-check.mjs`; Dataset scope ফল [নিরাপদ metadata artifact](../benchmarks/independent-validation/dataset-accounting.json)-এ। Expected/actual ও scanner/rule ID আগের case table-এও দেখানো আছে।

| Case / scanner / নির্বাচিত rule | Expected → actual | Root cause ও classification | নিরাপদ সিদ্ধান্ত |
|---|---|---|---|
| SAST-02 / SAST / DG-SAST-001 | − → detected, FP | Test-only lexical regex স্থির string concatenation-কে request flow ধরে; নতুন Acorn check-এ input flow নেই। একই synthetic input-এ read-only RAM Dataset pack দিয়ে ০ finding। **Test-rule FP**, production Dataset FP প্রমাণ নয়। | Score বাড়াতে test rule বদলানো হয়নি; আলাদা context-sensitive rule review দরকার। |
| SAST-04 / SAST / DG-SAST-001 | − → detected, FP | স্থির `echo` program-এ shell ছাড়া argv; তিন স্তরের AST/category heuristic tainted argv-কে command category হিসেবে report করে। RAM Dataset engine-এ `DPK-SAST-044` HIGH PROJECT category reporter-ও পাওয়া গেছে। **এই shell-injection label-এর জন্য বাস্তব scanner over-report**, exact Dataset pattern match বা অন্য argument risk-এর প্রমাণ নয়। | অপরীক্ষিত suppression নয়: shadowed/import binding, dynamic executable, `shell:true`, interpreter এবং program-specific argument injection হারানোর ঝুঁকি আছে। নিরাপদ binding/option-aware নকশা ও negative/positive tests ছাড়া অবশিষ্ট। |
| SCA-03 / SCA / DPK-SCA-9001 | + → not detected, FN | Fixture-এ `devDependencies.*`; নির্বাচিত test rule শুধু `dependencies.*` দেখে। RAM Dataset-এ `DPK-SCA-0718` dev wildcard পায়; advisory coverage partial। **Test-rule scope FN**, সব production SCA rule-এর FN নয়। | Production rule বা Dataset বদলানো হয়নি। |
| DAST-02 / DAST / DG-DAST-003 | + → not detected, FN | ভুল কিন্তু nonempty `nosniff` value; test rule কেবল header উপস্থিতি দেখে। RAM Dataset-এর value-aware `DPK-DAST-073` mock input-এ এটি ধরে। **Test-rule scope FN**। | Presence rule-কে গোপনে value rule বানানো হয়নি; অনুরূপ আলাদা `DG-DAST-900` positive control আছে। |
| DAST-04 / DAST / rule নেই | + → unassessed | Unsafe HTML reflection দেখা যায়, কিন্তু benchmark DAST run passive; active query দরকার। **Unsupported evaluation**। | অনুমতি ও target policy না বদলে unassessed রাখুন। |
| DAST-05 / DAST / rule নেই | − → unassessed | Escaped reflection; একই passive limitation। **Unsupported evaluation**। | TN নয়; active অনুমোদিত validation দরকার। |
| AX-SAST-12 / SAST / DG-SAST-001 | + → unassessed | Source-like flow unsupported text extension-এ; harness coverage-aware। **Unsupported format**। | শুধু count বাড়াতে arbitrary text execute/scan বা negative ধরা হয়নি। |
| AX-SEC-05 / Secrets / DG-SEC-002 | + → unassessed | Label empty environment ধরে; nonempty environment-এ outcome আলাদা। Dynamic value folding সীমার বাইরে। **Fixture assumption + unsupported analysis**। | Environment assumption প্রকাশ; unknown dynamic data-কে static secret বলে report নয়। |
| AX-SEC-06 / Secrets / DG-SEC-002 | + → unassessed | Escaped JS literal decode প্রয়োজন; bounded unescaped-only fold তা সমর্থন করে না। **Unsupported analysis**। | নিরাপদ bounded parser, privacy ও controls নিয়ে ভবিষ্যৎ কাজ; অনুমান করে detection নয়। |
| AX-SEC-09 / Secrets / DG-SEC-002 | + → unassessed | Python literal concatenation; JS/TS-only fold এটি দেখে না। **Unsupported language-specific analysis**। | Coverage বাড়াতে আলাদা নিরাপদ গবেষণা/পরীক্ষা দরকার; result জোর করে FN/TP নয়। |
| AX-SEC-11 / Secrets / DG-SEC-002 | + → unassessed | Synthetic value ignored dependency directory-তে; source path policy বাদ দেয়। **Policy-limited coverage**। | উপেক্ষিত path policy দুর্বল করা হয়নি। |
| AX-SCA-06 / SCA / DPK-SCA-9001 | + → unassessed | Bare unrestricted pip requirement; এই নির্বাচিত rule npm artifact-এর। **Fixture/rule scope mismatch**। | নতুন Dataset rule তৈরি বা অযথা npm rule প্রয়োগ নয়। |
| AX-DAST-06 / DAST / DG-DAST-003 | − → unassessed | Query-সহ target `DAST_TARGET_INVALID`; lab response safe হলেও production target request হয়নি। **Safety-policy block**। | Query/authorization control বজায়; এটিকে TN ধরা যাবে না। |
| SCA-04 / SCA / DPK-SCA-9001 | ? → unassessed | JSON অসমাপ্ত; declaration parse/evaluation সম্পূর্ণ নয়। **Malformed fixture / unknown truth**। | Partial হিসেবেই রাখুন, না TP না TN। |
| AX-SAST-13 / SAST / DG-SAST-001 | ? → unassessed | JavaScript syntax ভাঙা; valid executable flow সম্পর্কে ground truth নেই। **Malformed fixture / unsupported parse**। | Unknown রাখুন। |
| AX-SEC-10 / Secrets / DG-SEC-002 | ? → unassessed | Syntax অসম্পূর্ণ; fixture-specific literal-fold coverage নেই। Benchmark harness এটিকে unassessed বলে; base scan-এর `partial=false` একাই syntax completeness প্রমাণ করে না। **Malformed fixture / coverage limitation**। | Null সত্য ও coverage gap প্রকাশ; base-contract ভেঙে জোরপূর্বক ফল নয়। |
| AX-SCA-05 / SCA / DPK-SCA-9001 | ? → unassessed | ভাঙা JSON, completed declaration evaluation নেই। **Malformed fixture / unknown truth**। | Unknown রাখুন। |
| AX-SCA-10 / SCA / DPK-SCA-9003 | ? → unassessed | XML-এ অজানা entity; পৃথক XML parser প্রত্যাখ্যান করে। **Malformed fixture / unknown truth**। | Unknown/partial রাখুন। |
| AX-SCA-11 / SCA / DPK-SCA-9003 | ? → unassessed | XML trailing tag অসমাপ্ত। **Malformed fixture / unknown truth**। | Unknown/partial রাখুন। |

সংখ্যা: **২ FP + ২ scope-FN + ৯ unassessed + ৬ unknown = ১৯**। কোনো unsupported বা blocked case-কে pass/FN/TN বানানো হয়নি।

## ৫. এই phase-এ প্রতিপাদিত defect ও সংশোধন

### Main App: bounded XML declaration reader — এক production source file

Python `xml.etree.ElementTree` বনাম Drobon reader এবং `DPK-SCA-9003` test-only evaluator দিয়ে আগে পুনরুৎপাদিত তিন শ্রেণির defect:

1. **পাশাপাশি attribute-এর মাঝে XML whitespace ছাড়াই** malformed XML reader গ্রহণ করত।
2. **XML syntax position-এ non-XML Unicode whitespace**, যেমন attribute/equals, root-এর আগে/পরে বা closing tag-এ NBSP, গ্রহণ করত; XML শুধু space, tab, LF ও CR অনুমোদন করে।
3. Character data-তে literal **`]]>`** নিষিদ্ধ হলেও reader গ্রহণ করত।

পূর্বে NuGet input থেকে evaluator একটি finding দিয়ে completed evaluation দাবি করতে পারত। এখন ওই malformed input reader প্রত্যাখ্যান করে; নির্দিষ্ট declaration evaluation `rulesEvaluated=0`, `rulesNotEvaluated=1`, `partial=true`, findings ০। বৈধ চার XML whitespace, escaped `]]&gt;`, এবং মন্তব্যে `]]>` controls এখনও গ্রহণ করা হয়। রিপোর্টে input/source value কপি না হওয়ার assertion আছে। XML reader এখনও deliberately bounded subset; পূর্ণ XML-standard support বা সব malformed input শনাক্ত করার দাবি নয়। পৃথক probe-এ Python XML parser একটি attribute-এর literal `>` গ্রহণ করলেও এই conservative reader সেটি reject করে evaluation partial রাখে; escaped `&gt;` গ্রহণ করে। এটি প্রকাশিত unsupported coverage, pass বা completed negative নয়। Production Dataset, upload policy, authorization, severity ও public Main App report schema বদলানো হয়নি।

### Benchmark/oracle নির্ভুলতার সংশোধন — production scanner নয়

- Frozen oracle আগে `execFile`-এ `shell:true` থাকলেই input marker না থাকলেও positive বলত। Fixed program ও fixed argv-এর পৃথক counterexample-এ এটি ভুল প্রমাণিত; এখন marker flow দেখা হয়।
- Expanded oracle আগে shell interpreter-এর যেকোনো positional argument-কে command text বলত। এখন সরাসরি `-c` command-এ marker থাকলে positive; marker কেবল positional হলে **`null`/unknown**, কারণ shell script সেটি safe ভাবে ব্যবহারও করতে পারে, আবার `eval`-ও করতে পারে। এটিকে নিরাপদ negative ধরে নয়।
- In-range line-কে `sourceLocationCorrect=true` বলা বন্ধ; আলাদা `sourceLocationInFile` ও nullable semantic correctness রাখা হয়েছে।
- নতুন scanner-free checker-এর নিজস্ব adversarial control-এও positional shell data-কে নিশ্চিত negative বলার সমস্যা ধরা পড়ে; ৬টি test-এর ৫ pass / ১ fail থেকে সংশোধনের পর ৬/৬ pass। এখন `eval`-সম্ভাবনাসহ positional marker `null`।
- Corpus manifest `rules.mjs`-কে pin করলেও তার import করা `scaRule` object-কে pin করত না: isolated memory-তে rule path বদলালে manifest digest অপরিবর্তিত থেকেছে। Runner এখন inherited rule-এর পূর্ণ JSON object আলাদা SHA-256 pin-এ যাচাই করে, mismatch হলে scan-এর আগে fail-closed এবং output-এ pin দেয়; মূল frozen corpus digest বদলায়নি। নতুন control আগে ৬ pass / ১ fail, পরে ৭/৭ pass; কোনো Dataset বা fixture file বদলানো হয়নি।
- Controlled-environment নির্ভর fixture assumption প্রকাশ করা হয়েছে। এই oracle/measurement সংশোধন কোনো scanner TP বাড়ায়নি এবং fixture label বা Dataset বদলায়নি।

Pre-fix adversarial suite-এ ১৮টির মধ্যে **৮ pass / ১০ fail / ০ skip** ছিল: সাতটি malformed XML assertion এবং উপরের তিন oracle/location counterexample। পরবর্তী পরিমাপে সব pass; testগুলো বা security gate দুর্বল করা হয়নি। এখন Python না থাকলে core XML assertions চলবে, কেবল পৃথক Python cross-check স্পষ্টভাবে skipped হবে; এই পরিবেশে Python ও offline pip ছিল, তাই ওই দুই cross-check চালানো হয়েছে।

## ৬. User Dataset: read-only পুনর্গণনা

User-owned Dataset commit `3986082b22007b47930da3bc99be9c2f2b036080`; archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। Pinned archive কেবল memory-তে stream করা হয়েছে; Dataset checkout, extraction, file creation, rule modification বা database/migration পরিবর্তন করা হয়নি। Network request ছিল শুধু ওই user-owned pinned GitHub archive-এর জন্য; scanner test নিজে offline/mock ছিল।

- ৮,২৩৪ selected JSON file, ০ invalid; accepted ৪,০০৭ SAST/Secrets/DAST/SCA rule এবং ১৬,৩৭৭ declared conformance test: ১৬,৩৭৭ executed / ০ failed / ০ skipped। এটি Dataset-authored rule conformance, independent scanner accuracy নয়।
- SCA-র ৪,০০১ declared case: **৩,৮২৯ matched + ১৬৪ production path-blocked + ৮ unrenderable = ৪,০০১**; evaluated FP/FN ও parser failure প্রত্যেকটি ০। Coverage **PARTIAL**। ১৬৪টি reader-only memory diagnostic-এ ১৬৪/১৬৪ expectation মেলে, কিন্তু real upload/path gate এখনও সেগুলি আটকে দেয়; এগুলো pass নয়। আটটি unrenderable-ও pass নয়।
- আটটি NuGet alias conflict: `DPK-SCA-0679` index 1,3; `DPK-SCA-0689` index 0,1,3; `DPK-SCA-0753` index 0,1,3। প্রথম পাঁচটি ও শেষ index 3-এ conflicting `sources`/`add`, শেষ rule-এর index 0,1-এ `sources` আছে কিন্তু `add` অনুপস্থিত। `sources` ও `packageSources.add` একই input list থেকে derive হয়; লেখক-নির্ধারিত বিপরীত document সরল বাস্তব XML দিয়ে render করা যায় না। Artifact-এ প্রত্যেক index-এর sanitized কারণ ও প্রত্যেক blocked case-এর ID/path reason আছে।
- সম্পূর্ণ accepted pack-এর RAM-only probe-এ SAST-02 ০ finding, SAST-04 `DPK-SAST-044`, SCA-03 `DPK-SCA-0718`, DAST-02 `DPK-DAST-073`; এটি mounted-Dataset end-to-end production run নয়।

## ৭. শেষ পর্যায়ের test ও security ফল

নিচের পুনরায় চালানো suite-গুলো একে অন্যের সঙ্গে overlap করে; সংখ্যাগুলো যোগ করে unique test count দাবি করা হচ্ছে না। Fail ও skip সংখ্যা বাস্তব run অনুযায়ী; অনুপস্থিত external gate-কে pass বলা হয়নি।

| পরীক্ষা / scope | Pass বা মিলে | Fail | Skip | Not run |
|---|---:|---:|---:|---:|
| সম্পূর্ণ offline `npm run test` | **১,৭৩৭ test / ১৬৮ file** | ০ | ০ | ০ |
| নতুন XML + adversarial + মূল/expanded benchmark suites | ৩৩ / ৪ file | ০ | ০ | ০ |
| SCA/AST/DAST/Secrets targeted suites | ১১৭ / ৭ file | ০ | ০ | ০ |
| Secret/evidence/Assistant/report/privacy targeted suites | ২৭ / ৭ file | ০ | ০ | ০ |
| Scanner-free fixture check, প্রতিবার; দুই run | ৬২ agreement, যার ৬টি unknown | ০ mismatch | ০ | ০ |
| বিদ্যমান authored mechanical oracle | ৬২ agreement | ০ mismatch | ০ | ০ |
| Dataset conformance | ১৬,৩৭৭ | ০ | ০ | ০ |
| Dataset SCA production-path accounting | ৩,৮২৯ matched | ০ evaluated FP/FN | ১৬৪ blocked | ৮ unrenderable |
| ছয়টি external paid vendor | ০ | ০ | ০ | **৬** |

সম্পূর্ণ test ভাগ: shared ১৯ file/১৮৮, API ১১৫/১,২৩৪, worker ৩/৩২, web ৩১/২৮৩; সব pass। Scanner-free checker-এর ৬টি unknown agreement-কে vulnerability pass হিসেবে ধরা হয়নি। Dataset-এর blocked ও unrenderable সংখ্যাকে coverage gap হিসেবে আলাদা রেখেছি; উপরের টেবিলে 'skip/not run' তাদের প্রযুক্তিগত অবস্থা বোঝায়, test framework skip নয়।

শেষ fix-এর পরে ৬২ case runner **দুইবার** চালিয়ে output byte-identical, SHA-256 `e2f43634f8e0500d28c2a0357237a472a2ef4ec06da2cb496f818b24fe0651bb`; উভয়বার ২৩ TP / ২ FP / ২০ TN / ২ FN / ৯ unassessed / ৬ unknown এবং ০ internal error। সব ৬২ case accounted, ৬২ pass নয়। Independent checker-ও দুইবার byte-identical; আলাদা arithmetic/one-observation recount ৬২/৬২ scorer verdict-এর সঙ্গে মেলে।

নিম্নের ১০টি offline command/check সফল, প্রত্যেকটি **১ pass / ০ fail / ০ skip / ০ not-run**: সম্পূর্ণ tests, typecheck, lint, build, scope boundaries, repository integrity, secret matcher self-test, source/build secret scan, release-evidence self-test এবং `git diff --check`। Secret scan ৮৬০টি নির্বাচিত file scan করেছে; এটি সীমিত pattern check, সব secret অনুপস্থিতির নিশ্চয়তা নয়। Build সফল, তবে Vite-এর **508.37 kB** chunk warning আছে। Python 3.11.2 ও offline pip উপস্থিত থাকায় দুই optional independent-parser cross-check skip হয়নি; Node v22.22.3, lock-এ Acorn 8.18.0।

`npm audit` এবং সেটি অন্তর্ভুক্ত করা composite `npm run verify` **NOT RUN**: সেটি networked external security service-এ যায়। বাকি offline ধাপ আলাদাভাবে বাস্তবে চালানো হয়েছে। Full mounted-Dataset E2E, বাস্তব গ্রাহক scan, live credential validity, production deployment rehearsal ও স্বাধীন মানব review **NOT RUN**।

**Paid/vendor status — NOT RUN:** Burp Suite Professional, Invicti, Snyk, XBOW, Horizon3 NodeZero, Pentera। CLI নাম PATH-এ পাওয়া যায়নি; পূর্ব-বিদ্যমান বৈধ license/access বা নিরাপদ vendor environment প্রতিষ্ঠিত হয়নি। কোনো vendor চালানো, score বানানো বা তুলনামূলক শ্রেষ্ঠত্ব দাবি করা হয়নি।

## ৮. পুনরুৎপাদন ও evidence

সব output কেবল synthetic fixture ও sanitized metadata; কোনো fixture source বা synthetic secret-এর পূর্ণ মান result artifact-এ নেই। `fixture-check.mjs`-এর জন্য সাধারণ dev dependencies, Python 3 এবং offline pip-এর vendored packaging দরকার। `audit-dataset-archive.py` পিন করা user-owned archive stream করে; `--archive` দিয়ে আগে থেকেই থাকা সঠিক archive পড়লে network লাগে না।

```bash
# Scanner-output-বিহীন ground-truth cross-check; দুইবারের JSON তুলনা
node benchmarks/independent-validation/fixture-check.mjs > /tmp/fixture-1.json
node benchmarks/independent-validation/fixture-check.mjs > /tmp/fixture-2.json
cmp /tmp/fixture-1.json /tmp/fixture-2.json

# Existing test-only oracle ও সম্পূর্ণ scanner benchmark
node --import tsx benchmarks/accuracy-v2/verify-oracle.mjs
node --import tsx benchmarks/accuracy-v2/run.mjs > /tmp/run-1.json
node --import tsx benchmarks/accuracy-v2/run.mjs > /tmp/run-2.json
cmp /tmp/run-1.json /tmp/run-2.json
DROBON_BENCHMARK_CASE_ID=SAST-04 node --import tsx benchmarks/accuracy-v2/run.mjs

# Pinned Dataset: RAM-only read; কোনো Dataset file লেখা হয় না
python3 scripts/audit-dataset-archive.py > /tmp/dataset-accounting.json

# Regression ও offline checks
npm run test
npm run typecheck
npm run lint
npm run build
npm run check:boundaries
npm run check:repo-integrity
node scripts/check-no-secrets.mjs --self-test
npm run check:secrets
npm run check:release-evidence
git diff --check
```

- Corpus manifest SHA-256: `8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6`। এটি fixture, target, `testData.ts` ও `accuracy-v2/rules.mjs` pin করে; ওই module-এর বাইরে imported SCA rule-কে একা pin করে না। Runner-এর আলাদা inherited SCA rule SHA-256 `b9ee26e96f5022c8e113cbd7430cde44321e7c78ecbc964d3f4cf84aecbd8e2b`। কোনো pin reviewer identity, scanner implementation বা সব tools-এর correctness প্রমাণ করে না।
- [পৃথক fixture checker](../benchmarks/independent-validation/fixture-check.mjs), SHA-256 `558378ebf0db3c4e80d14a71b1a8538111ee5e11e9f32299cad3b1dae5295600`; [তার sanitized ফল](../benchmarks/independent-validation/fixture-check-results.json), SHA-256 `c9ef9f2c8ddb282e55628e760129904bd177b83c55ff124ac5ab065ff57985e2`।
- [সর্বশেষ Drobon case observations](../benchmarks/independent-validation/drobon-results.json); [authored oracle ফল](../benchmarks/independent-validation/oracle-results.json); [Dataset accounting ও RAM-only probe](../benchmarks/independent-validation/dataset-accounting.json)। এগুলো নতুন Main App evidence artifact, Dataset repository file নয়।
- পূর্বের frozen ২১-case before/after ও Dataset diagnostic: [baseline](SCANNER_ACCURACY_BASELINE_2026-10-31.md), [SCA exceptions](SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md), [prior corpus report](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md)। আগের artifact-এ `sourceLocationCorrect`-এর অতিরিক্ত দাবি সংশোধনের পূর্ববর্তী; semantic location proof হিসেবে ব্যবহার করবেন না।

## ৯. নয়টি completion fact ও release blocker

1. **Independent validation:** ৬২/৬২ scanner-free mechanical agreement; তার মধ্যে ৬টি unknown। স্বাধীন/blinded মানব review **০/৬২**।
2. **Oracle/fixture:** দুই shell oracle-এর false-positive সম্ভাবনা, in-range line-এর অতিরিক্ত correctness claim, checker-এর positional-argument false-negative এবং manifest-এর inherited-rule pin gap ঠিক করা হয়েছে; environment-dependent case-এর শর্ত প্রকাশ।
3. **বাস্তব scanner defect:** production XML reader-এর তিন শ্রেণির malformed acceptance ঠিক। `SAST-04`-এর নির্দিষ্ট shell-label FP এখনও আছে; blanket suppression নিরাপদ নয়।
4. **অবশিষ্ট:** ২ FP, ২ test-rule scope FN, ৯ unassessed, ৬ unknown; বাস্তব issue-level duplicate ও exact source-location human review বাকি।
5. **Test:** full offline ১,৭৩৭/১,৭৩৭; targeted ৩৩/৩৩, ১১৭/১১৭ ও privacy ২৭/২৭; fail/skip ০। দুই ৬২-case run একই। Networked dependency audit, ছয় vendor ও real-target/E2E test NOT RUN।
6. **Production NO-GO:** সাধারণ বহু-process/host single-writer persistence, historic sensitive data-at-rest, Partner cross-process transaction/provenance, legacy DAST authorization, incomplete scanner/Dataset coverage, স্বাধীন benchmark এবং deployment/recovery rehearsal বাকি। বর্তমান Linux lease কেবল কিছু cooperating process/network namespace রক্ষা করে।
7. **Main App files:** এই phase-এ ১৪টি path পরিবর্তিত/নতুন: ১ production reader, ৪ বিদ্যমান benchmark file, ২ benchmark helper/checker, ২ test, ৪ sanitized JSON artifact, ১ report। এটি পূর্ববর্তী phase-এর সব পরিবর্তনের সংখ্যা নয়।
8. **Dataset:** ৩,৮২৯ matched / ১৬৪ path-blocked / ৮ unrenderable, partial; Dataset ও database-এ কোনো পরিবর্তন হয়নি।
9. **Worktree:** আগের ২২১টি changed/untracked path-এর ২১৬টির hash অপরিবর্তিত; ৫টিতে কেবল এই phase-এর প্রয়োজনীয় সংযোজন/সংশোধন, ০ missing। Branch `arena/0056e643-drobon`, HEAD `e763eb938d67d4163dca817716231794bb45e372`; **কোনো stage, commit, push, merge বা branch switch নয়**।
