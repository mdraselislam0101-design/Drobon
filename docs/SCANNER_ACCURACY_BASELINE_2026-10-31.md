# Scanner accuracy: পরিবর্তনের আগের পুনরুৎপাদন — ৩১ অক্টোবর ২০২৬

এটি implementation পরিবর্তনের **আগের** evidence। ২১টি মূল case প্রত্যেকটি আলাদা Node process ও নতুন engine instance-এ চালানো হয়েছে; ফল আগের পূর্ণ run-এর সঙ্গে ২১/২১ verdict-এ মেলে। সম্পূর্ণ sanitized case-level observations: [`accuracy-before-isolated.json`](../benchmarks/local/results/accuracy-before-isolated.json)। Case label লেখক-নির্ধারিত; একই লেখকের mechanical oracle স্বাধীন মানব review নয়। DAST mock resolver/transport, SCA declaration-only, আসল credential/গ্রাহক source/বাহ্যিক লক্ষ্য নয়।

| Family | TP | FP | TN | FN | UNASSESSED | UNKNOWN_TRUTH |
|---|---:|---:|---:|---:|---:|---:|
| SAST | 4 | 2 | 2 | 0 | 0 | 0 |
| Secrets | 1 | 0 | 2 | 1 | 0 | 0 |
| SCA declaration | 1 | 0 | 1 | 1 | 0 | 1 |
| DAST passive | 1 | 0 | 1 | 1 | 2 | 0 |

## প্রতিটি পার্থক্যের নির্দিষ্ট কারণ

- **SAST-02, FP:** test-only `DG-SAST-001` lexical regex যেকোনো quoted string-এর পরে `+` দেখে; দুই operand স্থির কি না যাচাই করে না। একই input-এ shallow, structured ও project AST তিনটির কোনো candidate নেই। Pinned production pack-এর সব accepted rule দিয়ে পৃথক in-memory engine run-এ এই input-এ 0 finding। তাই এটিকে production Dataset rule-এর প্রমাণিত FP বলা যায় না।
- **SAST-04, FP:** একই input-এ lexical match নেই; shallow, structured ও project AST তিনটিই request-derived `execFile` argv-কে command category-তে ফেলে। Project pass একই finding-এর metadata-কে PROJECT করে। এই নির্দিষ্ট `echo`/no-shell fixture-এ shell-command interpolation হয় না; কিন্তু dynamic executable, interpreter, `shell:true`, অন্য program-এর argument injection ও shadowed binding সাধারণত নিরাপদ নয়। Pinned pack সহ engine-ও `DPK-SAST-044` category reporter থেকে 1 HIGH finding দেয়; exact rule pattern-এর প্রমাণ নয়। সব `execFile` suppress করা নিরাপদ নয়।
- **SECRET-02, FN:** line matcher পৃথক literal জোড়া লাগায় না; পরীক্ষার `DG-SEC-002` একক literal-এ match করে, বিভক্ত literal-এ করে না। Pinned pack সহ engine-এ `DPK-SEC-001` একক literal-এ 1টি, বিভক্ত literal-এ 0টি finding। এটিও আসল credential/live validity নয়।
- **SCA-03, FN:** নির্বাচিত test rule শুধু `dependencies.*`; fixture-এ wildcard `devDependencies.*`। তাই এটি test-rule scope mismatch, নির্বিচারে evaluator বদলানোর কারণ নয়। Pinned pack-এর in-memory SCA engine-এ `DPK-SCA-0718` এই dev field-এ match করে; অন্য 4টি finding ভিন্ন missing-field checks। Advisory source অনুপস্থিত বলে পূর্ণ SCA run PARTIAL।
- **SCA-04, UNKNOWN_TRUTH:** অসম্পূর্ণ JSON; parser valid declaration document তৈরি করতে পারে না, declaration check সম্পন্ন নয়। Pinned pack সহ engine-এ partial, 0 finding; এটিকে TN বা pass বলা যায় না।
- **DAST-02, FN:** নির্বাচিত test rule `missing-response-header` কেবল অনুপস্থিত/শূন্য মান দেখে, উপস্থিত `invalid` মূল্য নয়। Pinned pack-এর `DPK-DAST-005` presence check এটিকে ধরে না, কিন্তু ভিন্ন value-aware `DPK-DAST-073` in-memory/mock engine-এ ধরে; তাই নির্বাচিত test rule-এর FN-কে সব production rule-এর FN বলা যায় না।
- **DAST-04/05, UNASSESSED:** এই run passive; reflection case-এ active query প্রয়োজন। Production URL/query এবং target authorization policy অক্ষত; কোনো পরীক্ষাকে স্বয়ংক্রিয় pass বা negative ধরা হয়নি।

পূর্ণ pack scope ও engine facts: [`dataset-scope-before.json`](../benchmarks/local/results/dataset-scope-before.json)। Dataset commit `3986082b22007b47930da3bc99be9c2f2b036080`, archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`; read-only RAM stream, checkout/extraction/write নয়। এটি mounted-Dataset E2E বা independent benchmark নয়।

## অতিরিক্ত স্বাধীন mechanical counterexample (পরিবর্তনের আগেই পরীক্ষা)

1. NuGet XML-এর `http&#58;//registry.invalid/v3` valid numeric character reference। Python standard-library `xml.etree.ElementTree` value-কে `http://registry.invalid/v3` পড়েছে; বর্তমান bounded Main App XML reader `http&#58;//...` রেখে দিয়েছে। ফলে `^http:` declaration check miss করতে পারে। কোনো network access বা package install হয়নি।
2. `<project><name>fixture</name></project><broken` Python XML parser প্রত্যাখ্যান করেছে; বর্তমান reader অসমাপ্ত trailing tag উপেক্ষা করে object দিয়েছে। Malformed input-কে নির্ণীত বলা অনির্ভরযোগ্য।
3. DAST observation-এ একই header-এর `X-Frame-Options: DENY` ও `x-frame-options: ''` থাকলে current lowercasing map দ্বিতীয়টির দ্বারা প্রথমটি overwrite করে এবং missing-header FP দেয়। HTTP header name case-insensitive; evaluator-এ পৃথক value একত্রে রাখতে হবে, string join করে নয়। Node-এর production HTTP transport সাধারণত নাম lowercase করে; এটি evaluator/mixed-case observation boundary-র bug, `DAST-02`-এর একই কারণ নয়।

## ১৬৪ + ৮ unresolved

[`sca-case-diagnostics-before.json`](../benchmarks/local/results/sca-case-diagnostics-before.json)-এ 164টি case-এর **প্রত্যেকটির** rule ID, zero-based test index, artifact, parser, expected value, production `PATH_BLOCKED`, `HIDDEN_PATH_SEGMENT` reason ও reader-only diagnostic আছে। সব 164 reader-only expectation মিলে, কিন্তু production upload/scan blocked থাকায় কোনোটি pass নয়। আটটি XML case-এর প্রত্যেকটির expected ও alias-conflict structural reason একই ফাইলে `reader.otherGaps`-এ আছে। মোট accounting: 3,829 matching rendered scan cases / 164 blocked / 8 unrenderable / 0 parser failure; 4,001 total। এটা Dataset-authored fixture conformance, স্বাধীন accuracy নয়।

Production NO-GO: persistence/single-writer ও Partner transaction/provenance, historical sensitive data, legacy DAST authorization, mounted-Dataset E2E ও স্বাধীন benchmark/deployment rehearsal এখনও blocker।
