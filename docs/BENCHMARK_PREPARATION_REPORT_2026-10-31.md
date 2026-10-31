# Local benchmark প্রস্তুতি ও সীমা — ৩১ অক্টোবর ২০২৬

> **সর্বশেষ সংস্করণ:** ২১-case lab-এর বাইরে এখন ৬২-case v2 corpus এবং ছয়টি পৃথক vendor readiness package আছে। নিচের পুরোনো v1 নির্দেশ ও hash ঐতিহাসিক/পুনরুৎপাদনযোগ্য; v2-এর বর্তমান পদ্ধতি এই নথির শেষে এবং [corpus রিপোর্টে](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md)। ছয় vendor-ই এখনও **NOT RUN**; autonomous benchmark প্রস্তুত নয়।

## বর্তমান অবস্থা

একটি ছোট, সম্পূর্ণ synthetic corpus ও loopback-only HTTP lab প্রস্তুত: ৮ SAST, ৪ Secrets, ৪ SCA declaration এবং ৫ DAST case। ২১টির একটি malformed-input truth unknown, দুটি DAST reflection case Drobon-এর এই passive run-এ unassessed। Source/dependency এবং secret-সদৃশ মান কৃত্রিম; কোনো আসল credential, installation, package download বা গ্রাহক code ব্যবহার করা হয়নি। SCA corpus vulnerability-advisory benchmark নয়।

একটি পৃথক mechanical oracle fake sink, `JSON.parse` ও বাস্তব loopback HTTP response দিয়ে ২১/২১ authored label পুনরায় পরীক্ষা করেছে; সেটিও একই কাজের লেখকের তৈরি, তাই **independent human ground-truth review হয়নি**। Unsafe reflection মানে marker HTML-এ অক্ষত ফেরত আসে; browser exploit independently প্রমাণ করা হয়নি। Autonomous attack-path lab, independent adjudication, vendor license ও vendor execution এখনও নেই। তাই কোনো product ranking বা proprietary parity দাবি নেই।

Input manifest SHA-256: `26c75d9c3376c560ab1ec7c349dc99a083b8f8a5f00cfaa7ffe91eb485923220`। এটি source/dependency input-এর hash এবং HTTP lab implementation-এর hash ধারণ করে। Scripts: [`benchmarks/local`](../benchmarks/local/); redacted case-level ফল: [`drobon-provisional.json`](../benchmarks/local/results/drobon-provisional.json) এবং [`mechanical-oracle.json`](../benchmarks/local/results/mechanical-oracle.json)। Raw vendor report বা সত্যিকারের secret repository-তে রাখবেন না। Corpus বদলালে oracle চালানোর আগে সম্পূর্ণ source review করে digest pin ইচ্ছাকৃতভাবে update করতে হবে। Node `vm` নিরাপত্তা sandbox নয়—শুধু এই pinned, নিজের লেখা test code চালায়; কোনো customer/untrusted code এতে চালাবেন না।

## নিরাপদ স্থানীয় পুনরাবৃত্তি

পূর্বে ইনস্টল করা project dependencies ও Node 20.11–22 ব্যবহার করুন। বাস্তব Dataset checkout-এ কোনো কিছু তৈরি/পরিবর্তন করবেন না।

```sh
# Main App root; network ছাড়া, আগে থেকে dependencies থাকা চাই
npm run build --workspace @drobon/shared
node benchmarks/local/verify-oracle.mjs
node --import tsx benchmarks/local/run-drobon.mjs > /tmp/drobon-local-results.json

# নতুন disposable parent ও তার ভেতর নতুন corpus directory
parent="$(mktemp -d /tmp/drobon-local-lab.XXXXXX)"
node benchmarks/local/materialize.mjs "$parent/corpus"
```

Materializer বিদ্যমান directory overwrite করে না, mode 0700/0600 চায়, symlink দিয়ে পৌঁছানো Git checkout-সহ কোনো Git checkout-এর মধ্যে লেখে না, এবং `Drobon-Dataset` নামের path প্রত্যাখ্যান করে। তবুও operator-কে destination সত্যিই disposable ও Dataset-এর বাইরে নিশ্চিত করতে হবে। `$parent/corpus/SAST-01`, `SAST-02` … পৃথক source project; Secrets ও SCA একইভাবে পৃথক। এক case-এর alert যেন অন্য case-এর detection না হয়, প্রতিটি আলাদা project হিসেবে scan করুন। ফাইল execute, install, dependency resolve বা network contact করার প্রয়োজন নেই।

আলাদা terminal-এ, **শুধু একই machine-এর local operator**:

```sh
LAB_PORT=0 node benchmarks/local/target.mjs
```

প্রোগ্রাম নির্বাচিত `http://127.0.0.1:<port>/lab/header-missing` দেখাবে। এটি কেবল `127.0.0.1`-এ bind করে; Internet, reverse proxy বা Arena live preview-তে প্রকাশ করবেন না। এটি ইচ্ছাকৃতভাবে unsafe reflection রাখে এবং শুধু GET/HEAD গ্রহণ করে। Fixture routes `header-missing`, `header-invalid`, `header-safe`, `reflect-unsafe`, `reflect-safe`; reflection query-তে `input` আছে। বন্ধ করতে Ctrl+C। Fake sink/oracle কোনো shell, database, credential service বা browser চালায় না।

**Drobon-vs-HTTP পার্থক্য:** উপরের Drobon runner HTTP server scan করে না। Production engine-এ explicit test-only rule, synthetic DNS resolver ও in-memory transport inject করে একই response function ব্যবহার করে; authorization/API/real DNS/TCP/loopback scan পরীক্ষা করে না। Production target policy এখনও loopback/private address নিষিদ্ধ; এজন্য তা দুর্বল করবেন না। Vendor বাস্তব loopback HTTP ব্যবহার করলে transport, host, authorization ও configuration সমান নয়—এগুলো সমাধান এবং স্বাধীন review ছাড়া ফল direct comparison নয়।

## Scoring নিয়ম

- Case ID + প্রাসঙ্গিক vulnerability class + location অনুযায়ী মানব-reviewed mapping; একটি case-এ বহু alert থাকলেও binary case metric-এ এক detection। অন্য/unmapped alert আলাদা নথিভুক্ত; তা অদৃশ্য নয়।
- TP = সত্য positive case-এ mapped detection; FP = সত্য negative case-এ mapped detection; FN = সম্পূর্ণ assessed positive case-এ detection নেই; TN = সম্পূর্ণ assessed negative case-এ detection নেই। Precision `TP/(TP+FP)`, recall `TP/(TP+FN)`; denominator শূন্য হলে `null`।
- Missing, failed, timeout, out-of-scope, অসম্পূর্ণ বা অনুমতিহীন run `UNASSESSED`; malformed/অমীমাংসিত truth `UNKNOWN_TRUTH`। এগুলোকে false বা negative বানানো যাবে না। একই category ও একই বাস্তব scope-এ metrics আলাদা রাখুন। Alert-level precision চাইলে প্রতিটি alert-এর স্বাধীন সত্যতা, duplicate এবং unmapped alert-ও review করতে হবে—বর্তমান scorer তা গণনা করে না।
- Evidence যাচাইয়ের জন্য case/location, request/response বা source-point এবং সীমা নথিভুক্ত করুন; severity-এর সঙ্গে independent adjudicator-এর rating আলাদা রাখুন। Masking privacy রক্ষা করে, কিন্তু রিপোর্টের একা exploit proof নয়। রিপোর্ট digest signature নয়। Time/memory/performance এই run-এ মাপা হয়নি।
- Synthetic corpus ছোট ও author-defined; পরীক্ষার labels/finding blind review, অন্তত দুই reviewer ও মতভেদ নিষ্পত্তির পরই স্বাধীন benchmark বলা যেতে পারে। এই সময় পর্যন্ত সব সংখ্যা provisional। Manifest hash scanner, rules, transport বা পুরো working tree-র version প্রমাণ করে না; তুলনার আগে ওই configuration ও code state আলাদাভাবে record করুন।

## অন্য পণ্যের normalized record

`node benchmarks/local/score-external.mjs /absolute/path/to/redacted-observations.json` কেবল নিচের metadata গ্রহণ করে; raw report/body/credential গ্রহণ করে না। শীর্ষ key: `schemaVersion` (`drobon.vendor-observations/v1`), `product` (নিচের enum), `version` (না-চালানো হলে `null`), `executed` (boolean), `fixtureManifestSha256` (উপরের hash), `unmappedAlertCount` (অজানা হলে `null`), `observations` (array)। `executed: false` এবং খালি observations দিলে সব applicable truth-bearing case unassessed; এটি কোনো ফল নয়।

প্রতিটি বাস্তবে পর্যালোচিত entry-তে কেবল `id`, `status` (`DETECTED`/`NOT_DETECTED`/`UNASSESSED`), `coverage` (`COMPLETE`/`PARTIAL`/`NONE`), `reasonCode`, `mappingReviewed`, `evidenceReviewed`, `matchingFindings` থাকে। Assessed entry-র `reasonCode: null`; unassessed কারণগুলোর closed list script-এ আছে। Negative-এর জন্য complete scope ও reviewed completion evidence, positive-এর জন্য reviewed mapping/evidence আবশ্যক। অজানা/duplicate ID, unrun product-এর assessed দাবি, অমিল hash, extra field এবং অসম্পূর্ণ negative scorer প্রত্যাখ্যান করে। এই metadata operator-এর দাবি—tool নিজে vendor report সত্যতা যাচাই করে না।

উদাহরণ হিসেবে কেবল **না-চালানো** record (ফল নয়):

```json
{
  "schemaVersion": "drobon.vendor-observations/v1",
  "product": "SNYK",
  "version": null,
  "executed": false,
  "fixtureManifestSha256": "26c75d9c3376c560ab1ec7c349dc99a083b8f8a5f00cfaa7ffe91eb485923220",
  "unmappedAlertCount": null,
  "observations": []
}
```

## ছয় পণ্যের বাস্তব অবস্থান ও ভবিষ্যৎ operator procedure

এই session-এ নিচের নামের executable PATH-এ পাওয়া যায়নি; GUI/cloud installation বা license আছে কি না নিশ্চিতভাবে জানা যায়নি। কোনো account, license, external service, vendor engine বা vendor scan ব্যবহার করা হয়নি। প্রতিটি ফল **NOT RUN; এই session-এ access পাওয়া যায়নি**, zero detection নয়।

সব পণ্যের জন্য: আগে পৃথক লিখিত অনুমতি, isolated disposable host, প্রত্যাশিত case list, time/request/resource budget, scanner version, rules/license, প্রযোজ্য modality ও স্থির configuration লিখুন। কেবল একই operator-controlled lab-এ চালান; ইন্টারনেট/OAST/callback, credential validation, package install, external lookup এবং target-এর বাইরে কোনো discovery নিষিদ্ধ রাখুন। Tool-এর বাধ্যতামূলক cloud, license activation বা source upload লাগলে এই local-only অনুমতিতে **থামুন**; অতিরিক্ত অনুমোদন ছাড়া চালাবেন না। Scope/egress যাচাই না হলে ফল unassessed। Vendor version অনুযায়ী official documentation/operator controls যাচাই করা লাগবে; নিচে অনুমানভিত্তিক command line বানানো হয়নি।

| পণ্য / normalized enum | প্রযোজ্য প্রাথমিক procedure ও শর্ত | আজকের ফল |
|---|---|---|
| Burp Suite Professional / `BURP_SUITE_PROFESSIONAL` | একই host-এর loopback lab-এ scope সীমাবদ্ধ; passive ও অনুমোদিত active আলাদা; Collaborator/OAST/বাইরের callback বন্ধ আছে কিনা যাচাই। প্রতিটি header/reflection case আলাদা map করুন। | NOT RUN; license/installation অজানা |
| Invicti / `INVICTI` | উপরের local HTTP scope ও request budget দিয়ে operator-এর version-specific UI ব্যবহার; cloud/control-plane দরকার হলে অনুমতি ছাড়া থামুন। | NOT RUN; access অজানা |
| Snyk / `SNYK` | প্রতিটি source/dependency corpus আলাদা; SAST, Secrets ও SCA capability/লাইসেন্স যাচাই করে পৃথক ফল। Wildcard hygiene case advisory detection-এর সমতুল্য নয়। বাধ্যতামূলক cloud/upload হলে থামুন। | NOT RUN; access অজানা |
| XBOW / `XBOW` | অনুমোদিত স্বতন্ত্র local lab, evidence review ও autonomous validation/attack-path আলাদা নকশা ছাড়া চালাবেন না; cloud প্রয়োজন কি না অজানা। | NOT RUN; উপযুক্ত autonomous lab নেই |
| Horizon3.ai NodeZero / `HORIZON3_NODEZERO` | disposable infrastructure ও exact scope/side-effect authorization ছাড়া নয়; বর্তমান একক HTTP lab তার infrastructure/path capability মাপার জন্য যথেষ্ট নয়। | NOT RUN; উপযুক্ত lab নেই |
| Pentera / `PENTERA` | disposable infrastructure, explicit operations/rollback ও scope ছাড়া নয়; বর্তমান ছোট HTTP lab দিয়ে autonomous/network validation দাবি নয়। | NOT RUN; উপযুক্ত lab নেই |

Named products-এর সব version বা license একই modality সমর্থন করে বলে ধরে নেবেন না। Unsupported সত্যিই প্রমাণিত হলে `NOT_APPLICABLE`; তথ্য না থাকলে `UNASSESSED`।

## Autonomous validation ও attack-path — আলাদা, এখনও প্রস্তুত নয়

স্বাধীন reviewer দ্বারা যাচাইকৃত একটি bounded, disposable multi-step graph, known positive/negative paths, host isolation, নিষিদ্ধ operation তালিকা, cleanup/recovery, approval gate ও audit evidence আগে প্রয়োজন। আলাদাভাবে মাপতে হবে (ক) নিরাপদ validation-এর প্রমাণ ও reproducibility, (খ) পূর্ণ/আংশিক attack-path discovery এবং ভুল path, (গ) scope/side-effect violations। এই repository-তে এখন কোনো autonomous attack engine বা automatic fix/deployment তৈরি করা হয়নি; ভবিষ্যৎ design-ও human approval ছাড়া customer system পরিবর্তন করতে পারবে না।

## সর্বশেষ v2 readiness ও পৃথক package

৬২টি authored case (৫১ source/dependency, ১১ HTTP); manifest SHA-256 `8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6`। Mechanical oracle ৬২/৬২ authored expectation মিলিয়েছে, independent human review হয়নি। পূর্ণ case-level verdict, bounds, reproduction এবং Drobon-এর provisional ফল [corpus রিপোর্টে](SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md)। Engine runner test-only rules/mock DAST ব্যবহার করে; বাস্তব HTTP vendor run বা সমতুল্য configuration নয়।

| Product | নির্দিষ্ট package | প্রয়োগযোগ্যতা যাচাইয়ের সীমা | অবস্থা |
|---|---|---|---|
| Burp Suite Professional | [`burp-suite-professional`](../benchmarks/vendor-packages/burp-suite-professional/README.md) | ১১ HTTP case সম্ভাব্য; passive/active আলাদা | NOT RUN |
| Invicti | [`invicti`](../benchmarks/vendor-packages/invicti/README.md) | ১১ HTTP case সম্ভাব্য; cloud/OAST নিয়ন্ত্রণ অজানা | NOT RUN |
| Snyk | [`snyk`](../benchmarks/vendor-packages/snyk/README.md) | ৫১ source/dependency case, modality অনুযায়ী; advisory equivalence নয় | NOT RUN |
| XBOW | [`xbow`](../benchmarks/vendor-packages/xbow/README.md) | সীমিত HTTP; autonomous/path benchmark নয় | NOT RUN |
| Horizon3.ai NodeZero | [`horizon3-nodezero`](../benchmarks/vendor-packages/horizon3-nodezero/README.md) | একক HTTP lab infrastructure/attack path মাপার উপযুক্ত নয় | NOT RUN |
| Pentera | [`pentera`](../benchmarks/vendor-packages/pentera/README.md) | multi-host, operations/rollback অনুমোদন ছাড়া উপযুক্ত নয় | NOT RUN |

সব ছয় executable-এর সংশ্লিষ্ট নাম PATH-এ পাওয়া যায়নি; GUI, cloud, license ও version অজানা। কোনো vendor চালানো হয়নি, product capability/parity বা ranking প্রমাণিত নয়। প্রতিটি package-এর `observation-template.json`-এ `executed:false`, version/null, কোনো observation নেই। বর্তমান v2 digest দিয়ে strict scorer ছয় template-ই গ্রহণ করেছে এবং প্রতিটির **৬২টি accounting row** বানিয়েছে; এটি vendor execution বা pass নয়।

```sh
# শুধু একটি NOT RUN template-এর schema/accounting যাচাই; vendor চালায় না
node benchmarks/accuracy-v2/score-external.mjs benchmarks/vendor-packages/snyk/observation-template.json
```

বাস্তব execution হলে operator-কে প্রয়োজনীয় আলাদা অনুমতি, isolation, scope, egress, product/version/license এবং evidence নিজে যাচাই করতে হবে। Negative-এ সম্পূর্ণ coverage, positive-এ reviewed mapping/evidence ছাড়া scorer assessed ফল গ্রহণ করে না; scorer operator-এর দাবির সত্যতা বা স্বাধীন adjudication যাচাই করতে পারে না। Unknown/failed/out-of-scope ফল pass নয়; alert-level unmapped count লিখতে হবে। Third-party cloud, external AI/API, package download বা customer system-এ scan এই কাজের অনুমতি নয়।
