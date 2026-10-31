# Synthetic benchmark corpus ও case ফল — ৩১ অক্টোবর ২০২৬

## কী পরীক্ষা করা হয়েছে

Frozen ২১টি এবং নতুন ৪১টি মিলিয়ে **৬২টি** নিজস্ব synthetic case: SAST ২১, Secrets ১৫, SCA ১৫ ও DAST ১১। এতে positive/negative, পূর্বের FP/FN, comments, placeholders, bounded literal join, XML reference, malformed, unsupported extension এবং policy-blocked উদাহরণ আছে। বাস্তব credential, গ্রাহক code বা external dataset ব্যবহার হয়নি। এটি নতুন স্বাধীন holdout নয়; Rules/cases একই উন্নয়নকাজে লেখা এবং কিছু test-only।

Corpus manifest SHA-256 `8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6`; মূল ২১-case digest `26c75d9c3376c560ab1ec7c349dc99a083b8f8a5f00cfaa7ffe91eb485923220` অপরিবর্তিত। Pin source content hash, case metadata, local target ও test-rule files অন্তর্ভুক্ত করে; Main App সম্পূর্ণ source tree, installed dependencies বা deployment fingerprint নয়। Runtime Node `v22.22.3`। Result JSON SHA-256 `9e0f248ec7d56fafb54359ae31424949273bbc7bc79e8a7e7c6caf53ff6ce163`; oracle JSON SHA-256 `a939a70f4f276deaf6a07af58c10ef359792cc46ac25a6d1cf88c52ac2c14e9c`। একই configuration-এ runner দুবার byte-identical।

অ্যাপ scanner থেকে আলাদা mechanical oracle: নিজস্ব pinned fixture-এর fake sink-সহ Node execution, local HTTP response, JSON parse এবং Python standard-library XML/Python AST দিয়ে authored expectation **৬২/৬২** মেলে। এটি একই কাজের লেখকের mechanical cross-check; **স্বাধীন মানব review হয়নি**, exploitability বা deployed environment প্রমাণ নয়। `vm` নিরাপত্তা sandbox নয়; শুধুমাত্র pinned নিজস্ব fixture চালাতে হবে, customer/downloaded code কখনো নয়।

Drobon runner বিদ্যমান engine-এর সঙ্গে test-only rules inject করে; DAST mock resolver/transport, production localhost/private/query guard অক্ষত। SCA-তে declaration hygiene, advisory/CVE detection নয়। ৫৯টি report-producing observation-এ নির্বাচিত integrity/count ও source/synthetic-secret leak checks ৫৯/৫৯ মেলে—এটি সর্বাঙ্গীণ privacy guarantee নয়। Severity rule/category থেকে পাওয়া, স্বাধীনভাবে validate করা হয়নি; alert-level precision, exploitability, performance বা বাস্তব product-wide accuracy মাপা হয়নি।

## Provisional case-level স্কোর

| Family | মোট | TP | FP | TN | FN | UNASSESSED | UNKNOWN_TRUTH | Assessed case precision | Assessed case recall |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| SAST | ২১ | ১০ | ২ | ৭ | ০ | ১ | ১ | ১০/১২ | ১০/১০ |
| Secrets | ১৫ | ৬ | ০ | ৪ | ০ | ৪ | ১ | ৬/৬ | ৬/৬ |
| SCA declaration | ১৫ | ৪ | ০ | ৫ | ১ | ১ | ৪ | ৪/৪ | ৪/৫ |
| DAST passive | ১১ | ৩ | ০ | ৪ | ১ | ৩ | ০ | ৩/৩ | ৩/৪ |
| **মোট** | **৬২** | **২৩** | **২** | **২০** | **২** | **৯** | **৬** | — | — |

TP/FP/TN/FN কেবল labelled ও assessed case-এ গণিত; unassessed বা unknown কখনো TN/pass নয়। একই case-এ বহু finding একটি binary verdict; অন্য alert বিচার ও broad class coverage দাবি করা হয় না। একটি denominator-এ ভালো ফল মানে সম্পূর্ণ scanner coverage বা ১০০% security নয়।

## ৬২টি পৃথক case

`+`/`−` হলো authored expected detection; `?` অজানা truth। Result exact mapping/evidence metadata: [`drobon-results.json`](../benchmarks/accuracy-v2/drobon-results.json); [`oracle-results.json`](../benchmarks/accuracy-v2/oracle-results.json)। প্রতিটি রায়ের উদ্দেশ্য/সীমা নিচে; বিস্তারিত input নিজের fixture থেকে reproducible।

| Case | প্রত্যাশা | ফল | সংক্ষিপ্ত কারণ/সীমা |
|---|---|---|---|
| `SAST-01` | + | TP | Input shell command-এ যুক্ত |
| `SAST-02` | − | FP | স্থির string জোড়ায় test-only lexical FP |
| `SAST-03` | + | TP | দুই লাইনে input থেকে shell |
| `SAST-04` | − | FP | নির্দিষ্ট shell ছাড়া argv-তে category AST FP |
| `SAST-05` | + | TP | SQL text-এ input সংযুক্ত |
| `SAST-06` | − | TN | SQL parameter আলাদা |
| `SAST-07` | + | TP | HTML sink-এ unescaped input |
| `SAST-08` | − | TN | কেবল comment-এর ভেতর sink |
| `SECRET-01` | + | TP | একটি synthetic key-shaped literal |
| `SECRET-02` | + | TP | দুটি স্থির literal-এ synthetic shape; সংশোধনের পরে ধরা |
| `SECRET-03` | − | TN | স্পষ্ট example placeholder |
| `SECRET-04` | − | TN | কেবল environment lookup |
| `SCA-01` | + | TP | Runtime dependency wildcard |
| `SCA-02` | − | TN | নির্দিষ্ট runtime version |
| `SCA-03` | + | FN | Dev wildcard নির্বাচিত runtime-only rule-এর বাইরে |
| `SCA-04` | ? | UNKNOWN_TRUTH | অসম্পূর্ণ JSON; declaration truth অজানা |
| `DAST-01` | + | TP | নিরাপত্তা header অনুপস্থিত |
| `DAST-02` | + | FN | ভুল header value; নির্বাচিত rule শুধু presence দেখে |
| `DAST-03` | − | TN | সঠিক header value |
| `DAST-04` | + | UNASSESSED | Unsafe reflection; active query এই passive run-এ নেই |
| `DAST-05` | − | UNASSESSED | Escaped reflection; active query এই passive run-এ নেই |
| `AX-SAST-01` | + | TP | Input interpolation থেকে exec |
| `AX-SAST-02` | + | TP | Executable নাম নিজেই user-controlled |
| `AX-SAST-03` | + | TP | Explicit shell option ও input |
| `AX-SAST-04` | + | TP | Shell interpreter-এ constructed command |
| `AX-SAST-05` | − | TN | স্থির program ও argument |
| `AX-SAST-06` | − | TN | Input ছাড়া স্থির shell text |
| `AX-SAST-07` | − | TN | কেবল comment-এর মধ্যে source-like text |
| `AX-SAST-08` | + | TP | SQL text-এ input interpolation |
| `AX-SAST-09` | − | TN | SQL parameter আলাদা |
| `AX-SAST-10` | + | TP | HTML sink-এ unescaped input |
| `AX-SAST-11` | − | TN | HTML নয়, text sink |
| `AX-SAST-12` | + | UNASSESSED | Source unsupported text extension-এ |
| `AX-SAST-13` | ? | UNKNOWN_TRUTH | Malformed JavaScript; flow truth অজানা |
| `AX-SEC-01` | + | TP | একক synthetic key-shaped literal |
| `AX-SEC-02` | + | TP | দুটি unescaped static literal |
| `AX-SEC-03` | + | TP | তিন literal এবং parentheses |
| `AX-SEC-04` | − | TN | Literal fragments কেবল comment-এ |
| `AX-SEC-05` | + | UNASSESSED | Oracle-এ environment খালি; dynamic folding unsupported |
| `AX-SEC-06` | + | UNASSESSED | Reconstruction-এ escape দরকার; unsupported |
| `AX-SEC-07` | − | TN | স্পষ্ট placeholder fragments |
| `AX-SEC-08` | + | TP | Static join-এ খালি অংশ |
| `AX-SEC-09` | + | UNASSESSED | Python static folding unsupported |
| `AX-SEC-10` | ? | UNKNOWN_TRUTH | Malformed source; runtime truth অজানা |
| `AX-SEC-11` | + | UNASSESSED | Ignored dependency directory; scope-এর বাইরে |
| `AX-SCA-01` | + | TP | Dev wildcard test-only dev rule-এ |
| `AX-SCA-02` | − | TN | Dev dependency fixed version |
| `AX-SCA-03` | + | TP | Runtime dependencies-এ wildcard |
| `AX-SCA-04` | − | TN | Runtime wildcard field অনুপস্থিত |
| `AX-SCA-05` | ? | UNKNOWN_TRUTH | Malformed JSON; truth অজানা |
| `AX-SCA-06` | + | UNASSESSED | Bare unbounded requirement; নির্বাচিত npm rule artifact-এর বাইরে |
| `AX-SCA-07` | + | TP | XML numeric reference decode করলে HTTP source |
| `AX-SCA-08` | − | TN | HTTPS source, নির্বাচিত HTTP check-এর negative |
| `AX-SCA-09` | − | TN | Hex reference decode করলে HTTPS |
| `AX-SCA-10` | ? | UNKNOWN_TRUTH | অজানা XML entity; malformed truth |
| `AX-SCA-11` | ? | UNKNOWN_TRUTH | অসমাপ্ত trailing XML markup; truth অজানা |
| `AX-DAST-01` | + | TP | Value-aware test rule ভুল header value ধরে |
| `AX-DAST-02` | − | TN | Value-aware rule-এ সঠিক value negative |
| `AX-DAST-03` | − | TN | Value-only rule-এর বাইরে অনুপস্থিত value; absence পৃথক |
| `AX-DAST-04` | + | TP | Presence-only rule-এ অনুপস্থিত header |
| `AX-DAST-05` | − | TN | Presence-only rule-এ valid header |
| `AX-DAST-06` | − | UNASSESSED | Safe lab response কিন্তু query target policy-তে blocked |

## নিরাপদ পুনরাবৃত্তি

Main App root-এ পূর্বে ইনস্টল করা dependencies এবং Python 3 দরকার। Dataset বা অন্য কোনো Git checkout-এ output লিখবেন না। `verify-oracle` নিজস্ব local HTTP server অল্প সময়ের জন্য loopback-এ চালায়; scanner runner network ছাড়াই mock ব্যবহার করে।

```sh
npm run build --workspace @drobon/shared
node --import tsx benchmarks/accuracy-v2/verify-oracle.mjs > /tmp/drobon-v2-oracle.json
node --import tsx benchmarks/accuracy-v2/run.mjs > /tmp/drobon-v2-results.json
npm run test --workspace @drobon/api -- test/accuracyV2.test.ts test/localBenchmark.test.ts
# শুধু নতুন disposable, Git/Dataset-এর বাইরের directory:
parent="$(mktemp -d /tmp/drobon-v2-lab.XXXXXX)"
node benchmarks/accuracy-v2/materialize.mjs "$parent/corpus"
```

Materializer existing destination overwrite করে না, `.git` ancestor ও `Drobon-Dataset` নামের path প্রত্যাখ্যান করে, private permissions চায়; operator-কে প্রকৃত destination disposable এবং Dataset-এর বাইরে নিশ্চিত করতে হবে। ৫১টি source/dependency case পৃথক project, ১১টি HTTP case একই intentional lab-এর নির্দিষ্ট path/observation। এই corpus-এ ignored directory (`AX-SEC-11`) ইচ্ছাকৃত scope control। কখনো fixture install/execute/package resolve করবেন না (শুধু নিজস্ব pinned oracle-এর fake-sink verification ব্যতিক্রম)। Expanded corpus-এর একটি case correction-এর পরে নতুন digest স্থির করা হয়েছে; ফলে পূর্বের v2 hash-এর ফলের সঙ্গে সরাসরি তুলনা নয়। ভবিষ্যৎ পরিবর্তনে blind human review, নতুন version ও untouched holdout দরকার।
