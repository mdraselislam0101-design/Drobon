# SCA-এর অমীমাংসিত case — ৩১ অক্টোবর ২০২৬

## ফল ও সীমা

Pinned Dataset commit `3986082b22007b47930da3bc99be9c2f2b036080`; read-only RAM stream-এর archive SHA-256 `d1aac0cb5f6165b583d01b776d51018435441f771bd3e41b94f7fdb776b1f71d`। Dataset checkout clone, extract, modify বা তৈরি করা হয়নি। এটি Dataset-authored declaration fixture-এর সঙ্গে engine-এর মিল; স্বাধীন vulnerability truth, advisory/CVE accuracy বা mounted-Dataset HTTP end-to-end পরীক্ষা নয়।

| ৪,০০১টি declaration fixture | সংখ্যা | ব্যাখ্যা |
|---|---:|---|
| Uploadable, render ও evaluate করে প্রত্যাশা মিলেছে | ৩,৮২৯ | সীমিত fixture conformance, real-world accuracy নয় |
| Production source-path নীতিতে blocked | ১৬৪ | pass নয়; শুধু gate-বাইরে reader diagnostic |
| নির্ভরযোগ্য raw fixture বানানো যায়নি | ৮ | pass নয়; বাস্তব parser verdict অজানা |
| Evaluated mismatch / parser failure | ০ / ০ | বাকি ১৭২টি বাদ রেখে গণনা |

আগের পর্যায়ে স্পষ্ট খালি pip option গ্রহণ ও inventory-র অসম্পূর্ণ input `PARTIAL` দেখানোর সংশোধন করা হয়েছে। এই পর্যায়ে XML numeric reference একবার decode ও অসমাপ্ত/অবৈধ XML subset প্রত্যাখ্যানের নির্দিষ্ট ত্রুটি ঠিক হয়েছে; তা এই ১৭২টি case production-এ pass করায়নি। Upload, hidden-path ও credential-file policy অপরিবর্তিত।

## প্রতিটি ১৬৪টি blocked case

নিচে test index **zero-based**। প্রতিটি সারিতে `PATH_BLOCKED` মানে production upload/scan হয়নি: path-এর অন্তত একটি segment dot দিয়ে শুরু (`HIDDEN_PATH_SEGMENT`)। `MATCH` কেবল একই reader ও evaluator-কে upload gate-এর বাইরে RAM-এ চালিয়ে Dataset-এর authored expectation-এর সঙ্গে মিল; এটি production pass নয়। `true`/`false` authored expectation, স্বাধীন truth নয়। JSON evidence-এ একই প্রতিটি case-এর parser ও সব status আছে: [`sca-case-diagnostics-after.json`](../benchmarks/local/results/sca-case-diagnostics-after.json); আগে: [`sca-case-diagnostics-before.json`](../benchmarks/local/results/sca-case-diagnostics-before.json)।

| Rule | Index | Artifact | Expected | Production status / কারণ | Reader-only |
|---|---:|---|---|---|---|
| `DPK-SCA-0073` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0073` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0073` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0073` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0074` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0074` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0074` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0074` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0075` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0075` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0075` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0075` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0076` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0076` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0076` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0076` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0077` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0077` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0077` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0077` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0078` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0078` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0078` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0078` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0079` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0079` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0079` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0079` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0080` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0080` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0080` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0080` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0081` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0081` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0081` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0081` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0082` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0082` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0082` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0082` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0083` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0083` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0083` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0083` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0084` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0084` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0084` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0084` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0085` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0085` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0085` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0085` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0086` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0086` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0086` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0086` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0087` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0087` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0087` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0087` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0088` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0088` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0088` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0088` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0089` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0089` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0089` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0089` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0090` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0090` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0090` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0090` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0091` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0091` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0091` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0091` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0092` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0092` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0092` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0092` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0093` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0093` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0093` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0093` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0094` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0094` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0094` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0094` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0107` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0107` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0107` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0107` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0142` | 0 | `.pypirc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0142` | 1 | `.pypirc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0142` | 2 | `.pypirc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0142` | 3 | `.pypirc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0143` | 0 | `.pypirc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0143` | 1 | `.pypirc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0143` | 2 | `.pypirc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0143` | 3 | `.pypirc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0651` | 0 | `.yarnrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0651` | 1 | `.yarnrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0651` | 2 | `.yarnrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0651` | 3 | `.yarnrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0691` | 0 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0691` | 1 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0691` | 2 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0691` | 3 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0760` | 0 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0760` | 1 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0760` | 2 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0760` | 3 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0777` | 0 | `.Rprofile` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0777` | 1 | `.Rprofile` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0777` | 2 | `.Rprofile` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0777` | 3 | `.Rprofile` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0778` | 0 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0778` | 1 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0778` | 2 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0778` | 3 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0779` | 0 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0779` | 1 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0779` | 2 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0779` | 3 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0788` | 0 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0788` | 1 | `.cargo/config.toml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0788` | 2 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0788` | 3 | `.cargo/config.toml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0789` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0789` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0789` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0789` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0790` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0790` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0790` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0790` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0791` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0791` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0791` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0791` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0793` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0793` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0793` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0793` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0794` | 0 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0794` | 1 | `.npmrc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0794` | 2 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0794` | 3 | `.npmrc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0795` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0795` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0795` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0795` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0796` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0796` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0796` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0796` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0797` | 0 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0797` | 1 | `.yarnrc.yml` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0797` | 2 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0797` | 3 | `.yarnrc.yml` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0978` | 0 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0978` | 1 | `.condarc` | true | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0978` | 2 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |
| `DPK-SCA-0978` | 3 | `.condarc` | false | PATH_BLOCKED / HIDDEN_PATH_SEGMENT | MATCH |

## প্রতিটি ৮টি unrenderable case

সবগুলো `nuget.config` / XML। Production reader একই raw source list থেকে `sources` ও `packageSources.add` তৈরি করে। Authored object নিচের alias সম্পর্ক ভাঙে; ভিন্ন raw XML দিয়ে একই object বিশ্বস্তভাবে পুনরুৎপাদন করা যায় না। তাই renderer অনুমান বা Dataset বদলায়নি। `UNRENDERABLE` হলো fixture-র সীমা, parser-pass বা vulnerability-negative নয়।

| Rule | Index | Expected | অবস্থা | নির্দিষ্ট structural কারণ |
|---|---:|---|---|---|
| `DPK-SCA-0679` | 1 | true | UNRENDERABLE | `sources`-এ ১টি entry, `packageSources.add` স্পষ্ট খালি |
| `DPK-SCA-0679` | 3 | false | UNRENDERABLE | `sources`-এ ১টি entry, `packageSources.add` স্পষ্ট খালি |
| `DPK-SCA-0689` | 0 | true | UNRENDERABLE | দুই alias-এ ১টি করে entry, কিন্তু key/value ভিন্ন |
| `DPK-SCA-0689` | 1 | true | UNRENDERABLE | দুই alias-এ ১টি করে entry, কিন্তু key/value ভিন্ন |
| `DPK-SCA-0689` | 3 | false | UNRENDERABLE | দুই alias-এ ১টি করে entry, কিন্তু key/value ভিন্ন |
| `DPK-SCA-0753` | 0 | true | UNRENDERABLE | `sources`-এ ১টি entry, `packageSources.add` অনুপস্থিত |
| `DPK-SCA-0753` | 1 | true | UNRENDERABLE | `sources`-এ ১টি entry, `packageSources.add` অনুপস্থিত |
| `DPK-SCA-0753` | 3 | false | UNRENDERABLE | দুই alias-এ ১টি করে entry, কিন্তু key/value ভিন্ন |

## পরবর্তী সিদ্ধান্ত

১. Dataset মালিকের আলাদা অনুমোদিত review-এ সংশ্লিষ্ট authored alias expectation যাচাই; এই কাজে Dataset পরিবর্তন নয়। ২. Dotfile ingestion চাইলে credential exposure, traversal, symlink, quota এবং audit নিয়ে পৃথক security design/approval; বিদ্যমান policy শিথিল না করা। ৩. আরও বাস্তব parser differential tests, malformed/unsupported `PARTIAL` propagation এবং authorized read-only mounted-Dataset E2E চালানো। সব ১৭২ case অমীমাংসিত থাকে যতক্ষণ বাস্তব production পথ ও স্থির ground truth যাচাই না হয়।
