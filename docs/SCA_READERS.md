# SCA Declaration Readers — ৯টি parser, ১,০০০টি rule

> **বর্তমান সংশোধন (2026-10-31):** ৯টি reader-এর নাম নিবন্ধিত হলেও সব document shape সম্পূর্ণ সমর্থিত নয়। আগের “১,০০০ rule scan-reachable” দাবি সঠিক ছিল না: dotfile/source-path সীমা ও bounded parser coverage আছে। Status শুধু parser ও uploadable artifact অনুযায়ী *সম্ভাব্য* eligible rule গোনে; non-JSON reader ব্যবহার করা স্ক্যান `PARTIAL`। `requirements.txt` reader স্পষ্ট খালি pip option (`--option=`) গ্রহণ করে, কিন্তু argument ছাড়া option ও অজানা directive প্রত্যাখ্যান করে। আলাদা inventory parser include, constraint, editable, bare URL বা malformed লাইন বাদ দিলে `PARTIAL` দেখায়; কোনো referenced file নিজে থেকে পড়ে না। সীমিত fixture ফল বাস্তব scanner accuracy নয়।


**তারিখ:** 2026-10-26 · **Branch:** `arena/5bb07bd8-drobon` · **Scope:** শুধু মেইন অ্যাপ (`Drobon`)। ডেটাসেট repo / ডেটাবেস / নতুন npm dependency — কিছুই নেই। বিদ্যমান SCA declaration engine-এর উপর **additive**।

> **আপনি যা চেয়েছিলেন:** "বাকি ৮ document reader → আরও ৫৬৮ rule scan-এ চলবে"।
>
> **যা পেলেন:** ৯টি parser kind-এর জন্যই bounded reader (`json`, `toml`, `yaml`, `xml`, `ini`, `properties`, `requirements`, `gradle`, `lockfile-text`)। Status-এ parser এবং uploadable artifact অনুযায়ী সম্ভাব্য rule count দেখায়, পূর্ণ coverage নয়। নতুন করে **কোনো npm dependency যোগ করা হয়নি** — সব reader নিজে লেখা, bounded, pure TypeScript।

---

## ১) আগে বনাম এখন

| | আগে | এখন |
|---|---|---|
| Readable parsers | `["json"]` | **৯টি** (dataset-এর সব kind) |
| Parser-eligible rules | JSON-এ সীমিত | Artifact upload ও subset parser-এর সীমাসাপেক্ষ |
| Non-JSON manifest | evaluate হত না | ✅ evaluate হয় (Pipfile, pom.xml, requirements.txt, go.mod …) |
| যাচাই | শুধু declared-test parity | + **round-trip reader parity** (raw text → document → evaluator) |

---

## ২) নতুন reader-গুলো কী পড়ে

| Parser | Reader | উদাহরণ artifact → normalized document |
|---|---|---|
| `toml` | sections, `[[array of tables]]`, dotted keys, arrays, inline tables | `Pipfile` → `{ packages: { requests: "*" } }`; `Cargo.toml` → `{ dependencies: { serde: { version: "*" } } }`; `pyproject.toml`, `poetry.lock`, `Cargo.lock` |
| `yaml` | indentation maps, `- ` sequences, scalars | `pubspec.yaml` → `{ dependencies: { http: "any" } }`; `.yarnrc.yml`, `pnpm-lock.yaml`, `environment.yml`, `Gemfile.lock`, `Podfile` |
| `xml` | elements + attributes, repeated children → arrays | `pom.xml` → `{ project: { dependencies: [ {groupId,…}, … ] } }`; `nuget.config`, `packages.config`, `settings.xml`, `Directory.Packages.props`, `verification-metadata.xml` |
| `ini` | `[section]`, `key = value`, `key[]` arrays, continuation lines, dotted nested sections | `.npmrc` → root keys **ও** `{config:{…}}`; `setup.cfg`, `tox.ini`, `pip.conf`, `conanfile.txt`, `go.mod` |
| `properties` | `key: value` / `key=value`, `key[]` arrays | `gradle.properties` → `{properties:{…}}`; `DESCRIPTION` → `{Package,Version,Depends:[…]}` |
| `requirements` | PEP 508 names, specifiers, `[extras]`, `@ direct-source`, `--hash=` | `requirements.txt` → `{requirements:[{name,specifier,source?,extras?,hashes?}]}` |
| `gradle` | bounded block scanner: `repositories { maven { … } }`, `dependencies { … }`, settings.gradle | `build.gradle` → `{repositories:[{name,url}], dependencies:[…]}` |
| `lockfile-text` | artifact-specific bounded line readers | `yarn.lock` → `{entries:[…]}`; `go.mod`, `go.sum`, `Gemfile`, `Gemfile.lock`, `mix.exs`, `mix.lock`, `Podfile`, `Package.swift`, `Cargo.lock` |
| `json` | `JSON.parse` (অপরিবর্তিত) | `package.json`, `composer.json`, … |

**Dispatch:** `parseDeclarationDocument(parser, artifact, content)` — কিছু artifact parser-নির্বিশেষে বিশেষ reader পায় (`go.mod` → goMod reader, `DESCRIPTION` → properties reader)।

**Design rule:** অচেনা বা প্রত্যাখ্যাত shape-কে **`undefined`** দেওয়াই লক্ষ্য; subset parser সব অচেনা syntax সবসময় শনাক্ত করতে পারে না। Scan layer প্রত্যাখ্যাত rule-কে `declarationRulesNotEvaluated`-এ গোনে; non-JSON analysis `PARTIAL`, কখনো পূর্ণ grammar coverage নয়।

**XML subset (2026-10-31):** পাঁচটি predefined reference এবং bounded decimal/hex character reference একবার decode হয়; মন্তব্য ও processing instruction উপেক্ষিত হয়। অজানা entity, অবৈধ code point, duplicate attribute, অসমাপ্ত trailing markup, DTD/entity declaration ও CDATA প্রত্যাখ্যাত। External entity expansion, network, file read বা recursive expansion নেই। Namespace এবং XML-এর সব valid construct সমর্থনের দাবি নয়; unsupported valid input-ও `PARTIAL`/not evaluated হতে পারে। Python standard-library XML parser দিয়ে সীমিত স্বাধীন mechanical cross-check হয়েছে। ৮টি NuGet conflicting-alias authored fixture এখনও render করা যায় না; এটি Dataset পরিবর্তন করে ঠিক করা হয়নি।

---

## ৩) হার্ড বাউন্ড

| সীমা | মান |
|---|---|
| Text / file | ২৫৬ KiB |
| Lines | ৮,০০০ |
| Nesting depth | ৬৪ |
| Nodes / parsed document | ২,০০০ |
| Documents / scan | ৫০ (SCA manifest cap) |
| Evaluations / scan | ১০,০০০ |
| Findings / scan | ২০০ |

কোনো network বা source-code execution নেই। Parsers bounded text-এর উপর `String.match`/`matchAll` ব্যবহার করে; subset হওয়ায় সব ফরম্যাট বোঝার নিশ্চয়তা নেই।

---

## ৪) আগের যাচাইয়ের রেকর্ড (2026-10-26; এই আপডেটের পর পুনরায় চালানো হয়নি)

`npm run verify:dataset -- --path ../Drobon-Dataset` এখন একটি নতুন **round-trip harness** চালায়: dataset-এর প্রতিটি non-JSON declared test-এর PARSED document-কে realistic raw manifest text-এ render করে (`scripts/sca-reader-fixtures.mjs`), তারপর **অ্যাপের reader** দিয়ে parse করে একই rule-এর evaluator-এ চালায়।

| মেট্রিক | ফল |
|---|---|
| Reader-declared tests | **২,২৭৩** |
| Rendered raw fixtures | **২,২৬১** |
| Parsed documents | **২,২৩৬** |
| Verdict parity (parse failure-সহ সংশোধিত হিসাব) | **৯৩.৪৯%** (২,১২৫/২,২৭৩) |
| Residual mismatches | **১১১**, পাশাপাশি ৩৭ parse failure |
| Parse failures | ৩৭ |
| **JSON / XML / properties reader** | **০ mismatch** |
| TOML ৪, YAML ৮, INI ২, requirements ৫, Gradle ৩৮, lockfile-text ৫৪ | — |

> এই historical পরীক্ষায় ১১১টি mismatch ও ৩৭টি parse failure ছিল। Mismatch মানে reader ভুল ফলও দিতে পারে; সেগুলো সবসময় `not-evaluated` হিসেবে ধরা যায় না। তাই subset-parser ব্যবহারের scan এখন `partial`। Regression gate parse failure-কেও ব্যর্থতা হিসেবে গণনা করে; এটি পূর্ণ coverage-এর দাবি নয়।

**অন্যান্য verify:** `npm run verify` **PASS ১১/১১** · `npm test` **PASS ১,৩৬৭/১,৩৬৭** (shared ১৮৩ + api ৮৯০ + worker ২৮ + web ২৬৬) · `verify:dataset` **PASS** · SCA declared-test parity **৪,০০১/৪,০০১, 0 mismatch** (অক্ষত) · ১২টি নতুন reader test + engine integration test · lint/typecheck/builds/boundaries/secrets/repo-integrity সব PASS।

---

## ৫) দুটি সৎ সীমা (গুরুত্বপূর্ণ)

1. **Dotfile artifact upload-ই করা যায় না।** Shared `SOURCE_PATH_PATTERN` dotfile reject করে। তাই `.npmrc` (২১), `.yarnrc.yml` (১০), `.pypirc` (২), `.yarnrc` (১), `.cargo/config.toml` (৩), `.Rprofile` (১), `.condarc` (৩) — **মোট ৪১টি rule structurally unreachable**। Reader থাকা সত্ত্বেও এগুলোর artifact snapshot-ে আসতে পারে না। Evidence JSON-এ `unuploadableArtifacts` + `rulesWithUnuploadableArtifact: 41` হিসেবে স্পষ্ট করে দেখানো হয় — "reachable" বলা হয় না। (`SOURCE_BLOCKED_EXTENSIONS`-ও `.env`/key ফাইল বাদ দেয় — credential safety।)
2. **Subset parsers ≠ full grammar.** TOML/YAML/XML/Gradle-এর সব construct parse করা হয় না (JSONP, anchors, namespaces, Groovy DSL closure …)। আগের fixture-এ parse failure-সহ প্রায় ৯৩.৪৯% parity ছিল; বর্তমান code পুনরায় পরীক্ষা করা প্রয়োজন। Full parser চাইলে নতুন dependency লাগবে — আপনার নির্দেশে সেটি আনিনি।

---

## ৬) ফাইল

| ফাইল | কাজ |
|---|---|
| `apps/api/src/scans/sca/declarationReaders.ts` | ৯ reader + dispatcher + bounds (**নতুন**) |
| `apps/api/src/scans/sca/declarationScan.ts` | reader ব্যবহার; parser-per-file parse; honest counters |
| `apps/api/src/external/scaDeclaration.ts` | `SCA_READABLE_PARSERS = [...SCA_PARSERS]` |
| `scripts/sca-reader-fixtures.mjs` | verification-only renderer (**নতুন**, production-এ নয়) |
| `scripts/verify-dataset.mjs` | round-trip parity gate + per-parser stats + dotfile counter |
| `apps/api/test/declarationReaders.test.ts` | ১২টি নতুন test |
| `docs/SCA_READERS.md`, `SCA_DECLARATION_ENGINE.md`, `DATASET_CONNECTION.md`, `DATASET_INTEGRATION_EVIDENCE.json` | ডক + evidence |

---

## ৭) পরবর্তী ধাপ (ঐচ্ছিক)

1. Gradle/lockfile reader-এর unsupported shape ও false-positive/false-negative কমানো; বাস্তব fixture দিয়ে পুনরায় যাচাই করা।
2. Dotfile artifact-গুলোর জন্য নিরাপদ allowlist (credential-safety বজায় রেখে) — এটা shared path-policy decision, শুধু মেইন অ্যাপেই করা যাবে।
3. Cross-file import resolution / control-flow-sensitive AST (Deep SAST roadmap)।
