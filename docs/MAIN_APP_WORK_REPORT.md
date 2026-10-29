# Drobon মেইন অ্যাপ: কাজ ও যাচাই রিপোর্ট

**তারিখ:** ২৮ অক্টোবর ২০২৬  
**পরিধি:** শুধু মেইন অ্যাপ `Drobon`; `Drobon-Dataset`, `Drobon-Database` বা database migration পরিবর্তন করা হয়নি। এই রিপোর্ট তৈরির সময় পরিবর্তনগুলো `arena/5bb07bd8-drobon`-এর workspace-এ আছে; নতুন পরিবর্তনগুলো commit বা push করা হয়নি এবং `main`-এ merge করা হয়নি।

পরবর্তী paid-style সংযোজন ও এখনও বাকি কাজের বর্তমান বিবরণ: [`PAID_WORKFLOWS_BN.md`](./PAID_WORKFLOWS_BN.md)।

## কী কাজ করা হয়েছে

| অংশ | পরিবর্তন | গুরুত্বপূর্ণ সীমা |
|---|---|---|
| **SAST** | JS/TS, Python, Java ও PHP-তে সীমিত syntax-tree ও source-to-sink বিশ্লেষণ; JS/TS-এর কিছু স্থানীয় cross-file flow; কোন parser, ruleset ও ফাইল কতটুকু দেখা হয়েছে তার coverage। | এটি পূর্ণ data-flow বা সব ভাষার বিশ্লেষণ নয়। Candidate একটি review signal, নিশ্চিত exploit নয়। |
| **DAST** | অনুমোদিত target-এর ইতোমধ্যে পাওয়া baseline response-এর inline/direct JavaScript statically parse করে কিছু সম্ভাব্য flow শনাক্ত; রিপোর্টে সীমিত metadata। Passive default; consent-gated bounded Active Safe আছে। | Browser বা JavaScript চলে না; AST-এর জন্য নতুন request বা external script fetch হয় না। বর্তমান safety policy query-যুক্ত URL ও query-parameter probe পাঠায় না; বাদ পড়লে result partial। Path marker probe-ও scope/সীমার কারণে নাও চলতে পারে। |
| **Secrets** | বিদ্যমান শনাক্ত ও redacted finding JS/TS string/template literal-এর সঙ্গে মিললে শুধু অবস্থান ও context-এর metadata যোগ হয়। | এটি নতুন secret discovery বা credential সক্রিয় কি না যাচাই নয়। অশনাক্ত সব sensitive text লুকানো থাকবে—এমন নিশ্চয়তাও নয়। |
| **SCA** | নির্বাচিত `package.json`-এর JSON syntax tree থেকে dependency declaration-এর সংখ্যা যোগ হয়। | এটি installed dependency, vulnerability বা CVE count নয়। Advisory dataset না থাকলে vulnerability intelligence `NOT_ASSESSED`। |
| **SOC/SAC ও রিপোর্ট** | সংরক্ষিত scan থেকে সীমিত triage, partial coverage ও সতর্কতা; JSON, Markdown, SARIF, finding ও assistant-এ প্রাসঙ্গিক AST metadata/সীমাবদ্ধতা। | SOC live SIEM নয়। SAC-এর নামের অর্থ ব্যবহারকারী নির্দিষ্ট করেননি; এটি certification নয়, compliance `NOT_ASSESSED` ও residual risk `UNKNOWN`। |
| **User type** | Developer, Student, Security Professional ও Pentester-এর জন্য আলাদা ব্যাখ্যা ও পরবর্তী পদক্ষেপ; type নির্ধারিত না থাকলেও সাধারণ guidance। | User type শুধু presentation; permission, project ownership, quota ও নিরাপত্তা policy বদলায় না। |

একটি scan-এ parser ব্যর্থ হলে, সীমা অতিক্রম হলে, প্রয়োজনীয় reporter না থাকলে বা কিছু উপাদান বাদ পড়লে `PARTIAL`/উপযুক্ত সীমাবদ্ধতা দেখানো হয়। পুরোনো record-এ AST field না থাকলে নতুন করে scan ছাড়া coverage অজানা। Dataset rule-এর অতিরিক্ত বড় finding metadata অ্যাপের সীমায় স্বচ্ছভাবে ছাঁটা হয়, যাতে ফল নিরাপদে সংরক্ষণ করা যায়।

## যাচাইয়ের ফল

- `npm run verify`: **PASS** — boundaries, repository integrity, secret checks, typecheck, lint, test, production build ও high-severity audit gate পাস।
- Test: Shared **১৮৮**, API **৯৯০**, Worker **২৮**, Web **২৮১** — মোট **১,৪৮৭টি** পাস।
- Compiled production build দিয়েও DAST response AST, redacted Secrets context ও SCA JSON supplement-এর controlled smoke test পাস; SCA-তে dataset ছাড়া `NOT_ASSESSED` নিশ্চিত হয়েছে।
- পুরোনো, নির্দিষ্ট read-only dataset snapshot দিয়ে integration পরীক্ষা করা হয়েছে: ১,০০০ SAST, ১,০০০ Secrets ও ১,০০৭ DAST rule-এর metadata conversion guard যাচাই হয়েছে। এটি বর্তমান production dataset বা নতুন vulnerability coverage-এর প্রমাণ নয়। Dataset repository বদলানো হয়নি।
- `npm audit --audit-level=high` gate পাস, তবে test-only Vitest dependency-তে **২টি moderate advisory** রয়ে গেছে। Web production bundle-এর আকার নিয়েও build warning আছে।

## ব্যবহার ও নিরাপত্তা

1. প্রকল্পে নিজের উৎস ফাইল বা কেবল লিখিত অনুমতিপ্রাপ্ত ও নির্দিষ্ট scope-এর target ব্যবহার করুন। অ্যাপ নিজে বাস্তব অনুমতির সত্যতা স্বাধীনভাবে যাচাই করতে পারে না।
2. প্রকৃত নিয়ম/তথ্য ব্যবহার করতে আলাদা বৈধ dataset checkout কনফিগার করতে হবে: `VULN_INTEL_PROVIDER=filesystem` এবং `DATASET_PATH`। Default `none`-এ bundled production SAST/Secrets/DAST rules নেই; advisory তথ্যও স্বয়ংক্রিয়ভাবে বর্তমান বলে ধরা যাবে না।
3. Finding-এর evidence, scanner/AST coverage, partial status ও scope দেখে মানুষ দিয়ে যাচাই করুন; পরিবর্তনের পরে একই অনুমোদিত scope-এ retest করুন। কোনো finding না পাওয়া মানে সাইট নিরাপদ নয়।
4. সব vulnerability ধরার বা ১০০% নিরাপত্তার নিশ্চয়তা দেওয়া সম্ভব নয়। Production ব্যবহারের আগে deployment configuration, বর্তমান dataset, অবশিষ্ট advisory এবং আপনার পরিবেশে নিরাপত্তা পর্যালোচনা প্রয়োজন।

বিস্তারিত: [AST বিশ্লেষণ](AST_ANALYSIS.md), [DAST সীমা](DAST.md), [SOC/SAC ও coverage](SECURITY_OPERATIONS_COVERAGE.md), [রিপোর্ট](REPORTS.md)।
