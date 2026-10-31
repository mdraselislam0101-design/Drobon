# Drobon Main App: নির্ভরযোগ্যতা ও নিরাপত্তা উন্নয়ন

তারিখ: ৩১ অক্টোবর ২০২৬  
শাখা: `arena/0056e643-drobon`  
অবস্থা: পরিবর্তনগুলো commit বা push করা হয়নি। আগের অপ্রতিশ্রুত পরিবর্তন সংরক্ষিত আছে।

## এই ধাপে যা বদলেছে

### স্ক্যান, quota ও worker

- Usage ফাইলের write ব্যর্থ হলে FREE অ্যাকাউন্টের account/device কাউন্টার বা PRO-এর account কাউন্টার আর RAM-এ ভুলভাবে বেড়ে থাকে না। সফল persistence-এর পরই নতুন কাউন্টার দৃশ্যমান হয়। ব্যর্থ অস্থায়ী ফাইল সরানোর চেষ্টা করা হয়।
- Scan ফাইলে সাধারণ write/rename ব্যর্থ হলে এই process চলাকালে সংশ্লিষ্ট quota ফেরানোর চেষ্টা হয়। একই ফেরত একাধিকবার প্রয়োগ হয় না; একই device-এর অন্য অ্যাকাউন্টের হিসাব অক্ষত থাকে। ফেরত দেওয়ার write-ও ব্যর্থ হলে উভয় ব্যর্থতা গোপন না করে error দেওয়া হয়।
- **সীমা:** scan ও usage দুটি পৃথক JSON ফাইল। এটি crash-atomic transaction নয়। দুটি write-এর মাঝে process crash হলে অথবা ক্ষতিপূরণের write ব্যর্থ হলে এখনও scan ছাড়া quota কাটা থাকতে পারে। স্বয়ংক্রিয় durable recovery journal বা reconciliation নেই।
- DAST idempotency-তে একই key ব্যবহার করে PASSIVE ও ACTIVE_SAFE বা আলাদা consent দাবি করলে conflict হয়। আগের mode-হীন রেকর্ডকে PASSIVE ধরা হয়। conflict ও replay-তে নতুন quota কাটা হয় না।
- Worker-এর retry backoff আর timeout-এ আগে থেকে aborted signal ব্যবহার করে না। Attempt শেষ হলে তার timer বন্ধ হয়; backoff চলাকালে cancel করা যায় এবং backoff নিজে ব্যর্থ হলে job ঝুলে থাকে না।

### Subscription ও partner

- শুধু PRO+ACTIVE রেকর্ড দেখে আর `PAID` বলা হয় না। অনুমোদিত payment, activation audit এবং subscription-এর সময় মিলে paid activation সমর্থিত হলে `PAID` দেখানো হয়। Active admin grant আগের মতো `ADMIN_GRANT` দেখায়।
- Partner complimentary PRO, legacy PRO বা recovery-তে উৎস নিশ্চিত না হলে source বাদ থাকে; Account UI এটিকে unverified বলে। এতে entitlement বা quota-এর সিদ্ধান্ত বদলায় না। অনুমোদিত payment থাকলেও আগে থেকেই partner PRO সক্রিয় থাকলে সেটিকে স্বয়ংক্রিয়ভাবে paid activation বলা হয় না।
- Provenance নিশ্চিত না হওয়ায় প্রকৃত paid activation-এর কিছু recovery/পুরোনো রেকর্ডেও source অনির্দিষ্ট থাকতে পারে। এটি ইচ্ছাকৃত সতর্কতা; financial record বদলানো হয়নি।

### SCA এবং filesystem intelligence

- npm prerelease এবং PyPI development/prerelease, epoch, wildcard/compatible range ও exclusive-bound তুলনায় কিছু ভুল সংশোধন করা হয়েছে। অনির্দিষ্ট prerelease, সমর্থিত নয় এমন wildcard prefix, malformed version বা অতিরিক্ত বড় numeric অংশকে নিশ্চিত match কিংবা clean না বলে incomplete করা হয়। PyPI advisory-তে prerelease-সহ explicit `<`/`>` bound থাকলে prerelease তুলনা করা হয়; এটি installer-এর default filtering থেকে আলাদা security-coverage সিদ্ধান্ত।
- Filesystem intelligence loader symlink, অতিরিক্ত গভীরতা, খুব বেশি entry/file, বড় file ও মোট bytes-এর সীমা মানে; বাদ পড়া তথ্য incomplete হিসেবে জানায়। একটি অপরিবর্তিত file-এর final path `O_NOFOLLOW` দিয়ে খোলা হয়; FIFO দিয়ে আটকে যাওয়া রোধে nonblocking খোলা হয়। Dataset path বিশ্বস্ত এবং অন্য process দ্বারা পরিবর্তন-নিয়ন্ত্রিত রাখা এখনও প্রয়োজন; এটি hostile concurrent filesystem পরিবর্তনের বিরুদ্ধে পূর্ণ sandbox নয়।
- Dataset বা অন্য repository-র কোনো file তৈরি, পরিবর্তন বা মুছে দেওয়া হয়নি। নমুনা/test ফাইলগুলো কেবল অস্থায়ী synthetic fixture ছিল।

### Findings ও বিদ্যমান assistant

- Dataset guidance-এর দৈর্ঘ্য, Unicode normalization, control character, credential-shaped text এবং CWE ID এখন shared API contract অনুযায়ী সীমিত/পরীক্ষিত। দীর্ঘ বা ফাঁকা field-এর জন্য অবৈধ finding-detail response তৈরি হয় না।
- বিদ্যমান assistant নির্বাচিত finding-এর evidence ও dataset-সমর্থিত সম্ভাব্য risk দেখাতে পারে; সম্ভাব্য ঝুঁকিকে প্রমাণিত exploitability বলে না। এটি deterministic ও read-only, generative agent নয়; নতুন AI service/API যোগ করা হয়নি।
- পরিদর্শিত pinned dataset-এর ৪,০০৭টি remediation entry-ই in-memory পরীক্ষায় বৈধ rule-specific guidance দিয়েছে। কোনো detection rule বাদ দেওয়া হয়নি। Dataset-এ আটটি code example ছিল। তিনটি অপরিবর্তিত example, শুধু সংশ্লিষ্ট source language ও সাধারণ lexical finding-এর জন্য, **ব্যাখ্যামূলক নমুনা** হিসেবে দেখানো হয়:
  - `DPK-SAST-002`: text-এর জন্য `textContent`;
  - `DPK-SAST-005`: data-only JSON parsing ও schema validation-এর সতর্কতা;
  - `DPK-SAST-008`: driver-উপযোগী parameterized query-এর নমুনা।
- বাকি পাঁচটি example (`DPK-SAST-001`, `003`, `004`, `006`, `007`) অতিরিক্ত প্রসঙ্গ, input/argument নিরাপত্তা, rule-language মিল বা destination-size যাচাই ছাড়া প্রদর্শন করা হচ্ছে না। ওই পাঁচটি rule ও তাদের text guidance এখনও উপলব্ধ। Dataset-এর example বদলালে content hash না মিললে প্রদর্শন বন্ধ থাকে।
- কোনো নমুনা customer code নয়, verified patch নয়; Drobon code পরিবর্তন বা deploy করে না। বাস্তবে ব্যবহারের আগে দায়িত্বপ্রাপ্ত মানুষের review ও উপযুক্ত test প্রয়োজন। Persisted report-এ আলাদাভাবে এই code example যোগ করা হয়নি; finding detail ও assistant-এ পাওয়া যায়।

## পরীক্ষার ফল

- সর্বশেষ সম্পূর্ণ offline `npm test`: **১,৫৭৭টি পাস**, ১৪৬টি test file — shared ১৮৮, API ১,০৭৫, worker ৩২, web ২৮২। শেষ source পরিবর্তনগুলোর পর পুরো suite আবার চালানো হয়েছে।
- SCA range, filesystem, engine, API ও advisory-র সর্বশেষ focused run-এ **৬১টি test** পাস। Payment, partner, entitlement ও engine-সহ আরেকটি focused run-এ ৮৯টি পাস।
- Root `typecheck`, production `build`, `lint`, `check:secrets`, `check:repo-integrity`, `check:boundaries` ও `git diff --check` পাস। Secrets checker শুধু পরিচিত pattern যাচাই করে; এটি সব সম্ভাব্য secret শনাক্ত করার নিশ্চয়তা নয়।
- Build-এ web JavaScript bundle **৫০৭.৩৯ kB** minified হওয়ায় Vite-এর ৫০০ kB chunk warning আছে।
- স্থানীয় `node-semver`-এর সঙ্গে ৫২৮টি npm version/range ক্ষেত্রে ৪৫২টি নির্দিষ্ট ফল মিলেছে, ৭৬টি সতর্কভাবে unknown। Python pip-এর vendored `packaging` দিয়ে prerelease তুলনা চালু রেখে ১,৯৫৩টি PyPI ক্ষেত্রে ১,৬৭৯টি নির্দিষ্ট ফল মিলেছে, ২৭৪টি unknown। নির্বাচিত এই উদাহরণগুলো পূর্ণ semantics বা বাস্তব vulnerability coverage-এর প্রমাণ নয়।
- Pinned dataset archive থেকে RAM-এ ৪,০০৭টি remediation entry যাচাই: **৪,০০৭টি valid**, ০ invalid; ৮টি example-এর ৩টি নির্বাচিত, ৫টি withheld। RAM-ভিত্তিক filesystem mock-এ ১০০টি non-fixture npm/PyPI advisory record load এবং **১৬/১৬ provider vector পাস** হয়েছে। কাজ চলাকালে একটি vector-এর দুই advisory সাময়িকভাবে বাদ যাচ্ছিল; prerelease-bound সংশোধনের পর তা আবার মিলেছে। Archive disk-এ extract করা হয়নি। Dataset-এ GHSA provenance-যুক্ত record আছে; এগুলো স্বাধীন উৎস নয় এবং কোনো GHSA endpoint ডাকা হয়নি।
- DAST পরীক্ষা synthetic/mock response ও fake DNS ব্যবহার করেছে; কোনো অনুমতিবিহীন বাস্তব target scan করা হয়নি।

## গুরুত্বপূর্ণ বাকি কাজ ও সীমা

1. Scan–usage crash recovery ও compensation failure-এর জন্য durable, পুনরুদ্ধারযোগ্য পরিকল্পনা দরকার; database বা migration পরিবর্তনের অনুমতি ছাড়া এই ধাপে করা হয়নি।
2. SAST, Secrets, DAST ও SCA-র পূর্ববর্তী dataset integration উন্নয়ন এখনও working tree-তে আছে। আগের রিপোর্টে বর্ণিত SCA hidden-path সীমা, দুটি অনির্মাণযোগ্য ও দুটি unparsed fixture এবং অন্যান্য parser/coverage সীমা এখনও প্রযোজ্য; এই ধাপে সব dataset engine fixture নতুন করে benchmark করা হয়নি। বিস্তারিত: `DATASET_INTEGRATION_REPORT_2026-10-30.md`।
3. Assistant-এ local generative model নেই; সর্বত্র উপযুক্ত fix-code তৈরি, বাস্তবে পরীক্ষা বা প্রয়োগের ক্ষমতা দাবি করা যায় না।
4. Session ও rate limit process-local, JSON store single-writer; distributed deployment, শক্তিশালী account recovery/MFA এবং production অপারেশনসের আরও যাচাই প্রয়োজন। Raw source snapshot server-side সংরক্ষিত হয়।
5. Real-world detection accuracy, সব vulnerability ধরা, production security বা ১০০% readiness প্রমাণিত নয়। অর্থপ্রদান, partner grant-এর policy ও পুরোনো data provenance পৃথকভাবে যাচাই প্রয়োজন।
