# Drobon-এ নতুন paid-style কাজ: কী হয়েছে, কী হয়নি

**কাজের সীমা:** পুরোনো Drobon অ্যাপের ইঞ্জিন ও একই সুরক্ষা-সীমা ব্যবহার করা হয়েছে। Dataset বা Database repo, database schema বা migration বদলানো হয়নি। এই নথি কোনো deployed server-এ ফিচার চালু থাকার প্রমাণ নয়।

## যা নতুন যুক্ত হয়েছে

### ১. PDF রিপোর্ট

- একটি সম্পন্ন scan-এর আগের JSON/Markdown/SARIF-এর পাশাপাশি PDF পাওয়া যায়। আগে scan report তৈরি বা retrieve করার পর **Download PDF** চাপুন।
- Project-এর **Download project summary PDF** সর্বশেষ recorded request অনুযায়ী SAST, SCA, Secrets ও DAST-এর অবস্থা একসঙ্গে দেখায়। নতুনতম scan failed বা queued হলে পুরোনো সফল scan-কে নতুন ফল হিসেবে দেখানো হয় না। একাধিক request-এর সময় একই হলে `ORDER_UNCERTAIN` দেখিয়ে অনুমান করা হয় না।
- SCA-তে প্রকৃত matched advisory থাকলে PDF-এ দেখায়; `NOT_ASSESSED`-কে পরিষ্কারভাবে আলাদা করে। Snapshot, finding ও advisory details সীমাবদ্ধ; বাদ পড়লে রিপোর্টে লেখা থাকে। Scans ভিন্ন সময়ে/ভিন্ন scope-এ চলতে পারে এবং finding একাধিকবার গণনা হতে পারে।
- Owner-only API, `no-store`, ১ MiB PDF সীমা, ফাইলের নাম ও client-side PDF header যাচাই রাখা হয়েছে। Font বাংলা ও Latin দেখায়; unsupported glyph `?` হতে পারে, এবং বাংলা conjunct copy/paste-এ অতিরিক্ত zero-width character বা spacing থাকতে পারে। **Exact text-এর জন্য মূল JSON রিপোর্ট ব্যবহার করুন।** SHA-256 digest ডিজিটাল স্বাক্ষর নয়।
- রিপোর্ট নিরাপত্তা বা compliance certificate নয়, এবং তৃতীয় পক্ষের অনুমতি যাচাই করে না।

### ২. লোকাল/CI নিরাপত্তা চেক

`npm run security:ci` দেওয়া নির্দিষ্ট source directory-র ওপর **বিদ্যমান SAST, Secrets ও SCA** ইঞ্জিন চালায়। Severity threshold অনুযায়ী finding এবং আলাদাভাবে আসা সত্যিকারের SCA advisory গেট করে; SARIF export ও স্পষ্ট অসম্পূর্ণতার অবস্থা আছে। Dataset অনুপস্থিত বা যাচাইয়ে ব্যর্থ হলে সেটিকে clean pass বলা হয় না। বাস্তব app-এর account, data store, quota বা scan history বদলায় না।

ব্যবহারের নিয়ম, সীমা, exit code এবং PR, push ও GitHub Actions schedule-এর **ম্যানুয়ালি কনফিগার করার টেমপ্লেট**: [`CI_SECURITY_BN.md`](./CI_SECURITY_BN.md)। কোনো বাহ্যিক repository-তে workflow যোগ বা branch protection সক্রিয় করা হয়নি। টেমপ্লেট কনফিগার হওয়ার পরও required merge check repo admin-কে নিজে সেট করতে হবে।

### ৩. Dependency advisory নিয়ে dashboard triage

Project-এর **Security operations overview → Load operations snapshot**-এ সর্বশেষ সম্পন্ন SCA scan-এর বাস্তব `HIGH`/`CRITICAL` advisory matches ও `NOT_ASSESSED` অবস্থার সতর্কতা যোগ হয়েছে। এগুলো শুধু সংরক্ষিত scan থেকে চাওয়া হলে তৈরি হওয়া owner-only snapshot; live monitoring, স্বয়ংক্রিয় email, delivery বা intrusion alert নয়। আগের চেয়ে নতুন কোনো scan failed থাকলে তার সতর্কতাও আলাদাভাবে দেখা দরকার; সর্বশেষ সম্পন্ন scan মানে সর্বশেষ চেষ্টাটি সফল হয়েছে এমন নয়।

### ৪. ম্যানুয়াল task draft

Finding details-এ **Prepare a manual security task** থেকে severity, location, scan ID, workflow ও optional suggested assignee-এর একটি কপি-যোগ্য খসড়া পাওয়া যায়। Evidence, source code, notes ও credential ইচ্ছাকৃতভাবে এতে নেই। পাঠানোর আগে project name ও path-সহ প্রতিটি তথ্য মানুষের review করা জরুরি।

এটি শুধু স্থানীয় খসড়া: প্রকৃত Jira issue তৈরি, প্রকৃত team account-এ assignment, notification বা দুই সিস্টেমের status sync নয়। বিদ্যমান finding lifecycle, note ও rescan verification আগের মতোই কাজ করে; status পরিবর্তন নিজে fix-এর প্রমাণ নয়।

## যা এখনও তৈরি বা যুক্ত হয়নি

- GitHub-এ স্বয়ংক্রিয়ভাবে সংযোগ/PR comment/branch rule বদলানো বা server-side **secret push protection**, secret validity check এবং key revoke/rotate। CI check ও push protection আলাদা।
- স্বয়ংক্রিয় fix/upgrade PR, live vulnerability feed refresh বা সব package ecosystem-এর পূর্ণ advisory coverage। বর্তমান provider ও dataset-এর পরিধি/সতেজতা যাচাই জরুরি।
- Username/password/session-সহ authenticated crawling, browser/JS execution ও পূর্ণাঙ্গ DAST। বর্তমান DAST-এর অনুমতি, target scope ও network guards অপরিবর্তিত; লিখিত অনুমতি অবশ্যই প্রয়োজন।
- Cross-account team membership/assignment, প্রকৃত Jira integration, Drobon-এর নিজের scheduler, email sender ও স্বয়ংক্রিয় notification। GitHub Actions-এর ঐচ্ছিক schedule ও GitHub-এর নিজস্ব notification settings আলাদা বিষয়।

এগুলোকে সম্পন্ন বলে দাবি করা যাবে না; এগুলোর জন্য নিরাপদ নকশা, প্রকৃত permission/credential integration ও আরও end-to-end পরীক্ষা দরকার। **কোনো স্ক্যান ১০০% bug খুঁজে পাওয়া বা কোনো সাইট সম্পূর্ণ নিরাপদ হওয়ার নিশ্চয়তা দেয় না।**

## যাচাই

- `npm run verify`: shared ১৮৮, API ১,০০৩, worker ২৮ ও web ২৮২ = **১,৫০১টি test পাস**। এতে typecheck, lint, test, production build, boundary ও high-severity audit gate অন্তর্ভুক্ত।
- PDF-এর HTTP authorization, MIME/filename, latest-attempt/tie, `NOT_ASSESSED`, matched advisory, truncation, integrity, বাংলা font mapping ও UI পরীক্ষা করা হয়েছে। Production-build থেকে PDF তৈরি করে `%PDF-` স্বাক্ষর দেখা হয়েছে; আলাদা পাঠকে বাংলা visual rendering ও text extraction-ও পরীক্ষা করা হয়েছে। বাংলা conjunct থেকে exact copy-এর সীমা উপরে বলা আছে।
- আলাদা read-only dataset commit `3986082b22007b47930da3bc99be9c2f2b036080` দিয়ে dataset verification পাস হয়েছে। একটি **synthetic** স্থানীয় project-এ CI চালালে ৬টি finding-এর মধ্যে ২টি `MEDIUM` threshold-এ ধরা পড়ে; SAST ও Secrets SARIF-এ উপস্থিত, SCA `NOT_ASSESSED` স্পষ্ট। কোনো বাস্তব target scan করা হয়নি।
- Production dependency audit-এ পরিচিত vulnerability ০; পুরো development audit-এ Vitest-এর transitive `@vitest/mocker` সম্পর্কিত ২টি **moderate** সতর্কতা আছে। High-level audit gate পাস করলেও moderate সতর্কতা রয়ে গেছে। Web build বড় bundle-এর warning দিয়েছে।

## গোপনীয়তা ও অনুমতি

শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত target এবং অনুমোদিত তথ্য স্ক্যান করুন। CI-তে টার্গেট কোড install/execute করবেন না; trusted Drobon ও trusted dataset-কে pin করে বিচ্ছিন্ন runner ব্যবহার করুন। Report/SARIF/task draft-এর path, metadata বা অন্য অপ্রত্যাশিত তথ্য sensitive হতে পারে—শেয়ার করার আগে review করুন। বিদ্যমান অ্যাপের source snapshot storage encrypted-secret vault নয়।
