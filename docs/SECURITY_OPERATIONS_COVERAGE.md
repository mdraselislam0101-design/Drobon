# স্ক্যান, অপারেশন ও রিপোর্টের সীমা

এই আপডেট শুধুমাত্র মেইন অ্যাপের বিদ্যমান কোডে। এখানে **SOC** বলতে সংরক্ষিত স্ক্যানের উপর একটি read-only operations overview এবং **SAC** বলতে Security Assessment & Compliance-এর জন্য একটি coverage ledger বোঝানো হয়েছে। SAC কোনো সার্টিফিকেশন দেয় না। এই সংজ্ঞাগুলো আপনার উদ্দেশ্য থেকে ভিন্ন হলে বদলাতে হবে।

## কী চালু আছে

| অংশ | বর্তমান কাজ |
|---|---|
| SAST | আপলোড করা সমর্থিত সোর্স ফাইলে বিদ্যমান প্যাটার্ন ও সীমিত flow বিশ্লেষণ। সব ভাষা বা সব দুর্বলতা নয়। |
| DAST | কনফিগার করা HTTP(S) target-এর সীমিত পর্যবেক্ষণ। Passive ডিফল্ট; অনুমতির ঘোষণাসহ সীমিত Active Safe আছে, তবে বর্তমান safety policy-তে query URL ও query-parameter probe পাঠানো হয় না। আগেই পাওয়া baseline response-এর script statically parse হতে পারে, তবে AST-এর জন্য বাড়তি request বা script execution হয় না। |
| SCA | সমর্থিত manifest থেকে inventory/advisory ও declaration checks; subset পাঠক ব্যবহার হলে ফল `partial` দেখায়। |
| Secrets | আপলোড করা সোর্সে সম্ভাব্য secret খোঁজে; finding-এর evidence redacted। |
| SOC overview | নিজস্ব project-এর সংরক্ষিত স্ক্যান থেকে ব্যর্থ/অসম্পূর্ণ স্ক্যান, উচ্চ severity finding, সর্বশেষ সম্পন্ন SCA scan-এর HIGH/CRITICAL matched advisory বা NOT_ASSESSED অবস্থা এবং coverage/data-source সংক্রান্ত সতর্কতা দেখায়। এটি live notification নয়। |
| SAC ledger | নতুন single-scan report-এ কী চলেছে, কী রেকর্ড হয়নি, সীমাবদ্ধতা, residual risk এবং compliance status দেখায়। |

AST উপযুক্ত স্থানে scanner-এর অংশ; SOC/SAC **নতুন scan type নয়**। বিদ্যমান চারটি scan type একই থাকে। DAST response-script, Secrets literal-context বা SCA `package.json` AST supplement `PARTIAL` হলে SOC saved-scan alert দিতে পারে এবং SAC-তে সংশ্লিষ্ট scanner coverage `PARTIAL` হয়। যেখানে AST প্রযোজ্য নয় বা পুরোনো record-এ নেই, তা নিরাপদ বা সম্পূর্ণ coverage বোঝায় না। নতুন SOC endpoint: `GET /api/v1/projects/:projectId/soc`। Authentication ও server-side project ownership বাধ্যতামূলক; একই ডাটা project পেজে **Security operations overview** থেকে চাওয়া যায়। সর্বশেষ ১০০টি স্ক্যান দেখা হয়; বাদ পড়লে তা দেখানো হয়। এটি external log গ্রহণ, intrusion detection, incident response, notification বা ২৪/৭ monitoring নয়। Alert মানে আক্রমণ ঘটেছে—এমন প্রমাণও নয়।

## মালিকের রিপোর্ট কী বলবে

নতুন রিপোর্টের JSON, Markdown, SARIF ও UI-তে একটি coverage অংশ থাকে:

- কোন scanner `RAN`, `PARTIAL` বা `NOT_RUN` এবং স্ক্যানে রেকর্ড করা count। রেকর্ড না থাকলে `null`/`NOT RECORDED`, অনুমান করে শূন্য নয়।
- কোনো finding না থাকলে `NO_FINDINGS_RECORDED`। এর অর্থ **নিরাপদ বা দুর্বলতামুক্ত প্রমাণিত নয়**।
- `residualRisk: UNKNOWN`; `compliance: NOT_ASSESSED`। PCI DSS, ISO 27001, SOC 2 বা অন্য কোনো standard-এর certification নয়।
- স্ক্যানের সময়কার rule-pack identity/version সংরক্ষিত না থাকলে `NOT_RECORDED_AT_SCAN`। বর্তমান configuration থেকে অতীতের তথ্য অনুমান করা হয় না।
- পুরনো সংরক্ষিত রিপোর্ট ledger ছাড়া এখনও গ্রহণযোগ্য এবং UI/Markdown-এ সেটি জানানো হয়।

রিপোর্টের SHA-256 digest পরিবর্তন শনাক্ত করতে সাহায্য করে, **digital signature বা উৎসের প্রমাণ নয়**।

## এই আপডেটে বিদ্যমান ইঞ্জিনের সতর্কতা

- SAST-এ URL encoding-এর মতো একটি context-এর রূপান্তরকে অন্য context-এর sanitizer ধরে taint মুছে দেওয়া বন্ধ করা হয়েছে; mixed SQL query-তে শুধু `?` থাকলেই সেটিকে parameterized ধরা হয় না। এগুলো এখনও review candidate, নিশ্চিত exploit নয়।
- Advisory-তে manifest-এর version/constraint ইনস্টল করা runtime-এর প্রমাণ নয়: `UNKNOWN`/review হিসেবে দেখানো হয়। আংশিক version capture বা vendor suffix-এর ক্ষেত্রেও একই সতর্কতা। কোনো live advisory feed এই আপডেটে যুক্ত হয়নি।
- SCA-র অনির্ভরযোগ্য source keys থেকে evidence leak ও prototype pollution ঠেকানো হয়েছে; subset parser-এ স্ক্যানের `partial` প্রকাশ করা হয়। Parser label সমর্থিত হওয়া মানেই প্রতিটি ফরম্যাট বা rule সম্পূর্ণভাবে চালু নয়।
- Assessment-linked DAST-এর ক্ষেত্রে scan তৈরির সময় এবং প্রতিটি request-এর আগে বর্তমান scope/engagement আবার চেক করা হয়। লিখিত অনুমতি Drobon নিজে যাচাই করে না; engagement ছাড়া পুরনো unverified পথও এখনও আছে। ইতোমধ্যে চলমান request প্রত্যাহার করা যায় না।

## যে কাজগুলো এখনও লাগবে

Authenticated/browser-based testing, সব ভাষায় পূর্ণ parser/dataflow, verified fresh advisory sources, পূর্ণ SCA format coverage, নিরাপদ external telemetry ingestion/alert delivery এবং মানসম্মত মানব pentest এখনও নেই। Python/PHP/Java-তে bounded syntax parser এবং JS/TS-তে সীমিত project flow আছে, সম্পূর্ণ analysis নয়; নতুন SAST scan-এ effective-rule provenance ও missing categories রেকর্ড হতে পারে, অন্য scan/পুরোনো রিপোর্টে provenance অজানা থাকতে পারে। কোনোটিরই ১০০% vulnerability detection-এর নিশ্চয়তা নেই। অন্যের ওয়েবসাইটে কাজের আগে অনুমতি ও নির্দিষ্ট scope নিশ্চিত করতে হবে।
