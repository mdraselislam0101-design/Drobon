# Drobon-এর স্ক্যান ও রিপোর্টে AST বিশ্লেষণ

এখানে AST মানে **Abstract Syntax Tree**। এটি মেইন অ্যাপ `Drobon`-এর বিদ্যমান SAST, DAST, Secrets ও SCA-তে ব্যবহারযোগ্য সীমিত অতিরিক্ত বিশ্লেষণ; **নতুন scan type নয়**। পুরোনো scanner pass ও নিয়ম এখনও চলে; Dataset বা Database repo-তে কোনো পরিবর্তন করা হয়নি। SOC/SAC নিজে source parser নয়: তারা সংরক্ষিত স্ক্যান ও তার AST coverage থেকে সীমাবদ্ধতা দেখায়।

## SAST-এ কী পরীক্ষা হয়

| ভাষা | প্রকৃত parser ও সীমিত analysis |
|---|---|
| JavaScript, TypeScript, JSX, TSX | TypeScript syntax parser; destructuring, স্থির property/bracket, কিছু SQL/HTML/command/code sink এবং bounded intra-file flow। |
| Python | Lezer Python syntax tree; পরিচিত input থেকে variable ও কিছু sink পর্যন্ত intra-file heuristic। |
| PHP | `php-parser` syntax tree; পরিচিত superglobal/input থেকে variable, call ও echo/print পর্যন্ত intra-file heuristic। |
| Java | Lezer Java syntax tree; কিছু request source, variable ও method sink পর্যন্ত intra-file heuristic। |
| অন্যান্য ভাষা | আগের lexical বা shallow pass যতটুকু পারে; নতুন structured parser নেই। |

Parser গুলো code বা dependencies execute করে না। Syntax tree তৈরি হওয়া **পুরো ভাষার সব feature বোঝা**, সব route পরীক্ষা হওয়া, বা নিরাপত্তা প্রমাণ হওয়ার সমতুল্য নয়। Python/PHP/Java pass পূর্ণ interprocedural analysis করে না। Editor-ধরনের Lezer parser-এর recovery/error থাকলে ফাইলটি সম্পূর্ণ না দেখিয়ে `SYNTAX_ERROR` / `partial` করা হয়।

### JS/TS-তে সীমিত function ও file জুড়ে flow

অতিরিক্ত project pass কেবল আপলোড করা virtual snapshot-এর ভিতরে **top-level named function** এবং সেগুলোর **relative named import**-এর নির্দিষ্ট আকার অনুসরণ করে। যেমন এক ফাইলে `run(req.body.cmd)` এবং অন্য ফাইলে `export function run(x) { exec(x) }` থাকলে source, call ও sink অবস্থানসহ review candidate আসতে পারে। Local function ও function return-এর কিছু flow-ও দেখা হয়।

এটি সম্পূর্ণ call graph নয়। Default/namespace import, CommonJS, re-export, dynamic import/property, methods/classes, package dependency, runtime aliases, framework wiring, async control-flow এবং recursion সাধারণভাবে resolve হয় না। Filesystem বা network-এ target-এর import resolve করা হয় না। অনুপস্থিত relative **named** import গণনা করে project pass `INCOMPLETE` হয়; অন্য unsupported construct সব সময় আলাদা করে গণনা করা হয় না। Branch ও unknown function সম্পর্কে conservative অনুমান false positive দিতে পারে, আবার প্রবাহ মিসও করতে পারে।

## নিয়ম ও finding-এর attribution

1. SAST rule মেইন অ্যাপে embed করা নেই। Deploy-এ `VULN_INTEL_PROVIDER=filesystem` এবং `DATASET_PATH` দিয়ে বিদ্যমান validated dataset ব্যবহার করা যায়; authenticated `GET /api/v1/dataset/status`-এ availability ও conformance দেখুন। `none` বা unavailable dataset হলে rule শূন্য থাকতে পারে। আলাদা test fixture production dataset নয়।
2. Structured ও shallow AST-এর প্রতিটি `command`, `sql`, `html`, `code` category-র জন্য ভাষা-উপযোগী একটি loaded rule category অনুযায়ী বাছাই হয়। Category ঠিক কী ছিল তা normalized exact match দিয়ে দেখা হয়; `nosql`-কে `sql` ধরে নেওয়া হয় না। কোনো category-তে rule না থাকলে সে category-তে AST finding তৈরি হয় না এবং coverage-এ missing থাকে।
3. এই rule **category reporter**; তার নিজস্ব regex/pattern এই নির্দিষ্ট জায়গায় ম্যাচ করেছে—এমন নয়। AST-only finding-এ generic title/description থাকে, severity নির্বাচিত rule থেকে আসে এবং নির্দিষ্ট CWE দাবি করা হয় না। Result, UI, Markdown ও SARIF-এ attribution স্পষ্ট থাকে। পুরোনো lexical rule finding-এর আচরণ আলাদা। Manual review দরকার।
4. Project flow finding-এ যেখান থেকে শনাক্ত করা গেছে সেখানে source file/line/column, সর্বোচ্চ চারটি call location ও sink location থাকে। অন্য AST pass-এর source location বর্তমানে `not recorded` হতে পারে। Trace কোনো runtime execution বা exploit proof নয়। New structured/project evidence-এ raw source literal কপি করা হয় না; **পুরোনো lexical/shallow evidence policy অপরিবর্তিত**, ফলে সব ধরনের sensitive literal সব rule-এ redacted হওয়ার নিশ্চয়তা নেই।
5. একটি static SQL literal, placeholder ও আলাদা literal parameter collection-এর পরিচিত আকারে কিছু pass suppression করে। Driver, wrapper ও runtime semantics যাচাই করা হয় না; এটিও নিরাপত্তা প্রমাণ নয়।

## ব্যবহার ও রিপোর্ট

1. তৃতীয় পক্ষের target-এর জন্য আগে লিখিত অনুমতি ও নির্দিষ্ট scope নিন। App নিজে আইনগত অনুমতি যাচাই করে না।
2. Project-এ অনুমোদিত source snapshot আপলোড করুন, dataset status দেখুন, বিদ্যমান **SAST** চালান।
3. Scan-এর **Rule, parser and file coverage** খুলে parser status, অনুপস্থিত category, অসম্পূর্ণ file এবং project pass দেখুন। Finding-এ source/call/sink থাকলে পর্যালোচনা করুন।
4. একই saved scan থেকে JSON, Markdown বা SARIF report তৈরি করুন। `partial`, `truncated`, missing rules, parser error বা unresolved import থাকলে সীমা দূর করে আবার scan ও human review করুন। SOC derived alert এবং SAC `PARTIAL` দেখাতে পারে।

`astParser`-এর `parsedFiles`, `incompleteFiles`, `filesWithoutRules`, `findings` আগের compatible summary। `findings` হলো আগের pass-এর সঙ্গে dedup-এর পর structured/project pass-এর **অতিরিক্ত** finding, সব সম্ভাব্য flow নয়। `filesWithoutRules=0` থাকলেও অন্য category অনুপস্থিত থাকতে পারে। নতুন `astCoverage` রাখে:

- scan চলাকালে ব্যবহার হওয়া effective rule-এর source, count, normalized metadata/pattern-এর SHA-256 এবং manifest থাকলে pack ID/version;
- API-তে থাকা parser package-এর প্রকৃত version (না পাওয়া গেলে `unknown`);
- পরিবারভিত্তিক category → নির্বাচিত reporter এবং অনুপস্থিত category;
- পরীক্ষা করা ফাইলগুলোর parser status, structured parser ছাড়া ফাইলের সংখ্যা এবং bounded project pass-এর status, file count, unresolved named relative imports ও অতিরিক্ত finding count।

SAST, DAST ও Secrets-এর dataset pack থেকে finding তৈরির সময় অতিরিক্ত দীর্ঘ title/description/remediation অ্যাপের সীমার মধ্যে `…` দিয়ে ছাঁটা হয়; control character পরিষ্কার হয়, invalid CWE বাদ যায় এবং অনুপস্থিত guidance অনুপস্থিত বলেই দেখানো হয়। Hashটি এই কার্যকর converted rule-এর নির্বাচিত metadata, language ও pattern-কে তুলনা করতে সাহায্য করে; evidence-redactor-এর উপস্থিতি নথিভুক্ত হলেও তার closure/runtime semantics বা পুরো dataset snapshot hash করা হয় না। এটি ডিজিটাল signature নয় এবং rule, engine config বা source-এর সম্পূর্ণ reproducibility প্রমাণ করে না। Pack manifest অনুপস্থিত থাকতে পারে। JSON-এ তথ্য, Markdown-এ coverage ও incomplete files, SARIF-এ `drobon/astCoverage` ও finding-এর `drobon/astFlow` থাকে। পুরোনো report-এ এই নতুন field না থাকলে পুরোনো scope-ই দেখানো হয়; বর্তমান dataset দেখে অতীতের provenance অনুমান করা হয় না।

## DAST, Secrets এবং SCA-তে AST

| বিদ্যমান স্ক্যান | কী বাস্তবে হয় | গুরুত্বপূর্ণ সীমা |
|---|---|---|
| DAST | ইতোমধ্যে প্রাপ্ত প্রথম non-redirect baseline response-এর HTML থেকে সর্বোচ্চ ৮টি inline script, বা সরাসরি JavaScript response, syntax tree-তে বিশ্লেষণ হয়। কিছু browser-input → HTML/code sink-এর সম্ভাব্য flow পাওয়া গেলে category-selected reporter দিয়ে আলাদা review finding তৈরি হয়। | এটি static heuristic; browser, target code বা JavaScript execute করে না, external script fetch করে না, বাড়তি HTTP request পাঠায় না। Event-handler attribute, inert template, dynamic import ও অন্য response অনুসরণ করে না। Syntax error, response truncation, সীমা বা external script থাকলে `PARTIAL`। |
| Secrets | আগে থেকেই regex-এ শনাক্ত **redacted** finding কোনো JS/TS/JSX/TSX string/template literal-এর সঙ্গে মিলে কি না, positional metadata যোগ হয়। Multiline ও interpolated template-এর পরিচিত literal segment-ও দেখা হয়। | নতুন secret খোঁজার বা credential চালু আছে কি না যাচাই করার দাবি নয়; আগের finding বাদও দেয় না। অন্য ভাষা এই supplement-এ skip হয়। AST output কেবল metadata; আগের Secrets evidence policy শনাক্ত credential redaction করে, অশনাক্ত sensitive text সবসময় গোপন থাকবে এমন নিশ্চয়তা নয়। |
| SCA | নির্বাচিত `package.json`-এর JSON syntax tree-তে `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies` property-এর নিচের syntactic entry গণনা হয়। | এটি installed dependency বা CVE count নয়। বিদ্যমান SCA inventory ও provider-ই আলাদা authority; `package-lock.json`, Python manifest ও অন্য ফরম্যাট এই AST supplement-এ skip হয়। Advisory source না থাকলে `NOT_ASSESSED` থাকে। |

DAST-এ কেবল `content-injection` category-র নির্ভরযোগ্য loaded rule ID/severity থেকে reporter নেওয়া হয়। **ওই rule-এর নিজস্ব check ম্যাচ করেছে বা exploit সম্ভব—এমন দাবি নয়।** Reporter অনুপস্থিত থাকলে parsed script থাকলেও supplement `PARTIAL`, নতুন AST finding তৈরি হয় না। Code, raw response, script ও secret worker-এ ইনপুট হিসেবে পৌঁছায়, কিন্তু worker শুধু count ও location ফেরত দেয়। Worker একটি OS-level sandbox নয়।

প্রতিটি নতুন স্ক্যানের `astSupplement`-এ mode, `RAN`/`PARTIAL`/`NOT_APPLICABLE`, parsed/incomplete/skipped count, signals ও TypeScript parser version থাকে। `signals`-এর অর্থ DAST-এ সংরক্ষিত অতিরিক্ত candidate, Secrets-এ literal-context পাওয়া বিদ্যমান finding, SCA-তে syntactic entry সংখ্যা। `RAN` পুরো app বা সব ভাষা পরীক্ষা হওয়ার নিশ্চয়তা নয়। `NOT_APPLICABLE` মানে ওই pass-এ উপযুক্ত input ছিল না, নিরাপদ প্রমাণ নয়। পুরোনো record-এ field না থাকলে coverage **অজানা**, নতুন করে scan ছাড়া অনুমান করা হয় না। JSON, Markdown, SARIF (`drobon/astSupplement`, `drobon/astContext`) এবং project UI-তে তথ্য দেখা যায়।

SOC saved-scan triage-এ supplement partial হলে `SCAN_PARTIAL` alert তৈরি হতে পারে; SOC live SIEM নয়। SAC report-এ scanner `PARTIAL`, সীমাবদ্ধতা, `UNKNOWN` residual risk ও `NOT_ASSESSED` compliance দেখায়; এটি সার্টিফিকেশন নয়। Deterministic assistant সংরক্ষিত আংশিক supplement থাকলে প্রাসঙ্গিক scan summary-কে `PARTIALLY_SUPPORTED` দেখায় ও passive/active-safe DAST আলাদা করে; এটি নতুন scan বা runtime proof নয়। এখানে SAC-এর নাম/অর্থ পূর্বে অনুমান করা, ব্যবহারকারী নির্দিষ্ট করেননি।

## User type অনুযায়ী ব্যবহার

- **Developer:** source-flow ও redacted secret location পর্যালোচনা করুন, পরিবর্তনের পরে একই scope-এ পুনরায় scan করুন।
- **Student:** source → sink candidate ও incomplete coverage দেখে শেখার উদাহরণ হিসেবে ব্যবহার করুন; finding কোনো grade বা exploit proof নয়।
- **Security Professional:** rule attribution, missing coverage, scope ও অন্যান্য প্রমাণ মিলিয়ে validation এবং owner-facing report পর্যালোচনা করুন।
- **Pentester:** আগে লিখিত permission ও exact scope নিশ্চিত করুন; তারপর অনুমোদিত target-এর DAST observation এবং পাওয়া গেলে SAST source evidence মিলিয়ে human verification করুন।

চার user type একই server-authorized scanner ব্যবহার করে; type শুধু presentation/guidance, authorization বা entitlement নয়। App বাস্তব অনুমতি স্বাধীনভাবে যাচাই করতে পারে না।

## Resource সীমা

| বিষয় | সীমা / আচরণ |
|---|---|
| Source snapshot | সর্বোচ্চ ২০০ ফাইল, প্রতিটি ২৫৬ KiB ও মোট ৭৬৮ KiB upload policy; আরও SAST সীমা/১০ s deadline প্রযোজ্য। বড় project আগে scope অনুযায়ী ভাগ করতে হতে পারে। |
| প্রতি ফাইল structured pass | ১৩১,০৭২ UTF-8 bytes, ১৬,০০০ node, depth ৮০, ১,০০,০০০ work, ৫১২ bindings; প্রতি rule/file সর্বোচ্চ ৩ candidate, মোট ২০০। Limit/error হলে incomplete। |
| Project pass | সর্বোচ্চ ৬৪ JS/TS ফাইল, ৩৯৩,২১৬ bytes মোট, প্রতি ফাইল ১৩১,০৭২ bytes, ৯৬ function, ৩০,০০০ nodes, ১,৫০,০০০ work, ৪ summary round, ২০০ candidate। Limit বা unresolved relative named import হলে `INCOMPLETE`। |
| DAST supplement | সর্বোচ্চ ৩২,৭৬৮ response bytes, ৪,০০০ HTML nodes ও ৮টি inline/direct script; প্রতিটি script-এ structured pass সীমা প্রযোজ্য। |
| Secrets/SCA supplement | সর্বোচ্চ ৩২ eligible files/manifest, প্রতি file ১৩১,০৭২ bytes, ১৬,০০০ nodes, depth ৮০; Secrets-এ সর্বোচ্চ ১,০০০ literal span/file। বাদ পড়া input `PARTIAL`। |
| Worker ও queue | প্রতি scan-এ reusable আলাদা worker; সর্বোচ্চ ৪ worker, অতিরিক্ত সর্বোচ্চ ৮ waiter, queue wait সর্বোচ্চ ১.৫ s বা বাকি deadline। Queue পূর্ণ/timeout হলে pass `UNAVAILABLE`/partial। প্রতি worker request ৩ s বা অবশিষ্ট deadline; V8 old/young heap ৯৬/১৬ MiB, stack ৪ MiB। Abort/timeout-এ worker বন্ধ হয়। এটি OS sandbox নয়। |
| Dataset load | একই process-এর একাধিক concurrent scan একই in-flight validated load-এর জন্য অপেক্ষা করে; loading চলাকালে অস্থায়ী ফাঁকা ruleset সফল ফল হিসেবে ব্যবহার করা হয় না। |

Parser candidate হওয়ার মানে বাস্তব vulnerability নিশ্চিত নয়। বিদ্যমান lexical pass comments/string-এ আলাদাভাবে false positive দিতে পারে। **Zero findings, successful parsing বা এই সীমিত test suite কোনো সাইটকে নিরাপদ বা সব vulnerability শনাক্ত হয়েছে—এমন নিশ্চয়তা দেয় না।**

## পরীক্ষার অর্থ

`apps/api/test/astImprovements.test.ts`-এ ২৪টি ছোট synthetic labeled case আছে—১২ positive ও ১২ negative; বর্তমান fixture-এ ২৪/২৪ প্রত্যাশিত ফলের regression পরীক্ষা। পাশাপাশি PyGoat ও OWASP NodeGoat-এর প্রকাশিত **ইচ্ছাকৃতভাবে vulnerable training app**-এর তিনটি অভিযোজিত excerpt এবং তিনটি safe-form control আছে; সংশ্লিষ্ট MIT/Apache license test fixtures-এ রাখা হয়েছে। এই ৬টি মাত্র উদাহরণে syntax pass-এর ফল: ৩ true positive, ১ false positive, ২ true negative, ০ false negative। `shell=False` argument-array উদাহরণে shell injection label অনুযায়ী অতিরিক্ত review candidate এসেছে; সংশ্লিষ্ট program-এর argument নিজেও ঝুঁকিপূর্ণ হতে পারে।

এগুলো representative production benchmark নয়, তাই কোনো পরিমাপ থেকে বাস্তব precision/recall বা ১০০% detection দাবি করা যায় না। আলাদা পরীক্ষায় project flow, category attribution, guarded provenance, missing imports, concurrency queue, syntax failure এবং report compatibility পরীক্ষা হয়। প্রকৃত deployment dataset আলাদা কনফিগার ও যাচাই করতে হবে।
