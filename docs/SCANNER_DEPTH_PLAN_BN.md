# SAST ও DAST গভীরতা — সৎ সক্ষমতা-মানচিত্র ও পরিকল্পনা

তারিখ: ২০২৬-১১-০২ · শাখা: `arena/8821907b-drobon` · অবস্থা: **পরিকল্পনা (কোনো কোড পরিবর্তন এই ডকুমেন্টের জন্য নয়)**

এই ডকুমেন্টটি "কতটা উন্নত করব" প্রশ্নের উত্তর তিনটি ভাগে দেয়:
**(ক) এখন সত্যিই আছে কী** (সোর্স পড়ে যাচাই করা), **(খ) এই সিস্টেমের নিয়মের ভেতরে যা করা যায়**, এবং
**(গ) যা করা যায় না — কেন**। কোনো সংখ্যা (নির্ভুলতা, গতি, কভারেজ) দাবি করা হয়নি; যেখানে দরকার সেখানে
"পরিমাপ করা হয়নি" লেখা আছে।

---

## ১. এখনকার বাস্তব অবস্থা (যাচাই করা)

### SAST

| সামর্থ্য | আছে কী | সীমা |
|---|---|---|
| Snapshot | ২০০ ফাইল / ৭৬৮ KiB / ফাইল ২৫৬ KiB | এর বেশি upload হয় না |
| Per-file AST | `typescript` + `@lezer/python` + `php-parser` + `@lezer/java` | Go/Ruby/C# ইত্যাদি নেই |
| Taint | source → variable → sink, এক-ধাপ; template literal; parameter summary | field/property-level নয়, branch-sensitive নয় |
| Sanitizer | `SANITIZERS` তালিকা + `PARAMETERIZED_SQL` suppression | sanitizer এক sink-এর জন্য আরেকটিতেও বিশ্বাসযোগ্য নয় (by design) |
| Interprocedural | `projectAst.mjs`: fixed point ≤১২ round, relative import / default / `export *` / `namespace`, ৬-ধাপ trace, `callEdges`+`rounds` প্রকাশিত | **শুধু JS/TS**; class method, dynamic dispatch, package import নেই |
| Framework | শুধু **detection label** (Express/Django/Flask/Spring) | framework semantics নেই (middleware order, guard decorator) |
| Rule উৎস | dataset packs + built-in engine tables | dataset স্পর্শ করা নিষিদ্ধ, তাই নতুন **detection logic** engine-এ লিখতে হবে |

### DAST

| সামর্থ্য | আছে কী | সীমা |
|---|---|---|
| Passive | ৩ request, header/response check | crawl নেই |
| Active-safe | consent-gated, ≤২০ request, ≤১০ crawl link, ≤১০ injection | static HTML regex crawl, JS চালায় না |
| Payload | reflected-XSS marker, SQLi error, open redirect, path traversal, CRLF | ১টি করে payload, প্রতি point-এ ১টি |
| API spec | JSON OpenAPI 3 / Swagger 2, ≤২ probe, literal path param | YAML নেই, query-bearing URL policy-refused |
| Auth | operator-নিয়ন্ত্রিত একক static header, `authMode` ছাড়া কিছু প্রকাশ নয় | login/session, cookie jar, multi-role নেই |
| Method | **GET-only** | POST/PUT/GraphQL নেই |
| SSRF | target policy internal/loopback refuse করে | SSRF *test* করা যায় না — এটি ইচ্ছাকৃত নিরাপত্তা নিয়ন্ত্রণ |

---

## ২. আইটেম-ভিত্তিক রায়

সংকেত: ✅ আছে · 🟡 আংশিক/করা যায় · 🔴 এখন করা যায় না (কারণ সহ) · আকার: S = ছোট, M = মাঝারি, L = বড়

### SAST (১০ আইটেম)

| # | আইটেম | এখন | করণীয় ও শর্ত |
|---|---|---|---|
| 1 | Deep AST + Interprocedural | 🟡 | class method (same-file) → callback arg → tsconfig `paths`; **M**; নতুন dependency লাগে না |
| 2 | Advanced taint | 🟡 | field-sensitive (`req.body.user.id`), destructuring, reassignment chain, per-sink sanitizer allowlist; **M**; এটাই FP সবচেয়ে কমায় |
| 3 | Cross-file/cross-function flow | 🟡 (JS/TS) | Python/Java cross-file = ভাষা-ভিত্তিক নতুন resolver; **L**; ভাষা বাড়ালে টেস্ট fixture-ও বাড়াতে হবে |
| 4 | Framework-aware | 🔴→🟡 | Express/Django/Flask/Spring-এর bounded source/sink/guard টেবিল **engine-এ** (dataset নয়); **L**; সংস্করণ-নির্ভর দাবি করা যাবে না |
| 5 | AuthN/AuthZ bug | 🔴 | ৪-এর উপর নির্ভরশীল: route→handler ম্যাপ + guard অনুপস্থিতি। FP ঝুঁকি বেশি, তাই শুধু "guard পাওয়া যায়নি" + evidence দেখানো যাবে; **L** |
| 6 | Business logic | 🔴 | অ্যাপ-নির্দিষ্ট স্পেসিফিকেশন ছাড়া দাবি করলে fabrication; সর্বোচ্চ bounded pattern (request থেকে price/quantity/role) — কম মূল্য, বেশি FP; **L** |
| 7 | Crypto misconfiguration | 🟡 | md5/sha1/DES/RC4/ECB, hardcoded IV/key, `Math.random` token, `verify=False`, JWT `alg:none`; **S–M**; deterministic, কম FP — **সেরা ROI** |
| 8 | False-positive কমানো | 🟡 | labeled synthetic corpus + প্রতি rule-এ precision/recall (শুধু synthetic, তেমনই লেখা থাকবে) + negative fixture; sanitizer/parameterization suppression; **M** |
| 9 | Code-level evidence | 🟡 | সব AST finding-এ অভিন্ন `astFlow` (source/sink/sanitizer-absent + file:line:col), redacted snippet; **S** |

### DAST (৯ আইটেম)

| # | আইটেম | এখন | করণীয় ও শর্ত |
|---|---|---|---|
| 1 | Advanced crawling | 🟡 | GET form parsing, `sitemap.xml`/`robots.txt` seed, API response থেকে link; **S–M**; request budget একই থাকবে |
| 2 | Browser-based JS test | 🔴 | headless browser = নতুন ভারী dependency (Chromium ~১০০–৩০০ MB) + sandbox/isolation ডিজাইন; বর্তমানে কোনো OS sandbox নেই → **আপনার অনুমতি + নতুন আর্কিটেকচার সিদ্ধান্ত ছাড়া নয়** |
| 3 | REST + GraphQL | 🟡 | REST: OPTIONS/HEAD (নিরাপদ, body নেই); GraphQL: introspection সাধারণত **POST** — request-class পরিবর্তন, তাই opt-in + consent + নতুন authorization চেক লাগবে |
| 4 | Authenticated testing | ✅ (header) | চাইলে একই কাঠামোয় operator-দেওয়া `Cookie` হেডার — login automation নয় |
| 5 | XSS/SQLi/SSRF/IDOR | 🟡 | XSS/SQLi/redirect/traversal/CRLF আছে (reflection/error-ভিত্তিক)। **SSRF ইচ্ছাকৃতভাবে অসম্ভব** (policy internal host refuse করে)। IDOR = ২টি পরিচয় + object-id enumeration = নতুন authorization মডেল; এখন নয় |
| 6 | Access control + business logic | 🔴 | একক static credential মডেলে multi-role চলে না; business logic-এর জন্য অ্যাপ-স্পেসিফিক জ্ঞান দরকার |
| 7 | Safe fuzzing | 🟡 | প্রতি category-তে ২–৩টি bounded variant + throttle একই; মোট request cap না বাড়িয়ে |
| 8 | Evidence validation | 🟡 | একই request পুনরায় পাঠিয়ে (≤২ request) reflection-baseline diff, response hash, "reflected ≠ executed" লেবেল; **M** — accuracy-র জন্য সেরা DAST ROI |
| 9 | Endpoint coverage | 🟡 | `openApiEndpoints/Skipped` আছে, কিন্তু "আবিষ্কৃত vs probed vs skipped" কভারেজ রিপোর্ট নেই; **S** |

---

## ৩. প্রস্তাবিত ধাপ (ক্রম গুরুত্বপূর্ণ)

### Phase 1 — নির্ভুলতা ও প্রমাণ (নতুন dependency নেই, নতুন request class নেই) · সবচেয়ে কম ঝুঁকি
1. SAST crypto-misconfiguration rules (+ positivo/negative fixture)
2. সব AST finding-এ অভিন্ন code-level evidence
3. DAST evidence validation (replay confirm, baseline diff, লেবেল)
4. FP পরিমাপ harness: labeled synthetic corpus, প্রতি rule precision/recall, determinism hash
5. Coverage রিপোর্টিং (endpoint coverage + existing openApi numbers)

**গ্রহণযোগ্যতার শর্ত:** প্রতিটি নতুন rule-এ ≥১ positive + ≥২ negative fixture; corpus-এ মাপা FP/recall সংখ্যা রিপোর্টে শুধু "synthetic corpus" হিসেবে; একই input-এ byte-identical output; request budget ও bound অপরিবর্তিত।

### Phase 2 — SAST গভীরতা
field-sensitive taint → sanitizer propagation → class method/callback + tsconfig paths → framework tables v1 → (তখনই) authz-guard detection।
**শর্ত:** প্রতিটি ধাপে আগের সব corpus fixture অপরিবর্তিত পাস করবে; trace দৈর্ঘ্য ≤৬; round ≤১২।

### Phase 3 — DAST বিস্তার (gate-নির্ভর)
GET form + sitemap crawl → OPTIONS/HEAD → **opt-in GraphQL/REST POST** → coverage রিপোর্ট।

> সিদ্ধান্ত (২০২৬-১১-০২): ব্যবহারকারী **প্রতি-স্ক্যান explicit opt-in + consent + নতুন authorization চেক** সহ
> POST/GraphQL অনুমোদন করেছেন; browser-based testing **অনুমোদিত নয়**। বাস্তবায়ন এখনো শুরু হয়নি — এটি Phase 3-এর কাজ।

### Phase 4 — বড় সিদ্ধান্তের অপেক্ষায়
browser engine (dependency + isolation), multi-role/IDOR, business logic।

### কখনোই নয়
internal network-এ SSRF payload, exploit chain দাবি, CVSS স্কোর, "vendor parity", real-world accuracy দাবি — measurement ছাড়া।

---

## ৪. পরিমাপ পরিকল্পনা (দাবি করার আগে)

| যে মানদণ্ড আপনি বলেছেন | কীভাবে মাপা হবে | যা দাবি করা যাবে না |
|---|---|---|
| Detection | labeled synthetic corpus-এ rule-level true-positive | বাস্তব জগতের নির্ভুলতা |
| Accuracy | একই corpus-এ false-positive rate, rule অনুযায়ী | "শিল্প-মান" তুলনা |
| Coverage | ভাষা/ফাইল/endpoint গণনা স্ক্যান রিপোর্টে | "সব framework সাপোর্ট" |
| Evidence | প্রতিটি finding-এ file:line:col + redacted snippet | exploit proof |
| Performance | ২০০ ফাইল/৭৬৮ KiB max snapshot-এ মাপা wall time (এই মেশিনে) | production SLA |
| Reliability | determinism hash, retry/cancel/restart টেস্ট | "শতভাগ নির্ভরযোগ্য" |
| Reporting | রিপোর্টে coverage + limitation + disclosure | compliance certification |
| Security | credential কখনো persist/log হয় না (টেস্টে pinned) | third-party audit |

---

## ৫. চলমান কাজের সৎ অবস্থা (এই রাউন্ডের আগে)

Correlated **Risk Assessment** (SAST+SCA+SECRETS+DAST একসাথে) — এখন সম্পূর্ণ: contract, engine,
context, `GET /api/v1/projects/:projectId/risk`, project পেজের UI এবং ৩১টি নতুন টেস্ট। বিস্তারিত
`docs/RISK_ASSESSMENT.md`-এ।
