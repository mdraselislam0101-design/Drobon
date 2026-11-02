# Correlated Risk Assessment (SAST + SCA + SECRETS + DAST)

তারিখ: ২০২৬-১১-০২ · শাখা: `arena/8821907b-drobon`
Contract: `packages/shared/src/risk.ts` · Engine: `apps/api/src/risk/engine.ts` · Context: `apps/api/src/risk/context.ts` · Route: `apps/api/src/routes/risk.ts`

## ১. এটি কী

`GET /api/v1/projects/:projectId/risk` একটি **read-only projection** — নতুন স্ক্যান চালায় না, কিছু লেখে না,
কোনো schema migration করে না। এটি প্রজেক্টের ইতিমধ্যে সংরক্ষিত স্ক্যান-ফলাফল পড়ে এমন **cluster** তৈরি করে
যেখানে প্রমাণ সত্যিই ওভারল্যাপ করে, এবং তার সাথে ফিক্সড, প্রকাশিত scoring model দেয়।

একই রিপোর্টে চার স্ক্যানারের ফল একসাথে দেখা যায়, তাই "আলাদা আলাদা ৮টি finding" নয় — "একই endpoint-এ
৩টি দুর্বলতা, একই ফাইলে secret + injection" ধরনের **সম্মিলিত ঝুঁকি** দৃশ্যমান হয়।

## ২. কোন স্ক্যান পড়া হয় (selection rule)

- প্রতিটি scanner type-এর **সর্বশেষ COMPLETED** স্ক্যান: `completedAt` DESC, সমান হলে `id` ASC (deterministic)।
- পুরোনো স্ক্যান, চলমান/ব্যর্থ স্ক্যান, এবং **FALSE_POSITIVE** চিহ্নিত finding কোনোভাবেই স্কোর বা cluster-এ ঢোকে না।
- স্ক্যান না থাকলে সেই scanner `scanId: null, findings: 0` হিসেবে দেখানো হয় — অর্থ "স্ক্যান হয়নি", "পরিষ্কার" নয়।
- ownership: route-এ `ownProjectOr403`, তারপর store boundary-তে আবার `ownerId` ফিল্টার।

## ৩. Correlation rules (৫টি, বদ্ধ তালিকা)

| kind | কখন তৈরি হয় | কী প্রমাণ করে | কী প্রমাণ করে না |
|---|---|---|---|
| `ENDPOINT_CLUSTER` | একই origin+path-এ ≥২টি DAST finding (query বাদ দিয়ে) | একই endpoint-এ একাধিক ত্রুটি একসাথে রেকর্ড হয়েছে | exploit chain, বা ওই path-এ কোড চলছে |
| `SAME_RESPONSE` | একই response (path + observedAt + status) থেকে ≥২টি finding | একই response-এ একাধিক নিয়ন্ত্রণ দুর্বল | আক্রমণের সময় আচরণ |
| `CODE_AND_RUNTIME_CWE` | একই CWE একটি SAST এবং একটি DAST finding-এ | একই শ্রেণির দুর্বলতা কোডে ও লাইভ সারফেসে | flagged ফাইলটিই ওই endpoint সার্ভ করে |
| `SECRET_IN_WEAK_FILE` | একই ফাইলে SECRETS + SAST finding | credential ও কোড-দুর্বলতা একই ফাইলে | credential এখনো বৈধ/ব্যবহারযোগ্য |
| `RECURRING_RULE` | একই ruleId ≥২টি ভিন্ন asset-এ | সাধারণ নিয়ন্ত্রণ অনুপস্থিত (middleware/helper) | প্রতিটি আলাদা bug |

প্রতিটি cluster-এ: `asset`, `title`, `summary` (কী মেলে + **কী প্রমাণ করে না**), `scanners`, এবং
`evidence[]` — যেখানে প্রতিটি রেকর্ড করা `findingId`, scanner, severity, ruleId ও asset থাকে।

## ৪. Scoring model `SEVERITY_SUM_V1` (প্রকাশিত ও পুনর্গণনযোগ্য)

```
cluster score = Σ severity weight (প্রদর্শিত evidence, সর্বোচ্চ ৮টি)
              + (অতিরিক্ত distinct scanner সংখ্যা × ১)
              (সর্বোচ্চ 100)
severity weights: CRITICAL 10 · HIGH 6 · MEDIUM 3 · LOW 1 · INFO 0
band: CRITICAL ≥ 20 · HIGH ≥ 12 · MEDIUM ≥ 5 · LOW ≥ 1 · UNKNOWN = 0
assessment score = সব cluster-এর সর্বোচ্চ score; band = সেই score থেকে derived
```

উদাহরণ (একই CWE কোডে HIGH + রানটাইমে HIGH): `6 + 6 + 1 = 13` → `HIGH`।
যেহেতু স্কোর ঠিক যেই evidence দেখানো হয়েছে তার থেকেই আসে, ব্যবহারকারী হাতে মিলিয়ে যাচাই করতে পারেন।

এই স্কোর **CVSS নয়**, likelihood × impact মডেল নয়, এবং কোনো সার্টিফিকেশন নয়। disclosures-এ এটি লেখা থাকে।

## ৫. Guard যা প্রতিটি response-এ জোর করে (`isRiskAssessment`)

- `band === riskBandForScore(score)` — band কখনো caller নির্ধারিত নয়।
- `score === max(cluster.score)` — headline derived।
- `correlatedFindings + unclusteredFindings === findingsAnalysed === Σ sources[].findings`।
- প্রতিটি cluster-এ ≥২টি **distinct** finding; evidence-এর scanner সেট ঠিক `scanners`-এর সমান।
- evidence শুধু সেই scanner থেকে আসতে পারে যার completed scan আছে (FALSE_POSITIVE-মুক্ত)।
- `NO_FINDINGS` / `NO_COMPLETED_SCANS` অবস্থায় cluster থাকতে পারে না।
- `disclosures` কখনো খালি নয়; প্রতি string ≤400 অক্ষর।
- `sources` সবসময় চারটি scanner, নির্দিষ্ট ক্রমে; কোনো scanner-এর `scanId` null হলে তার findings ০।
- cluster `id` = `risk_` + sha256(`kind\nasset`)-এর ২৪ hex — একই ইনপুটে একই id।

Guard ব্যর্থ হলে route `500` দেয় (নীরবে ভুল ডেটা পাঠায় না)।

## ৬. সৎ অবস্থাগুলো

| status | অর্থ |
|---|---|
| `ASSESSED` | ✓ অন্তত একটি finding পড়া হয়েছে; cluster থাকতে পারে বা নাও থাকতে পারে |
| `NO_FINDINGS` | ✓ স্ক্যান শেষ হয়েছে কিন্তু কোনো finding রেকর্ড হয়নি — **নিরাপদ প্রমাণ নয়** |
| `NO_COMPLETED_SCANS` | ✓ কোনো completed scan নেই — কিছুই মূল্যায়ন করা যায়নি |

`clusters: []` মানে "কোনো ওভারল্যাপ পাওয়া যায়নি", disclosures-এ স্পষ্ট লেখা থাকে:
"That is an absence of correlation, not evidence that the project is safe."
কোনো cluster থাকলে band `UNKNOWN` হতে পারে না, এবং কোনো কিছু না থাকলে band কখনো HIGH/CRITICAL নয়।

## ৭. Bound ও performance

- `RISK_MAX_FINDINGS = 400` (skanner-দের মধ্যে round-robin, তাই এক scanner অন্যটিকে block করে না)
- `RISK_MAX_CLUSTERS = 50`, `RISK_MAX_EVIDENCE = 8`, `RISK_MAX_DISCLOSURES = 12`
- পুরো কাজ memory-তে, I/O শুধু `listByProject` + `getFindingWorkflowsForFindings`; কোনো নেটওয়ার্ক/স্ক্যান নয়।
- limit ছুঁলে `truncated: true` এবং disclosure-এ লেখা থাকে কত cluster বাদ পড়েছে।
- ধীর গতি বা "scalable" দাবি করা হয় না — কোনো load test হয়নি।

## ৮. Security

- কোনো secret value, evidence text, description, fingerprint বা file content response-এ যায় না —
  শুধু finding **id**, ruleId, severity, asset (path/endpoint)।
- `findingId` ইচ্ছাকৃতভাবে দেখানো হয়: এটিই provenance, যা দিয়ে মালিক আসল finding খুঁজে যাচাই করতে পারেন।
  (`packs`/mobile-এ এই id-ই finding detail-এর কী।)
- target/endpoint শুধু রেকর্ড করা bounded URL; engine কোনো URL fetch করে না।

## ৯. যা এই আপডেটে **নেই** (সৎ তালিকা)

- নতুন SAST/DAST/SCA detection নয় — শুধু বিদ্যমান finding-এর correlation।
- কোনো exploit chain, PoC, CVSS স্কোর, likelihood মডেল বা business impact হিসাব নয়।
- ইতিহাস/trend, SLA, notification, ticket automation নয়।
- PDF/Markdown রিপোর্টে cluster যুক্ত করা হয়নি (পরবর্তী ধাপ); এখন API + project পেজে দেখানো হয়।
- DAST-এর GET-only request profile অপরিবর্তিত। (opt-in POST/GraphQL স্ক্যান-ক্লাস পরিবর্তন — আলাদা অনুমোদিত ধাপ, এখনো বাস্তবায়িত নয়।)

## ১০. যাচাই (এই রাউন্ডে চালানো)

| ফাইল | টেস্ট | কী যাচাই হয় |
|---|---|---|
| `apps/api/test/riskEngine.test.ts` | 22 | rules, caps, determinism, guard tamper-rejection, scoring table |
| `apps/api/test/riskApi.test.ts` | 7 | auth 401 / ownership 403 / 422 / 404, honest states, latest-scan selection, FALSE_POSITIVE exclusion, redaction, truncation |
| `apps/web/test/riskAssessmentUi.test.tsx` | 2 | load-on-request, evidence citation, honest empty state |

সবগুলো **synthetic fixture**। কোনো বাস্তব টার্গেট, বাস্তব accuracy বা লোড-টেস্ট সংখ্যা দাবি করা হয় না।
