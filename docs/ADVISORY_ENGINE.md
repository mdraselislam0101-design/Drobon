# জেনেরিক Advisory Engine — নতুন যেকোনো সমস্যা, যেকোনো ভাষায়

**তারিখ:** 2026-10-26 · **Branch:** `arena/5bb07bd8-drobon` · **Scope:** শুধু মেইন অ্যাপ (`Drobon`)। ডেটাসেট repo বা ডেটাবেসে কোনো পরিবর্তন নেই, কোনো নতুন npm dependency নেই।

> **আপনি যা চেয়েছিলেন (এক লাইনে):** "PHP2Shell বাদেও ভবিষ্যতে নতুন নতুন সমস্যা এলে আমার টুল যেন সেগুলো ধরতে ও বিশ্লেষণ করতে পারে, সকল কোডিং ল্যাংগুয়েজে।"
>
> **যা বানানো হয়েছে:** একটি **data-driven, language-agnostic advisory engine**। নতুন CVE / নতুন runtime bug / নতুন ভাষার সমস্যা এলে **কোড বদলাতে হয় না** — শুধু একটি runtime advisory record যোগ করলেই টুল সেটা ধরবে।

---

## ১) কেন এটা "সব ভাষার" জন্য কাজ করে

অ্যাপে কোনো `if (language === 'php')` নেই। তিনটি জিনিসই **ডেটা** হিসেবে থাকে বাইরের runtime pack-এ:

| যা ডেটা থেকে আসে | মানে |
|---|---|
| `ecosystem` / `component` | `php`, `nodejs`, `python`, `go`, `java`, `ruby`, `dotnet`, `rust`, `nginx`, `wordpress`… যেকোনো লেবেল |
| `fingerprints[]` | version কোথায় পাওয়া যাবে — response header, response body, JSON manifest, text manifest — আর তার regex |
| `branches` / `constraints` / `eolBranches` | কোন version আক্রান্ত, কোনটা patched — একটি জেনেরিক dotted-numeric comparator দিয়ে |

আজকেই একই evaluator দিয়ে **PHP header, `composer.json`, `package.json`, `go.mod`, `requirements.txt`** — সব পরীক্ষা করা হয়েছে (টেস্ট + লাইভ প্রোব)। আগামীকাল `pom.xml`, `Cargo.toml`, `Gemfile`, বা `Server: nginx/...` যোগ করতে হলে শুধু নতুন record লাগবে।

---

## ২) কীভাবে চালু করবেন

`.env` / environment-এ একটি মাত্র variable:

```
ADVISORY_PATH=/opt/drobon/advisory-pack.json
```

- ফাইলটা **repo-র বাইরে** থাকে (যেমন `/home/user/advisory-pack.json`) — ঠিক যেমন `DATASET_PATH` বাইরের dataset repo-র দিকে নির্দেশ করে।
- অ্যাপে **কোনো advisory byte নেই**, কোনো hardcoded CVE rule নেই।
- ফাইল না দিলে status হয় `NOT_CONFIGURED` — কোনো findings নয়, কোনো মিথ্যে "clean" নয়।

দুটি নতুন endpoint (authenticated, read-only):

| Endpoint | কাজ |
|---|---|
| `GET /api/v1/advisory/status` | pack load হয়েছে কি, কত record, `generatedAt`, stale কি না, refused records |
| `POST /api/v1/advisory/analyze` | scan না বানিয়েই header/body/files দিয়ে সঙ্গে সঙ্গে বিশ্লেষণ — নতুন record যোগ করার সাথে সাথে যাচাই করার জন্য |

---

## ৩) Pack-এর গঠন (সম্পূর্ণ উদাহরণ)

```json
{
  "schemaVersion": "drobon.advisory-pack/v1",
  "packId": "operator-advisories",
  "version": "1.0.0",
  "generatedAt": "2026-10-26T00:00:00.000Z",
  "advisories": [
    {
      "id": "CVE-2026-109618",
      "ruleId": "ADV-0001",
      "title": "PHP core OOM memory-corruption RCE (PHP2Shell)",
      "description": "Unauthenticated RCE in the PHP engine. Patching is the only complete mitigation.",
      "severity": "CRITICAL",
      "cwe": "CWE-787",
      "ecosystem": "php",
      "component": "php",
      "remediation": "Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 immediately.",
      "limitation": "Version signal only — confirm with php -v on the host.",
      "references": ["https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching"],
      "introduced": "5.4",
      "branches": [
        { "branch": "8.5", "fixedVersion": "8.5.12" },
        { "branch": "8.4", "fixedVersion": "8.4.27" },
        { "branch": "8.3", "fixedVersion": "8.3.36" },
        { "branch": "8.2", "fixedVersion": "8.2.35" }
      ],
      "eolBranches": ["5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"],
      "fingerprints": [
        {
          "source": "response-header",
          "header": "x-powered-by",
          "pattern": "PHP/([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)",
          "selfTest": "PHP/8.1.2"
        },
        {
          "source": "manifest-json",
          "artifact": "composer.json",
          "path": "require.php",
          "pattern": "([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)",
          "selfTest": "^8.1"
        }
      ]
    }
  ]
}
```

**মূল নিয়ম:**

- `ruleId` → `ADV-0000` ফরম্যাট (finding-এর rule id)।
- `fingerprints[].pattern`-এর **capture group 1 = version**; `selfTest` সেই version বের করতে পারতেই হবে, নইলে record refused হয় (fail closed)।
- `branches` → runtime-এর release-line অনুযায়ী fixed version; `eolBranches` → যেগুলোর কোনো patch নেই (সবসময় AFFECTED)।
- `constraints` → লাইব্রেরির জন্য `{ min, maxExclusive }` range।
- Pattern নিরাপদ হতে হবে: backreference, lookaround, nested quantifier (`(a+)+`), repeated `.*` — refused। Version pattern-এ optional group `(?:\.[0-9]+)?` এর বদলে **alternation** ব্যবহার করুন (উপরের উদাহরণে যেমন) — তা না হলে safety lint false-positive দেবে।

---

## ৪) নতুন সমস্যা এলে ঠিক কী করবেন (কোড ছাড়াই)

ধরুন আগামীকাল **Go-তে নতুন CVE** বের হলো:

1. Pack-এ একটি নতুন record যোগ করুন:
   ```json
   {
     "id": "CVE-2027-XXXXX",
     "ruleId": "ADV-0042",
     "title": "Go stdlib issue",
     "description": "...",
     "severity": "HIGH",
     "ecosystem": "go",
     "component": "stdlib",
     "remediation": "Upgrade to Go 1.99.2",
     "constraints": [{ "min": "1.20", "maxExclusive": "1.99.2" }],
     "fingerprints": [{
       "source": "manifest-text",
       "artifact": "go.mod",
       "pattern": "go\\s+([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)",
       "selfTest": "go 1.20.4"
     }]
   }
   ```
2. `generatedAt` আপডেট করুন, `version` বাড়ান।
3. সার্ভার restart (বা নতুন process) → pack lazy-load হবে।
4. `POST /api/v1/advisory/analyze` দিয়ে যাচাই করুন → তারপর scan চালান।

**কোডে এক লাইনও বদলাতে হয়নি।** এইটাই আপনার চাওয়ার মূল জবাব।

---

## ৫) টুল ঠিক কী বলবে (বাস্তব ফলাফল)

একটি live probe-এ (`X-Powered-By: PHP/8.4.3`):

```
ADV-0001  CRITICAL  AFFECTED   observed 8.4.3 < fixed 8.4.27 on branch 8.4
ADV-0002  CRITICAL  AFFECTED   observed 8.4.3 < fixed 8.4.27 on branch 8.4
```

patched version-এ (`PHP/8.4.27`):

```
(no advisory finding)  → NOT_AFFECTED, honestly counted
```

অজানা branch-এ (`PHP/9.0.1`) — কখনো "clean" বলা হয় না:

```
ADV-0001  LOW  UNKNOWN  [NEEDS REVIEW] branch not covered — verify manually
```

Finding-এর evidence-এ শুধু **advisory id + component + version + location** থাকে — কোনো raw header/token value নেই। Finding সাধারণ `Finding` contract মেনে চলে, তাই findings list, workflow, assistant, report (JSON/Markdown/SARIF), SBOM — সব জায়গায় স্বয়ংক্রিয়ভাবে দেখা যায়।

---

## ৬) সৎ সীমা — এটা করলেও যা **থাকবে না**

| সীমা | কেন |
|---|---|
| **Version signal ≠ installed version** | `X-Powered-By` লুকানো/ভুয়া হতে পারে; `composer.json`-এ `"^8.1"` একটি constraint, ইনস্টল করা build নয়। তাই remediation-এ `php -v` দিয়ে confirm করতে বলা হয়। |
| **কোনো crafted traffic / exploit নেই** | Passive DAST-এর ৩টি GET-ই থাকে; নতুন request, payload বা fuzz যোগ হয় না। RCE "প্রমাণ" করা হয় না। |
| **নতুন CVE আপনাআপনি আসে না** | ডেটা operator/feed থেকে আসতে হয়। `generatedAt` ৩০ দিনের পুরনো হলে status `STALE` দেখায় এবং finding-এ সতর্কতা যোগ হয়। Live NVD/GHSA/OSV/KEV feed = license + refresh cadence = owner সিদ্ধান্ত (dataset GAP-001..004)। |
| **"সব বাগ" ধরা যাবে না** | কোনো স্ক্যানারই পারে না। এটা শুধু version/advisory signals + source pattern rules (SAST-এ ৫৪টি language family, `PARTIAL`) দেখে। Business-logic bug, auth bypass, runtime state — এখানে নেই। |
| **অন্যের সাইটে লিখিত অনুমতি লাগবে** | টুল project ownership + network safety চেক করে, third-party legal permission নয়; UI-তে target `UNVERIFIED` থাকে (`docs/DAST.md`)। |
| **Patch/WAF/monitoring করে দেবে না** | শুধু রিপোর্ট + remediation guidance; CISA-র পরামর্শ মেনে owner-কেই patch করতে হবে। |

---

## ৭) ফাইল / যাচাই

| নতুন/বদলা ফাইল | কাজ |
|---|---|
| `apps/api/src/external/advisory.ts` | pack validation, generic version comparator, signal extraction, evaluation, lazy loader, staleness |
| `apps/api/src/scans/advisoryFindings.ts` | advisory verdict → বৈধ `Finding` (DAST / SCA) |
| `apps/api/src/scans/dast/engine.ts` | passive response-এর version signal → advisory finding (কোনো extra request নেই) |
| `apps/api/src/scans/sca/engine.ts` | manifest-এ declared version → advisory finding (PHP/Node/Go/Python…) |
| `apps/api/src/routes/advisory.ts` | `GET /api/v1/advisory/status`, `POST /api/v1/advisory/analyze` |
| `apps/api/src/config.ts`, `.env.example` | `ADVISORY_PATH` |
| `packages/shared/src/scans.ts` | `ADV-####` rule-id family (finding contract) |
| `apps/api/test/advisory.test.ts`, `config.test.ts` | ১৬টি নতুন টেস্ট |

**Verify:** `npm run verify` **PASS ১১/১১** · `npm test` **PASS ১,৩৩৫/১,৩৩৫** (shared ১৮৩ + api ৮৫৮ + worker ২৮ + web ২৬৬; নতুন ১৬টি) · `verify:dataset` **PASS** (আগের ৪,০০১ SCA declared test + DAST/SAST parity অক্ষত) · `check:boundaries` / `check:repo-integrity` / `check:secrets` PASS · লাইভ preview-তে `ADVISORY_PATH` সহ পুরো flow যাচাই (`/api/v1/advisory/status` → ৫ records loaded; `/analyze` → PHP/Node/Go/Python; SCA scan → persisted `ADV-0001`/`ADV-0002` findings)।

---

## ৮) পরবর্তী ধাপ (ঐচ্ছিক)

1. **৮টি বাকি document reader** → SCA declaration pack-এর বাকি ৫৬৮ rule-ও scan-এ চলবে।
2. **Feed adapter seam** → operator যখন licensed advisory feed দেবেন, সেটা সরাসরি pack-এ sync করা যাবে (এখনও owner/license সিদ্ধান্ত বাকি)।
3. **Authorization/engagement record** → অন্যের site scan-এর লিখিত scope + audit log (`USER_DECLARED` কে আরও স্পষ্ট করা)।
4. **Deep SAST (AST)** → source-code ত্রুটির গভীর বিশ্লেষণ; এটা আলাদা বড় কাজ, নতুন dependency প্রয়োজন।
