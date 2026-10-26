# Deep SAST — বাউন্ডেড AST / Dataflow Engine

**তারিখ:** 2026-10-26 · **Branch:** `arena/5bb07bd8-drobon` · **Scope:** শুধু মেইন অ্যাপ (`Drobon`)। ডেটাসেট repo / ডেটাবেসে কোনো পরিবর্তন নেই, **কোনো নতুন npm dependency নেই** (parser নিজে লেখা, bounded)।

> **আপনি যা চেয়েছিলেন:** "কোডের ভেতরের ত্রুটি আরও গভীরে বিশ্লেষণ" — অর্থাৎ শুধু লাইনে regex ম্যাচ নয়, বরং **অবিশ্বস্ত ইনপুট → ভেরিয়েবল → বিপজ্জনক ফাংশন** এই প্রবাহটা ধরা।
>
> **যা পেলেন:** একটি **data-driven, language-agnostic, bounded AST/dataflow pass** — পুরনো SAST engine-এর উপর additive। ১১টি ভাষার জন্য একই analyzer; নতুন ভাষা যোগ করা মানে একটি profile entry, নতুন parser নয়।

---

## ১) আগে ছিল কী, এখন কী যোগ হলো

| স্তর | আগে | এখন |
|---|---|---|
| Line matcher | ১,০০০ dataset rule, প্রতি লাইনে regex | **অপরিবর্তিত** |
| Bounded semantic pass | literal masking + single-pass source→sink (কিন্তু dataset-এ `flow` field নেই → বাস্তবে চলে না) | **অপরিবর্তিত** (রেখে দেওয়া হয়েছে) |
| **AST/dataflow pass** | ছিল না | ✅ **নতুন** — tokenize → shallow structural tree → scope-aware taint → sink |

**নতুন pass-এর আসল লাভ:**

- **Comment / string body** আলাদা token — তাই `// exec(req.body.x)` বা `"exec(req.body.x)"` আর false positive দেয় না।
- **Dotted chain** (`req.body.name`, `db.query`, `os.system`) — আলগা identifier নয়, তাই unrelated নামে ভুল ম্যাচ কম।
- **Sanitizer** (`encodeURIComponent`, `DOMPurify.sanitize`, `intval`, `shlex.quote`…) আর **parameterized SQL** (`?`, `$1`, `%s`) সঠিকভাবে suppress করে।
- **Template literal**-এর `${...}` ভেতরের taint দেখা যায়।
- **এক স্তরের interprocedural flow** — `function run(v) { exec(v) } run(req.body.x)` ধরা পড়ে (একটি bounded extra iteration, কোনো fixpoint নেই)।

---

## ২) "সকল ভাষা" — কীভাবে

`apps/api/src/scans/sast/astProfiles.ts`-এ **profile গুলো ডেটা**:

| Family | Profile-এ যা আছে |
|---|---|
| `javascript`, `typescript`, `jsx`, `tsx` | `req.body/query/params`, `process.argv`, `location.search`… sinks: `exec`, `db.query`, `innerHTML`, `eval` |
| `python` | `request.args/form/json`, `sys.argv`… sinks: `os.system`, `subprocess.run`, `execute` |
| `php` | `$_GET/$_POST/$_REQUEST`… sinks: `system`, `shell_exec`, `mysqli_query`, `echo` |
| `java`, `kotlin` | `request.getParameter`, `getHeader`… `Runtime.getRuntime`, `executeQuery` |
| `go` | `r.FormValue`, `r.URL.Query`… `exec.Command`, `Query`, `Exec` |
| `csharp` | `Request.QueryString`, `Console.ReadLine`… `Process.Start`, `SqlCommand` |
| `ruby` | `params`, `ARGV`… `system`, `Kernel.system` |

একই tokenizer + একই taint engine সবগুলোতে চলে। আগামীকাল `C`, `Rust`, `Swift` বা `Dart` যোগ করতে হলে শুধু একটি profile object লাগবে — parser বদলাতে হবে না।

**Routing:** `supportsBoundedAst(family)` (`languages.ts`) দেখে pass চালাবে কি না। **`maturity` সব family-র জন্য `PARTIAL` থেকে যায়** — bounded AST মানে `FULL` নয়, এটা সৎভাবেই বলা হয়েছে।

---

## ৩) Rule কোথা থেকে আসে (কোনো embedded rule নেই)

অ্যাপে কোনো নতুন vulnerability rule hardcode করা হয়নি। Pass শুধু **সিদ্ধান্ত নেয়** যে একটি flow পৌঁছেছে; সেটা **report করার জন্য** লোড করা dataset rule-কে বেছে নেয়, `category` দেখে:

| Flow class | Category hint | উদাহরণ (real dataset) |
|---|---|---|
| `command` | `command-injection` | `DPK-SAST-044` |
| `sql` | `sql-injection` | `DPK-SAST-008` |
| `html` | `xss` / `cross-site-scripting` | `DPK-SAST-002` |
| `code` | `code-injection` | `DPK-SAST-001` |

`astReporterRules(effectiveRules, family)` → family-gating + category → deterministic (sorted id) → **একটি rule id**। ম্যাচিং rule না থাকলে সেই class-এ **কোনো finding নেই** (fail closed, ভুয়া rule বানানো হয় না)।

Finding সাধারণ `Finding` contract মেনে তৈরি — তাই findings list, workflow, assistant, Markdown/SARIF report, SBOM — সব জায়গায় স্বয়ংক্রিয়ভাবে দেখা যায়। একই `(ruleId, line)`-এ lexical + flow + AST-এর মধ্যে **একটিই** finding থাকে (dedupe)।

---

## ৪) বাস্তবে যা ধরা পড়েছে (probe + test)

| কোড | ফল |
|---|---|
| `const cmd = req.body.cmd; child_process.exec(cmd);` | ✅ `command` finding, line 2 |
| `// child_process.exec(req.body.x)` | ✅ **কোনো finding নেই** (comment) |
| `const s = "child_process.exec(req.body.x)";` | ✅ **কোনো finding নেই** (string body) |
| `exec(encodeURIComponent(req.body.n))` | ✅ suppress (sanitizer) |
| ``const q = `ls ${req.body.dir}`; exec(q);`` | ✅ `command` finding (template taint) |
| `db.query("... WHERE n = " + req.body.n)` | ✅ `sql` finding |
| `db.query("... WHERE n = ?", [req.body.n])` | ✅ suppress (parameterized) |
| `el.innerHTML = req.body.html` | ✅ `html` finding |
| `function run(v){exec(v)} run(req.body.x)` | ✅ `command` finding (১-স্তরের interprocedural) |
| Python / PHP / Go equivalent | ✅ তিনটিতেই `command` finding |

লাইভ engine integration-এ (fixture dataset): `findingsTotal: 1`, `astFilesAnalyzed: 1`, `astFlowsFound: 1`, `ruleId: DPK-SAST-901`, `scanner: SAST`, `isFinding: true` — আর dataset rule-টির নিজের pattern ওই সোর্সে **ম্যাচই করে না**, অর্থাৎ finding-টা সত্যিই AST pass থেকে এসেছে।

**লাইভ প্রিভিউ (real dataset, ১,০০০ rule):**
```js
const cmd = req.body.cmd;
child_process.exec(cmd);
const q = "SELECT * FROM t WHERE n = " + req.body.n;
db.query(q);
```
→ `findingsTotal: 2`, `astFilesAnalyzed: 1`, `astFlowsFound: 1`।
`DPK-SAST-044` line 2 lexical pattern-এ ধরা পড়েছে; কিন্তু **`DPK-SAST-008` line 4 (`db.query(q);`)-এ AST pass ছাড়া ধরা পড়ত না** — কারণ rule-টির regex একই লাইনে `query(... + ...)` খোঁজে, আর এখানে concat আগের লাইনে। অর্থাৎ AST pass সত্যিই নতুন ত্রুটি ধরেছে, শুধু নামমাত্র যোগ হয়নি।

---

## ৫) হার্ড বাউন্ড (সব টেস্টে যাচাই)

| সীমা | মান |
|---|---|
| Tokens / file | ১২,০০০ |
| Bytes / file | ২৬২,১৪৪ |
| Statements / file | ২,০০০ |
| Functions / file | ৬৪ |
| Tainted variables | ৫১২ |
| Nesting depth | ৩২ |
| Findings / rule / file | ৩ |
| Total AST findings / file | ২০০ (scan cap ২০০-এর ভেতরে) |
| Deadline | SAST-এর ১০ s deadline + processor-এর ৩০ s; loop-এ প্রতি ৬৪ statement-এ check |

বেশি হলে → **prefix analyse + `truncated: true`**, কখনো অনুমান নয়। Scan summary-তে `astFilesAnalyzed` ও `astFlowsFound` কাউন্টার আছে — কী analyse হলো, কী finding এলো, স্পষ্ট।

---

## ৬) সৎ সীমা — এটা এখনো যা **নয়**

| সীমা | ব্যাখ্যা |
|---|---|
| **Full parser নয়** | এটি একটি **shallow structural tree** (statement/call/assignment/function-summary), পূর্ণ ECMAScript/Python/PHP grammar নয়। JSX element, decorator, TS type-level construct, macro — parse করা হয় না। |
| **`FULL` maturity নয়** | সব family এখনো `PARTIAL`। "Bounded AST" ≠ complete semantic analysis। |
| **Cross-file নেই** | import/require resolve করা হয় না; flow একটিই ফাইলের ভেতরে সীমাবদ্ধ। |
| **Fixpoint নেই** | interprocedural propagation মাত্র **একটি** extra iteration; recursive/transitive call-chain ধরা পড়বে না। |
| **Control-flow insensitive** | `if (false) { exec(tainted) }` — branch condition বোঝা হয় না (conservative, over-report হতে পারে)। |
| **Sanitizer allowlist সীমিত** | তালিকায় নেই এমন sanitizer কে unsanitized ধরা হয় — অর্থাৎ **কম রিপোর্ট নয়, বেশি রিপোর্ট** হতে পারে; কখনো silently suppress করে না। |
| **"সব বাগ" নয়** | business logic, auth bypass, race condition, runtime state — এখনো বাইরে। কোনো স্ক্যানারই সব ধরে না। |
| **Auto-fix নেই** | শুধু read-only বিশ্লেষণ; source বদলায় না, patch করে না, code execute করে না। |
| **নতুন npm dependency নেই** | tree-sitter/parser library আনিনি — নিজের bounded lexer লিখেছি, তাই lockfile/audit/scan-boundary অক্ষত। |

---

## ৭) ফাইল / যাচাই

| ফাইল | কাজ |
|---|---|
| `apps/api/src/scans/sast/astProfiles.ts` | ১১টি language profile + source/sink/sanitizer matcher |
| `apps/api/src/scans/sast/astLexer.ts` | bounded tokenizer, chain resolver, matching-close, truncation |
| `apps/api/src/scans/sast/astAnalyzer.ts` | statement tree, function summaries, taint pass, reporters, caps |
| `apps/api/src/scans/sast/engine.ts` | AST pass wiring + dedupe + `astFilesAnalyzed` / `astFlowsFound` |
| `apps/api/src/scans/sast/languages.ts` | `supportsBoundedAst()` (maturity অপরিবর্তিত) |
| `packages/shared/src/scans.ts` | `ADV`/`DPK-SAST-####` rule-id pattern fix (dataset-এ ৪-digit id আছে), ২টি summary counter |
| `apps/api/test/deepSast.test.ts` | ১৩টি নতুন test |

**Verify:** `npm run verify` **PASS ১১/১১** · `npm test` **PASS ১,৩৪৮/১,৩৪৮** (shared ১৮৩ + api ৮৭১ + worker ২৮ + web ২৬৬) · `verify:dataset` **PASS** (SAST ১,০০০ rule / ৪,০৪৩ declared test অক্ষত) · lint / typecheck / builds / boundaries / secrets / repo-integrity সব PASS।

---

## ৮) নতুন ভাষা যোগ করার নিয়ম

`astProfiles.ts`-এ একটি entry:

```ts
rust: cLike('rust', {
  sources: ['std::env::args', 'request.body'],
  // sinks/sanitizers সংশ্লিষ্ট API নাম; বাকি syntax hints C-like ডিফল্ট
}),
```

তারপর `AST_SUPPORTED_FAMILIES` automatically আপডেট হয় (`Object.keys`)। কোনো parser বদলাতে হয় না, ডেটাসেট repo-তেও হাত দিতে হয় না — শুধু মেইন অ্যাপে একটি profile।

---

## ৯) পরবর্তী ধাপ (ঐচ্ছিক)

1. **Cross-file import resolution** — bounded module graph দিয়ে flow এক ফাইল থেকে অন্য ফাইলে নেওয়া।
2. **Control-flow sensitivity** — branch/loop-aware taint, false positive আরও কমানো।
3. **Fixpoint (bounded 2–3 iteration)** — recursive call chain।
4. **বাকি ৮টি document reader** (SCA declaration) — পরবর্তী কাজ। **Authorization/engagement record** ইতিমধ্যে সম্পন্ন ([`ENGAGEMENTS.md`](ENGAGEMENTS.md))।
