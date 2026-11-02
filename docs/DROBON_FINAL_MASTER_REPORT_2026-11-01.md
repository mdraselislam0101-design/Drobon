# Drobon — Final Master Report (Advanced Autonomous AI Cybersecurity Platform)

**তারিখ:** ২০২৬-১১-০১
**Branch:** `arena/8821907b-drobon` (base `c400493`, PR #8 merge-এর পরের main)
**সিদ্ধান্ত: storage gate (startup + per-job + per-write) + 7-role gateway + role→scanner wiring + capability report + loopback model config implemented; cutover design ready, production migration tool নেই; PRODUCTION NO-GO; Agent default-off**

এই প্রতিবেদনটিই বর্তমান একক authoritative report। পূর্ববর্তী প্রতিবেদনগুলো ইতিহাস হিসেবে অক্ষত আছে; কোনো ফাইল এই execution-এ মুছে ফেলা হয়নি বা সরানো হয়নি।

---

## ০. এক নজরে

| দিক | অবস্থা | প্রমাণ |
|---|---|---|
| Storage boundary (startup + per-job + **per-write** gate) | **IMPLEMENTED + TESTED**, কিন্তু same-UID সীমা অমীমাংসিত | `apps/api/src/lib/storageBoundary.ts`, `server.ts`, `scans/store.ts` (`beforePersist`), `apps/api/test/storageBoundary.test.ts` (১৯ test) |
| Legacy writer-এর ডেটা ক্ষতি | **পুনরুৎপাদিত, এখনো অসমাধান** | `scripts/verify-agent-downgrade.mjs`, `verify-agent-os-boundary.mjs`, `verify-agent-server-coexistence.mjs` — তিনটিই exit ০ এবং ক্ষতি দেখায় |
| Migration / rollback tool | **NOT IMPLEMENTED** | আগের copy-only rehearsal পূর্ণ migration নয় |
| সাত logical Agent role + tool grant | **IMPLEMENTED + TESTED** (১২ test) | `apps/api/src/agent/roles.ts`, `agentRoles.test.ts` |
| Local model adapter | **CONTRACT IMPLEMENTED + config wired; model নেই** | `apps/api/src/agent/localModel.ts`, `config.ts` (`LOCAL_MODEL_ENDPOINT`/`LOCAL_MODEL_NAME`, loopback-only), loopback stub দিয়ে test |
| Capability report (read-only) | **IMPLEMENTED + TESTED** | `GET …/agent/capabilities`, `apps/api/src/agent/capabilities.ts`, ড্যাশবোর্ড panel |
| প্রকৃত AI reasoning / exploit validation | **NOT IMPLEMENTED** | runtime/model অনুপস্থিত (§৪) |
| চারটি scanner | বিদ্যমান ও regression-এ সবুজ; আসল Dataset এই run-এ যাচাই হয়নি | §৩, §৫ |
| Role → scanner gateway (Phase C) | **IMPLEMENTED + TESTED (negative control সহ)** | `apps/api/src/agent/orchestration.ts`, `agentOrchestration.test.ts` (৭ test) |
| Evidence contract at review time | **IMPLEMENTED + TESTED** | `evidenceGaps()`; evidence ছাড়া finding আর `SUSPECTED` হয় না, `INCONCLUSIVE` হয় |
| Migration/rollback rehearsal (synthetic) | **REHEARSED, ১৭টি flag true; production tool নয়** | `scripts/verify-agent-store-migration.mjs`, exit 0 |
| Cutover design (dedicated identity) | **DESIGN ONLY — অনুমোদন বাকি** | `docs/AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md` |
| Full regression | **1,921 passed / 1 skipped** (185 file passed + 1 skipped) | `/tmp/drobon-master4-full-regression.log`, exit 0 |
| Typecheck / lint / build | **আলাদাভাবে exit 0**; Vite 526.17 kB chunk warning | §৫ |
| Production | **NO-GO** | §৭ |

---

## ১. এই execution-এ ঠিক কী বদলেছে (verified)

পরিবর্তিত/নতুন path (কোনোটি staged/commit/push হয়নি):

1. **নতুন** `apps/api/src/lib/storageBoundary.ts` — POSIX boundary attestation + `/proc` foreign-writer detection + `opaque-injected-adapter`।
2. **পরিবর্তিত** `apps/api/src/server.ts` — Agent সক্রিয় থাকলে boundary attest না হলে বা injected store opaque হলে startup **fail closed** (`StorageBlockedError`, log `STORAGE BLOCKED`)।
3. **পরিবর্তিত** `apps/api/src/agent/execution.ts` + `apps/api/src/app.ts` — প্রতিটি Agent job শুরুর আগে boundary পুনরায় যাচাই; ব্যর্থ হলে job `FAILED` ("STORAGE BLOCKED …"), কোনো scanner চলে না, findings লেখা হয় না।
4. **নতুন** `apps/api/src/agent/roles.ts` — সাতটি logical role, প্রতিটির tool grant, evidence requirement, `maxSteps`; Master/Recon/Validation-এর কাছে scanner বা network tool নেই।
5. **নতুন** `apps/api/src/agent/localModel.ts` — local-model contract: loopback-only, closed JSON schema, শুধু দেওয়া evidence-id cite করা যায়, timeout/size bound, কোনো fallback নেই, model না থাকলে `NONE`।
6. **নতুন** `apps/api/test/storageBoundary.test.ts` (১৯), `apps/api/test/agentRoles.test.ts` (১২), `apps/api/test/agentCapabilities.test.ts` (৬), এবং `agentApi.test.ts`-এ নতুন end-to-end test।
7. **নতুন** `apps/api/src/agent/capabilities.ts` + read-only route `GET /api/v1/projects/:projectId/assessments/:assessmentId/agent/capabilities` — সাত role, network role, model provider (`NONE`/`LOCAL_LOOPBACK`), storage verdict ও execution gate একসঙ্গে server-সত্য হিসেবে দেয়; কোনো side effect নেই, auth + ownership লাগে।
8. **পরিবর্তিত** `apps/api/src/scans/store.ts` — `beforePersist` hook; প্রতিটি scan-document write-এর ঠিক আগে boundary আবার যাচাই হয়, ব্যর্থ হলে write প্রত্যাখ্যাত হয় (test প্রমাণ করে file-এর byte অপরিবর্তিত)।
9. **পরিবর্তিত** `apps/api/src/config.ts` — `LOCAL_MODEL_ENDPOINT` ও `LOCAL_MODEL_NAME`; endpoint loopback না হলে, নাম না থাকলে বা production-এ config error (কোনো remote fallback নেই)।
10. **নতুন** `apps/api/src/agent/orchestration.ts` — role→scanner gateway: প্রতিটি scan type-এর owning role ও তার tool grant যাচাই (`planRoleExecution`), এবং finding-এর declared evidence যাচাই (`evidenceGaps`, `evidenceCoverage`)। ব্যর্থ হলে **fail closed**, কোনো path/source/secret leakage ছাড়া।
11. **পরিবর্তিত** `apps/api/src/agent/execution.ts` — engine-এ পৌঁছানোর **আগেই** role gateway; grant না থাকলে job `AGENT ROLE BLOCKED` নিয়ে ব্যর্থ হয় (negative control-এ প্রমাণিত)।
12. **পরিবর্তিত** `apps/api/src/agent/assessment.ts` — review এখন evidence-aware: declared evidence না থাকলে verdict `SUSPECTED` নয়, `INCONCLUSIVE` (কোনো field fill-in নয়)।
13. **নতুন** `apps/api/test/agentOrchestration.test.ts` (৭ test), `scripts/verify-agent-store-migration.mjs` (synthetic rehearsal, ১৭ flag), `docs/AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md` (design only)।
14. **পরিবর্তিত** `packages/shared/src/agent.ts`, `apps/web/src/api/client.ts`, `apps/web/src/components/AssessmentAgent.tsx` — strict capability validator এবং বিদ্যমান Agent panel-এর ভিতরে capability list; report load ব্যর্থ হলে UI স্পষ্টভাবে "unknown" দেখায়, "ready" ধরে নেয় না।

আগের কাজ (PR #8-এ merge হওয়া ৪৭ file) অপরিবর্তিত; কোনো existing test দুর্বল করা হয়নি (শুধু additive assertion ও stub যোগ হয়েছে), role/permission/API contract/scanner behaviour বদলায়নি।

**Preservation record:** `/tmp/drobon-master-prompt-baseline/` ও `/tmp/drobon-master2-baseline/` (১০ path + `changes.tar` + `sha256.txt`)।

---

## ২. PHASE A — সম্পূর্ণ audit (repository-visible)

### ২.১ Architecture যা বাস্তবে পাওয়া গেছে
- একক Node HTTP API (`apps/api/src/app.ts`, 724 lines) + React/Vite web (`apps/web`) + shared contract (`packages/shared`) + in-memory worker foundation (`apps/worker`)।
- Scan execution: `apps/api/src/scans/processor.ts` (durable store-ই queue), registry `scans/engines.ts`, চারটি engine: `scans/sast`, `scans/sca`, `scans/secrets`, `scans/dast`।
- Persistence: ১১টি JSON document store, প্রতিটি `lib/writePrivateJson.ts` দিয়ে atomic temp+rename (optional pre-rename fsync); scan/assessment-এ `lib/jsonFileWriteFence.ts` (snapshot hash/inode + advisory mkdir lock)।
- Cross-process guard: `lib/jsonStoreLease.ts` — Linux abstract-socket lease, শুধু সহযোগী server-এর জন্য।
- Agent: `agent/{snapshot,recon,execution,assessment}.ts` + `routes/agent.ts` — deterministic orchestration; `config.ts`-এ default off, production-এ enable করলে config error।

### ২.২ Write-path inventory (scan document)
| Writer | Operation | সীমা |
|---|---|---|
| HTTP scan/agent request | `createScanWithQuota` → full-document persist | স্বাভাবিক পথ |
| Embedded processor | `claimNextQueued`/`completeScan`/`timeoutScan`/`failScan` | ৫s sweep + `kick` |
| Cancel / report / workflow routes | `requestAgentCancellation`, `createReport`, lifecycle, notes | full-document rewrite |
| Startup recovery | `failAllRunning` | `SCAN_INTERRUPTED` |
| Pinned legacy API/binary | `writePrivateJson` v1 rewrite | lock/version জানে না |
| Injected / opaque adapter | যেকোনো custom repository | fence/lease-এর বাইরে |
| Raw filesystem actor | rename/unlink/restore | app-এর নিয়ন্ত্রণের বাইরে |

### ২.৩ User type / role / permission — **অপরিবর্তিত**
`packages/shared/src/authz.ts`: `ACCOUNT_ROLES = ['MEMBER','ADMIN','ACCOUNT_OWNER']`, `USER_TYPES = ['DEVELOPER','STUDENT','SECURITY_PROFESSIONAL','PENTESTER']`, `PERMISSIONS` table (৫টি capability), `hasPermission`/`roleAtLeast`। Plans `['FREE','PRO']` (`plans.ts`)। এই execution-এ এগুলোর একটি অক্ষরও বদলায়নি; regression-এ authz/tenant/ownership test সবুজ।

### ২.৪ Scanner ও Dataset
- Engines: SAST, SCA, SECRETS, DAST — সবই আগের implementation, নতুন করে লেখা হয়নি।
- Dataset আলাদা repository; এই environment-এ mount/clone করা নেই, তাই **বর্তমান Dataset rule count এই run-এ যাচাই করা যায়নি**।
- ইতিহাস (2026-10-26, `docs/DATASET_INTEGRATION_EVIDENCE.json`): SAST 1,000; Secrets 1,000; DAST 1,007; SCA 1,000; remediation 4,007; CWE 102। **এটি ঐতিহাসিক তথ্য, এই run-এর প্রমাণ নয়।**
- `VIRTUAL_DATASET` ছাড়া service `UNAVAILABLE`/0 rules; fail-closed আচরণ অপরিবর্তিত।

### ২.৫ AI অবস্থা — বাস্তব
`apps/api/src/assistant/provider.ts` ডিফল্ট `NONE`; কোনো model adapter, inference call বা tool loop নেই। Agent-এর "reasoning" নির্দিষ্ট নিয়ম (severity → priority, same-file pair `THEORETICAL`/`LOW`)।

---

## ৩. PHASE B — Storage security (এই turn-এর মূল কাজ)

### ৩.১ যা implement করা হয়েছে
`attestAgentStorage(paths)` নিম্নলিখিত প্রতিটি শর্ত verifies করে (একটিও ব্যর্থ হলে verdict `STORAGE_BLOCKED`):

- **Document:** regular file, `nlink === 1`, owner == effective UID, mode-এ group/other bit নেই (0600), symlink হলে reject।
- **Directory:** owner == EUID, group/other write নেই, symlink নয়।
- **Ancestors:** root থেকে প্রতিটি উপাদান directory হতে হবে; group/other-writable হলে সেটি **sticky** হতে হবে (যেমন `/tmp`), নাহলে reject — কারণ writable ancestor private directory-কে সরিয়ে দিতে পারে।
- **Foreign writers:** Linux-এ `/proc/<pid>/fd` + `fdinfo` পড়ে দেখে একই EUID-র অন্য কোনো live process store document বা তার directory write-open (`O_WRONLY`/`O_RDWR`) ধরে আছে কি না; থাকলে `foreign-writer-process`, আর অনির্ণেয় হলে `process-scan-inconclusive`। pid ছাড়া অন্য কিছু রিপোর্ট/লগ হয় না।
- `:memory:` store-এ filesystem boundary নেই, তাই সেটি skip হয়।

`startServer` এটি Chalায় **lease নেওয়া ও `createApp`-এর আগে**; ব্যর্থ হলে log-এ `STORAGE BLOCKED` এবং `StorageBlockedError` — অর্থাৎ insecure deployment serve করবে না। Agent disabled থাকলে আগের আচরণ অপরিবর্তিত (legacy deployment ভাঙে না)।

### ৩.২ প্রমাণ — ১৬টি test (`apps/api/test/storageBoundary.test.ts`)
সব synthetic temp directory-তে; ১৬/১৬ pass।

- owner-only 0700/0600 → `STORAGE_READY`; শুরুতেই document অনুপস্থিত থাকলে অনুমোদিত
- `0777`, `0770`, `0775` directory → blocked; `0640` document → `store-group-accessible`
- hard-link (`nlink=2`) → blocked; symlink document → `store-symlink`; symlink parent → `ancestor-symlink`
- non-sticky writable ancestor → `ancestor-world-writable`
- directory obstruction (path directory) → `store-not-regular`
- **আলাদা process** document write-open রাখলে `findForeignWriters` সেটি ধরে; verdict blocked
- সেই একই foreign writer থাকা অবস্থায় **real `startServer` refuse করে** (`foreign-writer-process`); writer মরে গেলে restart সফল — অর্থাৎ gate সত্যিই কাজ করে
- Agent enabled + unsafe path → `STORAGE BLOCKED`; Agent disabled + সেই path → server চালু (backward compatibility)
- attestation কোনো file create/modify করে না

**Test-first negative control:** `server.ts`-এ throw টি সাময়িকভাবে সরিয়ে startup-refusal test চালানো হয় → **failed**; ফিরিয়ে আনার পর pass। একইভাবে `app.ts` থেকে per-job check সরালে নতুন end-to-end test **fail** করে (job গুলো COMPLETED হয়ে যায়)। অর্থাৎ testগুলো সত্যিই নতুন enforcement যাচাই করছে।

**নতুন সংযোজন (এই turn):**
- **Opaque injected adapter:** durable path configured থাকা অবস্থায় Agent enabled + unknown-path injected store → startup refuse (`opaque-injected-adapter`); Agent disabled হলে আগের মতোই চলে (backward compatibility)।
- **Post-start re-attestation:** `setup(root,{storeDir})` → ৪টি job QUEUED → store directory `0777` → `scanProcessor.start()` → চারটি job-ই `FAILED`, message-এ `STORAGE BLOCKED`, শূন্য findings। অর্থাৎ startup-এর পরে boundary হারালে Agent আর লিখে না।
- **Skipped-অবস্থায় সীমা:** `/proc` re-scan প্রতিটি Agent job-এ হয়, তাই ব্যয় বাড়ে (measure করা হয়নি); এবং একই UID-র writer-কে এটি এখনো ঠেকাতে পারে না।

### ৩.৩ যা এখনো **অসমাধান** (স্পষ্টভাবে)
- **একই EUID-র legacy writer:** 0700/0600 বা `/proc` scan কোনো সাহায্য করে না। `verify-agent-os-boundary.mjs` আবারও দেখিয়েছে same-UID এবং UID-namespace-mapped writer v2 কে v1 বানিয়ে দুটি Agent job মুছে দেয়; writable ancestor থাকলে private directory-ও displace হয়।
- **Startup-এর পরে আসা writer:** `/proc` scan শুধু startup-এ; পরে খোলা descriptor ধরা পড়ে না (fence পরবর্তীতে ধরলেও তথ্য ততক্ষণে হারানো)।
- **Injected/opaque adapter:** attestation durable default path-এ প্রযোজ্য; opaque wrapper path অজানা থাকায় bypass করে (`verify-agent-server-coexistence.mjs`: `opaqueInjectedNewServerBypassedScanLease: true`)। Injection test seam; production config-এ injection নেই, কিন্তু এটি সীমা।
- **Distributed:** অন্য host/namespace, NFS/overlay semantics, root/`CAP_DAC_OVERRIDE` — অরক্ষিত।
- **সামগ্রিকভাবে:** এটি *prevention* নয়; **fail-closed refusal + detection**।

**তাই storage blocker এখনো OPEN।** অ্যাপ নিজে dedicated UID, trusted ancestor, legacy retirement বা cutover provision করে না; কেবল insecure অবস্থায় চলতে অস্বীকার করে।

---

## ৪. PHASE C — role→processor wiring (delivered), PHASE D/E — কেন এগোনো হয়নি

### ৪.০ Phase C — যা এই round-এ সত্যিই সংযুক্ত হলো
আগে `roles.ts` শুধু একটি ডিক্লারেশন ছিল; কোনো কোড সেটি ব্যবহার করত না। এখন:

- **Gateway:** `planRoleExecution(scanType, grant)` → owning role (`roleForScanType`) + সেই role-এর granted tool (`RUN_SAST`/`RUN_SCA`/`RUN_SECRETS`/`RUN_DAST`)। `agent/execution.ts` এই যাচাই **Dataset, authorization ও engine-এর আগে** চালায়; ব্যর্থ হলে job `AGENT ROLE BLOCKED: …` নিয়ে fail করে। অর্থাৎ grant table সংকুচিত হলে বা bug থাকলে কোনো scanner নীরবে চলবে না।
- **Negative control:** gateway সরিয়ে দিলে `agentOrchestration.test.ts`-এর revoked-grant test **fail** করে; ফিরিয়ে দিলে pass (৬+১ = ৭/৭)। Test আরও প্রমাণ করে যে grant প্রত্যাখ্যাত হলে downstream (project lookup) একবারও ছোঁয়া হয় না।
- **Evidence contract:** `evidenceGaps()` declared field নাম ফেরত দেয় (মান নয়)। `assessment.ts`-এর review এখন: evidence অসম্পূর্ণ → `INCONCLUSIVE` + basis-এ কোন field নেই; পূর্ণ → আগের মতো `SUSPECTED`। Negative control-এ প্রমাণিত।
- **Regression lock:** বিদ্যমান end-to-end Agent test-এ নতুন assertion — আসল চারটি engine-এর output-এ অন্তত একটি `SUSPECTED` review থাকতে হবে; অর্থাৎ evidence gate ভুল করে সব কিছু INCONCLUSIVE বানালে test ভাঙবে।
- **সীমা:** এটি এখনো model reasoning নয়; role গুলো deterministic coordinator-এর ধাপ, এবং Master/Recon/Validation-এর কাছে scanner/network tool নেই (আগের মতোই)।

### ৪.১ Phase D/E কেন এগোনো হয়নি
D-এর পূর্বশর্ত (local model/runtime) এই host-এ নেই — বাস্তব measurement:

| যাচাই | ফল |
|---|---|
| `ollama`, `llama-cli`, `llama-server`, `llamafile`, `vllm` | **absent** |
| `nvidia-smi`, `rocm-smi` | **absent** |
| Python `torch`, `transformers`, `llama_cpp`, `onnxruntime`, `tensorflow`, `sentence_transformers`, `vllm` | **সব absent** |
| Node `onnxruntime-node`, `@huggingface/transformers`, `node-llama-cpp` | **সব absent** |
| Model weights (`*.gguf`, `*.safetensors`, `*.onnx`, `*.ggml`) repo-তে | **পাওয়া যায়নি** |
| Hardware | **2 vCPU, ~3.85 GiB RAM, GPU নেই** |

তাই সাত logical Agent-এর বাস্তব model-backed reasoning, attack-path intelligence, remediation-and-retest এই turn-এ **দাবি করা হয় না**। কোনো paid/external AI API ব্যবহার বা fallback যোগ করা হয়নি।

**এই turn-এ যা সত্যিই তৈরি হয়েছে (model ছাড়া):**
- `apps/api/src/agent/roles.ts` — সাতটি logical role: MASTER, RECON, SAST, DAST, SCA, SECRETS, VALIDATION। প্রতিটির responsibility, tool allowlist, evidence requirement ও `maxSteps`। `authoriseAgentTool()` fail-closed: Master/Recon/Validation-এর কাছে কোনো scanner tool নেই, শুধু DAST role network tool (`RUN_DAST`) ধরে। `auditAgentTool()` প্রতিটি অনুরোধের allow/deny রেকর্ড দেয়, source বা secret ছাড়া।
- `apps/api/src/agent/localModel.ts` — loopback-only adapter: non-loopback endpoint construction-এই ব্যর্থ, default `NONE` (কোনো নেটওয়ার্ক কল নয়), closed JSON schema (অতিরিক্ত field, ভুল role/confidence, অচেনা evidence id সবই `contract-violation`), response size ও timeout bound, HTTP error/JSON error-এ `UNAVAILABLE`—কখনো fabricated answer নয়। synthetic loopback stub-এর সঙ্গে real HTTP round-trip test আছে।
- **যা এখনো নেই:** কোনো model/runtime/weights নেই, তাই "reasoning quality" বা "AI capability" দাবি করা হয়নি; role গুলো বর্তমানে deterministic coordinator-এর সঙ্গে সংযুক্ত, এবং model আউটপুট কোথাও report-এ ব্যবহার হচ্ছে না।

**Minimum-viable local design (প্রস্তাব, এখনো implement নয়):** একটিমাত্র local instruct model (7B-শ্রেণি, Q4 GGUF) একটি আলাদা inference daemon-এ, loopback-only; সাতটি role = সাতটি instruction/permission profile (আলাদা model নয়); model output closed JSON schema-তে, শুধু বিদ্যমান evidence ID reference করতে পারবে; প্রতিটি tool call allowlist + scope + quota + audit; prompt-injection ও secret redaction test বাধ্যতামূলক; feature flag default off। এই hardware-এ এটি চালানো সম্ভব নয় — অন্তত ~16 GiB RAM বা GPU দরকার; বাস্তব সংখ্যা মাপা হয়নি, তাই estimate হিসেবে ধরা হচ্ছে।

---

## ৫. PHASE F — এই run-এর প্রকৃত ফল

### ৫.১ Full regression (`npm test`, exit 0)
| Workspace | Files | Tests |
|---|---|---|
| shared | 20 passed | 193 passed |
| api | 130 passed + **1 skipped** | 1,408 passed + **1 skipped** |
| worker | 3 passed | 32 passed |
| web | 32 passed | 288 passed |
| **মোট** | **185 passed + 1 skipped** | **1,921 passed + 1 skipped** |

**Skipped:** `apps/api/test/mountedDatasetE2E.test.ts` — `describe.skipIf(datasetPath === undefined)`; এই environment-এ `DATASET_PATH` সেট নেই, তাই আসল Dataset mount ছাড়া চালানো অসম্ভব। এটি failure নয়, verified gap। নতুন ৫০টি test সহ আগের ১,৮৭১ থেকে ১,৯২১ হয়েছে (+50: boundary ১৯, role/model ১২, capability ৬, config ১, shared validator ২, orchestration/evidence ৭, end-to-end ও UI ৩), কোনো পুরোনো test দুর্বল বা skip বাড়ানো হয়নি।

**প্রথম full run-এ ১টি failure:** `test/staticSafety.test.ts` — নতুন ফাইলে `regex.exec(` লেখাটি "exec is forbidden" static rule-এ ধরা পড়ে। নিয়ম দুর্বল না করে `.match(` ব্যবহার করে সমাধান; এই turn-এও `no-control-regex` lint error কোডে control-character loop দিয়ে ঠিক হয়েছে—lint नियम শিথিল করা হয়নি।

### ৫.২ অন্যান্য gate
- `npm run typecheck` → **exit 0** (shared/api/worker/web)।
- `npm run lint` (`eslint .`) → **exit 0**।
- `npm run build` → **exit 0**; warning: `dist/assets/index-C0aYr-K_.js 526.17 kB` (>500 kB)। performance blocker নয়, তবে bundle-splitting বাকি।
- `check:secrets` PASS (929 files), secret self-test PASS, `check:boundaries` PASS, `check:repo-integrity` PASS, `check:release-evidence --self-test` PASS। Networked `npm audit` চালানো হয়নি।

### ৫.২ক Migration/rollback rehearsal (synthetic, exit 0)
`node scripts/verify-agent-store-migration.mjs` — **১৭টি flag true**, `passed: true`, script নিজেই বলে `productionMigrationTool: false`, `sameUidIsolationResolved: false`। যা প্রমাণ হলো: backup-এর পর source byte-identical, digest/manifest মেলে; migrated copy private (0700/0600), schema `version` ও record count অপরিবর্তিত, agent record টিকে আছে, migrate করা store পড়া যায় ও `agentStorageReady()` true; পুরোনো path-এ legacy writer লিখলেও migrated copy-এর digest বদলায় না; rollback-এ মূল bytes হুবহু ফিরে আসে; sandbox-এর বাইরের path ও marker-হীন directory refuse করে। এতে UID, unit, host বা production data **কোথাও** বদলায়নি।

### ৫.৩ Synthetic adversarial rehearsal (চারটিই exit 0, প্রত্যাশামতো)
- `verify-agent-downgrade.mjs` — ২১টি flag true; v2 rejection, unsafe-v1 claim, same-process ও separate-process ক্ষতি পুনরুৎপাদিত।
- `verify-agent-os-boundary.mjs` — ২০টি flag; same-UID ও namespace-mapped writer ক্ষতি করে; distinct UID + trusted ancestor হলে সব আক্রমণ `EACCES`; pre-rename barrier-এও deny।
- `verify-agent-server-coexistence.mjs` — ১৩টি flag; second default server ও known injected store lease-এ প্রত্যাখ্যাত, opaque wrapper bypass, পুরোনো server দুটি Agent job ফেলে দেয়।
- `verify-agent-store-migration.mjs` — ১৭টি flag; §৫.২ক দ্রষ্টব্য।

শেষ script-টি চালানোর আগে pinned commit `c01edd4`-এর Git object এই shallow clone-এ অনুপস্থিত ছিল (`git archive` ব্যর্থ, script fail closed)। শুধু ওই commit-এর object fetch করে পুনরায় চালানো হয় — কোনো working-tree পরিবর্তন নয়।

### ৫.৪ নতুন verified আচরণ (এই round-এ যোগ)
- **Capability report:** `GET …/agent/capabilities` — ৭ role, network role শুধু DAST, `model.provider`=`NONE` (configured local model ছাড়া), `storage.code`, `execution.enabled`, limitations। Test প্রমাণ করে: anonymous → 401, অন্য মালিকের/অচেনা assessment → 404, এবং call করার পরও কোনো scan record তৈরি হয় না (read-only)।
- **Capability truth in UI:** বিদ্যমান Assessment Agent panel এখন server-রিপোর্ট দেখায়; report আনতে ব্যর্থ হলে panel স্পষ্ট "unknown" লেখে এবং কিছুই "ready" দাবি করে না। strict shared validator (`isAgentCapabilitiesResponse`) অজানা/অতিরিক্ত field, ভুল role, `REMOTE_API`, ভুয়া `PRODUCTION_SAFE` — সব প্রত্যাখ্যান করে (২টি unit test)।
- **Per-write storage re-check:** `beforePersist` hook; test-এ directory শিথিল করার পর write refuse হয়, target file-এর bytes অপরিবর্তিত থাকে (`guardRuns=2`), `chmod 0700` ফিরিয়ে দিলে আবার লেখা যায়। এটি same-UID writer-কে ঠেকায় **না** — শুধু boundary ভাঙার পর লেখা বন্ধ করে।
- **Local model config:** `LOCAL_MODEL_ENDPOINT` non-loopback হলে config error, নাম ছাড়া model গ্রহণ নয়, production-এ endpoint দিলে প্রত্যাখ্যাত। অর্থাৎ "paid/remote AI" config স্তরেই অসম্ভব।

### ৫.৫ Benchmark (ঐতিহাসিক, এই run-এ পুনরায় চালানো হয়নি)
আগের synthetic four-scanner benchmark: TP 8, FP 0, TN 4, FN 0, **UNASSESSED 4**, ২টি runtime-exploitability **UNKNOWN**। ছোট fixture-এ rule-match, বাস্তব detection accuracy নয়; vendor parity দাবি করা যায় না। আসল Dataset/আসল target/human review: **NOT RUN**।

---

## ৬. Deliverables ১–২০

| # | Deliverable | ফল |
|---|---|---|
| 1 | Overall readiness | **NO-GO**; storage blocker + AI reasoning অনুপস্থিত |
| 2 | Feature-by-feature score | §৮ rubric |
| 3 | Engine status | চারটি engine বিদ্যমান, regression-এ সবুজ; নতুন engine নেই |
| 4 | Rule counts + integration evidence | বর্তমান Dataset যাচাই হয়নি; ঐতিহাসিক 1,000/1,007/1,000/1,000 |
| 5 | User type/role/permission preservation | **অপরিবর্তিত, verified** |
| 6 | Agent architecture + actual capability | deterministic coordinator + 7-role gateway + read-only capability endpoint; model-backed reasoning **নেই** |
| 7 | Local AI runtime status | **কোনোটিই নেই** (§৪) |
| 8 | Storage security | startup/per-job/per-write gate + isolation design; same-UID **অসমাধান** |
| 9 | Attack path analysis | শুধু same-file `THEORETICAL`/`LOW`; verified path নেই |
| 10 | Remediation + retest | **NOT IMPLEMENTED** (auto-modify নিষিদ্ধ); শুধু existing guidance + manual rerun |
| 11 | Confirmed bugs/weaknesses | §৩.৩ + legacy overwrite + opaque adapter bypass |
| 12 | Test results | §৫ exact counts |
| 13 | Performance/reliability | sweep 5s, bounded drain 1,000, per-request 5s timeout; scale benchmark নেই |
| 14 | Readiness % | §৮ (50/100, heuristic) |
| 15 | Production blockers | §৭ |
| 16 | Roadmap | §১০ |
| 17 | Report location | এই ফাইল |
| 18 | Cleanup list | §৯ (**অনুমোদন ছাড়া কিছু মুছবে না**) |
| 19 | Git/workspace status | §১১ |
| 20 | কী বদলেছে / কী অস্পর্শিত | §১ + §১১ |

---

## ৭. Production blockers

1. **Storage isolation:** same-EUID legacy writer এখনো নতুন store ধ্বংস করতে পারে; mandatory dedicated identity/cutover নেই → **BLOCKER**। startup gate, per-job attestation ও নতুন per-write re-check কোনোটি **identity isolation নয়**; এগুলো শুধু নিজের boundary হারালে লেখা বন্ধ করে, অন্য process-কে থামায় না।
2. **Migration/rollback:** backup→verify→copy→rollback **mechanics synthetic data-তে rehearsed** (১৭ flag), কিন্তু অনুমোদিত production tool, dedicated UID cutover ও observation window **নেই** → BLOCKER (design: `docs/AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md`)।
3. **AI reasoning:** কোনো local model/runtime/weights নেই; capability endpoint যা দেখায় তা **wiring**, reasoning নয় — "advanced AI" দাবি অসম্ভব → BLOCKER (capability gap, নিরাপত্তা নয়)।
4. **Independent validation:** exploitability/FP verification স্বতন্ত্রভাবে প্রমাণিত নয় → BLOCKER।
5. **Dataset provenance:** আসল Dataset digest/完整性 এই run-এ যাচাই হয়নি → OPEN।
6. **Distributed hardening & deployment review:** অন্য host/namespace, backup encryption, human review → OPEN।

---

## ৮. Readiness rubric (heuristic — measurement নয়)

| ক্ষেত্র | ওজন | প্রাপ্ত | কারণ |
|---|---|---|---|
| Storage integrity | 20 | 11 | startup gate + per-job re-attestation + **per-write** re-check + opaque refuse + detection; same-UID prevention নেই |
| Migration / rollback | 12 | 2 | synthetic copy/verify/rollback rehearsal ১৭ flag; production tool ও আসল cutover নেই; design অনুমোদনের অপেক্ষায় |
| Authorization / isolation | 10 | 8 | tenant/authz test সবুজ; distributed withdrawal নেই |
| Worker safety | 8 | 6 | cancel/shutdown/restart test; abort-ignoring সীমা |
| Scanner integration | 12 | 9 | চারটি engine একসাথে চলে; আসল Dataset যাচাই হয়নি |
| AI reasoning | 15 | 5 | role→scanner gateway + tool grant enforcement + evidence-aware verdict + loopback config + capability report; কোনো model/reasoning quality নেই |
| Validation / exploit proof | 8 | 1 | কোনো independent validation নেই |
| Regression health | 8 | 7 | 1,921 pass; 1 skip; সব gate pass |
| Deployment safety | 7 | 1 | rehearsal ছাড়া কিছু নেই |
| **মোট** | **100** | **50** | **50%** |

পদ্ধতি: প্রতিটি ঘরে verified evidence-এর ভিত্তিতে ০–full স্কোর, ওজনসহ যোগ। এটি প্রকৌশলী বিচার, কোনো automated metric নয়; তাই ±নির্ভুলতা দাবি করা যায় না।

---

## ৯. Historical report cleanup — প্রস্তাবিত, **কিছুই এখনো মোছা হয়নি**

নিয়ম: কোনো unique security evidence, test fixture বা verification data মুছবে না। প্রস্তাব শুধু **consolidation/archival**, এবং প্রতিটি আইটেমের আগে বিষয়বস্তু এই Master Report-এ স্থানান্তরিত হয়েছে কিনা যাচাই করতে হবে।

**Proposed ARCHIVE (master report-এ বিষয়বস্তু ইতিমধ্যে অন্তর্ভুক্ত):**
| Path | কারণ |
|---|---|
| `docs/FINAL_MAIN_APP_READINESS_AUDIT_2026-10-31.md` | superseded; সংখ্যা §৫-এ স্থানান্তরিত (১,০৭০ lines) |
| `docs/POST_IMPLEMENTATION_REVIEW_2026-10-31.md` | superseded review |
| `docs/MAIN_APP_COMPLETION_REPORT_2026-10-31.md` | superseded |
| `docs/MAIN_APP_RELIABILITY_REPORT_2026-10-31.md` | reliability সারাংশ §৫-এ আছে |
| `docs/MAIN_APP_WORK_REPORT.md` | পুরোনো কাজের log |
| `docs/DROBON_PROFESSIONAL_AI_AGENT_COMPLETION_REPORT.md` | superseded (আগের PR #8-এ ছিল) |
| `docs/PRODUCTION_BLOCKER_CLOSURE_REPORT_2026-10-31.md` | blocker সারাংশ §৭-এ |
| `docs/UNRESOLVED_BLOCKERS_2026-10-31.md` | §৭-এ অন্তর্ভুক্ত |
| `docs/PRIORITIZED_IMPROVEMENT_ROADMAP_2026-10-31.md` | §১০-এ প্রতিস্থাপিত |
| `docs/BUILD_VERIFICATION.md` | পুনরাবৃত্ত build log (১,৩৫২ lines); CI + §৫ প্রমাণ |
| `docs/BENCHMARK_PREPARATION_REPORT_2026-10-31.md` | methodology সারাংশ §৫.৫-এ |
| `docs/DATASET_INTEGRATION_AUDIT_2026-10-26.md` | পুরোনো; বর্তমান `DATASET_CONNECTION.md` + নতুন verification আছে |

**অবশ্যই KEEP (unique evidence):** `INDEPENDENT_BENCHMARK_VALIDATION_2026-10-31.md`, `SCANNER_RELIABILITY_REPORT_2026-10-31.md`, `SCANNER_ACCURACY_BASELINE_2026-10-31.md`, `SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md`, `SCA_UNRESOLVED_CASE_REPORT_2026-10-31.md`, `SEPARATE_DATASET_INTEGRATION_VERIFICATION_2026-10-31.md`, `DATASET_INTEGRATION_EVIDENCE.json`, এবং সব `ARCHITECTURE/SCANS/SAST/DAST/SCA/SECRETS/SECURITY/USERTYPES/...` reference doc।

→ **Delete/archive করতে আপনার স্পষ্ট অনুমোদন দরকার; এই execution-এ কিছুই সরানো হয়নি।**

---

## ১০. Roadmap (অগ্রাধিকার ক্রমে)

1. **Storage cutover (blocking):** design লেখা হয়েছে (§৫.২ক, `AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md`) — dedicated service identity, unit hardening, private state dir, ৭টি acceptance gate, rollback। এখনো কোনো host/UID/unit বদলায়নি; অনুমোদন দরকার।
2. **Migration tool:** backup + hash manifest + copy/verify + rollback rehearsal **হয়ে গেছে (synthetic)**; আসল store-এ dry-run ও cutover এখনো অনুমোদনের অপেক্ষায়, এবং কোনো বাস্তব migration এই execution-এ চালানো হয়নি।
3. **Post-start writer detection:** প্রতি Agent job-এ re-attestation **হয়ে গেছে**; কিন্তু নিয়মিত (idle-এও) re-check, real-time alert এবং নতুন writer-এর descriptor-borne overwrite এখনো বাকি।
4. **Local AI:** adapter contract **হয়ে গেছে**; অনুমোদিত hardware/runtime এলে loopback model সংযোগ, prompt-injection test suite ও reasoning-quality benchmark বাকি। তার আগে Agent deterministic-ই থাকবে (model output কোথাও ব্যবহৃত হয় না)।
5. **Independent validation benchmark + human review** (synthetic lab only)।
6. **Dataset provenance pinning** (digest + fail-closed on mismatch)।
7. **Bundle splitting** (526 kB chunk) ও performance benchmark।

---

## ১১. Git ও workspace অবস্থা

- Branch: `arena/8821907b-drobon`; base `c400493` (PR #8 merge)।
- **পরিবর্তিত (১৫):** `apps/api/src/server.ts`, `apps/api/src/app.ts`, `apps/api/src/config.ts`, `apps/api/src/routes/agent.ts`, `apps/api/src/scans/store.ts`, `apps/api/src/agent/execution.ts`, `apps/api/src/agent/assessment.ts`, `apps/api/test/agentApi.test.ts`, `apps/api/test/config.test.ts`, `apps/web/src/api/client.ts`, `apps/web/src/components/AssessmentAgent.tsx`, `apps/web/test/agentUi.test.tsx`, `apps/web/test/appFixtures.tsx`, `packages/shared/src/agent.ts`, `packages/shared/test/agent.test.ts`।
- **নতুন (১২):** `apps/api/src/lib/storageBoundary.ts`, `apps/api/src/agent/roles.ts`, `apps/api/src/agent/localModel.ts`, `apps/api/src/agent/capabilities.ts`, `apps/api/src/agent/orchestration.ts`, `apps/api/test/storageBoundary.test.ts`, `apps/api/test/agentRoles.test.ts`, `apps/api/test/agentCapabilities.test.ts`, `apps/api/test/agentOrchestration.test.ts`, `scripts/verify-agent-store-migration.mjs`, `docs/AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md`, এই report।
- **Staged: 0। Commit/push/merge: নেই।** Dataset repository: পড়া/লেখা/commit কিছুই হয়নি। Production/VPS/database: অস্পর্শিত।
- `npm ci` দিয়ে শুধু lockfile-ভিত্তিক dependency restore করা হয়েছে (node_modules snapshot-এ থাকে না); কোনো dependency version বদলানো হয়নি, lockfile অপরিবর্তিত।
- Backup: `/tmp/drobon-master-prompt-baseline/`, `/tmp/drobon-master2-baseline/`, `/tmp/drobon-master3-baseline/` (path list + tar + sha256 manifest); কিছুই মুছে ফেলা হয়নি বা reset হয়নি।

---

## ১২. অনুমোদনের জন্য অপেক্ষা

1. উপরের ১২টি report path archive/delete করা যাবে কি না (এবং archive হলে কোথায়)।
2. এই ১৫টি পরিবর্তিত + ১২টি নতুন path stage+commit+push করে PR খোলা যাবে কি না।
3. `docs/AGENT_STORAGE_CUTOVER_DESIGN_2026-11-01.md`-এর cutover (dedicated UID + unit + migration) **test host**-এ rehearsal করা যাবে কি না।
4. আসল store-এর একটি copy-তে backup+verify dry-run অনুমোদন (কোনো production data পরিবর্তন ছাড়া)।

**পর্যন্ত: Production NO-GO, Agent default-off, কোনো destructive operation নয়।**
