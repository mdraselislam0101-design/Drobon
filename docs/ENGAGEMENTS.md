# Third-party Engagement / Authorization Record

> **বর্তমান সীমা (2026-10-28):** Engagement ছাড়া পুরনো `UNVERIFIED` scan path এখনও খোলা; এই ব্যবস্থা সবার জন্য লিখিত অনুমতি বাধ্যতামূলক করে না। Assessment-linked DAST-এ বর্তমান scope প্রতিটি request-এর আগে পুনরায় দেখা হয়, কিন্তু স্বাধীন legal verification নয় এবং ইতোমধ্যে চলা request প্রত্যাহার করা যায় না।


**তারিখ:** 2026-10-26 · **Branch:** `arena/5bb07bd8-drobon` · **Scope:** শুধু মেইন অ্যাপ (`Drobon`)। ডেটাসেট repo / ডেটাবেস / নতুন npm dependency — কিছুই নেই। বিদ্যমান `apps/api/src/assessments/` store-এর উপর **additive**।

> **কেন:** আপনি টুলটা বানাচ্ছেন **অন্য কারো ওয়েবসাইট/অ্যাপ** সুরক্ষা দেওয়ার জন্য। আগে অ্যাপ শুধু project ownership + network safety চেক করত; "ওই সাইট scan করার আমার অনুমতি আছে" — তার কোনো অডিটেবল রেকর্ড ছিল না (`UNVERIFIED`)। এখন সেটার জন্য একটি **লিখিত, সময়-বাঁধা, scope-বাঁধা, append-only engagement record** আছে, আর সেটি linked scan-এর gate হিসেবে কাজ করে।

---

## ⚠️ প্রথমেই সৎ কথা

> **এটা আইনি verification নয়।** Drobon ক্লায়েন্টের সই, কর্তৃত্ব বা third-party permission **স্বাধীনভাবে যাচাই করে না**। এটি অপারেটরের নিজের লিখিত সাক্ষ্য (`statement`) — একটি **অডিট রেকর্ড**, প্রমাণ নয়। UI/API সব জায়গায় এটা স্পষ্ট করে বলা হয়। লিখিত engagement letter/chapter আপনাকেই নিশ্চিত করতে হবে।

---

## ১) Record-এ কী থাকে

| Field | অর্থ |
|---|---|
| `id`, `declaredBy`, `declaredAt` | কে, কবে declare করল (server-set; ক্লায়েন্ট দিতে পারে না) |
| `clientName` | ক্লায়েন্ট/সংস্থার নাম (≤120) |
| `targetUrl` | নিরাপদ canonical HTTP(S) URL — assessment scope-এর ভেতরে হতে হবে |
| `inScopeHosts` | **exact** hostname; subdomain inherit হয় না; assessment scope-এর subset |
| `scopePaths` | ঐচ্ছিক URL path prefix (যেমন `/api/`); খালি = সব path |
| `allowedScanTypes` | `SAST / SCA / SECRETS / DAST` — শুধু এগুলোই scan করা যাবে |
| `validFrom` / `validUntil` | ISO timestamp; সর্বোচ্চ ১ বছর; মেয়াদ শেষ = gate বন্ধ |
| `statement` | অপারেটরের লিখিত সাক্ষ্য (≤2000) |
| `state`, `withdrawnAt` | `DECLARED → WITHDRAWN` (append-only; edit/delete নেই) |

**বাউন্ড:** প্রতি assessment-এ সর্বোচ্চ ২০ engagement, ২০ host, ২০ path, history ১০০ event। সব shared guard দিয়ে validate হয় — খারাপ hostname, traversal path, উল্টো তারিখ, অজানা scan type → reject।

---

## ২) API (authenticated, owner/project-scoped)

| Method | Path | কাজ |
|---|---|---|
| `GET` | `/api/v1/projects/:projectId/assessments/:assessmentId/engagements` | তালিকা + computed `status` |
| `POST` | `.../engagements` | নতুন declare |
| `POST` | `.../engagements/:engagementId/withdraw` | withdraw (append-only event) |

POST body উদাহরণ:

```json
{
  "clientName": "Acme Corp",
  "targetUrl": "https://fixture.example.org/",
  "inScopeHosts": ["fixture.example.org"],
  "scopePaths": ["/api/"],
  "allowedScanTypes": ["SAST", "DAST"],
  "validFrom": "2026-10-26T00:00:00.000Z",
  "validUntil": "2026-11-26T00:00:00.000Z",
  "statement": "Written owner-attested authorization for this engagement window.",
  "confirm": true
}
```

Responses: `EngagementResponse` / `EngagementsResponse` — প্রতিটিতে `status`: `ACTIVE | NOT_YET_VALID | EXPIRED | WITHDRAWN` (সময় থেকে computed, কখনো stored claim নয়)।

**যা চেক করা হয়:** project ownership, archived project, assessment `ACTIVE`, target safe URL + assessment scope-এ আছে কি না, প্রতিটি engagement host assessment scope-এর ভেতরে কি না, path traversal নেই কি না, scan type বৈধ কি না, তারিখ future + ≤১ বছর কি না। সব ব্যর্থতা **quota কাটার আগেই** 409/422।

---

## ৩) Scan authorization gate

`apps/api/src/routes/scans.ts`-এ, **quota consume করার আগে**:

```
assessmentId linked? ── না ──> আগের মতোই (legacy path)
        │ হ্যাঁ
        ▼
engagement record আছে? ── না ──> legacy UNVERIFIED path অক্ষত (পুরনো টেস্ট/flow ভাঙে না)
        │ হ্যাঁ
        ▼
ACTIVE + scanType allowed + host + path + validity মিলল? ── না ──> 409 (scan/block, quota intact)
        │ হ্যাঁ
        ▼
scan create ✅
```

- Gate-টি **তখনই সক্রিয় হয় যখনে অন্তত একটি engagement declare করা আছে**। এর মানে: আগের সব workspace behaviour অপরিবর্তিত; কিন্তু আপনি একবার engagement লিখলেই সেটিই কর্তৃত্ব হয়ে যায়।
- DAST-এ `targetUrl`-এর hostname + pathname চেক হয়; source scan-এ (SAST/SCA/SECRETS) শুধু scanType + validity।
- withdraw/expire করলে পরের linked scan **সঙ্গে সঙ্গে blocked** — কিন্তু আগের scan/report ইতিহাস অক্ষত থাকে।

---

## ৪) UI

Assessment panel-এ নতুন **"Third-party engagement record"** ব্লক:

- engagement না থাকলে: `NO ENGAGEMENT — target authorization remains UNVERIFIED.`
- থাকলে: `DECLARED · ACTIVE · <client> · <scan types> · <hosts> · valid until <ISO>` (+ withdraw timestamp)।
- নিচে স্পষ্ট লেখা: এটি operator-এর নিজের সাক্ষ্য; Drobon legal permission verify করে না।

পুরনো `Authorization status: USER_DECLARED/UNVERIFIED` ব্যাজ অপরিবর্তিত — নতুন ব্লক আলাদা (`assessment-engagement`)।

---

## ৫) ফাইল / যাচাই

| ফাইল | কাজ |
|---|---|
| `packages/shared/src/assessments.ts` | `AssessmentEngagement`, `EngagementView`, guards, `engagementStatus()`, `engagementAllowsScan()`; `Assessment.engagements?` optional (পুরনো records সব valid) |
| `apps/api/src/assessments/store.ts` | `recordEngagement()` — append-only declare/withdraw, caps, restart-safe validation |
| `apps/api/src/routes/assessments.ts` | ৩টি নতুন route |
| `apps/api/src/routes/scans.ts` | authorization gate (quota-র আগে) |
| `apps/web/src/pages/ProjectDetailPage.tsx` | read-only engagement status ব্লক |
| `apps/api/test/engagements.test.ts` | ৭টি নতুন test (contract + store + API + gate) |

**Verify:** `npm run verify` **PASS ১১/১১** · `npm test` **PASS ১,৩৬৭** (shared ১৮৩ + api ৮৯০ + worker ২৮ + web ২৬৬; Pump 18 reader tests সহ) · `verify:dataset` PASS · lint/typecheck/builds/boundaries/secrets/repo-integrity সব PASS।

---

## ৬) এখনো যা নেই (open, সৎভাবে)

1. **Report-এ engagement reference** — বর্তমানে engagement assessment detail + API response-এ আছে; persisted `SecurityReport`-এ reference যোগ করা বাকি (shared contract change)।
2. **UI declare form** — এখন API দিয়ে declare করতে হয়; UI শুধু read-only দেখায়।
3. **Digital signature / counter-signature / attachment** — ইচ্ছাকৃতভাবে নয়; Drobon verify করার দাবি করে না।
4. **Automatic expiry notification** — status computed হয়, কিন্তু push notification নেই।
5. **Owner decision থেকে আলাদা:** licensed advisory feed, active DAST boundary — এই কাজে ছোঁয়া হয়নি।
