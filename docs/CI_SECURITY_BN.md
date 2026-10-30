# Drobon-এর CI/PR নিরাপত্তা চেক ও সীমা

এই কাজ Drobon-এর পুরোনো SAST, Secrets ও SCA ইঞ্জিনই ব্যবহার করে; নতুন কোনো সমান্তরাল স্ক্যানার বা ডেটাবেস যোগ করে না। অ্যাডাপ্টারটি শুধু অপারেটর যে স্থানীয় ডিরেক্টরি নির্দিষ্ট করেন তার সীমিত টেক্সট ফাইল পড়ে। টার্গেটের কোড চালায় না, প্যাকেজ ইনস্টল করে না, GitHub API-তে লেখে না, স্বয়ংক্রিয় সমাধান বা PR তৈরি করে না, এবং অ্যাপের স্ক্যান হিস্টরি/কোটা পরিবর্তন করে না। এটি ওয়েব অ্যাপের সার্ভারের ভেতর গোপনভাবে চলে না।

## আগে যা প্রয়োজন

1. অনুমোদিত সংগ্রহস্থল এবং সংরক্ষিত বা পর্যালোচিত Drobon কোড। অপরিচিত PR-এর পরিবর্তিত Drobon কোডকে নিরাপত্তা-টুল হিসেবে চালাবেন না।
2. Node.js 20.11–22 এবং Drobon ডিরেক্টরিতে `npm ci --ignore-scripts`, তারপর `npm run build --workspace @drobon/shared`। এসব কমান্ড টার্গেটের বদলে **Drobon-এর বিশ্বস্ত চেকআউটে** চালান।
3. আলাদা, পর্যালোচিত এবং লাইসেন্স-অনুমোদিত `Drobon-Dataset` চেকআউট। সেটি এই কমান্ডে শুধু পড়া হয়, বদলানো হয় না। অ্যাপের ডিফল্ট provider `none`; তাই dataset না দিলে বাস্তব নিয়ম পাওয়া যাবে না। বর্তমান dataset-এ পূর্ণ সর্বশেষ vulnerability তথ্য আছে বলে ধরে নেবেন না।
4. ইচ্ছা করলে পরিচিত dataset snapshot-এর জন্য আগে `npm run verify:dataset -- --path ../Drobon-Dataset` চালান। ওই যাচাইয়ের কিছু reader সীমা ও regression budget আছে; পাস মানে সম্পূর্ণ coverage নয়।

## স্থানীয়ভাবে চালানো

Drobon ডিরেক্টরি থেকে, প্রয়োজনমতো path বদলে:

```bash
npm run security:ci -- --root ../my-project --dataset ../Drobon-Dataset --severity HIGH --sarif ../drobon-check.sarif
```

- `--scanners SAST,SECRETS,SCA` ডিফল্ট। উদাহরণস্বরূপ শুধু SAST চালাতে `--scanners SAST` দিন। এটি **পুরো প্রকল্পের নিরাপত্তা পরীক্ষা নয়**।
- `--severity INFO|LOW|MEDIUM|HIGH|CRITICAL`: এই severity বা তার উপরের finding বা আসল matched SCA advisory গেটে ধরা হয়। ডিফল্ট `HIGH`।
- `--project-key`-এ একই repository-র জন্য একই স্থিতিশীল নাম দিলে ভিন্ন checkout path-এও একই finding fingerprint থাকে। এটি শুধু CI পরিচয়, app-এর project ID বা authorization নয়। না দিলে canonical root path থেকে পরিচয় তৈরি হয়; runner path বদলালে fingerprint-ও বদলাতে পারে। আলাদা repo-তে আলাদা key দিন।
- `--sarif` ঐচ্ছিক। পথটি dataset-এর বাইরে থাকতে হবে, parent directory আগে থাকতে হবে এবং ফাইলটি আগে থেকে থাকলে লেখা হবে না। SARIF-এ নিয়ম, severity, অবস্থান ও মিল পাওয়া advisory থাকে; সূত্র কোড ও evidence ইচ্ছাকৃতভাবে রাখা হয় না। তবু ফাইলের নাম, project path বা metadata সংবেদনশীল হতে পারে—শেয়ার করার আগে পরীক্ষা করুন।
- Output JSON-এ `status`, প্রকৃত ফাইল/স্ন্যাপশট সংখ্যা, finding, advisory, omissions ও অসম্পূর্ণতার কারণ থাকে। SCA-এর `NOT_ASSESSED` কখনো শূন্য finding-এর সমান নিরাপদ verdict নয়।
- Exit **0**: threshold-এ finding নেই এবং অননুমোদিত coverage gap নেই। Exit **1**: threshold-এ এক বা একাধিক finding/advisory। Exit **2**: চালাতে সমস্যা বা coverage অসম্পূর্ণ। একই সঙ্গে finding ও gap থাকলে exit 1; JSON-এ উভয় তথ্য থাকে।
- কেবল সীমাবদ্ধতা বুঝে সিদ্ধান্ত নিলে `--allow-incomplete` দেওয়া যায়: কিছু পরিচিত gap থাকা সত্ত্বেও finding না থাকলে exit 0 হবে, কিন্তু status `INCOMPLETE` থাকবে। অনুপস্থিত নির্বাচিত rule pack, অবৈধ pack, অনুপস্থিত SCA intelligence, কোনো উপযুক্ত ইনপুট না থাকা বা ইঞ্জিনের ব্যর্থতা এই flag দিয়েও সফল করা যায় না।

## GitHub Actions-এ উদাহরণ

নিচেরটি **টেমপ্লেট**, কোনো repo-তে স্বয়ংক্রিয়ভাবে যোগ বা চালু করা হয়নি। নিজের অনুমোদিত repo-র `.github/workflows/drobon-security.yml`-এ ব্যবহার করার আগে placeholder দুটি নিজের পর্যালোচিত **পূর্ণ commit SHA** দিয়ে বদলাতে হবে। পূর্ণ SHA দিয়ে actions pin করা হয়েছে; আপডেটের আগে তাদেরও review করুন। টার্গেট checkout থেকে কোনো install বা shell script চালানো হচ্ছে না।

```yaml
name: Drobon security
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '25 2 * * 1' # প্রতি সোমবার 02:25 UTC; GitHub schedule বিলম্বিত হতে পারে
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    name: Drobon security check
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout target without saved credentials
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          path: target
          persist-credentials: false
      - name: Checkout reviewed Drobon
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          repository: mdraselislam0101-design/Drobon
          ref: '<REVIEWED_DROBON_COMMIT_SHA>'
          path: tooling
          persist-credentials: false
      - name: Checkout reviewed intelligence
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          repository: mdraselislam0101-design/Drobon-Dataset
          ref: '<REVIEWED_DATASET_COMMIT_SHA>'
          path: intelligence
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: '22'
      - name: Install trusted Drobon dependencies
        working-directory: tooling
        run: npm ci --ignore-scripts --no-audit --no-fund
      - name: Build shared contracts
        working-directory: tooling
        run: npm run build --workspace @drobon/shared
      - name: Check dataset against this app's verification contract
        working-directory: tooling
        run: npm run verify:dataset -- --path ../intelligence
      - name: Run bounded source check
        working-directory: tooling
        run: npm run security:ci -- --root ../target --dataset ../intelligence --project-key "$GITHUB_REPOSITORY" --severity HIGH --sarif ../drobon-results.sarif
      - name: Store SARIF artifact for authorized reviewers
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: drobon-security-results
          path: drobon-results.sarif
          if-no-files-found: ignore
          retention-days: 7
```

PR workflow-এর checkout-এ যে snapshot পাওয়া যায় তার সমর্থিত ফাইলগুলো স্ক্যান হয়; এটি শুধু পরিবর্তিত line বা নতুন issue-র diff নয়, স্বয়ংক্রিয় PR comment-ও করে না। GitHub-এর branch protection/ruleset-এ এই job-টিকে required check হিসেবে **repo admin-কে নিজে** নির্বাচন করতে হবে; এই টেমপ্লেট সেটি পরিবর্তন করে না। Merge check সার্ভার-side secret push protection নয়। Workflow-এর failure notification GitHub-এর নিজস্ব user/repository settings-এর ওপর নির্ভর করে; Drobon-এর নিজস্ব email service বা live dashboard notification এতে যুক্ত নয়। Security tab-এ SARIF upload এই উদাহরণে নেই—তা করতে আলাদা অনুমতি, action configuration, এবং GitHub plan/ফর্কের সীমা পরীক্ষা করতে হবে। Artifact ব্যবহার না চাইলে শেষ step মুছে দিন।

## গুরুত্বপূর্ণ সীমা

- সর্বোচ্চ ২০,০০০ directory entry দেখা হয়; প্রতি snapshot-এ সর্বোচ্চ ২০০ ফাইল ও মোট ৭৬৮ KiB, প্রতি ফাইলে ২৫৬ KiB; সর্বোচ্চ ১০টি snapshot। ফাইলভিত্তিক সীমা, বাদ পড়া path, hidden folder, key ও `.env` policy, symlink, binary এবং multiple snapshot হলে ফল অসম্পূর্ণ হতে পারে। তৃতীয় পক্ষের dependency/build/cache folder বাদ যায়। Filesystem-এ সমান্তরাল পরিবর্তন ঠেকাতে এটি OS sandbox নয়; আলাদা অস্থায়ী runner ব্যবহার করুন।
- শুধু সমর্থিত নাম/extension-এর বর্তমান টেক্সট ফাইল দেখা হয়; Git history, সব format, hidden files, keys, `.env`, JS চালিয়ে পাওয়া source, সব language বা সব dependency দেখা হয় না। একাধিক snapshot-এর মধ্যে cross-file flow ও manifest/lockfile সম্পর্ক হারাতে পারে।
- SAST/Secrets নিয়ম ও SCA provider dataset-এর ওপর নির্ভরশীল; detected secret সত্যি সক্রিয় কি না যাচাই, revoke বা rotate করা হয় না। GitHub push block, fix PR, upgrade PR বা Jira issue স্বয়ংক্রিয় হয় না।
- Offline SCA data সীমিত/পুরোনো হতে পারে, কিছু declaration reader সীমাবদ্ধ; `NOT_ASSESSED`, partial ও বাদ পড়া বিষয়গুলো নিজে review করতে হবে। `PASS` বা exit 0 নিরাপদ বা শতভাগ শনাক্তের প্রমাণ নয়।
- DAST এই source CI adapter-এ নেই। আলাদা DAST-এর জন্য আগে থেকে লিখিত অনুমতি ও নির্দিষ্ট scope দরকার; authenticated crawling এখনও যুক্ত হয়নি।
- বিশ্বাসযোগ্য dataset বেছে নিন। CI preflight dataset-এর loader-পড়া অংশে symlink, অতিরিক্ত বড় ফাইল ও কিছু malformed rule চিহ্নিত করে, কিন্তু স্বেচ্ছাচারী dataset-কে নিরাপদ বা সম্পূর্ণ প্রমাণ করতে পারে না। সংবেদনশীল credential ছাড়া বিচ্ছিন্ন runner ব্যবহার করুন।
