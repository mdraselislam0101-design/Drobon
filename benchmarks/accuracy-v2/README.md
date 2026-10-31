# DROBON synthetic accuracy corpus v2

৬২টি নিজস্ব synthetic case; স্বাধীন মানব ground-truth review হয়নি। বিস্তারিত সীমা, সব verdict, reproducible commands ও digest: [`docs/SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md`](../../docs/SYNTHETIC_BENCHMARK_CORPUS_REPORT_2026-10-31.md)।

- `fixtures.mjs` ও `rules.mjs`: ২১টি frozen case + ৪১টি নতুন case, test-only rules।
- `verify-oracle.mjs`: পৃথক mechanical check; pinned নিজের fixture ছাড়া `vm` ব্যবহার নয়।
- `run.mjs`: বিদ্যমান Drobon engine-এ mock DAST ও test-only rules; vendor scan নয়।
- `materialize.mjs`: শুধু নতুন private disposable directory-তে আলাদা source projects।
- `score-external.mjs`: human-reviewed, redacted metadata-এর strict validator; product চালায় না বা operator দাবি যাচাই করে না।
- `oracle-results.json` / `drobon-results.json`: এই session-এর sanitized ফল।
- [`../vendor-packages`](../vendor-packages): ছয়টি আলাদা NOT RUN package।

No customer source, real credential, external target, package installation, unauthorized callback বা Dataset write নয়। Production readiness, independent vendor তুলনা, autonomous validation বা ১০০% security দাবি নয়।
