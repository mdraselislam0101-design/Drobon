# XBOW — local benchmark package

**Status: NOT RUN.** এই session-এ সংশ্লিষ্ট CLI নাম PATH-এ পাওয়া যায়নি; GUI/cloud installation ও license অজানা। কোনো vendor performance বা parity দাবি নয়।

**প্রাথমিক প্রযোজ্যতা:** DAST / autonomous readiness। ১১টি local HTTP case সম্ভাব্য সীমিত DAST input; এই corpus autonomous attack-path discovery বা validation পরীক্ষা করে না। Autonomous operation, external callback বা cloud বাধ্যতামূলক হলে আলাদা পূর্ণ অনুমতি ও উপযুক্ত lab ছাড়া থামুন।

## একই reproducible package

Main App root-এ পূর্বে ইনস্টল করা Node 20.11–22 ও project dependencies ব্যবহার করুন। Dataset repository-তে কিছু তৈরি বা বদলাবেন না। নতুন, disposable ও অন্য কোনো Git checkout-এর বাইরে private directory বেছে নিন; আগের directory পুনর্ব্যবহার করলে materializer থামে।

```sh
node benchmarks/accuracy-v2/materialize.mjs /tmp/drobon-v2-NEW
# শুধু authorised, একই host-এর HTTP পরীক্ষার জন্য; এটি ইচ্ছাকৃত দুর্বল lab:
node benchmarks/local/target.mjs
# আলাদা terminal-এ, operator-completed REDACTED observations থাকলে:
node benchmarks/accuracy-v2/score-external.mjs /absolute/path/to/redacted-observations.json
```

Loopback listener পাওয়া port-এর কেবল `/lab/` path ব্যবহার করুন; এটি preview server নয় এবং ইন্টারনেটে প্রকাশ করবেন না। Source fixture execute, install, package-manager network, বাস্তব account/credential, অন্য host discovery বা customer system scan করবেন না। প্রতিটি case আলাদা রাখতে হবে। `fixtureManifestSha256` exact hash, scanner version/config, local scope, time/request budget ও applicable modality লিখে রাখুন। প্রতিটি detection-এর mapping/evidence এবং প্রতিটি negative-এর complete coverage operator review ছাড়া score করবেন না। `observation-template.json` একটি **NOT RUN** খালি template, ফল নয়। Raw vendor output, source ও sensitive strings Git-এ রাখবেন না। Scorer operator-এর দাবি স্বাধীনভাবে যাচাই করে না; ground truth independent-human-reviewed নয়।

External AI API, cloud control plane, source upload, package download, out-of-band/OAST বা credential validation দরকার/চালু থাকলে, প্রয়োজনীয় পৃথক অনুমতি ও যাচাই ছাড়া চালাবেন না। License/availability/capability অজানা মানে zero detection নয়। কোনো অস্পষ্ট বা অসম্পূর্ণ case `UNASSESSED`; unknown ground truth score-এর বাইরে।
