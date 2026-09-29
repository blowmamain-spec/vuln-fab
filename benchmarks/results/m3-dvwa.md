# Evaluasi: dvwa

- Precision: **97%** (TP 30, FP 1)
- Recall: **86%** (24/28 label dalam scope)
- Decoy terpicu: 0 · Duplikat: 0 · Di luar scope: 0 · Belum di-review: 0

| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| cmd-injection | 6 | 0 | 100% | 6 | 6 | 100% |
| path-traversal | 8 | 1 | 89% | 7 | 6 | 86% |
| redirect | 1 | 0 | 100% | 1 | 1 | 100% |
| sqli | 11 | 0 | 100% | 13 | 11 | 85% |
| xss | 4 | 0 | 100% | 1 | 0 | 0% |

| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A | 24 | 0 | 100% | 28 | 24 | 86% |

## Terlewat (false negative)
- T005 `sqli` vulnerabilities/sqli/source/high.php:11-11
- T006 `sqli` vulnerabilities/sqli/source/high.php:31-31
- T033 `xss` vulnerabilities/xss_r/source/low.php:8-8
- T035 `path-traversal` vulnerabilities/fi/index.php:36-36
