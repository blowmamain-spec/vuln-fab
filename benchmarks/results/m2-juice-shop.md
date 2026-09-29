# Evaluasi: juice-shop

- Precision: **82%** (TP 14, FP 3)
- Recall: **100%** (7/7 label dalam scope)
- Decoy terpicu: 0 · Duplikat: 0 · Di luar scope: 0 · Belum di-review: 0

| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| dynamic-eval | 1 | 1 | 50% | 1 | 1 | 100% |
| idor | 1 | 0 | 100% | 1 | 1 | 100% |
| path-traversal | 2 | 0 | 100% | 0 | 0 | n/a |
| sqli | 2 | 0 | 100% | 2 | 2 | 100% |
| ssrf | 1 | 0 | 100% | 1 | 1 | 100% |
| xss | 7 | 2 | 78% | 2 | 2 | 100% |

| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A | 6 | 1 | 86% | 6 | 6 | 100% |
| B | 1 | 0 | 100% | 1 | 1 | 100% |
