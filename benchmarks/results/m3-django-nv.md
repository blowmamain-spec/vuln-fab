# Evaluasi: django-nv

- Precision: **100%** (TP 30, FP 0)
- Recall: **94%** (29/31 label dalam scope)
- Decoy terpicu: 0 · Duplikat: 8 · Di luar scope: 0 · Belum di-review: 0

| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| cmd-injection | 1 | 0 | 100% | 1 | 1 | 100% |
| cookie-httponly | 1 | 0 | 100% | 1 | 1 | 100% |
| csrf-exempt | 4 | 0 | 100% | 4 | 4 | 100% |
| debug-true | 1 | 0 | 100% | 1 | 1 | 100% |
| idor | 11 | 0 | 100% | 12 | 10 | 83% |
| modelform-all | 1 | 0 | 100% | 1 | 1 | 100% |
| password-hasher | 1 | 0 | 100% | 1 | 1 | 100% |
| pickle-session | 1 | 0 | 100% | 1 | 1 | 100% |
| redirect | 1 | 0 | 100% | 1 | 1 | 100% |
| secret-key | 1 | 0 | 100% | 1 | 1 | 100% |
| sqli | 1 | 0 | 100% | 1 | 1 | 100% |
| template-safe | 6 | 0 | 100% | 6 | 6 | 100% |

| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A | 19 | 0 | 100% | 19 | 19 | 100% |
| B | 11 | 0 | 100% | 12 | 10 | 83% |

## Terlewat (false negative)
- T003 `idor` taskManager/views.py:244-244
- T010 `idor` taskManager/views.py:533-533
