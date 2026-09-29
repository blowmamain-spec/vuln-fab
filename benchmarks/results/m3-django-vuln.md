# Evaluasi: django-vuln

- Precision: **100%** (TP 21, FP 0)
- Recall: **100%** (21/21 label dalam scope)
- Decoy terpicu: 0 · Duplikat: 0 · Di luar scope: 0 · Belum di-review: 0

| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| allowed-hosts | 1 | 0 | 100% | 1 | 1 | 100% |
| cmd-injection | 1 | 0 | 100% | 1 | 1 | 100% |
| cookie-httponly | 1 | 0 | 100% | 1 | 1 | 100% |
| csrf-exempt | 1 | 0 | 100% | 1 | 1 | 100% |
| debug-true | 1 | 0 | 100% | 1 | 1 | 100% |
| deserialization | 1 | 0 | 100% | 1 | 1 | 100% |
| dispatch-input | 1 | 0 | 100% | 1 | 1 | 100% |
| idor | 1 | 0 | 100% | 1 | 1 | 100% |
| modelform-all | 1 | 0 | 100% | 1 | 1 | 100% |
| password-hasher | 1 | 0 | 100% | 1 | 1 | 100% |
| path-traversal | 1 | 0 | 100% | 1 | 1 | 100% |
| pickle-session | 1 | 0 | 100% | 1 | 1 | 100% |
| redirect | 1 | 0 | 100% | 1 | 1 | 100% |
| secret-key | 1 | 0 | 100% | 1 | 1 | 100% |
| sqli | 1 | 0 | 100% | 1 | 1 | 100% |
| ssrf | 1 | 0 | 100% | 1 | 1 | 100% |
| template-autoescape | 1 | 0 | 100% | 1 | 1 | 100% |
| template-csrf | 1 | 0 | 100% | 1 | 1 | 100% |
| template-safe | 1 | 0 | 100% | 1 | 1 | 100% |
| view-no-auth | 1 | 0 | 100% | 1 | 1 | 100% |
| xss | 1 | 0 | 100% | 1 | 1 | 100% |

| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A | 20 | 0 | 100% | 20 | 20 | 100% |
| B | 1 | 0 | 100% | 1 | 1 | 100% |
