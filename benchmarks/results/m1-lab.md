# Evaluasi: supabase-vuln

- Precision: **100%** (TP 25, FP 0)
- Recall: **100%** (25/25 label dalam scope)
- Decoy terpicu: 0 · Duplikat: 0 · Di luar scope: 0 · Belum di-review: 0

| Kelas | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| cmd-injection | 1 | 0 | 100% | 1 | 1 | 100% |
| config-signup | 1 | 0 | 100% | 1 | 1 | 100% |
| default-priv | 1 | 0 | 100% | 1 | 1 | 100% |
| definer-no-path | 1 | 0 | 100% | 1 | 1 | 100% |
| dynamic-eval | 1 | 0 | 100% | 1 | 1 | 100% |
| dynamic-sql | 1 | 0 | 100% | 1 | 1 | 100% |
| edge-no-jwt | 1 | 0 | 100% | 1 | 1 | 100% |
| grant-broad | 1 | 0 | 100% | 1 | 1 | 100% |
| idor-eq-id | 1 | 0 | 100% | 1 | 1 | 100% |
| policy-anon-write | 1 | 0 | 100% | 1 | 1 | 100% |
| policy-no-uid | 1 | 0 | 100% | 1 | 1 | 100% |
| policy-true | 1 | 0 | 100% | 1 | 1 | 100% |
| policy-user-metadata | 1 | 0 | 100% | 1 | 1 | 100% |
| rls-missing | 2 | 0 | 100% | 2 | 2 | 100% |
| secret-hardcoded | 1 | 0 | 100% | 1 | 1 | 100% |
| seed-secret | 1 | 0 | 100% | 1 | 1 | 100% |
| service-role-client | 2 | 0 | 100% | 2 | 2 | 100% |
| storage-policy | 1 | 0 | 100% | 1 | 1 | 100% |
| storage-public | 1 | 0 | 100% | 1 | 1 | 100% |
| supabase-or-inject | 1 | 0 | 100% | 1 | 1 | 100% |
| table-no-rls | 1 | 0 | 100% | 1 | 1 | 100% |
| view-no-invoker | 1 | 0 | 100% | 1 | 1 | 100% |
| xss-dangerous-html | 1 | 0 | 100% | 1 | 1 | 100% |

| Tier | TP | FP | Precision | Label | Terdeteksi | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A | 23 | 0 | 100% | 23 | 23 | 100% |
| B | 2 | 0 | 100% | 2 | 2 | 100% |
