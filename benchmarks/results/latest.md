# Hasil benchmark terbaru

Dibuat oleh `benchmarks/run_all.py` · vulnfab 1.0.0 · 2026-09-30.
Label lab ditulis oleh pembuat rule (gerbang regresi, bukan bukti akurasi); label DVWA,
django.nV, Juice Shop, NodeGoat dan catatan bias ada di `m2.md` / `m3.md`.

## Per target

| Target | Waktu (dtk) | Temuan | Recall | Precision | Decoy terpicu | Belum di-review |
|---|---:|---:|---:|---:|---:|---:|
| supabase-vuln | 0.4 | 25 | 100% (25/25) | 100% (TP 25, FP 0) | 0 | 0 |
| django-vuln | 0.3 | 22 | 100% (21/21) | 100% (TP 21, FP 0) | 0 | 0 |
| laravel-vuln | 0.2 | 21 | 100% (20/20) | 100% (TP 20, FP 0) | 0 | 0 |
| nodegoat | 1.0 | 8 | 100% (5/5) | 100% (TP 5, FP 0) | 0 | 0 |
| juice-shop | 45.8 | 121 | 100% (7/7) | 87% (TP 20, FP 3) | 0 | 0 |
| dvwa | 2.5 | 41 | 86% (24/28) | 97% (TP 30, FP 1) | 0 | 0 |
| django-nv | 10.5 | 60 | 94% (29/31) | 100% (TP 30, FP 0) | 0 | 0 |

## Per rule (gabungan semua target, hanya kelas yang berlabel)

| Rule | Severity | TP | FP | Precision | Ambang | Status |
|---|---|---:|---:|---:|---:|---|
| dj-allowed-hosts | medium | 1 | 0 | 100% | 70% | ok |
| dj-cookie-httponly | medium | 2 | 0 | 100% | 70% | ok |
| dj-csrf-exempt | medium | 5 | 0 | 100% | 70% | ok |
| dj-debug-true | high | 3 | 0 | 100% | 80% | ok |
| dj-dispatch-input | high | 1 | 0 | 100% | 80% | ok |
| dj-mark-safe | medium | 1 | 0 | 100% | 70% | ok |
| dj-modelform-all | medium | 2 | 0 | 100% | 70% | ok |
| dj-password-hasher | high | 2 | 0 | 100% | 80% | ok |
| dj-pickle-session | high | 2 | 0 | 100% | 80% | ok |
| dj-secret-key | high | 2 | 0 | 100% | 80% | ok |
| dj-template-autoescape | high | 1 | 0 | 100% | 80% | ok |
| dj-template-csrf | medium | 1 | 0 | 100% | 70% | ok |
| dj-template-safe | high | 7 | 0 | 100% | 80% | ok |
| dj-view-no-auth | high | 1 | 0 | 100% | 80% | ok |
| env-service-role-client | critical | 1 | 0 | 100% | 90% | ok |
| js-xss | medium | 7 | 2 | 78% | 70% | ok |
| lv-app-debug | high | 1 | 0 | 100% | 80% | ok |
| lv-app-key | high | 1 | 0 | 100% | 80% | ok |
| lv-blade-csrf | medium | 1 | 0 | 100% | 70% | ok |
| lv-blade-raw | high | 1 | 0 | 100% | 80% | ok |
| lv-csrf-exempt | medium | 1 | 0 | 100% | 70% | ok |
| lv-fillable-privileged | medium | 1 | 0 | 100% | 70% | ok |
| lv-guarded-empty | high | 1 | 0 | 100% | 80% | ok |
| lv-hidden-missing | medium | 1 | 0 | 100% | 70% | ok |
| lv-mass-assign | high | 1 | 0 | 100% | 80% | ok |
| lv-route-no-auth | high | 2 | 0 | 100% | 80% | ok |
| lv-seeder-password | medium | 1 | 0 | 100% | 70% | ok |
| sb-config-signup | medium | 1 | 0 | 100% | 70% | ok |
| sb-default-priv | medium | 1 | 0 | 100% | 70% | ok |
| sb-definer-no-path | high | 1 | 0 | 100% | 80% | ok |
| sb-dynamic-sql | high | 1 | 0 | 100% | 80% | ok |
| sb-edge-no-jwt | high | 1 | 0 | 100% | 80% | ok |
| sb-grant-broad | high | 1 | 0 | 100% | 80% | ok |
| sb-policy-anon-write | high | 1 | 0 | 100% | 80% | ok |
| sb-policy-no-uid | medium | 1 | 0 | 100% | 70% | ok |
| sb-policy-true | high | 1 | 0 | 100% | 80% | ok |
| sb-policy-user-metadata | high | 1 | 0 | 100% | 80% | ok |
| sb-rls-missing | critical | 2 | 0 | 100% | 90% | ok |
| sb-seed-secret | high | 1 | 0 | 100% | 80% | ok |
| sb-storage-policy | high | 1 | 0 | 100% | 80% | ok |
| sb-storage-public | medium | 1 | 0 | 100% | 70% | ok |
| sb-view-no-invoker | medium | 1 | 0 | 100% | 70% | ok |
| sec-secret-hardcoded | high | 1 | 0 | 100% | 80% | ok |
| tjs-cmdi | critical | 1 | 0 | 100% | 90% | ok |
| tjs-codei | critical | 4 | 0 | 100% | 90% | ok |
| tjs-idor | medium | 1 | 0 | 100% | 70% | ok |
| tjs-nosqli | high | 6 | 1 | 86% | 80% | ok |
| tjs-pathtrav | high | 2 | 0 | 100% | 80% | ok |
| tjs-redirect | medium | 1 | 0 | 100% | 70% | ok |
| tjs-sqli | high | 2 | 0 | 100% | 80% | ok |
| tjs-ssrf | high | 2 | 0 | 100% | 80% | ok |
| tphp-cmdi | critical | 7 | 0 | 100% | 90% | ok |
| tphp-deser | high | 1 | 0 | 100% | 80% | ok |
| tphp-idor | medium | 1 | 0 | 100% | 70% | ok |
| tphp-pathtrav | high | 9 | 1 | 90% | 80% | ok |
| tphp-redirect | medium | 2 | 0 | 100% | 70% | ok |
| tphp-sqli | high | 12 | 0 | 100% | 80% | ok |
| tphp-ssrf | high | 1 | 0 | 100% | 80% | ok |
| tphp-xss | medium | 5 | 0 | 100% | 70% | ok |
| tpy-cmdi | critical | 2 | 0 | 100% | 90% | ok |
| tpy-deser | high | 1 | 0 | 100% | 80% | ok |
| tpy-idor | medium | 19 | 0 | 100% | 70% | ok |
| tpy-pathtrav | high | 1 | 0 | 100% | 80% | ok |
| tpy-redirect | medium | 2 | 0 | 100% | 70% | ok |
| tpy-sqli | high | 2 | 0 | 100% | 80% | ok |
| tpy-ssrf | high | 1 | 0 | 100% | 80% | ok |
| ts-dynamic-eval | high | 1 | 0 | 100% | 80% | ok |
| ts-idor-eq-id | high | 1 | 0 | 100% | 80% | ok |
| ts-service-role-client | critical | 1 | 0 | 100% | 90% | ok |
| ts-supabase-or-inject | medium | 1 | 0 | 100% | 70% | ok |
| ts-table-no-rls | high | 1 | 0 | 100% | 80% | ok |
| ts-xss-dangerous-html | high | 1 | 0 | 100% | 80% | ok |
