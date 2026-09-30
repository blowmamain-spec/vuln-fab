# Pertanyaan yang menunggu jawaban pengguna

Dikumpulkan supaya pekerjaan tidak terhenti. Jawab kapan saja; hasilnya dipakai untuk kalibrasi rule.
(Tidak ada nilai secret di sini — hanya lokasi dan pertanyaan.)

## A. Verdict temuan scan `gurindam-hub-main` (benar / false positive?)
A5 (`.env.test`) sudah dijawab: bekas tes, sudah diganti. C (kerentanan terlewat): tidak ada. A1-A4 sudah diverifikasi oleh sesi Claude lain dengan akses ke repo (bukan manusia; independen dari tool ini, tapi tetap LLM): semua TP
(`sb-rls-missing`, `sb-policy-true`/`anon-write`, `sb-definer-no-path`, `ts-supabase-or-inject`); `tphp-pathtrav` 0/6 TP,
`sec-secret-hardcoded` 0/9 (file gitignored), `js-innerhtml-assign` 0/15 dari sampel; 1 false negative
(`sb-definer-no-path` pada fungsi di baseline `000`, belum bisa direproduksi tanpa potongan SQL-nya).
Perbaikan yang diturunkan dari laporan itu ada di CHANGELOG. Sebuah penilaian manusia atas sampel yang sama masih dibutuhkan.
1. `sb-rls-missing` — `..._penomoran_otomatis_surat.sql:18`
2. `sb-policy-true` / anon-write — `..._rls_dan_pelengkap.sql:34` dan `:67`
3. `sb-definer-no-path` (SECURITY DEFINER tanpa `search_path`)
4. `ts-supabase-or-inject` — `dashboard-pic.js:1063`
5. Secret di `.env.test`: apakah nilainya asli dan pernah di-commit? Kalau ya, rotasi key.

## B. Sampel `innerHTML`
Beberapa temuan `js-innerhtml-var` (confidence low) yang tersisa: mana yang memang data dari user/DB
tanpa escape, mana yang konstanta/ter-escape?

## C. Kerentanan yang menurutmu terlewat
Apakah ada celah yang kamu tahu ada di aplikasimu tetapi tidak muncul di laporan? (Ini bahan recall
untuk WP-0.7.)

## D. WP-0.7
Migrasi Supabase pribadi hanya dijalankan lokal (`benchmarks/labs/private/` di-gitignore); jangan di-commit.

## E. Ditinjau ulang secara independen (dibuat oleh pembuat tool)
- `benchmarks/verdicts/juice-shop.json`, `dvwa.json`, `django-nv.json`: verdict TP/FP saya atas temuan tak berlabel.
- `juice-shop.json`: 7 verdict `tjs-nosqli` (6 TP, 1 FP) ditulis setelah rule itu dibuat; aturan ini belum pernah diuji pada target lain.
- Label "reviewer" (bukan resmi) di `benchmarks/truth/*.json` dan `benchmarks/labels/*.py`.
- Angka M2/M3 di `benchmarks/results/` sebelum dikutip di luar repo.
