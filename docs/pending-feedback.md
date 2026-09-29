# Pertanyaan yang menunggu jawaban pengguna

Dikumpulkan supaya pekerjaan tidak terhenti. Jawab kapan saja; hasilnya dipakai untuk kalibrasi rule.
(Tidak ada nilai secret di sini — hanya lokasi dan pertanyaan.)

## A. Verdict temuan scan `gurindam-hub-main` (benar / false positive?)
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
