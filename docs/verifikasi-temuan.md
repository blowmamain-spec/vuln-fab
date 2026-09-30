# Panduan verifikasi temuan (untuk reviewer)

Tujuan: menilai apakah temuan vulnfab pada proyek **gurindam-hub** benar atau tidak. Penilaian ini
dipakai untuk mengukur akurasi tool, jadi yang dibutuhkan adalah penilaian jujur, bukan menyetujui
tool. "Temuan salah" sama berharganya dengan "temuan benar".

## Yang perlu dikerjakan

1. Jalankan scan (tanpa mengirim kode ke mana pun, semuanya lokal):
   `uv run vulnfab scan <path-gurindam-hub> --format json -o hasil.json`
2. Untuk tiap temuan, buka berkas dan baris yang ditunjuk, baca konteksnya (bukan hanya barisnya),
   lalu putuskan salah satu:
   - **TP**: kerentanan nyata dan bisa dieksploitasi pada aplikasi ini.
   - **FP**: bukan kerentanan (ada proteksi lain, nilainya konstan, memang disengaja, dll.).
   - **DUP**: sama dengan temuan lain yang sudah dinilai.
   - **?**: tidak yakin. Tulis apa yang perlu diketahui; jangan dipaksakan.
3. Tulis alasan singkat satu kalimat. Alasan penting untuk FP ("RLS tabel ini di-enable di migrasi
   lain", "input sudah di-escape di fungsi X").
4. Catat hasil di tabel di bawah, atau langsung lewat CLI:
   `vulnfab triage set <fingerprint> -v tp|fp|dup -n "alasan" --reviewer <nama>`
   (`vulnfab triage list` menampilkan temuan yang belum dinilai.)

## Aturan supaya penilaian adil

- Nilai **sebelum** melihat penilaian orang lain, termasuk penilaian Claude/tool.
- Satu temuan dinilai oleh minimal dua orang bila memungkinkan; selisih dibahas, bukan dihapus.
- Jangan mengubah kode aplikasi sebelum semua temuan dinilai.
- Jangan menempel nilai secret ke tabel, cukup lokasinya.
- Kerentanan nyata yang **tidak** muncul di laporan juga dicatat (bagian "Terlewat"): itu bahan recall.

## Temuan yang perlu dinilai lebih dulu

| # | Rule | Lokasi | TP / FP / DUP / ? | Alasan | Reviewer |
|---|---|---|---|---|---|
| 1 | `sb-rls-missing` | migrasi `..._penomoran_otomatis_surat.sql:18` | | | |
| 2 | `sb-policy-true` (anon write) | `..._rls_dan_pelengkap.sql:34` | | | |
| 3 | `sb-policy-true` (anon write) | `..._rls_dan_pelengkap.sql:67` | | | |
| 4 | `sb-definer-no-path` | fungsi SECURITY DEFINER tanpa `search_path` | | | |
| 5 | `ts-supabase-or-inject` | `dashboard-pic.js:1063` | | | |

Petunjuk per rule:
- `sb-rls-missing`: apakah RLS diaktifkan untuk tabel itu di migrasi mana pun (urutan nama berkas =
  urutan jalan)? Apakah tabel bisa diakses lewat API publik Supabase?
- `sb-policy-true`: apakah role `anon` benar-benar bisa menulis? Cek `TO` pada policy dan grant.
- `sb-definer-no-path`: fungsi dipanggil dengan hak pemilik; tanpa `search_path` tetap, schema palsu
  bisa membelokkan pemanggilan. Apakah role tak tepercaya bisa membuat objek di schema yang dicari?
- `ts-supabase-or-inject`: apakah string di `.or(...)` mengandung input pengguna tanpa dibersihkan?

## Terlewat (kerentanan nyata yang tidak dilaporkan)

| Lokasi | Jenis | Catatan |
|---|---|---|
| | | |
