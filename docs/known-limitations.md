# Batasan yang diketahui

Ini daftar jujur apa yang **tidak** ditangkap atau bisa salah. Angka terukur ada di `benchmarks/results/`.

## Umum

* Analisis statis, tanpa menjalankan kode. Kode yang dibangun/di-eval saat runtime, refleksi, dan konfigurasi dari
  environment dilaporkan sebagai `unresolved` atau diabaikan; bagian *Coverage & limitations* menyebutnya.
* Tiga bahasa punya front-end taint: Python, JS/TS, PHP. Bahasa lain hanya lewat rule konfigurasi/teks.
* Berkas dengan syntax error hanya dianalisis sebagian (rule pola); analisis alur data melewatinya.
* Kondisi cabang tidak dievaluasi, kecuali `validators` yang dideklarasikan rule (optimistis: blocklist regex yang
  lemah dianggap validasi).
* Elemen array/dict digabung; objek dibedakan per field (`a.b` ≠ `a.c`). Alur lewat callback/promise/event dan
  injeksi dependensi framework tidak diikuti.
* Alur antar-berkas: impor Python/JS/TS. PHP antar-berkas hanya lewat pemanggilan yang bisa dipetakan namanya.
  Variabel global, sesi (`$_SESSION`), dan data yang dibaca dari basis data (second-order) bukan sumber.

## IDOR (tingkat B)

Heuristik: pengambilan record berdasar kunci dari request tanpa bukti kepemilikan di fungsi tersebut. Bukti =
menyebut `request.user`/`auth()`/`Auth::`/`current_user`, dsb. di mana pun di fungsi → menekan false positive,
tetapi melewatkan kasus "menyebut user hanya untuk logging". Model tanpa relasi ke pengguna (data referensi)
diturunkan confidence-nya. Confidence maksimum `medium`; kasus semantik (IDOR bisnis) adalah tingkat C dan tidak
dilaporkan default.

## Per stack

* **Supabase**: skema hanya dari migration (perubahan lewat dashboard tak terlihat; gunakan `--schema-dump`).
  Blok `DO` dengan SQL dinamis dilaporkan sebagai `unresolved` dan menurunkan confidence rule terkait.
* **Django**: model dibaca dari `models.py` (migration tidak diterapkan); `settings` yang bergantung environment
  dianggap dinamis. View tanpa `login_required` yang memeriksa user di dalam fungsi dianggap "inline".
* **Laravel**: skema dari `up()` migration; `Route::group` dengan berkas eksternal, `Route::resources([...])`, dan
  middleware yang ditambahkan lewat `RouteServiceProvider`/`bootstrap/app.php` tidak dipahami penuh.
* **Templates**: `|safe`/`{!! !!}` dilaporkan tanpa mengetahui apakah nilainya sudah dibersihkan di tempat lain.

## Hal yang perlu peninjauan manusia

Verdict pada `benchmarks/verdicts/` dan label bertanda `reviewer` di `benchmarks/truth/` ditulis oleh pembuat
alat dan belum ditinjau independen; lihat catatan bias di `benchmarks/results/m2.md` dan `m3.md`.
