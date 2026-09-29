# Paket Kerja (Work Packages)

Dikerjakan berurutan menurut dependensi. Centang `[x]` hanya bila kriteria "Lulus jika" terpenuhi **dan** `uv run ruff check . && uv run mypy && uv run pytest` hijau. Setelah tiap WP: commit + push.

Ukuran (kecepatan manusia, sebagai patokan relatif): **S** ≤ 3 jam · **M** ≈ 6 jam · **L** ≈ 12 jam · **XL** ≈ 25+ jam. Sebuah WP berukuran XL harus dipecah bila ternyata lebih besar.

Rujukan: strategi di [`rencana-sast-multistack-v3.md`](rencana-sast-multistack-v3.md), kontrak di [`spec.md`](spec.md).

Legenda: `⛔` butuh masukan dari pemilik proyek · `🔬` spike berbatas waktu (keputusan go/no-go dicatat di `docs/spikes/`).

---

## Fase 0: Fondasi

- [x] **WP-0.1 Scaffold repo** (S). Lisensi GPL-3.0-or-later, `pyproject.toml` (uv, Python ≥ 3.11), `src/vulnfab/`, ruff, mypy (strict untuk `core/`), pytest, `.gitignore` (termasuk `benchmarks/targets/`, `benchmarks/labs/private/`), README stub, `THIRD_PARTY_LICENSES.md`, workflow CI GitHub Actions, `CHANGELOG.md`.
  *Lulus jika*: `uv run vulnfab --version` mencetak versi; ruff, mypy, pytest hijau lokal; workflow CI valid.
- [x] **WP-0.2 Model & kontrak** (M) — dep: 0.1. `core/models.py` (Finding, TraceStep, IR dan SchemaModel sesuai `spec.md`), `plugins/base.py` (Protocol), `core/sqlparser.py` (antarmuka + impl. `pglast`), `core/fingerprint.py`.
  *Lulus jika*: test serialisasi JSON; test fingerprint (stabil terhadap sisipan baris/komentar, berubah bila kode berubah); mypy strict bersih; hanya `sqlparser.py` yang meng-import `pglast` (dicek test).
- [x] **WP-0.3a 🔬 S1: pglast pada migration nyata** (S) — dep: 0.2. Parse migration dari repo `supabase/supabase` (contoh) dan lab awal: policy, `ALTER TABLE … ENABLE RLS`, `DO $$`, plpgsql.
  *Lulus jika*: `docs/spikes/s1-pglast.md` mencatat statement yang gagal/tidak tertangani dan keputusan go/no-go.
- [x] **WP-0.3b 🔬 S2: matcher snippet + metavariable** (M) — dep: 0.1. Prototipe: parse snippet pola dengan tree-sitter yang sama dan cocokkan `$X`/`...` pada Python, TS, PHP.
  *Lulus jika*: `docs/spikes/s2-matcher.md` + prototipe lulus 10 kasus per bahasa; keputusan mempertahankan D4.
- [x] **WP-0.3c 🔬 S3: parsing template** (S) — dep: 0.1. Kelayakan parser sederhana untuk Django template (`|safe`, `autoescape`) dan Blade (`{!! !!}`).
  *Lulus jika*: `docs/spikes/s3-templates.md` memuat pendekatan yang dipilih (tokenizer regex terbatas vs grammar) dan batasannya.
- [x] **WP-0.3d 🔬 S4/S5: SCA offline & adaptor eksternal** (S) — dep: 0.1. Cek ketersediaan dump OSV, gitleaks, osv-scanner di lingkungan; desain deteksi ketiadaan binary.
  *Lulus jika*: `docs/spikes/s4-adapters.md` mencatat apa yang tersedia dan jalur fallback.
- [x] **WP-0.4 Target benchmark** (M) — dep: 0.1. `benchmarks/fetch_targets.sh` + `targets.lock` (SHA di-pin) untuk Juice Shop, NodeGoat, DVWA, django.nV; skrip berjalan idempoten.
  *Lulus jika*: menjalankan skrip dari nol mengkloning semua target pada SHA yang di-pin.
- [x] **WP-0.5 Lab Supabase rentan + ground truth** (L) — dep: 0.3a. `benchmarks/labs/supabase-vuln/`: migration dengan masalah yang disengaja (tiap rule di katalog Supabase) **dan decoy aman**, frontend TS kecil (service_role bocor, akses ke tabel tanpa RLS), `config.toml`, `seed.sql`. Tulis `benchmarks/truth/supabase-vuln.json`.
  *Lulus jika*: setiap kelas rule Supabase/TS punya ≥ 1 label `vulnerable` dan ≥ 1 `decoy` (dicek test); seluruh SQL terparse tanpa issue oleh `parse_lenient`, TS/TSX tanpa error tree-sitter, TOML valid; `truth_from_markers.py --check` sinkron (dicek test). Label dibuat dari penanda `@lab` di berkas lab.
- [x] **WP-0.6 Harness evaluasi** (M) — dep: 0.2, 0.5. `benchmarks/evaluate.py`: memuat truth + verdict, mencocokkan temuan (aturan di `spec.md` §8), mencetak tabel precision/recall per rule dan tier, gagal bila ada temuan tak berlabel tanpa verdict.
  *Lulus jika*: unit test dengan truth/temuan sintetis mencakup TP, FP (decoy), FN, tak berlabel.
- [ ] **WP-0.7 ⛔ Migration aplikasi Supabase milikmu** (S). Salin ke `benchmarks/labs/private/` (tidak di-commit); anonimkan bila akan dijadikan contoh publik.
  *Lulus jika*: berkas tersedia lokal; catatan di `docs/` menyebut lokasi tanpa isinya. Dibutuhkan pada gate M1.

## Fase 1: Pipeline dasar

- [x] **WP-1.1 Loader** (M) — dep: 0.2. Walk repo, `.vulnfabignore`, abaikan `node_modules`/`vendor`/`.git`/`benchmarks/targets`, batas ukuran, hash SHA-256, deteksi bahasa dari ekstensi, `RepoView`.
  *Lulus jika*: test pada direktori sintetis (ignore, symlink loop, file besar, biner).
- [x] **WP-1.2 Detektor stack + registry plugin** (S) — dep: 1.1. Penemuan plugin via entry point + folder bawaan; deteksi file penanda; dukungan monorepo (banyak stack).
  *Lulus jika*: test repo sintetis multi-stack memilih plugin yang benar.
- [x] **WP-1.3 Reporter JSON + console + coverage** (M) — dep: 0.2. Sesuai `spec.md` §2; bagian Coverage & limitations selalu ada; HTML di-escape (bila ada).
  *Lulus jika*: keluaran JSON tervalidasi terhadap `docs/schema/scan-output.schema.json` (dicek `jsonschema` di test); snapshot e2e.
- [x] **WP-1.4 CLI `scan` + batas sumber daya** (M) — dep: 1.1-1.3. Opsi di `spec.md` §1 yang relevan, exit code, timeout per file (proses terisolasi atau `signal`/thread dengan batas), kegagalan file dicatat sebagai `skipped`.
  *Lulus jika*: file patologis (sangat dalam, sangat besar, biner) tidak membuat `scan` crash atau hang; exit code sesuai spec.
- [x] **WP-1.5 Rule sepele end-to-end** (S) — dep: 1.4. Hardcode satu deteksi `eval()` Python untuk menguji pipeline (akan digantikan rule YAML di Fase 2).
  *Lulus jika*: e2e menghasilkan Finding dengan file dan baris benar; snapshot tersimpan.

## Fase 2: Rule engine

- [x] **WP-2.1 Skema rule + validator** (M) — dep: 0.2. Model pydantic sesuai `spec.md` §7; pesan error menyebut file, baris, dan field; `vulnfab rules list`.
  *Lulus jika*: test untuk tiap kelas kesalahan (id ganda, tanpa test safe, kind tak dikenal, field hilang).
- [x] **WP-2.2 Evaluator ekspresi aman** (S) — dep: 2.1. Whitelist node; tanpa pemanggilan fungsi, tanpa akses dunder.
  *Lulus jika*: test adversarial (`__import__`, atribut dunder, komprehensi berat) semuanya ditolak.
- [x] **WP-2.3 Kompiler pola snippet → matcher** (L) — dep: 0.3b, 1.1. Metavariable, `...`, `pattern-not`, `pattern-inside`, `where`; adaptor tree-sitter Python/TS/PHP.
  *Lulus jika*: ≥ 30 kasus per bahasa (cocok/tidak cocok/tepi) lulus.
- [x] **WP-2.4 Harness test rule** (M) — dep: 2.1, 2.3. Anotasi `# vuln: <id>`; `vulnfab rules test`; cek CI "rule tanpa test gagal".
  *Lulus jika*: rule sengaja rusak (safe menghasilkan temuan) membuat harness gagal dengan pesan jelas.
- [x] **WP-2.5 Suppression & baseline** (M) — dep: 1.4. `# nosec`, `.vulnfab.yml`, `--baseline`/`--write-baseline`.
  *Lulus jika*: baseline menyembunyikan temuan lama dan tetap menampilkan yang baru setelah baris bergeser.
- [x] **WP-2.6 Rule generik awal (15-20)** (L) — dep: 2.4. Python (`eval`/`exec`, `pickle`, `subprocess shell=True`, `yaml.load`, hash lemah), PHP (`eval`, `unserialize`, `exec`), JS/TS (`eval`, `child_process` literal). Tiap rule: vuln + safe.
  *Lulus jika*: `vulnfab rules test` hijau; CI gate "tiap rule punya test" aktif.
- [x] **WP-2.7 Scoring & dedup** (S) — dep: 1.3. Sesuai `spec.md` §4.
  *Lulus jika*: test untuk urutan prioritas, penurunan confidence, `supersedes`.

## Fase 3: Plugin Supabase/Postgres (inti produk)

- [x] **WP-3.1 Loader migration** (S) — dep: 1.2. Urut timestamp/nama; tangani berkas tak valid sebagai `Unresolved` (tidak crash).
  *Lulus jika*: test urutan, duplikat timestamp, SQL rusak.
- [x] **WP-3.2 SchemaBuilder: DDL inti** (L) — dep: 0.2, 3.1. `CREATE/ALTER/DROP TABLE`, `RENAME`, `SET SCHEMA`, kolom, constraint, `ENABLE/FORCE RLS`, `CREATE/ALTER/DROP POLICY`, `GRANT/REVOKE`, `ALTER DEFAULT PRIVILEGES`, `CREATE SCHEMA`, view (+ `security_invoker`).
  *Lulus jika*: test tabel-per-pernyataan menghasilkan SchemaModel keadaan akhir yang benar (termasuk drop lalu recreate, rename).
- [x] **WP-3.3 Fungsi & plpgsql** (M) — dep: 3.2. `CREATE FUNCTION` (`security_definer`, `search_path`, bahasa), parse body via `parse_plpgsql`, deteksi `EXECUTE` dinamis; `DO $$` → `Unresolved`.
  *Lulus jika*: fungsi definer tanpa `search_path` dan `EXECUTE` konkatenasi terdeteksi di test; `DO` menghasilkan `Unresolved`.
- [x] **WP-3.4 Akses efektif** (L) — dep: 3.2. `effective_access` sesuai `spec.md` §5 (OR permissive, restrictive AND, deny-default, `auth.uid()` owner, `service_role` bypass).
  *Lulus jika*: tabel kebenaran ≥ 25 kasus lulus (termasuk RLS aktif tanpa policy = deny, `(select auth.uid())`, policy `true`, `FORCE RLS`).
- [x] **WP-3.5 Storage, config.toml, seed.sql** (M) — dep: 3.2. Bucket (SQL `storage.buckets` + config), policy `storage.objects`, `config.toml` (signup, jwt, `verify_jwt` per fungsi), password/akun hardcoded di seed.
  *Lulus jika*: test fixture untuk tiap sumber; TOML rusak → `Unresolved`.
- [x] **WP-3.6 Rule pack Supabase (14 rule)** (L) — dep: 3.4, 3.5, 2.4. Katalog di rencana Bagian 9; tiap rule vuln + safe.
  *Lulus jika*: `rules test` hijau; setiap rule memakai `check` Python teruji atau `condition` aman.
- [x] **WP-3.7 Cek drift (`--schema-dump`)** (M) — dep: 3.2. Bandingkan SchemaModel dengan dump `pg_dump --schema-only`; perbedaan menjadi temuan `info` + catatan asumsi.
  *Lulus jika*: dump sintetis dengan tabel/RLS berbeda memunculkan perbedaan yang diharapkan.
- [x] **WP-3.8 E2E lab Supabase** (M) — dep: 3.6, 0.6. Evaluasi terhadap `supabase-vuln`; tinjau semua temuan tak berlabel (verdict).
  *Lulus jika*: recall tier A ≥ 90%, precision ≥ 90%, 0 FP pada decoy; snapshot e2e tersimpan; waktu < 10 s.

## Fase 4: Plugin TypeScript + cross-check → **M1**

- [x] **WP-4.1 Parser & symbol table TS/JS/TSX** (M) — dep: 1.2, 2.3. Fungsi, kelas, import/export, ekspor default, alias sederhana.
  *Lulus jika*: test pada fixture TS/TSX/JS; sintaks tak valid → `skipped`.
- [x] **WP-4.2 Rule pack TS (pola)** (L) — dep: 4.1, 2.4. `service_role` di frontend, `NEXT_PUBLIC_*`/`VITE_*` berisi secret, `dangerouslySetInnerHTML`/`innerHTML`, `eval`/`new Function`, `child_process` dengan input (versi pola; taint menyusul), `.or(\`…${x}\`)`.
  *Lulus jika*: vuln + safe per rule; `rules test` hijau.
- [x] **WP-4.3 Secret bawaan + adaptor gitleaks** (M) — dep: 1.4. Regex spesifik provider, entropi, allowlist, `.env` ter-commit; adaptor gitleaks opsional (ketiadaan → status `missing` di coverage).
  *Lulus jika*: test secret palsu (jangan pakai kredensial nyata) terdeteksi; kunci contoh di allowlist tidak; ReDoS test lulus.
- [x] **WP-4.4 Ekstraksi `DataAccess` supabase-js** (L) — dep: 4.1. `from().select/insert/update/delete/upsert`, `rpc`, deteksi `client_kind` (createClient + kunci `service_role`/anon/user), `filter_columns` dari `.eq/.match/.filter`, resolusi nama tabel literal/konstanta.
  *Lulus jika*: ≥ 20 kasus (chain multi-baris, variabel klien, tabel dinamis → `Unresolved`).
- [x] **WP-4.5 Engine cross-check + rule** (M) — dep: 3.4, 4.4. Kelas cek: akses ke tabel tanpa RLS/`Allow` untuk `anon`; klien anon menulis ke tabel dengan policy write terbuka; `.eq('id', param)` pada tabel tanpa policy owner (tier B awal, tanpa taint). Trace ke policy/migration.
  *Lulus jika*: temuan memuat trace ganda (baris kode + lokasi schema); e2e lab cocok truth.
- [x] **WP-4.6 Entrypoint & Edge Functions** (M) — dep: 4.1, 3.5. Next.js route handler/server action, Express, `supabase/functions/*`; `verify_jwt = false` dari config; input tanpa validasi (pola).
  *Lulus jika*: fixture per framework menghasilkan entrypoint yang benar.
- [x] **WP-4.7 Gate M1** (M) — dep: 3.8, 4.5, 0.7. Evaluasi lengkap lab + aplikasi milikmu; simpan `benchmarks/results/m1.md`; tag `v0.1.0`.
  *Lulus jika*: seluruh gate M1 di rencana Bagian 17 terpenuhi; catatan false positive/negatif ditulis.
  *Status*: gate lab terpenuhi (`benchmarks/results/m1.md`). Bagian "aplikasi milikmu" **belum**: contoh resmi supabase/supabase dipakai sebagai pengganti sementara sampai WP-0.7 tersedia.

## Fase 5: Taint engine → **M2**

- [x] **WP-5.1 Normalisasi TIR** (XL) — dep: 4.1. Penerjemah tree-sitter → TIR untuk Python, TS/JS, PHP; `vulnfab ir <file>`.
  *Lulus jika*: golden test TIR per bahasa untuk konstruksi inti (assign, call, f-string/template/interpolasi, concat, subscript, atribut, branch, loop, return); konstruksi tak dikenal → `Unknown` bukan crash.
- [x] **WP-5.2 Loader rule taint** (M) — dep: 2.3, 5.1. Sources/sinks/sanitizers/propagators sebagai pola snippet yang dicocokkan pada TIR.
  *Lulus jika*: validasi rule taint + test pencocokan pola pada TIR.
- [x] **WP-5.3 Taint intra-fungsi (5a)** (XL) — dep: 5.1, 5.2. Propagasi lewat assign/concat/format, constant propagation, sanitizer, trace.
  *Lulus jika*: ≥ 40 kasus vuln/safe (sanitizer, percabangan, reassign, kill) lulus; **titik evaluasi**: catat keputusan lanjut sendiri vs backend Semgrep di `docs/decisions/d5.md`.
- [x] **WP-5.4 Antar-fungsi satu file (5b)** (XL) — dep: 5.3. Ringkasan fungsi (param→return, param→sink), batas kedalaman.
  *Lulus jika*: kasus rekursi, fungsi saling memanggil, dan kedalaman melebihi batas tidak hang dan menambah `unresolved_hops`.
- [x] **WP-5.5 Antar-file (5c) + call graph** (XL) — dep: 5.4. Resolusi import (Python module, TS import/export, PHP `use`/namespace), call graph, edge `unresolved`.
  *Lulus jika*: proyek fixture multi-file (3+ file) menghasilkan trace lintas file dengan urutan baris/berkas benar.
- [x] **WP-5.6 Batas & ketahanan** (M) — dep: 5.5. Timeout per file, batas path per sink, fixpoint loop ≤ 3, laporan `unresolved` di coverage.
  *Lulus jika*: file patologis (loop bersarang, grafik panggilan besar) selesai < batas dan melaporkan pemotongan.
- [x] **WP-5.7 Rule taint generik & TS** (L) — dep: 5.5. SQLi, XSS, command injection, path traversal, SSRF, deserialisasi untuk Python/TS/PHP dasar (tanpa model framework); pindahkan rule pola `ts-cmd-injection` ke taint.
  *Lulus jika*: vuln + safe per rule.
- [x] **WP-5.8 IDOR tier B (kerangka)** (M) — dep: 5.5. Model "sanitizer kepemilikan" (filter `owner=user`, `auth.uid()`), sink fetch-by-key, confidence ≤ medium, `tier: B`.
  *Lulus jika*: fixture fetch-by-pk dengan/tanpa filter pemilik membedakan benar.
- [x] **WP-5.9 Gate M2** (L) — dep: 5.7, 0.4. Evaluasi NodeGoat + Juice Shop (label dibuat dan di-review); `benchmarks/results/m2.md`; tag `v0.2.0`.
  *Lulus jika*: gate M2 di rencana Bagian 17 terpenuhi.

## Fase 6: Plugin Django

- [x] **WP-6.1 Parse & schema dari models/migrations** (L) — dep: 5.1. `models.py`/`migrations/*.py` (pembacaan struktural, tanpa mengeksekusi) → SchemaModel; kolom sensitif.
  *Lulus jika*: fixture app dengan operasi migration umum menghasilkan skema akhir benar.
- [x] **WP-6.2 Entrypoint** (M) — dep: 5.5. `urls.py` → view (fungsi/CBV), `request.GET/POST/body/FILES/headers/COOKIES` sebagai source, decorator auth.
  *Lulus jika*: fixture URL nested/`include` menghasilkan entrypoint benar.
- [x] **WP-6.3 Parser template Django** (M) — dep: 0.3c. `|safe`, `{% autoescape off %}`, `mark_safe` dari konteks.
  *Lulus jika*: fixture template dengan dan tanpa autoescape.
- [x] **WP-6.4 Model ORM & rule pack** (L) — dep: 6.2, 5.7. Sink `.raw()`/`.extra()`/`cursor.execute`, sanitizer ORM terparameter; rule settings (`DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY`), `csrf_exempt`, `ModelForm __all__`, view tanpa auth (tier A), `dj-idor-get-by-pk` (tier B), `dj-dynamic-dispatch-input`.
  *Lulus jika*: vuln + safe per rule.
- [x] **WP-6.5 Refactor kontrak + bekukan** (M) — dep: 6.4. Catat semua perubahan core yang dibutuhkan Django; perbarui `spec.md`; bekukan kontrak.
  *Lulus jika*: `docs/decisions/plugin-contract-freeze.md` menyebut versi kontrak; test kontrak (plugin contoh minimal) lulus.

## Fase 7: Plugin Laravel → **M3**

- [ ] **WP-7.1 Migration Laravel → schema** (L) — dep: 6.5. `Schema::create/table`, `$table->…`, foreign key.
  *Lulus jika*: fixture migration umum menghasilkan skema benar.
- [ ] **WP-7.2 Routes & entrypoint** (M) — dep: 6.5. `routes/*.php`, group/middleware, `Route::resource`, controller; `$request->*` sebagai source; route tanpa `auth`.
  *Lulus jika*: fixture grup middleware bersarang.
- [ ] **WP-7.3 Parser Blade** (M) — dep: 0.3c. `{!! !!}` vs `{{ }}`, `@php` blok.
  *Lulus jika*: fixture Blade dengan komentar/escaping.
- [ ] **WP-7.4 Model Eloquent & rule pack** (L) — dep: 7.2, 5.7. Mass assignment, `$hidden`, `DB::raw`/`whereRaw`, `unserialize`, `APP_DEBUG`, seeder password, `lv-idor-find` (tier B).
  *Lulus jika*: vuln + safe per rule.
- [ ] **WP-7.5 Lab Laravel & Django + Gate M3** (L) — dep: 6.4, 7.4. Lab buatan sendiri + DVWA + django.nV; `benchmarks/results/m3.md`; tag `v0.3.0`.
  *Lulus jika*: gate M3 di rencana Bagian 17 terpenuhi.

## Fase 8: Scanner pelengkap (opsional, lihat tangga pemangkasan)

- [ ] **WP-8.1 Config scanner** (M) — dep: 1.4. Dockerfile, `docker-compose`, nginx (CORS longgar, header), `.env` ter-commit, `APP_DEBUG` lintas stack.
  *Lulus jika*: vuln + safe per rule.
- [ ] **WP-8.2 SCA offline** (M) — dep: 0.3d. Parse `package-lock.json`, `composer.lock`, `requirements.txt`/`poetry.lock`/`uv.lock`; cocokkan dengan dump OSV lokal; adaptor osv-scanner opsional.
  *Lulus jika*: lockfile fixture + dump OSV mini menghasilkan temuan yang benar tanpa jaringan.
- [ ] **WP-8.3 Riwayat git untuk secret** (S) — dep: 4.3. Opsional via gitleaks atau pemindaian objek git bawaan.
  *Lulus jika*: repo fixture dengan secret di commit lama terdeteksi.

## Fase 9: Kualitas dan akurasi

- [ ] **WP-9.1 Benchmark otomatis semua target** (M) — dep: 5.9, 7.5. Satu perintah menjalankan evaluasi semua target dan menulis tabel per rule.
  *Lulus jika*: `benchmarks/run_all.sh` menghasilkan `benchmarks/results/latest.md` tanpa langkah manual.
- [ ] **WP-9.2 `vulnfab triage`** (S) — dep: 2.5. Simpan verdict (fingerprint → tp/fp/dup) yang dibaca evaluator.
  *Lulus jika*: verdict tersimpan dan mengubah hasil evaluator.
- [ ] **WP-9.3 Pengetatan rule** (L) — dep: 9.1. Semua rule di bawah ambang precision diperbaiki/diturunkan confidence-nya/dihapus; catat di `CHANGELOG`.
  *Lulus jika*: tabel per rule memenuhi ambang di rencana Bagian 17.
- [ ] **WP-9.4 Dogfooding di CI** (S) — dep: 1.4. Scan repo sendiri dan lab di CI; regresi snapshot gagal CI.
  *Lulus jika*: CI menjalankan scan dan membandingkan snapshot.

## Fase 10: Produk dan integrasi → **M4**

- [ ] **WP-10.1 SARIF** (M) — dep: 1.3. Sesuai SARIF 2.1.0, `partialFingerprints` dari fingerprint, code flows dari trace.
  *Lulus jika*: keluaran lolos validasi terhadap skema SARIF resmi (skema disimpan di repo untuk uji offline).
- [ ] **WP-10.2 Laporan HTML mandiri** (M) — dep: 1.3. Satu berkas, di-escape penuh.
  *Lulus jika*: test XSS (snippet berisi `<script>`/atribut) tidak menghasilkan HTML aktif.
- [ ] **WP-10.3 Mode diff/PR** (L) — dep: 5.5. `--since REF`: file berubah + dependen via call graph/impor.
  *Lulus jika*: uji otomatis: hasil diff = hasil scan penuh yang dibatasi pada set terdampak.
- [ ] **WP-10.4 Cache & paralelisasi** (M) — dep: 1.4. Cache berbasis hash file + versi rule; `--jobs`.
  *Lulus jika*: scan kedua pada repo tak berubah ≥ 5× lebih cepat; hasil identik dengan tanpa cache.
- [ ] **WP-10.5 GitHub Action + pre-commit** (M) — dep: 10.1. Action komposit, hook.
  *Lulus jika*: workflow contoh pada repo fixture mengunggah SARIF dan gagal sesuai `--fail-on`.
- [ ] **WP-10.6 `vulnfab explain` + dokumentasi** (L) — dep: 9.3. Panduan menulis rule/plugin, referensi rule (dihasilkan otomatis dari YAML), batasan yang diketahui, `THIRD_PARTY_LICENSES.md` final.
  *Lulus jika*: referensi rule ter-generate di CI dan sinkron dengan rule pack; tautan dokumen valid.
- [ ] **WP-10.7 Gate M4 + rilis** (M) — dep: semua di atas. `benchmarks/results/m4.md`; tag `v1.0.0`; build wheel via `uv build`.
  *Lulus jika*: gate M4 di rencana Bagian 17 terpenuhi.
- [ ] **WP-10.8 (opsional) Triase LLM** (L) — dep: 10.7. Snippet minimal + trace, kode diperlakukan sebagai data, keluaran LLM tidak pernah menjadi detektor tunggal; nonaktif secara default.
  *Lulus jika*: uji prompt-injection pada komentar kode tidak mengubah verdict; tanpa kunci API fitur mati dengan pesan jelas.

## Fase 11: Ekspansi (di luar 1.0)

- [ ] **WP-11.1 Verifikasi DAST dengan OWASP ZAP** — untuk temuan tier B/C dan unresolved.
- [ ] **WP-11.2 Plugin tambahan** — Express, Flask, Rails, Spring.
