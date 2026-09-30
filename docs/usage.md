# Panduan pemakaian

vulnfab adalah scanner statis: membaca kode dan konfigurasi, **tidak pernah mengeksekusi** kode target.

## Pasang dan jalankan

```bash
uv sync                       # dari checkout repo ini
uv run vulnfab scan <path>    # laporan di terminal
```

Yang dipindai ditentukan otomatis (Supabase, Django, Laravel, TypeScript, plus rule bahasa-generik untuk
Python/JS/PHP). Paksa stack tertentu dengan `--stack django` (boleh diulang).

## Opsi penting

| Opsi | Fungsi |
|---|---|
| `--format console\|json\|sarif\|html`, `-o berkas` | Bentuk keluaran. `sarif` untuk GitHub code scanning; `html` satu berkas tanpa skrip |
| `--min-confidence low\|medium\|high` | Temuan di bawah ambang disembunyikan (default `medium`) |
| `--fail-on critical\|high\|medium\|low\|info` | Exit code 1 bila ada temuan sekurang-kurangnya setinggi ini |
| `--baseline b.json` / `--write-baseline b.json` | Hanya tampilkan temuan baru / simpan temuan sekarang sebagai baseline |
| `--since REF` | Mode diff: hanya temuan yang terpengaruh perubahan sejak `REF` (lihat di bawah) |
| `--jobs N` | Paralel dengan N proses; hasil identik dengan tanpa paralel |
| `--no-cache` | Jangan baca/tulis cache hasil |
| `--rules dir` | Tambah rule sendiri |
| `--schema-dump live.sql` | Bandingkan migration Supabase dengan `pg_dump --schema-only` (deteksi drift) |
| `--max-per-rule N` | Terminal: jumlah baris per rule (0 = semua) |

Exit code: `0` bersih, `1` ada temuan ≥ `--fail-on`, `2` salah pakai/konfigurasi, `3` galat internal.

## Membaca laporan

Setiap temuan punya **severity** (dampak), **confidence** (seberapa yakin), dan bila berasal dari analisis
alur data, **jalur** sumber → sink. Confidence turun untuk setiap pemanggilan tak dikenal di jalur
(`unresolved hop`). Tingkat: **A** struktural, **B** pola kepemilikan (IDOR; maksimum medium), **C** kandidat
semantik (tersembunyi). Bagian *Coverage & limitations* di akhir laporan menyebut apa yang tidak dianalisis
(berkas dilewati, konstruk dinamis, asumsi). Baca bagian itu sebelum menyimpulkan "bersih".

Penjelasan satu rule: `vulnfab explain tpy-sqli`. Daftar lengkap: [`rules.md`](rules.md).

## Menekan temuan

1. Satu baris: komentar `# nosec: <rule-id>` (atau `// nosec: ...`) di baris temuan.
2. Per berkas: `per_file_ignores` di `.vulnfab.yml`.
3. Sekumpulan temuan lama: baseline (`--write-baseline`, lalu `--baseline`). Fingerprint tidak memakai nomor
   baris, jadi tahan terhadap pergeseran kode.

## `.vulnfab.yml`

```yaml
exclude: ["vendor/**", "**/*.min.js"]      # berkas yang diabaikan
disable_rules: [py-hash-weak]
min_confidence: medium
severity_overrides: {js-innerhtml-var: low}
per_file_ignores: {"scripts/**": [py-os-system]}
max_file_kb: 1024
file_timeout: 10
```

`.vulnfabignore` (sintaks seperti `.gitignore`) juga dibaca.

## Laporan HTML interaktif untuk triase

`vulnfab scan . --format html-triage -o triage.html` membuat halaman mandiri dengan filter (severity,
rule, pencarian), tombol **TP / FP / DUP** dan kolom alasan per temuan. Penilaian tersimpan di
browser (localStorage) dan tombol **Export verdicts** mengunduh `vulnfab-verdicts.json` dalam format
yang sama dengan `vulnfab triage`. Halaman ini memuat satu skrip statis tanpa data pindaian dan CSP
yang melarang akses jaringan; format `html` biasa tetap tanpa skrip.

## Sanitizer dan validator milik proyek

Kalau proyekmu punya fungsi pembersih/validasi sendiri, beri tahu taint engine di `.vulnfab.yml`:

```yaml
taint:
  sanitizers: ["call escapeHtml", "call clean_path"]  # hasil panggilan dianggap bersih
  validators: ["call path_aman"]                       # dipakai di `if`: operand dianggap tervalidasi
```

Entri berlaku untuk semua rule taint. Tulis hanya fungsi yang benar-benar aman; entri yang salah
akan menyembunyikan temuan yang asli.

## Mode diff dan cache

`vulnfab scan . --since origin/main` memindai seluruh repo lalu melaporkan hanya: berkas yang berubah, berkas yang
mengimpornya (Python/JS/TS lewat impor, PHP lewat nama kelas), dan temuan yang jalur datanya melewati berkas
berubah. Bila berkas global berubah (settings, migration, routes, `.env`, `composer.json`, `package.json`, dsb.)
seluruh temuan dianggap terpengaruh. Butuh riwayat git yang cukup (di CI: `fetch-depth: 0`).

Hasil analisis di-cache di `~/.cache/vulnfab` (atau `$VULNFAB_CACHE_DIR`). Kuncinya mencakup versi/kode alat, semua
rule, hash setiap berkas, konfigurasi, dan opsi analisis; jadi hasil dari cache selalu identik dengan pemindaian
baru. Pindai ulang repo yang tidak berubah biasanya < 1 detik.

## Dependensi rentan (offline)

`vulnfab scan . --osv-db ./osv-advisories` mencocokkan versi di `package-lock.json`, `composer.lock`,
`Pipfile.lock`, `poetry.lock`, `uv.lock` dan `requirements*.txt` (versi terkunci `==`) dengan dump
advisori OSV lokal (direktori/berkas `.json`/`.jsonl`). Tanpa jaringan, hasil deterministik.
Database dibuat sekali (perlu internet) dan diperbarui kapan saja dengan
`vulnfab osv update ./osv-advisories` (`-e npm -e PyPI -e Packagist` untuk memilih ekosistem);
pemindaian setelah itu tetap offline. Hanya paket yang ada di lockfile yang dimuat, jadi
dump npm (~230 ribu advisori) tetap cepat (~2 dtk).
`--osv-scanner` menjalankan biner `osv-scanner` bila ada. Tanpa keduanya, lockfile dicatat
di *coverage* sebagai "tidak diperiksa".

## Rahasia di riwayat git

`vulnfab scan . --history [--history-limit 200]` juga memeriksa baris yang *ditambahkan* di commit
lama. Rahasia yang sudah dihapus dari pohon kerja tetapi masih ada di riwayat dilaporkan sebagai
`sec-secret-history` (nilai disamarkan; rotasi kredensialnya). Rahasia yang masih ada di pohon kerja
tidak diduplikasi. Pemindaian dibatasi ke N commit terbaru dan batasnya dicatat di *coverage*.

## CI

GitHub Action (komposit) di root repo ini:

```yaml
- uses: actions/checkout@v4
  with: {fetch-depth: 0}
- uses: blowmamain-spec/vuln-fab@main
  with:
    fail-on: high          # gagal bila ada temuan high ke atas
    min-confidence: medium
    upload-sarif: "true"   # hasil muncul di tab Security → Code scanning
```

Pada `pull_request`, `since` otomatis berisi `origin/<base>`. Pre-commit: `repo: https://github.com/blowmamain-spec/vuln-fab`,
`hooks: [{id: vulnfab}]` (atau `vulnfab-changed` untuk hanya perubahan sejak `HEAD`).

## Triase

```bash
vulnfab scan . --format json -o hasil.json
vulnfab triage list hasil.json -f verdicts.json          # yang belum diberi verdict
vulnfab triage set <fingerprint> -v fp -n "konstanta" -f verdicts.json
```

Format berkas verdict sama dengan yang dibaca evaluator benchmark (`benchmarks/verdicts/*.json`).
