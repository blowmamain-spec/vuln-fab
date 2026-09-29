# Rencana Proyek: SAST Multi-Stack (v3, siap eksekusi)

Scanner statis untuk kode aplikasi web. Satu engine inti, banyak plugin: **Supabase/Postgres, Django, Laravel, TypeScript**. Nama paket dan CLI: **`vulnfab`** (mengikuti nama repo; mudah diganti).

**Peta dokumen**
- Dokumen ini: strategi, keputusan final, gate milestone, tangga pemangkasan scope (Bagian 15-19).
- [`spec.md`](spec.md): kontrak teknis (CLI, exit code, skema JSON, IR, skema rule, fingerprint, scoring, format ground truth).
- [`work-packages.md`](work-packages.md): daftar paket kerja bercentang, dengan dependensi dan kriteria lulus yang bisa dijalankan. **Inilah yang dikerjakan berurutan sampai selesai.**

Perubahan v3 terhadap v2:
- Bagian 15-19 baru: keputusan final, konvensi engineering, gate numerik per milestone, tangga pemangkasan, catatan lingkungan.
- Pencocokan pola memakai **tree-sitter untuk semua bahasa** (termasuk Python), bukan `ast`, agar hanya ada satu matcher. `ast` tetap boleh dipakai untuk kebutuhan khusus (mis. mengevaluasi `migrations/*.py`).
- Taint engine bekerja pada **IR bertipe kecil (TIR)** yang dinormalisasi per bahasa, agar satu engine melayani semua stack.
- Spike berbatas waktu di Fase 0 untuk menguji asumsi paling berisiko sebelum membangun di atasnya.
- Adaptor gitleaks/osv-scanner bersifat opsional dengan fallback bawaan (alat tidak terpasang di lingkungan pengembangan; API OSV diblokir di sandbox).

Perubahan v2 terhadap v1:
- Broken access control (IDOR) dan kode dinamis **masuk scope** sebagai cakupan bertingkat dengan confidence eksplisit, bukan lagi pengecualian.
- Diferensiator produk: analisis skema Supabase + cross-check skema ↔ kode.
- Kontrak plugin diperbaiki (fakta `DataAccess`, pembekuan setelah plugin ke-3).
- Scanner pelengkap membungkus alat yang ada (gitleaks, osv-scanner).
- Estimasi waktu dihitung ulang; kriteria berhenti per milestone.
- Lisensi: **GPL-3.0-or-later** (karena `pglast`).

## 1. Tujuan, cakupan, dan batasan

**Tujuan**
- Membaca repo (tanpa menjalankan aplikasi) dan melaporkan kerentanan lengkap dengan file, baris, jalur data, CWE, severity, confidence, dan saran perbaikan.
- Menangani kode aplikasi **dan** migration/skema database.
- Menambah stack baru cukup dengan menulis plugin, tanpa menyentuh core.

**Cakupan bertingkat untuk access control (IDOR)**

| Tingkat | Contoh | Pendekatan | Confidence default |
|---|---|---|---|
| A. Struktural | Route tanpa middleware `auth`, view tanpa `login_required`, policy RLS `USING (true)`, edge function tanpa JWT | Rule pola/skema | High |
| B. Pola kepemilikan | `Model.objects.get(pk=request.GET['id'])` tanpa filter pemilik; `find($id)` tanpa scope; `supabase.from('x').select().eq('id', param)` pada tabel yang policy-nya tidak memakai `auth.uid()` | Taint: source = ID dari request, sink = fetch by key, "sanitizer" = filter kepemilikan | Medium |
| C. Semantik | Aturan bisnis kustom, state machine, izin lintas-tim | Hanya *kandidat* (`info`/low), muncul dengan `--include-candidates`; verifikasi lewat triase manusia/LLM atau DAST | Low |

**Kode dinamis (`eval`, reflection, dynamic dispatch)**
- Diresolusi untuk kasus umum: constant propagation (`getattr(o, "literal")`), dispatch table literal, konvensi framework (class-based view, `Route::resource`, DI).
- Sink dinamis dengan input request adalah temuan tersendiri (CWE-95, CWE-502).
- Panggilan yang tidak bisa diresolusi ditandai `unresolved`. Taint yang menyentuhnya diteruskan secara konservatif dengan confidence turun ke low. Jumlahnya muncul di bagian "Coverage & limitations" pada setiap laporan.
- Verifikasi dinamis (DAST/ZAP) dipakai untuk temuan tingkat B/C dan yang unresolved (Fase 11).

**Batasan yang tetap didokumentasikan**
- Analisis statis tidak bisa lengkap untuk kode dinamis; recall tidak dijamin.
- Migration ≠ keadaan database sebenarnya (drift lewat dashboard). Laporan menyebut asumsi ini.
- Bukan DAST (awal).

**Prinsip**
1. Akurasi sebelum cakupan: lebih baik 20 rule presisi daripada 200 rule berisik. Temuan berconfidence rendah disembunyikan secara default.
2. Rule sebagai data (YAML); logika rumit ditulis sebagai fungsi Python teruji yang dirujuk dari YAML.
3. Setiap rule wajib punya test (kode rentan + kode aman).
4. Jangan pernah mengeksekusi kode target.
5. Jangan menulis ulang yang sudah ada dan matang (secret, SCA) kecuali tujuannya belajar.
6. Jujur soal blind spot: setiap laporan memuat coverage & limitations.

## 2. Keputusan teknis

| Aspek | Pilihan | Alasan |
|---|---|---|
| Bahasa core | Python 3.11+ | `pglast`, `ast`, tree-sitter tersedia |
| Lisensi proyek | **GPL-3.0-or-later** | `pglast` berlisensi GPL-3.0-or-later; proyek yang meng-import-nya harus kompatibel |
| Parser SQL Postgres | `pglast` di belakang antarmuka `SqlParser` | Parser asli PostgreSQL. Antarmuka menjaga opsi mengganti ke wrapper `libpg_query` (BSD) bila lisensi berubah |
| Parser plpgsql | `pglast.parse_plpgsql` | Body fungsi tidak diparse oleh `parse_sql` |
| Parser Python/PHP/TS/JS | `tree-sitter` + grammar (versi di-pin) | Satu API dan satu matcher untuk semua bahasa; pin mencegah AST berubah diam-diam. Modul `ast` hanya untuk kebutuhan khusus |
| IR taint | TIR: assign, call, return, concat/fstring, subscript, attribute, branch, loop | Dinormalisasi per bahasa dari tree-sitter; satu engine untuk semua stack |
| Parser template | Django template & Blade: parser sederhana buatan sendiri (lihat Fase 6/7) | Tidak tercakup `ast`/tree-sitter |
| Pola rule | Meniru sintaks Semgrep (snippet dengan metavariable `$X`, diparse dengan grammar bahasa yang sama) | Tidak merancang bahasa pola sendiri; rule bisa dirujuk silang |
| Ekspresi kondisi rule skema | Evaluator aman (whitelist node AST, mis. `simpleeval`) atau fungsi Python teruji | **Dilarang `eval` string**: ini security tool |
| CLI | `typer` | Help otomatis |
| Output | JSON (`schema_version`), SARIF, HTML, console (`rich`) | SARIF untuk GitHub/CI |
| Test | `pytest` + snapshot | Regresi rule |
| Paket | `uv` (final) | Lebih cepat dan sederhana; tidak memengaruhi runtime scanner |
| Penemuan plugin | Python entry points (`importlib.metadata`) + folder bawaan | Plugin pihak ketiga tanpa mengubah core |
| Secret | Adaptor **gitleaks** opsional + detektor regex/entropi bawaan sebagai fallback | Alat tidak selalu terpasang; fallback menjaga fungsi dasar |
| SCA | Adaptor **osv-scanner** opsional; mode offline dari dump OSV lokal | API OSV bisa diblokir; SCA berprioritas rendah (Fase 8) |
| Pembanding | Semgrep, Database Advisors Supabase | Referensi akurasi |

## 3. Arsitektur

```
Repo target
   │
   ▼
Loader (walk, ignore, hash) ──► Detektor stack (pilih plugin aktif)
   │
   ▼
Plugin.parse() ──► IR bersama:
                     • AST per file
                     • Symbol table + call graph (termasuk penanda unresolved)
                     • Schema model (tabel, kolom, RLS, policy, grant, fungsi)
                     • Fakta DataAccess (table, op, file, line)   ◄── jembatan kode ↔ skema
   │
   ▼
Rule engine (pola AST) + Taint engine (source→sink) + Cross-check (fakta ↔ skema)
   │
   ▼
Scanner pelengkap (adaptor): gitleaks · osv-scanner · config
   │
   ▼
Dedup → Scoring (severity × confidence) → Suppression/Baseline → Reporter
                                                  (+ bagian Coverage & limitations)
```

**Pembagian tanggung jawab**
- **Core**: loader, IR, rule engine, taint engine, cross-check, scoring, reporter, CLI.
- **Plugin**: detektor stack, parser, ekstraktor skema, penghasil fakta `DataAccess`, model framework (source/sink/sanitizer), rule pack.

Cross-check lintas-plugin terjadi **di core** melalui fakta IR, sehingga plugin tetap tidak saling mengimpor.

## 4. Kontrak plugin

Bekukan **setelah plugin ke-3 (Django)**, bukan ke-2. Supabase dan TypeScript tidak mewakili plugin framework penuh (route, template, ORM), jadi kontrak hampir pasti berubah di Fase 6.

```python
class StackPlugin(Protocol):
    name: str
    languages: list[str]

    def detect(self, repo: RepoView) -> Confidence: ...
    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit: ...
    def extract_schema(self, repo: RepoView) -> SchemaModel | None: ...
    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]: ...
    def data_access(self, unit: ParsedUnit) -> list[DataAccess]: ...   # baru
    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]: ...  # baru: resolusi dinamis berbasis konvensi framework
    def templates(self, repo: RepoView) -> list[TemplateUnit]: ...     # baru: Django template, Blade
    def rule_packs(self) -> list[Path]: ...
```

Aturan: plugin **tidak** mengimpor plugin lain; komunikasi hanya lewat IR bersama.

## 5. Model data

**Finding**
```python
@dataclass
class Finding:
    rule_id: str
    title: str
    cwe: list[str]
    owasp: str | None          # catat edisi (2021 atau lebih baru)
    severity: Severity
    confidence: Confidence
    tier: Literal["A", "B", "C"] | None   # untuk access control
    file: str
    line: int; end_line: int
    snippet: str
    trace: list[TraceStep]
    unresolved_hops: int       # jumlah lompatan tak teranalisis di jalur
    fix: str | None
    fingerprint: str           # hash(rule + konteks ternormalisasi + nama simbol pembungkus); BUKAN nomor baris
```

**SchemaModel (netral framework)**
```
Table(name, schema, columns[], constraints[], rls_enabled, rls_forced, policies[], grants[])
Column(name, type, nullable, default, unique, sensitive_hint)
Policy(name, table, permissive, command, roles[], using_expr, check_expr)
Function(name, security_definer, search_path, language, body)
View(name, security_invoker, definition)
DefaultPrivilege(role, schema, object_type, privileges)
Unresolved(source_file, reason)      # DO $$...$$, SQL dinamis di migration
```

**DataAccess (fakta lintas-plugin)**
```
DataAccess(table, schema?, op: select|insert|update|delete|rpc, file, line,
           filter_columns[], client_kind: anon|user|service_role|unknown)
```

## 6. Format rule

Rule pola (sintaks snippet ala Semgrep):
```yaml
id: dj-raw-sql-interp
languages: [python]
stack: django
severity: high
confidence: medium
cwe: [CWE-89]
message: "Raw SQL dengan interpolasi string. Gunakan parameter."
pattern: "$MODEL.objects.raw(f\"...\")"
fix: "Model.objects.raw('... WHERE id = %s', [value])"
tests:
  vulnerable: ["tests/dj_raw_sql_interp/vuln.py"]
  safe:       ["tests/dj_raw_sql_interp/safe.py"]
```

Rule taint (dengan sanitizer kepemilikan untuk IDOR tingkat B):
```yaml
id: dj-idor-get-by-pk
stack: django
kind: taint
tier: B
sources: ["request.GET[...]", "request.GET.get(...)", "$KWARGS['pk']"]
sinks:   ["$M.objects.get(pk=$X)", "get_object_or_404($M, pk=$X)"]
sanitizers: ["$M.objects.filter(owner=request.user, ...)", "$X in request.user.$REL.values_list(...)"]
cwe: [CWE-639]
severity: high
confidence: medium
```

Rule skema (kondisi lewat evaluator aman atau fungsi teruji):
```yaml
id: sb-rls-missing
stack: supabase
kind: schema
check: "vulnfab.plugins.supabase.checks:rls_missing"   # fungsi Python teruji
severity: critical
cwe: [CWE-862]
message: "Tabel {table.name} di schema public tanpa RLS."
```

Rule cross-check (fakta ↔ skema):
```yaml
id: ts-table-no-rls
kind: crosscheck
facts: DataAccess
check: "vulnfab.core.crosscheck:access_to_table_without_rls"
severity: high
```

## 7. Struktur folder

```
vulnfab/
├── pyproject.toml
├── LICENSE                     # GPL-3.0-or-later
├── THIRD_PARTY_LICENSES.md     # lisensi pglast, tree-sitter grammar, rule pinjaman
├── README.md
├── docs/                       # panduan plugin & rule, batasan yang diketahui
├── src/vulnfab/
│   ├── cli.py                  # scan, rules test, explain, ast, triage
│   ├── core/
│   │   ├── loader.py
│   │   ├── models.py
│   │   ├── sqlparser.py        # antarmuka SqlParser (impl. pglast)
│   │   ├── rules.py
│   │   ├── matcher.py
│   │   ├── taint.py
│   │   ├── callgraph.py
│   │   ├── crosscheck.py
│   │   ├── scoring.py
│   │   └── suppress.py
│   ├── adapters/               # gitleaks, osv-scanner, semgrep (opsional)
│   ├── scanners/config.py
│   ├── reporters/
│   └── plugins/
│       ├── base.py
│       ├── supabase/
│       ├── django/
│       ├── laravel/
│       └── typescript/
├── rules/
├── tests/{unit,rules,e2e}
└── benchmarks/                 # skrip + ground truth berlabel + hasil
```

## 8. Fase pengerjaan

Estimasi dihitung ulang untuk 10-15 jam/minggu dan disertai kriteria berhenti.

> Rincian eksekusi tiap fase (paket kerja, dependensi, kriteria lulus) ada di [`work-packages.md`](work-packages.md). Daftar di bawah adalah ringkasan cakupan.

### Fase 0: Persiapan (1-2 minggu)
- [ ] Repo, `pyproject`, ruff, mypy, CI dasar dengan `uv` (keputusan final).
- [ ] Spike berbatas waktu (S1-S5) untuk menguji asumsi berisiko; hasil di `docs/spikes/`.
- [ ] Lisensi GPL-3.0-or-later; `THIRD_PARTY_LICENSES.md`; cek lisensi tree-sitter grammar yang dipilih.
- [ ] Antarmuka `SqlParser` (`parse`, `parse_plpgsql`) dengan implementasi `pglast`.
- [ ] Draf kontrak plugin dan model data (Bagian 4-5), termasuk `DataAccess` dan `Unresolved`.
- [ ] Siapkan target lab (kloning sumber; Docker hanya bila perlu): Juice Shop, NodeGoat, DVWA, Django.nV, aplikasi Supabase sengaja rentan (buat sendiri).
- [ ] **Ground truth**: `expected.json` berlabel (file, baris, jenis) per target lab; dataset berlabel bila ada (NIST SARD/Juliet untuk PHP).
- [ ] Definisikan metrik keberhasilan proyek dan ambang precision per severity.
- [ ] Alat debug: `vulnfab ast <file>`.

**Selesai jika**: `vulnfab --version` jalan, CI hijau, draf kontrak terdokumentasi, ground truth lab Supabase ada.

### Fase 1: Pipeline dasar (2 minggu)
- [ ] CLI `vulnfab scan <path> --format json`.
- [ ] Loader: walk, `.vulnfabignore`, abaikan `node_modules`/`vendor`/`.git`, batas ukuran file.
- [ ] Detektor stack lewat file penanda (dukung monorepo multi-stack).
- [ ] Reporter JSON (dengan `schema_version`) dan console; bagian Coverage & limitations.
- [ ] Satu rule sepele end-to-end untuk menguji pipeline.

### Fase 2: Rule engine (2-3 minggu)
- [ ] Loader/validator YAML (pydantic), evaluator ekspresi aman.
- [ ] Matcher pola snippet ala Semgrep (metavariable, wildcard).
- [ ] Harness test rule (`vuln/` harus terdeteksi, `safe/` tidak); `vulnfab rules test`.
- [ ] 15-20 rule awal.

### Fase 3: Plugin Supabase/Postgres (3-4 minggu) — inti produk
- [ ] Baca `supabase/migrations/*.sql` berurutan dan bangun `SchemaModel` **keadaan akhir**: `CREATE`, `ALTER`, `DROP`, `ENABLE/FORCE RLS`, `CREATE POLICY`, `GRANT`, `ALTER DEFAULT PRIVILEGES`.
- [ ] Semantik yang benar: policy permissive bersifat OR; RLS aktif tanpa policy = deny; `service_role` melewati RLS; view default berjalan dengan hak pemilik; grant bawaan Supabase ke `anon`/`authenticated`; policy `storage.objects`; schema yang diekspos PostgREST (`config.toml`).
- [ ] Parse body plpgsql; tandai `DO $$ ... $$` dan SQL dinamis di migration sebagai `Unresolved`.
- [ ] Opsi membaca `pg_dump --schema-only` untuk memeriksa drift.
- [ ] Rule skema (Bagian 9), `config.toml`, `seed.sql`.
- [ ] Uji ke aplikasi Supabase milikmu; catat temuan dan false positive.

**Selesai jika**: semua tabel public tanpa RLS di lab terdeteksi, tidak ada false positive pada tabel aman, dan semantik OR/deny-default terbukti lewat test.

### Fase 4: Plugin TypeScript + cross-check (3-4 minggu)
- [ ] Parser tree-sitter TS/JS/TSX.
- [ ] Rule: `service_role` di frontend, `NEXT_PUBLIC_*`/`VITE_*` berisi secret, `dangerouslySetInnerHTML`, `eval`, `child_process` dengan input.
- [ ] Ekstraksi fakta `DataAccess` dari `supabase.from('x')`/`.rpc()`; rule cross-check di core.
- [ ] Entry point Next.js (route handler, server action), Express, Edge Functions (`verify_jwt = false`).
- [ ] Adaptor gitleaks (secret) diaktifkan lebih awal karena murah.

**Selesai jika (M1)**: Supabase + TypeScript menemukan kebocoran key dan tabel tanpa RLS dalam satu laporan.
**Kriteria berhenti/evaluasi**: bila M1 memenuhi metrik Fase 0, proyek sudah berguna; lanjutan bersifat opsional.

### Fase 5: Taint engine (8-12 minggu)
Rilis tiap tahap:
- [ ] 5a. Intra-fungsi: propagasi lewat assignment dan konkatenasi; constant propagation.
- [ ] 5b. Antar-fungsi dalam satu file.
- [ ] 5c. Antar-file: resolusi import, call graph, penanda `unresolved`.
- [ ] Sanitizer (termasuk sanitizer kepemilikan untuk IDOR tingkat B), batas kedalaman, loop/rekursi, timeout per file.
- [ ] Trace lengkap (`line 10 → 25 → 40`) dan `unresolved_hops`.
- [ ] **Titik evaluasi setelah 5a**: apakah 5b/5c dibangun sendiri atau memakai Semgrep sebagai backend dengan adaptor (desain adaptor dibuat di Fase 0-1).

**Selesai jika (M2)**: SQLi dan XSS di NodeGoat/Juice Shop terdeteksi dengan jalur; tidak ada scan yang hang.

### Fase 6: Plugin Django (4 minggu)
- [ ] `models.py`/`migrations/*.py` (modul `ast`) → `SchemaModel`.
- [ ] Entry point: `urls.py` → view; `request.GET/POST/body` sebagai source; class-based view sebagai `dispatch_hints`.
- [ ] Parser template Django untuk `|safe`, `{% autoescape off %}`.
- [ ] Model ORM: sanitizer otomatis (query terparameter), sink `.raw()`/`.extra()`.
- [ ] Rule (Bagian 9) termasuk IDOR tingkat A/B.
- [ ] **Refactor checkpoint**: catat semua perubahan core; perbaiki kontrak; **bekukan kontrak setelah fase ini**.

### Fase 7: Plugin Laravel (4 minggu)
- [ ] Migration (`Schema::create`) → `SchemaModel`; `routes/*.php` → controller; deteksi route tanpa middleware `auth`.
- [ ] Parser Blade untuk `{!! !!}`.
- [ ] Model Eloquent (sink/sanitizer, `$fillable`/`$guarded`/`$hidden`).
- [ ] Rule (Bagian 9) termasuk IDOR tingkat A/B (`find($id)` tanpa scope).

**M3**: tiga stack didukung.

### Fase 8: Scanner pelengkap (1 minggu)
- [ ] Adaptor osv-scanner (lockfile `package-lock.json`, `composer.lock`, `requirements.txt`/`poetry.lock`; mode offline).
- [ ] Config: Dockerfile, `docker-compose`, `nginx.conf`, CORS longgar, header keamanan.
- [ ] Riwayat git untuk secret (opsional, via gitleaks).

### Fase 9: Kualitas dan akurasi (berjalan terus, intensif 3 minggu)
- [ ] Scoring: severity × confidence; dedup berdasarkan fingerprint; tingkat C tersembunyi secara default.
- [ ] Suppression: `# nosec`, `.vulnfab.yml`, mode **baseline**.
- [ ] `vulnfab triage` untuk menandai false positive; simpan sebagai data.
- [ ] Benchmark otomatis per stack terhadap ground truth; tabel precision/recall per rule.
- [ ] Ambang precision per severity (critical lebih ketat); rule di bawah ambang diperbaiki atau confidence diturunkan.
- [ ] Dogfooding: scan repo sendiri dan aplikasimu di CI.

### Fase 10: Produk dan integrasi (3-4 minggu)
- [ ] SARIF, laporan HTML mandiri, exit code CI (`--fail-on high`).
- [ ] **Mode diff/PR** (`--since main`): call graph menjawab "file mana yang terdampak".
- [ ] GitHub Action, pre-commit hook.
- [ ] Cache, paralelisasi (`multiprocessing`), scan inkremental.
- [ ] `vulnfab explain <finding>`, dokumentasi (menulis rule, menulis plugin, referensi rule, batasan yang diketahui).
- [ ] Opsional: triase LLM (snippet minimal + trace; kode target diperlakukan sebagai data). LLM bukan satu-satunya detektor.

**M4**: rilis publik (GPLv3).

### Fase 11: Ekspansi dan verifikasi dinamis
- DAST (OWASP ZAP) untuk memverifikasi temuan tingkat B/C dan yang unresolved.
- Plugin baru (Express, Flask, Rails, Spring).

## 9. Katalog rule awal

**Supabase/Postgres (skema)**
| ID | Deteksi | Severity | Tingkat |
|---|---|---|---|
| sb-rls-missing | Tabel `public` tanpa RLS | Critical | A |
| sb-policy-true | Policy `USING (true)` / `WITH CHECK (true)` | High | A |
| sb-policy-anon-write | Policy `anon` untuk INSERT/UPDATE/DELETE | High | A |
| sb-policy-user-metadata | Policy memakai `user_metadata` JWT | High | A |
| sb-policy-no-uid | Policy tanpa `auth.uid()` pada tabel ber-`user_id` | Medium | B |
| sb-definer-no-path | `SECURITY DEFINER` tanpa `SET search_path` | High | A |
| sb-view-no-invoker | View tanpa `security_invoker = true` | Medium | A |
| sb-grant-broad | `GRANT ALL` ke `anon`/`authenticated`/`public` | High | A |
| sb-default-priv | `ALTER DEFAULT PRIVILEGES` terlalu longgar | Medium | A |
| sb-dynamic-sql | `EXECUTE` dengan konkatenasi dari parameter | High | - |
| sb-storage-public | Bucket publik untuk data sensitif | Medium | A |
| sb-storage-policy | Policy `storage.objects` terlalu longgar | High | A |
| sb-seed-secret | Akun/password hardcoded di `seed.sql` | High | - |
| sb-config-signup | Signup tanpa konfirmasi email di `config.toml` | Medium | - |

**TypeScript**
| ID | Deteksi | Severity | Tingkat |
|---|---|---|---|
| ts-service-role-client | `service_role` di frontend/`NEXT_PUBLIC_*` | Critical | - |
| ts-secret-hardcoded | Key/token literal (via gitleaks + rule) | High | - |
| ts-xss-dangerous-html | `dangerouslySetInnerHTML`, `innerHTML` dengan input | High | - |
| ts-cmd-injection | `exec`/`spawn` dengan input | Critical | - |
| ts-dynamic-eval | `eval`/`new Function` dengan input | High | - |
| ts-supabase-or-inject | `.or(\`...${input}\`)` | Medium | - |
| ts-edge-no-jwt | `verify_jwt = false` | High | A |
| ts-table-no-rls | Akses ke tabel tanpa RLS (cross-check) | High | A |
| ts-idor-eq-id | `.eq('id', param)` pada tabel tanpa kebijakan berbasis `auth.uid()` | High | B |

**Django**
| ID | Deteksi | Severity | Tingkat |
|---|---|---|---|
| dj-raw-sql-interp | `.raw()`/`.extra()`/`cursor.execute` interpolasi | High | - |
| dj-mark-safe | `mark_safe`/`|safe` dengan input | High | - |
| dj-csrf-exempt | `@csrf_exempt` pada view state-changing | Medium | - |
| dj-debug-true | `DEBUG = True` | High | - |
| dj-allowed-hosts | `ALLOWED_HOSTS = ['*']` | Medium | - |
| dj-secret-key | `SECRET_KEY` hardcoded | High | - |
| dj-fields-all | `ModelForm` `fields = '__all__'` | Medium | - |
| dj-view-no-auth | View sensitif tanpa `login_required`/permission | Medium | A |
| dj-idor-get-by-pk | Fetch by pk dari request tanpa filter pemilik | High | B |
| dj-dynamic-dispatch-input | `getattr`/`eval`/`exec`/`importlib` dari input | High | - |

**Laravel**
| ID | Deteksi | Severity | Tingkat |
|---|---|---|---|
| lv-sqli-dbraw | `DB::raw`/`whereRaw` dari input | High | - |
| lv-blade-unescaped | `{!! $x !!}` | High | - |
| lv-mass-assign | `$guarded = []` atau `role`/`is_admin` di `$fillable` | High | - |
| lv-hidden-password | `password` tidak di `$hidden` | Medium | - |
| lv-route-no-auth | Route sensitif tanpa middleware `auth` | Medium | A |
| lv-idor-find | `find($id)`/`findOrFail($id)` dari input tanpa scope pemilik | High | B |
| lv-unserialize | `unserialize` dengan input | High | - |
| lv-app-debug | `APP_DEBUG=true` di config produksi | High | - |
| lv-seed-secret | Seeder dengan password hardcoded | High | - |

## 10. Strategi pengujian

1. **Unit test** core (parser, matcher, taint, scoring, evaluator ekspresi).
2. **Rule test**: tiap rule punya `vuln/` dan `safe/`; CI gagal jika ada rule tanpa test.
3. **E2E**: scan repo lab, bandingkan dengan `expected.json` berlabel (ground truth).
4. **Benchmark**: Juice Shop, NodeGoat (TS/JS); DVWA + Laravel rentan buatan sendiri (PHP); Django.nV/buatan sendiri (Python); Supabase rentan + aplikasimu. Tambahkan dataset berlabel (NIST SARD/Juliet) bila cocok.
5. **Metrik**: precision, recall, waktu scan per rule/stack; ambang per severity; disimpan per rilis.
6. **Pembanding**: Semgrep dan Database Advisors Supabase pada target yang sama.
7. **Dogfooding**: scan repo sendiri di CI.
8. **Stabilitas**: snapshot AST/IR dengan grammar yang di-pin; uji fingerprint tetap stabil saat baris bergeser.

## 11. Keamanan tool itu sendiri

- Jangan `import`/`exec`/`eval` kode target. Hanya parsing.
- Jangan `eval` string dari rule YAML; gunakan evaluator aman atau fungsi teruji.
- Batasi ukuran file, kedalaman AST, dan waktu parsing per file (ZIP bomb, file patologis, ReDoS).
- Hindari regex dengan backtracking berat; uji rule regex terhadap input adversarial.
- Repo tak tepercaya dipindai di container tanpa jaringan.
- Laporan HTML di-escape agar snippet target tidak menjadi XSS.
- Jika memakai LLM: kirim snippet minimal, perlakukan isi kode sebagai data (prompt injection dari komentar).
- Adaptor alat eksternal dijalankan tanpa shell dan dengan argumen yang di-escape.

## 12. Risiko dan mitigasi

| Risiko | Dampak | Mitigasi |
|---|---|---|
| Estimasi terlalu optimis | Proyek mandek | Estimasi dihitung ulang; kriteria berhenti per milestone; M1 sudah berguna |
| False positive tinggi (terutama IDOR tingkat B/C) | Tool tidak dipakai | Filter confidence default, baseline, triage, ambang precision per severity |
| Taint engine terlalu ambisius | Proyek mandek | Rilis bertahap 5a→5c; titik evaluasi setelah 5a; adaptor Semgrep |
| Kontrak plugin salah | Refactor besar | Fakta `DataAccess` sejak awal; bekukan setelah plugin ke-3 |
| Template & ORM tak tercakup | Rule XSS/SQLi lemah | Parser template dan model ORM masuk Fase 6/7 |
| Drift migration ≠ DB sebenarnya | False negative Supabase | Opsi `pg_dump`, asumsi dicatat di laporan |
| Kode dinamis | Recall turun | Penanda `unresolved`, sink dinamis sebagai rule, coverage report, DAST |
| Tidak ada ground truth | Klaim akurasi tak terbukti | Fase 0 menyiapkan `expected.json`; ukur sejak Fase 3 |
| Lisensi GPL (`pglast`) | Tidak bisa dirilis permisif/closed | Diputuskan: proyek GPL-3.0-or-later; antarmuka `SqlParser` menjaga opsi penggantian |
| Cakupan melebar | Tidak selesai | Satu stack sampai akurasi baik; kriteria berhenti |
| Grammar tree-sitter berubah | Rule/snapshot rusak | Pin versi, snapshot AST |

## 13. Estimasi (belajar sambil kerja, ~10-15 jam/minggu)

| Fase | Durasi |
|---|---|
| 0-2: fondasi + rule engine | 5-6 minggu |
| 3-4: Supabase + TypeScript (M1) | 6-8 minggu |
| 5: taint engine (M2) | 8-12 minggu |
| 6-7: Django + Laravel (M3) | 8 minggu |
| 8-10: pelengkap, akurasi, integrasi (M4) | 7-9 minggu |
| **Total** | **~8-11 bulan** (rentang konservatif hingga ~12-18 bulan bila taint dibangun penuh sendiri) |

**Milestone**
- **M1 (akhir Fase 4)**: Supabase + TypeScript + cross-check. Berguna untuk aplikasimu; titik berhenti yang sah.
- **M2 (akhir Fase 5)**: taint analysis dengan trace, IDOR tingkat B.
- **M3 (akhir Fase 7)**: tiga stack.
- **M4 (akhir Fase 10)**: rilis publik.

## 14. Langkah pertama (minggu ini)

1. Buat repo dengan kerangka folder (Bagian 7), lisensi GPL-3.0-or-later.
2. Tulis `plugins/base.py`, `core/models.py` (Finding, SchemaModel, DataAccess), dan `core/sqlparser.py` (antarmuka + impl. `pglast`).
3. Instal `pglast`, buka satu migration Supabase milikmu, cetak AST.
4. Tulis rule pertama `sb-rls-missing` dengan test vuln/safe.
5. Jalankan ke aplikasi Supabase-mu dan catat hasilnya (bukti konsep pertama).
6. Mulai `expected.json` untuk aplikasi itu (ground truth).

## 15. Keputusan final (tidak dibuka ulang tanpa alasan kuat)

| # | Keputusan | Catatan |
|---|---|---|
| D1 | Lisensi GPL-3.0-or-later | Karena `pglast`; antarmuka `SqlParser` menjaga opsi ganti parser |
| D2 | Nama paket/CLI `vulnfab`, layout `src/vulnfab/` | Ubah lewat rename tunggal bila perlu |
| D3 | Manajer paket `uv`; Python ≥ 3.11 | |
| D4 | Satu matcher berbasis tree-sitter untuk semua bahasa | Rule pola ditulis sebagai snippet dengan metavariable `$X` |
| D5 | Taint bekerja di atas TIR per-bahasa | Titik evaluasi Semgrep-backend setelah WP-5.3 |
| D6 | Rule skema/kondisi tidak boleh `eval` string | Evaluator aman atau fungsi Python teruji |
| D7 | Fingerprint tanpa nomor baris | Lihat `spec.md` |
| D8 | Temuan confidence rendah tersembunyi secara default | `--min-confidence low` untuk menampilkan |
| D9 | Tool tidak pernah mengeksekusi kode target | Termasuk `import`, `eval`, migration |
| D10 | Setiap rule wajib punya test vuln dan safe | CI gagal bila tidak |
| D11 | Ground truth berlabel dan verdict manual sebelum klaim akurasi | Format di `spec.md` |
| D12 | Adaptor eksternal (gitleaks, osv-scanner, Semgrep) opsional | Ada fallback bawaan atau dilewati dengan catatan di laporan |

## 16. Konvensi engineering

- **Alur per paket kerja (WP)**: tulis test dulu (unit atau rule vuln/safe) → implementasi → `uv run ruff check . && uv run mypy && uv run pytest` hijau → centang WP di `work-packages.md` → commit satu WP satu commit (atau beberapa commit kecil) → push. Setiap sesi kerja diakhiri dengan commit dan push.
- **Gerbang CI**: ruff, mypy (strict untuk `core/`), pytest, cek "setiap rule punya test", cek skema rule valid.
- **Tanpa jaringan di test**: test tidak boleh butuh internet. Target lab dikloning oleh skrip terpisah (`benchmarks/fetch_targets.sh`, SHA di-pin di `benchmarks/targets.lock`, direktori `benchmarks/targets/` di-gitignore).
- **Data privat**: migration aplikasi Supabase milikmu disalin ke `benchmarks/labs/private/` (di-gitignore) dan tidak pernah di-commit. Hanya `expected.json` yang sudah dianonimkan yang boleh masuk repo.
- **Snapshot**: e2e membandingkan keluaran JSON ternormalisasi (tanpa timestamp/path absolut) dengan snapshot; perubahan snapshot harus disengaja dan direview di diff.
- **Benchmark**: `uv run python benchmarks/evaluate.py --target <nama>` menghasilkan tabel precision/recall per rule dan tingkat; hasil per milestone disimpan di `benchmarks/results/`.
- **Dependensi baru** harus dicatat di `THIRD_PARTY_LICENSES.md` beserta lisensinya.

## 17. Gate milestone (kriteria angka)

Milestone dianggap selesai hanya jika semua gate terpenuhi dan hasil benchmark disimpan di `benchmarks/results/<milestone>.md`.

**M1 (Supabase + TypeScript)**
- Lab `supabase-vuln`: recall ≥ 90% pada label tingkat A; precision ≥ 90% pada temuan yang sudah di-review; **0 false positive** pada decoy (kode/skema aman).
- Cross-check: setiap akses ke tabel tanpa RLS di lab terdeteksi dengan trace ke migration dan ke baris kode.
- Waktu scan lab < 10 detik; tidak ada crash pada migration yang tidak valid (menghasilkan `Unresolved`, bukan exception).
- Satu aplikasi Supabase nyata (milikmu) dipindai; setiap temuan diberi verdict manual; precision tercatat.

**M2 (Taint)**
- NodeGoat + Juice Shop: recall ≥ 60% pada label SQLi/XSS/command injection yang dalam scope; precision ≥ 75%.
- Tidak ada scan > 60 detik per target; timeout per file bekerja dan dilaporkan.
- Trace lengkap (source → sink) pada ≥ 95% temuan taint.

**M3 (Tiga stack)**
- DVWA + lab Laravel buatan sendiri (PHP) dan django.nV + lab Django buatan sendiri (Python): recall ≥ 60%, precision ≥ 75% pada label dalam scope.
- IDOR tingkat B: recall ≥ 50% pada label, precision ≥ 70% (default confidence medium).
- Kontrak plugin dibekukan; tidak ada perubahan core yang dibutuhkan untuk menambah rule baru.

**M4 (Rilis)**
- Output SARIF valid terhadap skema SARIF 2.1.0; GitHub Action berjalan pada repo contoh.
- Mode diff (`--since`) memberi hasil identik dengan scan penuh pada file yang berubah + dependennya (uji otomatis).
- Dokumentasi: menulis rule, menulis plugin, referensi rule, batasan yang diketahui. `THIRD_PARTY_LICENSES.md` lengkap.
- Tabel precision/recall per rule dipublikasikan; rule di bawah ambang diturunkan confidence-nya atau dihapus.

Ambang precision per severity: critical ≥ 90%, high ≥ 80%, medium ≥ 70%, low/info tanpa ambang (tersembunyi default).

## 18. Tangga pemangkasan scope

Bila pekerjaan tertinggal, potong dari atas ke bawah. Yang **tidak boleh** dipotong: ground truth, test rule, coverage & limitations, tidak mengeksekusi kode target.

1. Fase 11 (DAST, plugin tambahan)
2. Triase LLM
3. Laporan HTML mandiri (JSON, SARIF, console cukup)
4. SCA (Fase 8) dan pemindaian riwayat git
5. Plugin Laravel (M3 menjadi dua stack + Supabase)
6. Taint antar-file (5c); berhenti di 5b
7. IDOR tingkat B di luar Supabase
8. Mode diff/PR

M1 sudah merupakan produk yang berguna; berhenti di sana adalah hasil yang sah.

## 19. Catatan lingkungan pengembangan

- Tersedia: Python 3.11, `uv`, `poetry`, `node` 22, `php`, `git`; `pglast` 8.x dan tree-sitter (Python/JS/TS/PHP) terpasang lewat pip tanpa masalah.
- Target lab (Juice Shop, NodeGoat, DVWA, django.nV, repo Supabase) bisa dikloning dari GitHub.
- **`api.osv.dev` diblokir** (HTTP 403) dari sandbox ini: SCA online tidak bisa diuji di sini; gunakan dump OSV lokal atau lewati dengan catatan.
- gitleaks dan osv-scanner belum terpasang: adaptor harus mendeteksi ketiadaan binary dan menurun ke fallback bawaan.
- `php` tersedia untuk memvalidasi sintaks lab PHP (`php -l`); `node` untuk lab TS.
- Sandbox bersifat sementara: **commit dan push setelah setiap WP**.
