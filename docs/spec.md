# Spesifikasi Teknis vulnfab

Kontrak yang dipegang seluruh kode. Perubahan pada dokumen ini harus disengaja dan dicatat di `CHANGELOG` bagian "Spec".

## 1. CLI

```
vulnfab scan <path> [opsi]
vulnfab rules test [--rule ID] [--stack NAME]
vulnfab rules list
vulnfab ast <file> [--lang LANG]          # cetak pohon tree-sitter (debug rule)
vulnfab ir <file>                          # cetak TIR (debug taint)
vulnfab explain <fingerprint|rule_id>
vulnfab triage <fingerprint> --verdict tp|fp|dup [--note TEXT]
vulnfab --version
```

Opsi `scan`:

| Opsi | Default | Keterangan |
|---|---|---|
| `--format` | `console` | `console`, `json`, `sarif`, `html` (boleh diulang) |
| `--output PATH` | stdout | Untuk `json`/`sarif`/`html` |
| `--stack NAME` | auto | Paksa plugin tertentu (boleh diulang) |
| `--min-confidence` | `medium` | `low` menampilkan tier C dan temuan unresolved-heavy |
| `--include-candidates` | off | Sertakan kandidat IDOR tier C |
| `--fail-on SEVERITY` | tidak ada | Exit code 1 bila ada temuan ≥ severity itu |
| `--baseline PATH` | tidak ada | Hanya laporkan temuan yang fingerprint-nya tidak ada di baseline |
| `--write-baseline PATH` | tidak ada | Tulis fingerprint semua temuan saat ini |
| `--since REF` | tidak ada | Mode diff: hanya file berubah + dependen (Fase 10) |
| `--max-file-kb` | 1024 | Lewati file lebih besar |
| `--file-timeout` | 10 | Detik per file per tahap |
| `--schema-dump PATH` | tidak ada | `pg_dump --schema-only` untuk cek drift (Supabase) |
| `--jobs N` | CPU | Paralelisasi |

**Exit code**: `0` sukses tanpa temuan yang memenuhi `--fail-on`; `1` ada temuan ≥ `--fail-on`; `2` kesalahan penggunaan (argumen, rule tidak valid); `3` kesalahan internal. Kegagalan parse satu file **tidak** menghasilkan exit code non-nol; dicatat sebagai `skipped` di coverage.

## 2. Skema output JSON (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "tool": {"name": "vulnfab", "version": "0.1.0"},
  "target": {"path": ".", "stacks": ["supabase", "typescript"]},
  "findings": [ /* Finding */ ],
  "coverage": {
    "files_scanned": 120,
    "files_skipped": [{"file": "x.ts", "reason": "too_large|timeout|parse_error|ignored"}],
    "unresolved": [{"kind": "dynamic_call|dynamic_sql|do_block|import", "file": "…", "line": 10, "detail": "…"}],
    "assumptions": ["schema derived from migrations only (no drift check)"],
    "adapters": [{"name": "gitleaks", "status": "missing|ok|error"}]
  }
}
```

**Finding**

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    cwe: tuple[str, ...]
    owasp: str | None
    severity: Severity            # critical|high|medium|low|info
    confidence: Confidence        # high|medium|low
    tier: Literal["A", "B", "C"] | None
    file: str                     # relatif terhadap root scan, separator "/"
    line: int
    end_line: int
    snippet: str
    trace: tuple[TraceStep, ...]  # source -> ... -> sink; kosong untuk rule pola
    unresolved_hops: int
    fix: str | None
    fingerprint: str
```

`TraceStep(file, line, kind: source|propagate|call|return|sink|schema|policy, detail)`.

## 3. Fingerprint

`sha256` hex (dipotong 32 karakter) dari string dengan pemisah `\x1f`:

1. `rule_id`
2. path relatif file
3. snippet ternormalisasi: token-token kode inti tanpa komentar dan whitespace, string literal dipertahankan
4. nama simbol pembungkus yang dikualifikasi (fungsi/kelas/`table.policy`), atau `""`
5. indeks kemunculan (0, 1, …) dari tiga komponen sebelumnya dalam file yang sama

Nomor baris **tidak** ikut. Test wajib: menyisipkan baris kosong/komentar di atas temuan tidak mengubah fingerprint; mengubah kode temuan mengubahnya.

## 4. Severity, confidence, dan scoring

- `priority = severity_weight × confidence_weight` (critical 5, high 4, medium 3, low 2, info 1; high 1.0, medium 0.7, low 0.4). Dipakai untuk urutan tampilan.
- Penurunan otomatis confidence: setiap `unresolved_hop` pada trace menurunkan satu tingkat (minimum `low`); rule tier B tidak pernah `high`; tier C selalu `info`/`low`.
- Tampilan default: confidence ≥ `medium`. Temuan `info` hanya muncul dengan `--min-confidence low`.
- Dedup: fingerprint sama → satu temuan; temuan dari beberapa rule pada lokasi yang sama tetap dipertahankan bila `rule_id` berbeda, kecuali rule mendeklarasikan `supersedes: [ID]`.

## 5. Intermediate Representation (IR)

```python
@dataclass
class SourceFile: path: str; language: str; text: str; sha256: str

@dataclass
class ParsedUnit:
    files: dict[str, ParsedFile]          # path -> tree-sitter tree + TIR per fungsi
    symbols: SymbolTable                  # nama terkualifikasi -> definisi
    callgraph: CallGraph                  # edge(caller, callee, site) + edge unresolved
    entrypoints: list[Entrypoint]

@dataclass
class Entrypoint: kind: str; file: str; line: int; handler: str; params: list[str]; auth: AuthInfo | None
@dataclass
class DispatchHint: file: str; line: int; targets: list[str]          # resolusi dinamis berbasis konvensi
@dataclass
class DataAccess:
    table: str; schema: str | None; op: Literal["select","insert","update","delete","upsert","rpc"]
    file: str; line: int; filter_columns: list[str]
    client_kind: Literal["anon","user","service_role","unknown"]
@dataclass
class Unresolved: kind: str; file: str; line: int; detail: str
```

**TIR (taint IR)**: per fungsi, daftar instruksi bertipe. Bahasa apa pun harus dinormalisasi ke bentuk ini:

```
Assign(dst, expr)          Call(dst, callee, args, kwargs, site)
Return(expr)               Concat(dst, parts)  # termasuk f-string/interpolasi/template literal
Subscript(dst, base, key)  Attr(dst, base, name)
Branch(cond, then, else)   Loop(body)          Unknown(dst, reason)   # -> unresolved
```

Nilai di TIR: `Var`, `Const(literal)`, `Param(i)`, `Field(base, name)`. Constant propagation berjalan di atas TIR.

**SchemaModel** (netral framework):

```
Table(name, schema, columns[], constraints[], rls_enabled, rls_forced, policies[], grants[])
Column(name, type, nullable, default, unique, sensitive_hint)
Policy(name, table, permissive: bool, command: all|select|insert|update|delete, roles[], using_expr, check_expr)
Function(name, schema, security_definer, search_path, language, body_ast?)
View(name, schema, security_invoker, definition)
Grant(role, object, privileges, with_grant)
DefaultPrivilege(role, schema, object_type, privileges)
Bucket(name, public)
Unresolved(source_file, reason)
```

Semantik akses efektif Supabase (`effective_access(table, role, command) -> Allow | Deny | Conditional(expr) | Unknown`):

1. Tanpa `GRANT` yang berlaku untuk role → `Deny`.
2. RLS nonaktif → `Allow` (sesuai grant).
3. RLS aktif tanpa policy yang berlaku → `Deny`.
4. Policy permissive digabung OR; policy restrictive digabung AND dengan hasilnya.
5. Ekspresi policy dievaluasi konservatif: literal `true` → `Allow`; `auth.uid() = <kolom>` (juga bentuk `(select auth.uid())`) → `Conditional(owner)`; ekspresi lain → `Unknown`.
6. `service_role` selalu melewati RLS.

## 6. Kontrak plugin

```python
class StackPlugin(Protocol):
    name: str
    languages: list[str]
    def detect(self, repo: RepoView) -> Confidence: ...
    def parse(self, files: Iterable[SourceFile]) -> ParsedUnit: ...
    def extract_schema(self, repo: RepoView) -> SchemaModel | None: ...
    def entrypoints(self, unit: ParsedUnit) -> list[Entrypoint]: ...
    def data_access(self, unit: ParsedUnit) -> list[DataAccess]: ...
    def dispatch_hints(self, unit: ParsedUnit) -> list[DispatchHint]: ...
    def templates(self, repo: RepoView) -> list[TemplateUnit]: ...
    def rule_packs(self) -> list[Path]: ...
```

Semua method selain `detect`, `parse`, `rule_packs` boleh mengembalikan daftar kosong/`None`. Penemuan lewat entry point `vulnfab.plugins`. Plugin tidak boleh mengimpor plugin lain. Dibekukan setelah plugin ke-3 (Django).

Antarmuka SQL:

```python
class SqlParser(Protocol):
    def parse(self, sql: str) -> list[Statement]: ...
    def parse_plpgsql(self, sql: str) -> list[PlStatement]: ...
```

Implementasi awal memakai `pglast`; hanya `core/sqlparser.py` yang boleh meng-import `pglast`.

## 7. Skema rule (YAML, divalidasi pydantic)

Field umum: `id` (unik, `^[a-z]+-[a-z0-9-]+$`), `stack`, `kind` (`pattern` default, `taint`, `schema`, `crosscheck`), `languages`, `severity`, `confidence`, `tier?`, `cwe[]`, `owasp?`, `message`, `fix?`, `supersedes?`, `tests`, `enabled` (default true).

- `pattern`: `pattern` (snippet dengan metavariable `$X`, `...` untuk wildcard argumen) atau `patterns: [...]` (semua harus cocok), `pattern-not`, `pattern-inside`, `where: [{metavariable: X, kind: fstring_or_concat|literal|identifier|regex, regex?}]`.
- `taint`: `sources[]`, `sinks[]`, `sanitizers[]`, `propagators[]?` (pola snippet).
- `schema`: `check` (`modul:fungsi` Python teruji) **atau** `condition` (ekspresi aman; hanya akses atribut, perbandingan, `and/or/not`, `in`, literal).
- `crosscheck`: `facts` (`DataAccess`), `check` (`modul:fungsi`).
- `tests.vulnerable[]` dan `tests.safe[]`: path relatif ke `tests/rules/<rule_id>/`. Validator gagal bila kosong.

Rule `pattern` tanpa satu pun file `safe` ditolak. Anotasi pada file uji: komentar `# vuln: <rule_id>` (atau `// vuln:`) pada baris yang harus dilaporkan; harness memeriksa kecocokan tepat (baris + rule) dan bahwa file `safe` tidak menghasilkan temuan rule itu.

## 8. Ground truth dan evaluasi

`benchmarks/truth/<target>.json`:

```json
{
  "target": "supabase-vuln",
  "revision": "…",
  "items": [
    {"id": "T001", "kind": "vulnerable", "file": "supabase/migrations/001.sql",
     "line_start": 12, "line_end": 12, "class": "rls-missing", "cwe": ["CWE-862"],
     "tier": "A", "note": "tabel profiles tanpa RLS"},
    {"id": "D001", "kind": "decoy", "file": "supabase/migrations/002.sql",
     "line_start": 3, "line_end": 20, "class": "rls-missing", "note": "RLS aktif + policy owner"}
  ]
}
```

Pencocokan temuan → label: file sama, rentang baris beririsan (toleransi ±3), dan `class` sama atau CWE beririsan. Temuan yang cocok dengan `vulnerable` = TP; cocok dengan `decoy` = FP; tidak cocok label apa pun = "tak berlabel" dan **wajib di-review**: verdict (`tp|fp|dup`) dicatat di `benchmarks/verdicts/<target>.json`. Gate memakai angka setelah semua temuan tak berlabel punya verdict; sebelum itu evaluator gagal dengan daftar yang belum di-review.

- Recall = TP unik / jumlah label `vulnerable` dalam scope.
- Precision = TP / (TP + FP) atas temuan yang sudah di-review, per rule dan per tier.
- Label di luar scope ditandai `"in_scope": false` dan tidak dihitung dalam recall.

## 9. Batas sumber daya

Default: file ≤ 1 MiB, kedalaman AST ≤ 512, timeout 10 s per file per tahap, kedalaman taint antar-fungsi ≤ 8, iterasi fixpoint loop ≤ 3, jumlah path taint per sink ≤ 50. Pelanggaran → catat di `coverage.files_skipped`/`unresolved`, jangan crash dan jangan berhenti membisu.
