# Menulis plugin stack

Kontrak plugin **1.0 dibekukan** (`docs/decisions/plugin-contract-freeze.md`). Plugin baru tidak perlu mengubah core.
Contoh minimal yang hanya memakai kontrak publik: `tests/unit/test_plugin_contract.py`.

## Kontrak

```python
class StackPlugin(Protocol):
    name: str
    languages: list[str]
    def detect(self, repo) -> Confidence                # seberapa yakin ini proyek stack tsb
    def parse(self, files) -> ParsedUnit                # berkas bahasa milik plugin
    def extract_schema(self, repo) -> SchemaModel | None
    def entrypoints(self, unit) -> list[Entrypoint]     # rute/view + status auth
    def data_access(self, unit) -> list[DataAccess]
    def dispatch_hints(self, unit) -> list[DispatchHint]
    def templates(self, repo) -> list[TemplateUnit]
    def rule_packs(self) -> list[Path]                  # direktori YAML rule
```

Semua method selain `detect`, `parse`, `rule_packs` boleh mengembalikan daftar kosong/`None`. Hook opsional
(dicari lewat `getattr`): `fixture_path(filename)` (tempat berkas uji di repo fixture), `attach_drift(...)`,
`refine(raw_findings, model)` (sesuaikan temuan memakai model skema plugin).

Aturan: plugin tidak boleh mengimpor plugin lain; hanya `core/sqlparser.py` dan `plugins/supabase/` yang boleh
mengimpor `pglast`; tidak pernah mengeksekusi kode target (baca `ast`/tree-sitter saja).

## Mendaftar

Plugin bawaan didaftarkan di `plugins/registry.py`. Paket pihak ketiga memakai entry point:

```toml
[project.entry-points."vulnfab.plugins"]
mystack = "mypkg.plugin:MyPlugin"
```

## Alur kerja yang disarankan

1. `detect` + `parse` (mulai dari yang sederhana), rule pack minimal dengan uji.
2. `extract_schema` bila stack punya model data (model ORM, migration) — isi `SchemaModel` (tabel, kolom,
   `references`, `extras`) dan `configs` untuk konfigurasi.
3. `entrypoints` (rute → handler + `AuthInfo` + `traits`) supaya rule `crosscheck` bisa menilai "rute tanpa auth".
4. Rule taint memakai sumber/sink stack; tambahkan `guards`/`validators` bila framework punya idiom kepemilikan/validasi.
5. Lab kecil berpenanda `@lab` di `benchmarks/labs/<nama>` dan skrip label untuk target nyata; jalankan
   `benchmarks/run_all.py`.

Contoh nyata: `plugins/django` (settings/models via `ast`, URL → view, template), `plugins/laravel` (migration,
rute, Blade), `plugins/supabase` (migration SQL → model akses efektif).
