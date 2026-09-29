# vulnfab

Scanner statis (SAST) multi-stack untuk aplikasi web: **Supabase/Postgres, Django, Laravel, TypeScript**.
Satu engine inti, banyak plugin. Tidak pernah mengeksekusi kode target.

Status: dalam pengembangan awal. Lihat [`docs/`](docs/):

- [`docs/rencana-sast-multistack-v3.md`](docs/rencana-sast-multistack-v3.md): strategi dan keputusan
- [`docs/spec.md`](docs/spec.md): kontrak teknis
- [`docs/work-packages.md`](docs/work-packages.md): paket kerja dan progres

## Pemakaian

```bash
uv run vulnfab scan <path>                          # laporan di terminal
uv run vulnfab scan <path> --format json -o out.json
uv run vulnfab scan <path> --min-confidence low     # tampilkan juga temuan berconfidence rendah
uv run vulnfab scan <path> --fail-on high           # exit code 1 untuk CI
uv run vulnfab scan <path> --schema-dump live.sql   # bandingkan migration dengan pg_dump database
uv run vulnfab scan <path> --baseline base.json     # hanya temuan baru
uv run vulnfab rules list | rules test
```

Yang dipahami saat ini: **Supabase/Postgres** (RLS, policy, grant, fungsi, view, storage,
config.toml, seed, drift), **TypeScript/JavaScript** (supabase-js, Next.js, edge functions),
rule generik Python/JS/PHP, dan secret. Setiap laporan memuat bagian *Coverage & limitations*
yang menyebut apa yang tidak dianalisis. Hasil terukur ada di
[`benchmarks/results/`](benchmarks/results/).

## Pengembangan

```bash
uv sync
uv run vulnfab --version
uv run ruff check . && uv run mypy && uv run pytest
```

## Lisensi

GPL-3.0-or-later (lihat `LICENSE`). Dependensi pihak ketiga: `THIRD_PARTY_LICENSES.md`.
