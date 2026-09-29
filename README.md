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
uv run vulnfab scan <path> --format sarif -o r.sarif   # atau json | html
uv run vulnfab scan <path> --fail-on high           # exit code 1 untuk CI
uv run vulnfab scan <path> --since origin/main      # hanya yang terpengaruh perubahan
uv run vulnfab scan <path> --baseline base.json     # hanya temuan baru
uv run vulnfab explain tpy-sqli                     # jelaskan satu rule
uv run vulnfab rules list | rules test
```

Yang dipahami: **Supabase/Postgres** (RLS, policy, grant, fungsi, view, storage, config, drift), **Django**
(settings, model, URL→view + auth, template), **Laravel** (migration, Eloquent, rute, Blade, config),
**TypeScript/JavaScript** (supabase-js, Next.js, edge functions), analisis alur data (SQLi, XSS, command injection,
path traversal, SSRF, deserialisasi, open redirect, IDOR tingkat B) untuk Python/JS/PHP, dan secret.
Setiap laporan memuat bagian *Coverage & limitations*. Hasil terukur: [`benchmarks/results/`](benchmarks/results/).

Panduan: [pemakaian & CI](docs/usage.md) · [referensi rule](docs/rules.md) ·
[menulis rule](docs/writing-rules.md) · [menulis plugin](docs/writing-plugins.md) ·
[batasan](docs/known-limitations.md).

## Pengembangan

```bash
uv sync
uv run vulnfab --version
uv run ruff check . && uv run mypy && uv run pytest
```

## Lisensi

GPL-3.0-or-later (lihat `LICENSE`). Dependensi pihak ketiga: `THIRD_PARTY_LICENSES.md`.
