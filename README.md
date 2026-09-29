# vulnfab

Scanner statis (SAST) multi-stack untuk aplikasi web: **Supabase/Postgres, Django, Laravel, TypeScript**.
Satu engine inti, banyak plugin. Tidak pernah mengeksekusi kode target.

Status: dalam pengembangan awal. Lihat [`docs/`](docs/):

- [`docs/rencana-sast-multistack-v3.md`](docs/rencana-sast-multistack-v3.md): strategi dan keputusan
- [`docs/spec.md`](docs/spec.md): kontrak teknis
- [`docs/work-packages.md`](docs/work-packages.md): paket kerja dan progres

## Pengembangan

```bash
uv sync
uv run vulnfab --version
uv run ruff check . && uv run mypy && uv run pytest
```

## Lisensi

GPL-3.0-or-later (lihat `LICENSE`). Dependensi pihak ketiga: `THIRD_PARTY_LICENSES.md`.
