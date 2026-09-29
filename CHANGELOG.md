# Changelog

## 0.1.0 (M1: Supabase + TypeScript)
- Pipeline: loader, plugin registry, tree-sitter parsing, reporters JSON/console, baseline, nosec, config.
- Rule engine: skema rule (pydantic), evaluator ekspresi aman, matcher snippet, harness test, scoring.
- Plugin Supabase: model skema keadaan-akhir, akses efektif (RLS, policy permissive/restrictive), 15 rule, drift.
- Plugin TypeScript: ekstraksi `DataAccess` supabase-js, 5 rule pola, cross-check `ts-table-no-rls`/`ts-idor-eq-id`.
- Scanner: secret (pola provider + heuristik), `.env` service_role.
- 24 rule generik Python/JS/PHP.
- Bug upstream ditemukan dan dihindari: py-tree-sitter 0.26.0 `Point` use-after-free (lihat docs/decisions).

## Unreleased
- Fase 5 (taint engine) dan seterusnya.

## Spec
Perubahan pada `docs/spec.md` dicatat di sini.
