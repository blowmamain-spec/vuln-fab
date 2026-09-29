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
- TIR (WP-5.1) dan taint engine intra-fungsi (WP-5.2/5.3): DSL source/sink/sanitizer/propagator, rule `kind: taint` (tpy-sqli, tpy-cmdi, tjs-sqli), trace + hop `unresolved`.
- Ringkasan fungsi intra-file (WP-5.4): param→return, param→sink, source→return; rekursi aman.
- Taint antar-file (WP-5.5): resolusi import Python (absolut/relatif) dan JS/TS (ES import, alias `@/`, `require`, `exports.x`); PHP menyusul di fase Laravel.
- Berikutnya: batas/robustness (5.6), rule taint (5.7).

## Spec
Perubahan pada `docs/spec.md` dicatat di sini.
