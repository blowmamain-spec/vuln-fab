# Changelog

## 0.1.0 (M1: Supabase + TypeScript)
- Pipeline: loader, plugin registry, tree-sitter parsing, reporters JSON/console, baseline, nosec, config.
- Rule engine: skema rule (pydantic), evaluator ekspresi aman, matcher snippet, harness test, scoring.
- Plugin Supabase: model skema keadaan-akhir, akses efektif (RLS, policy permissive/restrictive), 15 rule, drift.
- Plugin TypeScript: ekstraksi `DataAccess` supabase-js, 5 rule pola, cross-check `ts-table-no-rls`/`ts-idor-eq-id`.
- Scanner: secret (pola provider + heuristik), `.env` service_role.
- 24 rule generik Python/JS/PHP.
- Bug upstream ditemukan dan dihindari: py-tree-sitter 0.26.0 `Point` use-after-free (lihat docs/decisions).

## 0.2.0 (M2: taint analysis)
- TIR (WP-5.1) dan taint engine intra-fungsi (WP-5.2/5.3): DSL source/sink/sanitizer/propagator, rule `kind: taint` (tpy-sqli, tpy-cmdi, tjs-sqli), trace + hop `unresolved`.
- Ringkasan fungsi intra-file (WP-5.4): param→return, param→sink, source→return; rekursi aman.
- Taint antar-file (WP-5.5): resolusi import Python (absolut/relatif) dan JS/TS (ES import, alias `@/`, `require`, `exports.x`); PHP menyusul di fase Laravel.
- Batas kerja taint + laporan pemotongan di coverage (WP-5.6).
- 25 rule taint (WP-5.7): sqli, cmdi, codei, pathtrav, ssrf, deser, xss, redirect (+ ssti Python) untuk Python/JS-TS/PHP; menggantikan (supersedes) rule pola sejenis bila alirannya terbukti. Rule pola `ts-cmd-injection` tetap sebagai fallback tanpa aliran.
- IDOR tier B via taint + *guards* kepemilikan (WP-5.8): `tpy-idor`, `tjs-idor`, `tphp-idor`.
- *Validator* pada rule taint (cek di dalam `if` membersihkan operand), `throw`/`raise` sebagai jalur berhenti, semantik `map.get`.
- Rule `js-xss` (Angular `bypassSecurityTrust*`).
- Gate M2 terpenuhi pada Juice Shop dan NodeGoat; lihat `benchmarks/results/m2.md` (termasuk catatan bias).

## Unreleased
- Berikutnya: Fase 6 (Django) dan Fase 7 (Laravel).

## Spec
Perubahan pada `docs/spec.md` dicatat di sini.
