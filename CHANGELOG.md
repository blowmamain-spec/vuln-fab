# Changelog

## Unreleased

- `vulnfab osv update DIR`: download OSV advisories (npm, PyPI, Packagist) for offline SCA; database loading limited to packages present in lockfiles; one finding per advisory; malicious-package advisories are critical.
- JS/TS web coverage: Next.js sources (`request.json()`, `nextUrl.searchParams`, page `searchParams`), browser sources (`location.*`, `document.URL/referrer/cookie`, storage, `event.data`) for XSS/redirect/eval; client redirect sinks (`location.href = …`, `location.assign`, `window.open`, `NextResponse.redirect`, `redirect`, `router.push`); jQuery `.html()`.
- New rules: `tjs-nosqli` (Mongo collections), `tjs-nosqli-odm` (Mongoose/MongoDB models, low confidence, gated on the library import), `tjs-ssti`, `tjs-protopollution`, `js-tls-verify-disabled`, `js-cookie-insecure`, `js-cors-wildcard-credentials`, `js-jwt-insecure`, `env-public-secret`.
- Field feedback (real project, reviewer with repo access): `js-innerhtml-assign` now understands `items.map(x => `...${escapeHtml(x)}...`).join("")`, ternaries and `a || ''`; secrets in git-ignored untracked files are reported at low confidence with an accurate message; `$_FILES[..]['tmp_name']` is not user input; `.vulnfab.yml` accepts `taint: {sanitizers: [...], validators: [...]}` for project-specific helpers.
- SCA: one finding per package (all advisories listed, highest fixed version), `devDependencies` lowered one severity level, direct/transitive labels for package-lock.
- `--format html-triage`: interactive report with filters and TP/FP/DUP verdicts exportable to the `vulnfab triage` file format.
- Taint rules accept `file_matches` (regex on the sink file) to limit a rule to files that use the library it is about.

## 1.0.0

- SCA offline: `sca-known-vuln`, `--osv-db`, `--osv-scanner` (WP-8.2).
- `--history` / `--history-limit`: secrets removed from the tree but still in git history (`sec-secret-history`, WP-8.3).

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

## 0.3.0 (M3: tiga stack)
- Plugin Django: settings/models (tanpa eksekusi), URL→view dengan analisis auth, 15+ rule (settings, view tanpa auth, csrf_exempt, ModelForm, SQL mentah, mark_safe, dispatch), template (`|safe`, autoescape, csrf_token).
- Plugin Laravel: migrations→skema, model Eloquent, rute→entrypoint (grup/middleware/resource), Blade (`{!! !!}`, `@csrf`), rule config/model, mass assignment (taint), IDOR sadar-model.
- Taint: validator, escaper sadar-konteks-kutip, guards kepemilikan, penanda CLEAN, sanitizer hash, sumber/sink Laravel.
- Kontrak plugin 1.0 dibeku; kontrak diuji dengan plugin pihak ketiga minimal.
- Lab Django dan Laravel; ground truth DVWA dan django.nV; gate M3 terpenuhi (`benchmarks/results/m3.md`, termasuk catatan bias).

## Unreleased
- Berikutnya: Fase 8 (scanner pelengkap), 9 (kualitas), 10 (produk).

## Spec
Perubahan pada `docs/spec.md` dicatat di sini.
