# Menulis rule

Rule adalah YAML yang divalidasi (`extra=forbid`); kesalahan menyebut berkas, baris, dan id. Setiap rule **wajib**
punya minimal satu berkas rentan dan satu aman di `tests/rules/<rule-id>/`, dan `vulnfab rules test` harus lulus.

Medan umum: `id` (`prefix-nama`, huruf kecil), `stack`, `kind`, `languages`, `severity`, `confidence`, `tier?`,
`cwe[]`, `owasp?`, `title?`, `message`, `fix?`, `supersedes?`, `tests`, `enabled`.

## Jenis rule

### `pattern` — bentuk sintaks

```yaml
- id: py-eval
  stack: generic
  languages: [python]
  severity: high
  confidence: medium
  cwe: [CWE-95]
  message: "eval() executes arbitrary code."
  pattern: "eval($X)"                 # $X = metavariabel, ... = argumen bebas
  where:
    - {metavariable: X, kind: not_literal}   # literal|not_literal|identifier|regex|unsafe_interpolation ...
  tests: {vulnerable: [vuln.py], safe: [safe.py]}
```

`pattern-either`, `pattern-not`, `pattern-inside`, `pattern-not-inside` tersedia. `unsafe_interpolation` benar bila
string dibangun dengan nilai yang tak terlihat di-escape (template literal, f-string, `%`, `.format`, `+`, PHP `"$x"`).

### `taint` — alur data

```yaml
- id: tpy-sqli
  kind: taint
  stack: generic
  languages: [python]
  sources: ["field *request.GET", "call input"]
  sinks: ["call *.execute arg0"]
  sanitizers: ["call int"]
  validators: ["call re.match"]        # dipakai di kondisi `if` -> operand dianggap tervalidasi
  guards: []                           # bukti kepemilikan (IDOR): fungsi yang memakainya tak dilaporkan
  escapers: ["call mysqli_real_escape_string"]  # aman hanya di dalam literal berkutip
  file_matches: "(?i)mongoose"         # opsional: hanya laporkan sink di berkas yang teksnya cocok regex ini
  supersedes: [py-sql-execute-interp]  # menggantikan rule pola yang sama bila alur terbukti
```

Setiap entri: `<call|field|var|param|assign> <glob> [arg0|argN|args|any|recv|kw:nama]` (pemilih argumen hanya untuk
sink). Glob memakai `*`. `field request.args` juga cocok untuk `request.args.get(...)` dan `request.args['x']`.
`call` mencocokkan nama callee apa adanya (`os.system`, `DB::raw`, `new Function`, `t7.whereRaw` untuk rantai).
Uji dengan `# vuln: <rule-id>` di baris sink pada berkas rentan. Panduan desain: sanitizer membersihkan hasil
panggilan; propagator (`propagators`) meneruskan taint tanpa menurunkan confidence; panggilan tak dikenal tetap
meneruskan taint tetapi menurunkan confidence.

### `schema`, `scanner`, `crosscheck`

- `schema`: `condition` (ekspresi aman, tanpa `eval`) atau `check: "vulnfab.plugins.x.checks:fungsi"` atas model
  skema/konfigurasi milik plugin.
- `scanner`: `scanner: "vulnfab.plugins.x.mod:fungsi"` atas isi berkas (`languages` memilih jenis berkas).
- `crosscheck`: `facts: DataAccess|Entrypoint` + `check:`; `model:` memilih plugin pemilik skema.

Modul `check`/`scanner` harus berada di bawah paket `vulnfab.`.

## Menguji

`tests/rules/<rule-id>/` berisi berkas uji; anotasi `# vuln: <rule-id>` (atau `// vuln:`) pada baris yang harus
dilaporkan — kecocokan dicek tepat (baris + rule) dan berkas `safe` tak boleh menghasilkan temuan rule itu.
Untuk rule yang memerlukan proyek (Django/Laravel) letakkan berkas pendukung di `_repo/` di direktori uji.

```bash
uv run vulnfab rules test --rule tpy-sqli
uv run python scripts/gen_rule_docs.py      # perbarui docs/rules.md (CI memeriksa)
```

## Pedoman

* Preferensi: rule taint bila ada sumber/sink jelas; rule pola hanya untuk bentuk yang pasti berbahaya.
* Rule pola yang hanya berkata "argumen tidak konstan" sebaiknya `supersedes`-kan pasangan taint-nya; alat menurunkan
  confidence-nya bila argumen terbukti hanya konstanta/komputasi murni.
* Jangan menaruh nilai rahasia (bahkan palsu yang mirip asli) di berkas uji.
* Ukur dulu: `benchmarks/run_all.py` mencetak precision per rule; rule di bawah ambang (critical 90%, high 80%,
  medium 70%) harus diperketat, diturunkan confidence-nya, atau dihapus.
