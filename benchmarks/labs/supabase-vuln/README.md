# Lab: supabase-vuln

Aplikasi Supabase + Next.js **sengaja rentan** untuk menguji vulnfab. Jangan gunakan sebagai contoh kode.
Semua kunci/kata sandi di sini palsu.

Baris berpenanda `@lab` adalah ground truth yang ditulis pembuat lab:

```
-- @lab <vuln|decoy> <kelas> [cwe=CWE-x,..] [tier=A|B|C] [lines=N] [in_scope=false] :: catatan
```

Penanda berlaku untuk `N` baris (default 1) mulai baris pertama setelah rangkaian penanda.
`decoy` = kode/skema aman yang tidak boleh dilaporkan untuk kelas itu.
`benchmarks/labs/truth_from_markers.py` menghasilkan `benchmarks/truth/supabase-vuln.json`.
