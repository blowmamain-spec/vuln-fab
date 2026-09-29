# py-tree-sitter 0.26.0: `Node.start_point`/`end_point` use-after-free

**Keputusan**: pin `tree-sitter>=0.25,<0.26` dan **jangan pernah** membaca `Node.start_point` /
`Node.end_point`. Nomor baris dihitung dari offset byte (`vulnfab.core.parsing.node_lines`).

## Gejala
Scan DVWA penuh menghasilkan 0 temuan (padahal ada `shell_exec('ping ' . $target)`), dan dalam
proses yang sama muncul segfault acak. Nomor baris yang terbaca kadang sampah (mis. 20184 untuk
file 692 baris). Perilaku bergantung tata letak memori: satu file, satu rule, atau
`PYTHONMALLOC=malloc MALLOC_PERTURB_=165` mengubah kapan gejala muncul.

## Diagnosis
1. Hipotesis pertama (buffer sumber pola dibebaskan) **salah**: `Tree` menahan buffer sumber
   (refcount naik saat `parse`).
2. Traversal cursor bukan penyebab (crash tetap dengan traversal berbasis `.children`).
3. `valgrind` melaporkan `Invalid read` pada `PyNumber_Add` untuk `start_point.row + 1`, dengan blok
   yang dialokasikan di `point_new_internal (point.c:8)` dan sudah di-`free`: refcount `PyLong`
   pada objek `Point` salah.
4. `tree-sitter==0.25.2` bersih pada uji yang sama; `0.26.0` gagal.

## Pengamanan
- `pyproject.toml` mem-pin `<0.26`.
- `tests/unit/test_no_point_api.py` gagal bila `start_point`/`end_point` dipakai di `src/`.
- CI menjalankan test suite sekali lagi dengan `MALLOC_PERTURB_=165 PYTHONMALLOC=malloc`.

Tinjau ulang pin ini ketika rilis tree-sitter berikutnya memperbaiki `point.c`.
