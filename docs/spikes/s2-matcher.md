# S2: matcher snippet + metavariable di atas tree-sitter

**Keputusan: GO. Keputusan D4 dipertahankan** (satu matcher tree-sitter untuk Python, TS/JS, PHP).

Prototipe: [`s2_matcher_proto.py`](s2_matcher_proto.py) (throwaway; versi produksi adalah WP-2.3).

## Pendekatan
1. Pola ditulis sebagai snippet kode di bahasa target. Metavariable `$NAMA` (huruf kapital/angka/underscore) diganti identifier `__MV_NAMA` sebelum pola diparse dengan grammar yang sama; `...` diganti `__ELLIPSIS__`.
2. Pola di-unwrap ke ekspresi tunggal, lalu dicocokkan terhadap setiap node target bertipe sama secara rekursif: tipe node harus sama, leaf dibandingkan teksnya, metavariable mengikat seluruh subpohon target (dengan konsistensi: `$X == $X` hanya cocok jika kedua sisi identik), `...` cocok dengan nol atau lebih saudara (argumen).
3. Komentar dilewati; string dan komentar di kode target tidak memicu kecocokan (`x = 'eval(a)'`, `# eval(a)`).

## Hasil
40/40 kasus: 30 kasus utama (10 per bahasa) + 10 kasus adversarial (jumlah argumen berbeda, prefix objek berbeda, `+=` vs `=`, komentar, literal string, binding metavariable).

## Aturan yang harus dijaga di WP-2.3
- **Konvensi PHP**: metavariable = `$` + huruf kapital saja (`$X`); variabel PHP asli di pola memakai huruf kecil (`$request`). Dokumentasikan; validator rule menolak pola PHP yang ambigu.
- PHP: snippet dibungkus `<?php … ;` sebelum diparse.
- Belum diuji di prototipe (masuk daftar test WP-2.3): `pattern-not`, `pattern-inside`, `where` (kind `fstring_or_concat`, `regex`), pola string interpolasi (`f"..."`, template literal, string PHP ber-`"…$x…"`), JSX/TSX (`dangerouslySetInnerHTML`), keyword argument yang urutannya berbeda, dan decorator.
- Untuk TSX gunakan grammar `tsx`, bukan `typescript`.
