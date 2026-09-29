# S1: pglast pada migration nyata

**Keputusan: GO.** `pglast` layak menjadi fondasi plugin Supabase.

## Uji
57 berkas `.sql` dari repo `supabase/supabase` (`examples/`, `docker/`), sparse checkout dangkal.

| Hasil | Angka |
|---|---|
| Berkas parse penuh (`parse`) | 49 / 57 |
| Statement terparse (`parse_lenient`) | 480 |
| Issue tersisa setelah pemulihan | 12 (semua valid, lihat bawah) |

Statement yang muncul: `CreatePolicyStmt` (84), `CreateStmt`, `AlterTableStmt`, `CreateFunctionStmt`, `GrantStmt`, `AlterDefaultPrivilegesStmt`, `DoStmt`, `CreateTrigStmt`, `IndexStmt`, dll. Semua tipe yang dibutuhkan plugin ada.

## Temuan
1. **Meta-command psql** (`\set`, `\c`) dan variabel psql (`:'pgpass'`) membuat `parse_sql` gagal untuk seluruh berkas (`docker/volumes/db/*.sql`). Ditangani: `strip_psql_meta` mengosongkan baris `\...` (nomor baris tetap), dan pernyataan berisi `:'var'` menjadi `ParseIssue` (bukan crash).
2. **SQL yang memang salah** ada di contoh nyata (`slack-clone/full-schema.sql`: titik koma hilang setelah `using (true)`). Satu statement rusak tidak boleh membuang seluruh berkas: `parse_lenient` memecah per statement (sadar dollar-quote, string, komentar) dan mengurai tiap potongan. Statement yang bergabung dengan statement rusak ikut hilang; itu dicatat sebagai `Unresolved` oleh loader (WP-3.1).
3. **Ekspresi policy** dapat diserialisasi kembali ke teks lewat `pglast.stream.RawStream` dan dikenali polanya. Bentuk yang paling sering di data nyata: `auth.uid() = user_id`, `TRUE`, `auth.role() = 'authenticated'`, `is_project_member(project_id)`, `bucket_id = '…'`. Evaluator akses efektif (WP-3.4) cukup mengenali: literal `true`, `auth.uid() = kolom` (juga `(select auth.uid())`), `auth.role()`, dan sisanya `Unknown`.
4. **Opsi fungsi** tersedia terstruktur (`CreateFunctionStmt.options`: `security`, `language`, `as`, `set`), sehingga `SECURITY DEFINER` dan `SET search_path` bisa dibaca tanpa regex.
5. **Body plpgsql** diparse terpisah lewat `parse_plpgsql`; `PLpgSQL_stmt_dynexecute` muncul untuk `EXECUTE` dinamis.
6. `DoStmt` muncul 5 kali dalam sampel: harus ditandai `Unresolved(do_block)` karena isi DDL-nya tidak dianalisis.

## Implikasi ke rencana
- `SqlParser` mendapat `parse_lenient` (sudah diimplementasikan di WP-0.3a).
- WP-3.1 harus melaporkan `ParseIssue` sebagai `Unresolved` di coverage.
- Tidak ada perubahan pada keputusan D1 (GPLv3, `pglast`).
