# Lisensi pihak ketiga

Proyek ini berlisensi GPL-3.0-or-later. Dependensi runtime:

| Paket | Lisensi | Catatan |
|---|---|---|
| pglast | GPL-3.0-or-later | Alasan proyek ini GPL. Hanya di-import dari `core/sqlparser.py` |
| tree-sitter (+ grammar python/javascript/typescript/php) | MIT | Pin versi |
| pydantic | MIT | |
| PyYAML | MIT | |
| typer | MIT | |
| rich | MIT | |

Verifikasi ulang lisensi setiap kali dependensi ditambahkan atau versi mayor berubah.

## Artefak yang disalin ke repositori

| Berkas | Sumber | Catatan |
|---|---|---|
| `docs/schema/sarif-schema-2.1.0.json` | OASIS SARIF TC (`oasis-tcs/sarif-spec`) | Skema resmi SARIF 2.1.0, dipakai hanya untuk validasi uji offline; tidak dikirim di wheel |
