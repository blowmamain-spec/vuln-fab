# S4/S5: SCA offline dan adaptor eksternal

**Keputusan: GO. Adaptor bersifat opsional** (D12), dengan deteksi ketiadaan binary.

## Ketersediaan di lingkungan pengembangan
| Alat | Status |
|---|---|
| gitleaks 8.18.4 | Binary bisa diunduh dari GitHub Releases dan berjalan (`gitleaks version`). Tidak terpasang secara default |
| osv-scanner 1.9.2 | Binary bisa diunduh dan berjalan. Tidak terpasang secara default |
| `api.osv.dev` | **Diblokir** (koneksi gagal) dari sandbox |
| Dump OSV (`osv-vulnerabilities.storage.googleapis.com/<ekosistem>/all.zip`) | **Bisa diakses** (HTTP 206 pada range request) |

## Implikasi
- **SCA offline** (WP-8.2) dibangun di atas dump OSV per ekosistem (`PyPI`, `npm`, `Packagist`) yang diunduh sekali dan di-cache; tidak memerlukan API online. Adaptor `osv-scanner` opsional untuk pengguna yang memilikinya.
- **Secret** (WP-4.3): detektor regex/entropi bawaan tetap menjadi fallback; adaptor gitleaks dipakai bila ada di PATH. Status adaptor (`missing|ok|error`) selalu muncul di `coverage.adapters`.
- Test tidak boleh butuh jaringan: gunakan dump OSV mini sebagai fixture; unduhan dump nyata hanya di skrip terpisah (`benchmarks/`).
- Binary tidak di-commit ke repo.
