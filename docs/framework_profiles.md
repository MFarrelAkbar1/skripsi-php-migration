# Profil Framework (CI3 dan Laravel)

> Status: sudah diimplementasikan dan diuji pada aplikasi dummy. Belum diuji pada aplikasi
> Laravel sungguhan. Tanpa flag, pipeline tetap memakai profil CI3.

## 1. Cara pakai

```bash
python pipeline/main.py --framework laravel --target-laravel 12 --target-php 8.2 --input <folder>
```

- `--framework`: `ci3` (default) atau `laravel`.
- `--target-laravel`: versi major tujuan. Jika dikosongkan, aturan upgrade Laravel tidak dijalankan.
- Sumber yang didukung: Laravel 6 sampai 8. Versi 9 ke atas tetap berjalan dengan peringatan,
  dan 5.x ditolak.
- Jangan menaruh aplikasi di dalam folder `tests/`, karena Semgrep mengabaikannya secara
  default dan melaporkan 0 file. `tests/sample_laravel/` perlu disalin ke luar `tests/` dulu.

## 2. Prinsip

1. **Tanpa flag, perilaku tidak berubah.**
2. **Profil hanya berisi data.** Modul pipeline tidak bercabang berdasarkan nama framework.
3. **Tetap analisis statis.** Kode aplikasi dan kode paket tidak dijalankan, dan kode aplikasi
   tidak dikirim ke layanan luar.

## 3. Struktur

| File | Isi |
|---|---|
| `pipeline/profiles.py` | `FrameworkProfile`, profil `CI3` dan `LARAVEL`, `resolve_framework_run()` |
| `pipeline/laravel_version.py` | Deteksi versi, set Rector, validasi target, unduhan sumber Laravel |
| `rules_frameworks/laravel/` | Rule Semgrep Laravel, sengaja di luar `rules/` |
| `tests/test_profiles.py` | Uji regresi CI3 dan uji Laravel |
| `tests/fixtures/ci3_baseline.json` | Rekaman output CI3 dari kode sebelum profil ditambahkan |
| `tests/sample_laravel/` | Aplikasi dummy, tanpa data UGM |
| `.cache/laravel_sources/` | Sumber Laravel per major, tidak masuk git |

`FrameworkProfile` berlaku tetap untuk satu framework. `FrameworkRun` menambahkan nilai yang
bergantung pada aplikasi, yaitu versi, target, set Rector, dan lokasi sumber Laravel.

## 4. Keputusan dan buktinya

Diperiksa pada 2026-11-07.

| Temuan | Keputusan |
|---|---|
| Dataset MCK dijalankan pada `mck/application/` tanpa `system/`, jadi deteksi otomatis bisa gagal | Default `ci3`, dengan peringatan jika ada file `artisan` |
| Filter CI3 seperti `::$input.` dan `Google\\` bisa menyembunyikan error asli di Laravel | Laravel memakai regex yang hanya cocok dengan simbol yang hilang |
| Semgrep memuat `rules/` secara rekursif | Rule Laravel berada di `rules_frameworks/` |
| `rector-laravel` terbaru butuh Rector yang lebih baru | Dikunci di `2.5.*`, yang cocok dengan Rector 2.3.8. Rector tidak dinaikkan |
| Set versi `rector-laravel` deprecated di versi terbaru, tetapi tidak di 2.5.0. Penggantinya membaca `vendor/` aplikasi | Pakai set per versi, misalnya `LARAVEL_90` |
| Tanpa kelas `Illuminate`, Rector berhenti dengan system error dan aturan Laravel tidak berjalan | Sumber Laravel diunduh sebagai referensi simbol |
| Memindai seluruh `vendor/` membuat worker Rector timeout | Rector hanya membaca `laravel/framework/src/Illuminate`. PHPStan membaca seluruh `vendor/` |
| Larastan menjalankan bootstrap aplikasi, dan versi terbarunya menarik Laravel ke `vendor/` pipeline | Larastan tidak dipakai |

## 5. Sumber Laravel

- Diunduh saat pertama dipakai dengan `--no-scripts --no-plugins`, jadi tidak ada kode paket yang
  dijalankan. Kode aplikasi tidak ikut terkirim.
- Versi yang diunduh adalah versi target, karena set Rector versi baru membutuhkan kelas yang
  belum ada di versi lama. Contohnya, set Laravel 9 membutuhkan `Factory` dari Laravel 8.
- Jika unduhan gagal, pipeline berhenti ketika upgrade diminta. Tanpa upgrade, pipeline hanya
  memberi peringatan.

### Security advisory

Composer 2.9.5 memblokir versi Laravel yang punya security advisory, dan pada 2026-11-07 ini
berlaku untuk Laravel 8, 9, 10, dan 11. Laravel 12 dan 13 tidak diblokir.

Sumber di cache hanya dibaca, sehingga unduhannya memakai `--no-security-blocking`. Pipeline lalu
menampilkan peringatan, karena aplikasinya sendiri tidak aman jika memakai versi tersebut. Pilih
target 12 atau 13 kecuali ada alasan khusus.

## 6. Versi Laravel dan PHP

Constraint Packagist untuk `laravel/framework`:

| Laravel | PHP | Catatan |
|---|---|---|
| 5.8 | `^7.1.3` | Tidak bisa PHP 8, ditolak sebagai sumber |
| 6 | `^7.2.5\|^8.0` | Menerima PHP 8 mulai 6.20 |
| 7 | `^7.2.5\|^8.0` | Menerima PHP 8 mulai 7.29 |
| 8 | `^7.3\|^8.0` | Menerima PHP 8 mulai 8.12 |
| 9 | `^8.0.2` | |
| 10 | `^8.1` | |
| 11, 12 | `^8.2` | |
| 13 | `^8.3` | |

Constraint hanya menunjukkan batas minimum. `^8.0` tidak menjamin aplikasi berjalan baik di PHP
8.3, sehingga pipeline memberi peringatan dan tidak memilih target secara otomatis.

## 7. Rule Semgrep Laravel

| Rule | Mendeteksi | Kategori |
|---|---|---|
| `laravel-raw-query-concat-sql-injection` | Penggabungan string pada `DB::select`, `whereRaw`, dan sejenisnya | SQL Injection |
| `laravel-blade-raw-output-xss` | `{!! ... !!}` | XSS |
| `laravel-mass-assignment-empty-guarded` | `protected $guarded = []` | Mass Assignment |
| `laravel-mass-assignment-request-all` | `create`, `update`, `fill` dengan `$request->all()` | Mass Assignment |
| `laravel-env-outside-config` | `env()` di luar `config/` | Other |
| `laravel-debug-enabled` | `'debug' => true` di `config/app.php` | Other |

Mass Assignment berprioritas 3, jadi ikut dikirim ke AI. `scanner.py` memberi kategori dari kata
kunci pada `rule_id` dan pesan, sehingga rule baru harus menghindari kata seperti `auth`, `token`,
`include`, dan `require`.

## 8. Hasil pengujian

**Uji otomatis:** jalankan `python -m pytest tests/test_profiles.py -q`.

**Regresi CI3, kode lama dibanding kode baru pada `tests/sample_php74`:**

- File hasil konversi identik.
- Ringkasan konversi, ringkasan PHPStan, dan pesan error PHPStan sama.
- `rector.php`, perintah Semgrep, prompt AI, dan filter noise sama dengan rekaman.
- Jumlah temuan Semgrep tidak bisa dibandingkan langsung. Perintah yang sama dan kode yang sama
  memberi 7, 10, 10, dan 10 temuan pada empat kali jalan, jadi yang dibandingkan adalah perintahnya.

**Regresi CI3, kode lama (commit `5a405f1`) dibanding kode baru pada MCK dan CBT, 2026-11-07:**

| | MCK lama | MCK baru | CBT lama | CBT baru |
|---|---|---|---|---|
| Total file | 245 | 245 | 326 | 326 |
| Converted / skipped / failed | 239 / 4 / 2 | 239 / 4 / 2 | 299 / 25 / 2 | 299 / 25 / 2 |
| Error PHPStan | 2758 | 2758 | 2340 | 2340 |
| Noise tersaring | 386 | 386 | 333 | 333 |
| Semgrep pre / post | 11 / 11 | 11 / 11 | 11 / 11 | 11 / 11 |

- Semua file hasil konversi identik sampai ke byte-nya, yaitu 245 file MCK dan 326 file CBT.
- `pipeline_result` hanya berbeda pada path folder `rules` dan key baru `framework`. `iso_report`
  sama setelah stempel waktu dan path diabaikan.
- Log kini punya baris `Framework : ci3`, dan teks `+4 quality sets` menjadi `+4 other sets`.
- Yang dibandingkan pada PHPStan adalah jumlah error per severity dan per kontrol ISO, bukan isi
  tiap pesan, karena laporan tidak menyimpannya.
- Langkah AI dilewati dengan `--skip-ai`. Kesamaan prompt diperiksa terpisah lewat rekaman di
  `tests/fixtures/ci3_baseline.json`.
- Laporan tersimpan di `reports/regresi_mck` dan `reports/regresi_cbt`, dan laporan kode lama ada
  di subfolder `kode_lama`. Folder ini tidak masuk git.

Perintah untuk kode baru, dan perintah yang sama untuk kode lama dari worktree commit `5a405f1`:

```bash
python pipeline/main.py --input "C:\Users\HP VICTUS\Documents\GitHub\mck" --output output/regresi_mck --reports reports/regresi_mck --target-php 8.3 --phpstan-level 5 --exclude validation --skip-ai
python pipeline/main.py --input "C:\Users\HP VICTUS\Documents\GitHub\cbt" --output output/regresi_cbt --reports reports/regresi_cbt --target-php 8.3 --phpstan-level 5 --exclude tcpdf libraries PHPExcel vendor --skip-ai
```

Pada MCK, `--exclude validation` diperlukan. Tanpa flag ini ikut terbaca 24 file tambahan, dan
laporan `mck_qwen_rerun` yang berisi 269 file hanya menghasilkan 12 error PHPStan dari 1 file.

**Temuan yang tidak disebabkan oleh profil, karena muncul juga pada kode lama:**

1. **Angka PHPStan berbeda dari laporan `mck_qwen` dan `cbt_qwen`.** MCK berubah dari 2790 menjadi
   2758, dan CBT dari 2354 menjadi 2340. Penyebab utamanya perubahan filter noise pada commit
   `831ca0f`. Total error ditambah noise pada MCK tetap 3144, sedangkan pada CBT berubah dari 2672
   menjadi 2673, dan selisih 1 ini belum ditelusuri.
2. **Rector kadang timeout pada MCK.** Run 2026-11-07 menampilkan `Child process timed out after
   120 seconds` dan `Reached system errors count limit of 50, exiting...`. Run ulang 2026-11-08
   tidak menampilkan pesan itu, tetapi hasilnya identik sampai ke byte-nya, jadi timeout ini tidak
   mengubah output.
3. **Empat file berbeda dari output lama, dengan line ending diabaikan.** Run 2026-11-07 dan run
   ulang 2026-11-08 menghasilkan output yang sama persis (folder `regresi_*_ulang`), jadi
   perbedaannya konsisten dan bukan hasil acak satu run.

   | File | Output lama | Output sekarang | Penilaian |
   |---|---|---|---|
   | MCK `application/controllers/Indikator.php` | Menambah 8 deklarasi properti seperti `public $m_indikator` | Tidak menambahkannya | Output lama lebih baik. CI 3.1.11 tidak memakai `#[AllowDynamicProperties]`, jadi properti dinamis memicu deprecation di PHP 8.2 ke atas |
   | CBT `system/core/Security.php` | Tidak ada cast | `(string)` pada `rawurldecode` dan dua `preg_replace_callback` | Output sekarang lebih baik untuk deprecation `null` di PHP 8.1 |
   | CBT `system/core/Utf8.php` | Return type `string\|array\|null` pada `safe_ascii_for_xml` | Tanpa return type | Netral, keduanya berjalan |
   | CBT `system/database/drivers/postgre/postgre_result.php` | `_fetch_assoc(): array` | `_fetch_assoc(): array\|false`, ditambah perubahan format docblock | Output sekarang lebih baik, karena `pg_fetch_assoc` mengembalikan `false` saat baris habis dan `array` akan memicu `TypeError` |

   Yang sudah dipastikan sama antara run lama dan run sekarang: versi Rector (2.3.8) dan PHPStan
   (2.1.40), `converter.py` (terakhir diubah 2026-05-09), level set yang dipakai, isi dataset
   (commit terakhir MCK 2025-12-30 dan CBT 2026-05-07), dan jumlah file. Output lama juga ditulis
   saat run-nya sendiri, tidak diubah sesudahnya. Penyebabnya belum diketahui. Dilihat dari bentuk
   perubahannya, rule yang terlibat kemungkinan `CompleteDynamicPropertiesRector`,
   `NullToStrictStringFuncCallArgRector`, dan rule return type, yang semuanya bergantung pada
   inferensi tipe. Log Rector tidak mencatat nama rule per file, jadi ini belum dipastikan.

**Laravel, pada aplikasi dummy:**

- Sumber Laravel 8 ke target 10 dan 12, serta sumber Laravel 6 ke target 12, selesai tanpa error
  Rector.
- Aturan Laravel berjalan. Contohnya `$dates` menjadi `$casts`, dan accessor menjadi `Attribute`.
- Seluruh 6 rule Semgrep mendeteksi contohnya, dan `{{ }}` tidak ikut terdeteksi.
- PHPStan tetap melaporkan variabel tak terdefinisi dan tipe argumen yang salah.
- Kombinasi versi yang mustahil berhenti sebelum `output/` dibersihkan.

## 9. Batasan

1. **Belum diuji pada aplikasi sungguhan.** Aplikasi dummy hanya berisi 5 file PHP, jadi waktu
   proses dan akurasi filter pada aplikasi besar belum diketahui.
2. **`output/` belum bisa langsung dijalankan.** Pipeline tidak menjalankan `composer update`,
   tidak menyalin file selain `.php`, dan tidak mengubah `composer.json`.
3. **Rector tidak menyelesaikan seluruh upgrade.** Perubahan config, middleware, dan struktur
   folder tetap perlu ditangani manual.
4. **Paket pihak ketiga tidak terlihat.** PHPStan hanya melihat Laravel dan dependensinya. Error
   dari paket lain seperti Spatie tetap muncul sebagai kelas tidak ditemukan.
5. **Daftar metode Eloquent ditulis manual.** Metode yang diteruskan Eloquent tetapi tidak ada di
   daftar `_ELOQUENT_FORWARDED` tetap dilaporkan sebagai error, dan nama yang sama pada kelas
   `App\` non-model ikut tersaring.
6. **`TYPE_DECLARATION` dimatikan untuk Laravel.** Set ini perlu diuji pada aplikasi sungguhan
   sebelum diaktifkan.
7. **Konteks Laravel belum masuk ke `--compare-all`.** Mode perbandingan LLM sengaja tidak diubah
   agar prompt eksperimen tetap sama.
8. **File `.env` tidak dipindai,** karena Semgrep dibatasi `--include *.php`.
