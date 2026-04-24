# PHP Legacy Migration Pipeline - Skripsi Muhammad Farrel Akbar

Sistem Otomatis Migrasi Kode PHP 7.4 ke PHP 8.x dengan Kerangka Keamanan ISO/IEC 27001:2022

---

## Deskripsi Proyek

Penelitian skripsi ini mengembangkan **pipeline otomatis** untuk migrasi kode PHP legacy (PHP 7.4) ke PHP 8.x modern dengan fokus pada **keamanan dan kepatuhan ISO/IEC 27001:2022**. 

### Tujuan Utama
- Mengotomatisasi konversi kode PHP 7.4 -> PHP 8.x menggunakan Rector
- Mengidentifikasi kerentanan keamanan dengan Semgrep dan analisis statis
- Memberikan rekomendasi perbaikan berbasis AI (DeepSeek Coder 6.7B)
- Memetakan temuan ke kontrol keamanan ISO/IEC 27001:2022
- Memastikan privasi data dengan menjalankan AI model secara lokal (Ollama)

### Studi Kasus
Kolaborasi dengan **DTI UGM** - migrasi aplikasi web PHP 7.4 legacy ke PHP 8.x dengan standar keamanan tinggi.

---

## Stack Teknologi

| Komponen | Teknologi | Versi | Fungsi |
|----------|-----------|-------|--------|
| AI Model | DeepSeek Coder via Ollama | 6.7B | Rekomendasi perbaikan kode |
| Code Conversion | Rector | v2.3+ | Migrasi PHP 7.4 -> PHP 8.x otomatis |
| Static Analysis | PHPStan / Psalm | v2.1+ | Validasi tipe, error detection |
| Security Scanning | Semgrep | latest | Deteksi kerentanan (SQL Injection, XSS) |
| Backend Pipeline | Python | 3.11+ | Orkestrasi keseluruhan pipeline |
| Output Formatting | Rich (Python) | v13.0+ | Terminal UI yang user-friendly |
| PHP Runtime | PHP | 8.0+ | Untuk menjalankan Rector |

---

## Instalasi Cepat

```bash
# Clone repository
git clone https://github.com/<org>/skripsi-php-migration.git
cd skripsi-php-migration

# Install Python dependencies
pip install -r requirements.txt

# Install PHP tools (Rector, PHPStan)
composer install

# (Opsional) Setup Ollama untuk AI step
ollama pull deepseek-coder:6.7b
ollama serve  # jalankan di terminal terpisah

# Jalankan pipeline
python pipeline/main.py --input tests/sample_php74
```

---

## Cara Menggunakan Pipeline

### Usage Dasar
```bash
python pipeline/main.py --input tests/sample_php74
```

### Dengan Custom Input Folder
```bash
python pipeline/main.py --input path/to/your/php74/code
```

### Command-Line Arguments
```bash
python pipeline/main.py \
  --input <path>        # Wajib: folder input PHP 7.4
  --output output/      # Folder output (default: output/)
  --reports reports/    # Folder reports (default: reports/)
  --skip-ai             # Skip step 5 (AI review) untuk cepat
  --verbose             # Verbose logging untuk debug
```

---

## Alur Kerja Pipeline (6 Steps)

Pipeline berjalan dengan urutan 6 langkah:

```
INPUT (input/)
   |
   v
[STEP 1: PRE-SCAN]   Semgrep scan kode asli (PHP 7.4)
   |
   v
[STEP 2: CONVERT]    Rector konversi PHP 7.4 -> PHP 8.x
   |
   v
OUTPUT (output/)     Kode PHP 8.x hasil konversi
   |
   v
[STEP 3: POST-SCAN]  Semgrep scan kode hasil konversi
   |
   v
[STEP 4: ANALYZE]    PHPStan static analysis & type checking
   |
   v
[STEP 5: AI REVIEW]  DeepSeek Coder rekomendasi perbaikan
   |
   v
[STEP 6: ISO MAP]    Pemetaan ke kontrol ISO 27001:2022
   |
   v
REPORTS (reports/)   iso_report.json + pipeline_result.json
```

### Detail Setiap Step

**STEP 1: PRE-SCAN (Semgrep)**
- Input: Folder input/ dengan PHP 7.4 asli
- Tool: Semgrep dengan ruleset p/php + p/owasp-top-ten
- Output: Daftar kerentanan sebelum konversi

**STEP 2: CONVERT (Rector)**
- Input: Kode PHP 7.4 dari input/
- Tool: Rector dengan target PHP 8.0+
- Output: Kode PHP 8.x di folder output/
- Transformasi: mysql_* -> mysqli, modern syntax, type hints

**STEP 3: POST-SCAN (Semgrep)**
- Input: Kode PHP 8.x hasil Rector
- Output: Daftar issue yang tersisa setelah konversi
- Tujuan: Verifikasi tidak ada kerentanan baru

**STEP 4: ANALYZE (PHPStan)**
- Input: Kode PHP 8.x dari output/
- Tool: PHPStan level 8 (strictness maksimum)
- Output: Laporan validasi tipe, method existence, dead code

**STEP 5: AI REVIEW (Ollama + DeepSeek Coder)**
- Input: Issues dari Step 3 & 4
- Output: AIRecommendation objects dengan patch suggestions

**STEP 6: ISO MAPPING**
- Input: Semua findings
- Output: JSON report dengan status COMPLIANT / PARTIAL / NON_COMPLIANT

---

## Output yang Dihasilkan

### 1. Folder output/ - Kode PHP 8.x Hasil Konversi

Kode PHP 8.x siap untuk code review dan testing:
- Kompatibel PHP 8.0+
- Deprecated functions sudah diganti
- Modern syntax (union types, nullsafe operator, property promotion)

### 2. Folder reports/ - Laporan Hasil Pipeline

**iso_report.json** - Laporan ISO 27001:2022
```json
{
  "overall_status": "COMPLIANT",
  "findings_summary": { "total": 8, "resolved": 6 },
  "control_mapping": {
    "A.8.25": "COMPLIANT",
    "A.8.28": "COMPLIANT"
  }
}
```

**pipeline_result.json** - Detail setiap stage dengan status success/failed

---

## Struktur Folder Proyek

```
skripsi-php-migration/
├── CLAUDE.md                # Aturan wajib dan konteks
├── README.md                # File ini
├── requirements.txt         # Python dependencies
├── composer.json            # PHP dependencies
├── pipeline/                # Core pipeline modules
│   ├── main.py              # Entry point & orkestrasi
│   ├── scanner.py           # Semgrep scanning
│   ├── converter.py         # Rector conversion
│   ├── analyzer.py          # PHPStan analysis
│   ├── ai_engine.py         # Ollama/DeepSeek integration
│   └── iso_mapper.py        # ISO 27001 mapping
├── input/                   # PHP 7.4 files (input)
├── output/                  # PHP 8.x files (Rector output)
├── reports/                 # JSON reports hasil pipeline
├── tests/sample_php74/      # Sample files untuk testing
├── docs/                    # Dokumentasi (architecture, ISO controls)
└── vendor/                  # Composer packages (Rector, PHPStan)
```

---

## Pola Kerentanan yang Diprioritaskan

Pipeline deteksi kerentanan sesuai OWASP Top 10:

| Priority | Jenis | Solusi |
|----------|-------|--------|
| 1 | SQL Injection | Prepared statements |
| 2 | XSS | htmlspecialchars() |
| 3 | Deprecated Functions | Modern API |
| 4 | Hardcoded Credentials | Environment variables |
| 5 | Path Traversal | Input validation |
| 6 | Weak Cryptography | password_hash(), bcrypt |
| 7 | No Input Validation | Filter & sanitize |
| 8 | Missing Authentication | Auth checks |

---

## Reproducibility — Local Semgrep Rulesets

Secara default, Semgrep mengunduh ruleset `p/php` dan `p/owasp-top-ten` dari server
Semgrep saat runtime. Jika Semgrep memperbarui ruleset tersebut di sisi server, hasil
scan bisa berbeda antar run — ini mengurangi reproducibility penelitian.

**Untuk mempin ruleset agar hasil scan konsisten:**

```bash
# 1. Buat folder rules/ di root project
mkdir rules

# Unix / macOS / Git Bash:
semgrep --config p/php --dump-rules > rules/php.yaml
semgrep --config p/owasp-top-ten --dump-rules > rules/owasp-top-ten.yaml

# Windows PowerShell:
semgrep --config p/php --dump-rules | Out-File -Encoding utf8 rules/php.yaml
semgrep --config p/owasp-top-ten --dump-rules | Out-File -Encoding utf8 rules/owasp-top-ten.yaml
```

Setelah `rules/` terisi, scanner otomatis mendeteksinya dan menggunakan file lokal —
**tidak perlu ubah kode apapun**. Panel output akan menampilkan `(local (pinned))`
sebagai konfirmasi.

Jika `rules/` tidak ada, scanner tetap berjalan dengan ruleset online sambil menampilkan
peringatan di console.

> **Catatan untuk skripsi:** Commit file `rules/*.yaml` ke repository agar eksperimen
> dapat direproduksi oleh reviewer dengan ruleset yang identik.

---

## Troubleshooting & FAQ

**Q: Ollama tidak bisa terhubung**
A: Jalankan `ollama serve` di terminal lain terlebih dahulu

**Q: Output folder kosong**
A: Cek Rector dengan: `vendor/rector/rector/bin/rector --version`

**Q: Report JSON kosong atau error**
A: Gunakan `--verbose` untuk debug:
```bash
python pipeline/main.py --input tests/sample_php74 --verbose
```

**Q: Non-ASCII characters crash**
A: Windows CP1252 issue - sudah diperbaiki dengan ASCII equivalents

---

## Kontrol ISO/IEC 27001:2022

Pipeline memetakan ke 5 kontrol utama:

| Kontrol | Deskripsi |
|---------|-----------|
| A.8.25 | Secure Development Lifecycle |
| A.8.26 | Application Security Requirements |
| A.8.28 | Secure Coding |
| A.8.29 | Security Testing in Development |
| A.5.17 | Authentication Information |

---

## Referensi Eksternal

- DeepSeek Coder: https://ollama.com/library/deepseek-coder
- Rector: https://getrector.com/documentation
- Semgrep: https://semgrep.dev/p/php
- PHPStan: https://phpstan.org/
- ISO 27001:2022: https://www.iso.org/standard/27001
- OWASP Top 10: https://owasp.org/www-project-top-ten/

---

## Lisensi & Disclaimer

Proyek ini adalah **Proof of Concept** untuk keperluan akademis dan penelitian.

**Tidak untuk production**. Semua tools dan recommendations harus diverifikasi oleh human expert sebelum diterapkan.

---

**Muhammad Farrel Akbar** - Skripsi Magister, DTI UGM (2024-2026)

**Last Updated**: April 22, 2026 | **Status**: Active Research

**Questions?** Baca CLAUDE.md untuk konteks project lebih detail.
