# PHP Legacy Migration Pipeline

**Sistem Otomatis Migrasi Kode PHP 7.4 ke PHP 8.x dengan Kerangka Keamanan ISO/IEC 27001:2022**

Penelitian skripsi **Muhammad Farrel Akbar** — Kolaborasi studi kasus dengan **FT UGM (Fakultas Teknik, Universitas Gadjah Mada)**.

---

## Deskripsi Proyek

Pipeline otomatis untuk migrasi kode PHP legacy (PHP 7.4) ke PHP 8.x dengan fokus pada keamanan dan kepatuhan ISO/IEC 27001:2022. Seluruh inferensi AI berjalan **lokal via Ollama** — tidak ada kode yang dikirim ke API eksternal (privasi data terjamin).

### Studi Kasus

Aplikasi web berbasis **CodeIgniter 3.x** dari FT UGM — 245 file PHP.

### Tujuan Penelitian

- Mengotomatisasi konversi PHP 7.4 ke PHP 8.x menggunakan Rector
- Mendeteksi kerentanan keamanan dengan Semgrep + PHPStan
- Membandingkan 5 model LLM lokal secara zero-shot untuk rekomendasi perbaikan kode
- Memetakan seluruh temuan ke kontrol ISO/IEC 27001:2022
- Menjamin privasi data dengan inferensi lokal via Ollama

---

## Stack Teknologi

| Komponen | Teknologi | Fungsi |
|---|---|---|
| Konversi kode | Rector | Migrasi otomatis PHP 7.4 -> PHP 8.x |
| Scan keamanan | Semgrep (`p/php`, `p/owasp-top-ten`) | Deteksi kerentanan pre & post konversi |
| Analisis statis | PHPStan | Validasi tipe, method existence, dead code |
| AI lokal | Ollama + 5 LLM (lihat bawah) | Rekomendasi perbaikan keamanan |
| Backend pipeline | Python 3.11+ | Orkestrasi 6-step pipeline |
| Terminal UI | Rich v13+ | Output pipeline yang terstruktur |
| Visualisasi | Matplotlib | Chart perbandingan LLM & metrik akurasi |

### Model LLM yang Dibandingkan (Zero-Shot Comparison)

| Model | Parameter | Default |
|---|---|---|
| `qwen2.5-coder:7b` | 7B | Ya (current default) |
| `deepseek-coder:6.7b` | 6.7B | |
| `codellama:7b` | 7B | |
| `mistral:7b` | 7B | |
| `llama3.1:8b` | 8B | |

---

## Struktur Folder

```
skripsi-php-migration/
├── CLAUDE.md                       <- Aturan wajib dan konteks
├── README.md                       <- File ini
├── requirements.txt                <- Python dependencies
├── composer.json                   <- PHP dependencies (Rector, PHPStan)
│
├── pipeline/                       <- Semua modul Python
│   ├── main.py                     <- Entry point & orkestrasi 6-step
│   ├── scanner.py                  <- Semgrep security scanning
│   ├── converter.py                <- Rector PHP conversion
│   ├── analyzer.py                 <- PHPStan static analysis
│   ├── ai_engine.py                <- Ollama / LLM integration & comparison
│   ├── iso_mapper.py               <- ISO 27001:2022 compliance mapping
│   ├── composer_analyzer.py        <- Analisis kompatibilitas composer.json
│   ├── llm_quality_checker.py      <- Syntax validity rate per model
│   ├── accuracy_checker.py         <- Metrik akurasi pipeline
│   ├── accuracy_validator.py       <- Validasi hasil migrasi
│   ├── capture_responses.py        <- Capture raw LLM responses
│   ├── llm_comparison_chart.py     <- Chart perbandingan LLM
│   ├── generate_condition_a_charts.py  <- Chart eksperimen kondisi A
│   ├── generate_condition_b_charts.py  <- Chart eksperimen kondisi B
│   └── pipeline_result_chart.py    <- Chart hasil pipeline keseluruhan
│
├── input/                          <- PHP 7.4 asli (JANGAN dimodifikasi)
├── output/                         <- PHP 8.x hasil Rector
├── reports/                        <- JSON reports + PNG charts
├── rules/                          <- Semgrep rules lokal (pinned)
├── tests/
│   └── sample_php74/               <- 3 sample PHP untuk testing cepat
│       ├── sample_login.php
│       ├── sample_realistic.php
│       └── sample_upload.php
├── docs/
│   ├── architecture.md
│   ├── iso_controls.md
│   └── pseudocode_appendix.md
└── vendor/                         <- Composer packages
```

---

## Instalasi

### Prasyarat

- Python 3.11+
- PHP 8.0+ (untuk Rector & PHPStan)
- Composer
- Semgrep (`pip install semgrep` atau via package manager)
- Ollama ([ollama.com](https://ollama.com))
- RAM minimal 8GB (16GB direkomendasikan untuk model 7-8B)

### Setup

```bash
# 1. Clone repository
git clone https://github.com/farrel212/skripsi-php-migration.git
cd skripsi-php-migration

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install PHP tools (Rector + PHPStan)
composer install

# 4. Pull semua model LLM via Ollama
ollama pull qwen2.5-coder:7b
ollama pull deepseek-coder:6.7b
ollama pull codellama:7b
ollama pull mistral:7b
ollama pull llama3.1:8b

# 5. (Opsional) Pin ruleset Semgrep agar reproducible
mkdir rules
semgrep --config p/php --dump-rules | Out-File -Encoding utf8 rules/php.yaml
semgrep --config p/owasp-top-ten --dump-rules | Out-File -Encoding utf8 rules/owasp-top-ten.yaml
```

---

## Cara Menjalankan

### Pipeline Utama

```bash
# Pastikan Ollama berjalan di terminal terpisah
ollama serve

# Jalankan pipeline dengan sample test
python pipeline/main.py --input tests/sample_php74

# Jalankan dengan input kustom
python pipeline/main.py --input path/to/php74/code

# Skip AI step (lebih cepat, tanpa Ollama)
python pipeline/main.py --input tests/sample_php74 --skip-ai

# Verbose logging untuk debug
python pipeline/main.py --input tests/sample_php74 --verbose
```

### Script Analisis Tambahan

```bash
# Perbandingan 5 model LLM (menghasilkan chart ke reports/)
python pipeline/llm_comparison_chart.py

# Cek syntax validity output AI per model
python pipeline/llm_quality_checker.py

# Generate chart eksperimen kondisi A/B
python pipeline/generate_condition_a_charts.py
python pipeline/generate_condition_b_charts.py

# Analisis kompatibilitas composer.json dengan PHP 8
python pipeline/composer_analyzer.py
```

---

## Alur Kerja Pipeline (6 Steps)

```
INPUT (input/)
    |
    v
[STEP 1: PRE-SCAN]     Semgrep scan kode PHP 7.4 asli
    |
    v
[STEP 2: CONVERT]      Rector migrasi PHP 7.4 -> PHP 8.x (output ke output/)
    |
    v
[STEP 3: POST-SCAN]    Semgrep scan kode PHP 8.x hasil konversi
    |
    v
[STEP 4: ANALYZE]      PHPStan static analysis & type validation
    |
    v
[STEP 5: AI REVIEW]    Ollama LLM -> rekomendasi perbaikan keamanan
    |                  (bisa di-skip dengan --skip-ai)
    v
[STEP 6: ISO MAP]      Pemetaan ke kontrol ISO/IEC 27001:2022
    |
    v
REPORTS (reports/)     iso_report_<timestamp>.json
                       pipeline_result_<timestamp>.json
```

| Step | Tool | Input | Output |
|---|---|---|---|
| PRE-SCAN | Semgrep | `input/` | Daftar kerentanan awal |
| CONVERT | Rector | `input/` | `output/` (PHP 8.x) |
| POST-SCAN | Semgrep | `output/` | Kerentanan yang tersisa |
| ANALYZE | PHPStan | `output/` | Type errors, dead code |
| AI REVIEW | Ollama (5 model) | Findings step 3 & 4 | Patch recommendations |
| ISO MAP | iso_mapper | Semua findings | Compliance report JSON |

---

## Output yang Dihasilkan

### `output/` — Kode PHP 8.x Hasil Konversi

- Fungsi deprecated sudah diganti (`mysql_*` -> `mysqli`, `ereg_*` -> `preg_*`)
- Syntax modern PHP 8.x (union types, nullsafe operator, named arguments)
- Input asli di `input/` **tidak pernah dimodifikasi**

### `reports/` — Laporan & Chart

| File | Deskripsi |
|---|---|
| `iso_report_<timestamp>.json` | Status kepatuhan per kontrol ISO 27001 |
| `pipeline_result_<timestamp>.json` | Detail hasil setiap step pipeline |
| `llm_comparison_<timestamp>.json` | Data mentah perbandingan 5 model LLM |
| `llm_quality_<timestamp>.json` | Syntax validity rate per model |
| `llm_chart_*_1_boxplot_confidence.png` | Boxplot confidence score 5 model |
| `llm_chart_*_2_format_compliance.png` | Format compliance rate |
| `llm_chart_*_3_inference_time.png` | Inference time comparison |
| `llm_chart_*_4_stats_table.png` | Tabel statistik ringkasan |
| `llm_quality_chart_<timestamp>.png` | Syntax validity rate chart |

### Contoh `iso_report.json`

```json
{
  "overall_status": "COMPLIANT",
  "findings_summary": { "total": 8, "resolved": 6 },
  "control_mapping": {
    "A.8.25": "COMPLIANT",
    "A.8.28": "COMPLIANT",
    "A.8.29": "PARTIAL"
  }
}
```

---

## Kerentanan yang Diprioritaskan

| Prioritas | Jenis | Penanganan |
|---|---|---|
| 1 | SQL Injection (`mysql_*` tanpa prepared statements) | Rector + AI patch |
| 2 | XSS (output tanpa `htmlspecialchars`) | AI recommendation |
| 3 | Fungsi deprecated PHP 7.x | Rector auto-fix |
| 4 | Hardcoded credentials | AI recommendation |
| 5 | Path traversal | AI recommendation |
| 6 | Weak cryptography (`md5`/`sha1` untuk password) | AI recommendation |

---

## Kontrol ISO/IEC 27001:2022

| Kontrol | Deskripsi | Ditangani Oleh |
|---|---|---|
| A.8.25 | Secure Development Lifecycle | Rector (CONVERT step) |
| A.8.26 | Application Security Requirements | Semgrep (SCAN steps) |
| A.8.28 | Secure Coding | AI REVIEW step |
| A.8.29 | Security Testing in Development | PHPStan + LLM quality check |
| A.8.24 | Use of Cryptography | Semgrep (weak crypto rules) |
| A.5.17 | Authentication Information | Semgrep (hardcoded creds rules) |

---

## Reproducibility — Pinned Semgrep Rulesets

Semgrep mengunduh ruleset dari server saat runtime secara default, yang dapat mengubah hasil antar run. Untuk hasil yang konsisten dan dapat direproduksi:

```powershell
# Windows PowerShell
mkdir rules
semgrep --config p/php --dump-rules | Out-File -Encoding utf8 rules/php.yaml
semgrep --config p/owasp-top-ten --dump-rules | Out-File -Encoding utf8 rules/owasp-top-ten.yaml
```

Setelah folder `rules/` terisi, scanner otomatis menggunakannya (ditandai `(local (pinned))` di output). Commit file `rules/*.yaml` agar eksperimen dapat direproduksi oleh reviewer.

---

## Troubleshooting

| Masalah | Solusi |
|---|---|
| Ollama tidak konek | Jalankan `ollama serve` di terminal terpisah |
| Folder `output/` kosong | Cek Rector: `vendor/rector/rector/bin/rector --version` |
| Report JSON tidak muncul | Gunakan `--verbose` untuk debug |
| Error karakter non-ASCII di Windows | Sudah diperbaiki — semua karakter non-ASCII diganti ASCII equivalents |
| Model LLM tidak tersedia | Jalankan `ollama pull <model-name>` terlebih dahulu |

---

## Batasan Penelitian

Yang **dikerjakan**:
- Static analysis saja (bukan dynamic/active testing)
- Proof of concept, bukan production-ready tool
- Studi kasus aplikasi web PHP CodeIgniter 3.x dari FT UGM

Yang **tidak dikerjakan**:
- Fine-tuning model AI (hanya prompt engineering)
- Perubahan arsitektur aplikasi studi kasus
- Integrasi SSO / autentikasi UGM
- Pengujian di sistem production UGM

---

## Referensi

- Rector: https://getrector.com/documentation
- Semgrep PHP rules: https://semgrep.dev/p/php
- PHPStan: https://phpstan.org/
- Ollama: https://ollama.com
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- OWASP Top 10: https://owasp.org/www-project-top-ten/

---

## Lisensi & Disclaimer

Proyek ini adalah **Proof of Concept** untuk keperluan akademis. Tidak untuk production. Semua rekomendasi AI harus diverifikasi oleh human expert sebelum diterapkan ke sistem nyata.

---

**Muhammad Farrel Akbar** | Skripsi S1 | FT UGM | 2024–2026
