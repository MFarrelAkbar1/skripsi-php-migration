● Berikut command-command utama untuk menjalankan pipeline migrasi (dijalankan dari root project, Ollama harus sudah
  ollama serve di terminal lain):

  1. Run dasar (full pipeline, default)
  python pipeline/main.py
  Pakai input/ → output/, model default qwen2.5-coder:7b, target PHP 8.3.

  2. Pakai dataset test sample
  python pipeline/main.py --input tests/sample_php74

  3. Skip step AI (kalau Ollama belum/nggak mau dijalankan)
  python pipeline/main.py --skip-ai

  4. Ganti model AI
  python pipeline/main.py --model deepseek-coder:6.7b

  5. Eksperimen perbandingan 5 LLM (zero-shot, 3x per model)
  python pipeline/main.py --compare-all
  Tambahan opsi yang sering dipakai bareng ini:
  - --prompt-mode optimized — pakai prompt teroptimasi per-model
  - --save-raw-responses — simpan teks respons mentah (untuk Bab 4)
  - --temperature 0.1 — atur temperature
  - --models qwen2.5-coder:7b,codellama:7b — filter model tertentu saja

  6. Quality check (cek validitas sintaks output 5 model)
  python pipeline/main.py --compare-all --quality-check

  7. Atur target PHP version / level PHPStan / exclude folder
  python pipeline/main.py --target-php 8.5 --phpstan-level 5 --exclude vendor third_party

  8. Custom folder input/output/reports
  python pipeline/main.py --input input --output output --reports reports

  Cek reports/ setelah selesai untuk iso_report_<timestamp>.json, pipeline_result_<timestamp>.json, dan
  llm_comparison_<timestamp>.json (kalau pakai --compare-all).

✻ Worked for 18s

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ 