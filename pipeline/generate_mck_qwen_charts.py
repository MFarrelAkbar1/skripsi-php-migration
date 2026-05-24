"""
generate_mck_qwen_charts.py -- Generate pipeline charts untuk FT UGM run
dengan model Qwen2.5-Coder:7b (mck_qwen run).

Menggunakan fungsi chart yang sama dengan pipeline_result_chart.py,
dengan timestamp tetap "mck_qwen" supaya nama file mencantumkan "qwen"
dan tidak overwrite chart run DeepSeek sebelumnya.

Output charts (contents/chapter-4/):
  pipeline_chart_mck_qwen_1_prescan_postscan_severity.png
  pipeline_chart_mck_qwen_2_prescan_postscan_vulntype.png
  pipeline_chart_mck_qwen_3_rector_conversion.png
  pipeline_chart_mck_qwen_4_phpstan_iso.png

Data source:
  reports/mck_qwen/pipeline_result_20260524_130749.json
"""

from __future__ import annotations

import sys
from pathlib import Path

# Pastikan pipeline/ ada di sys.path supaya import pipeline_result_chart bisa
sys.path.insert(0, str(Path(__file__).parent))

from pipeline_result_chart import (  # type: ignore[import]
    _chart_severity,
    _chart_vuln_type,
    _chart_conversion,
    _chart_phpstan_iso,
    _load,
)

ROOT     = Path(__file__).parent.parent
JSON     = ROOT / "reports" / "mck_qwen" / "pipeline_result_20260524_130749.json"
OUT_DIR  = ROOT / "contents" / "chapter-4"
TS       = "mck_qwen"   # menggantikan timestamp — masuk ke nama file


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    data     = _load(JSON)
    pre      = data.get("pre_scan",   {})
    post     = data.get("post_scan",  {})
    conv     = data.get("conversion", {})
    analysis = data.get("analysis",   {})
    source   = JSON.name

    print("=" * 60)
    print("FT UGM -- Qwen2.5-Coder:7b pipeline charts")
    print(f"  Source : {JSON.relative_to(ROOT)}")
    print(f"  Output : {OUT_DIR.relative_to(ROOT)}")
    print("=" * 60)

    charts = [
        _chart_severity(pre, post, OUT_DIR, TS, source),
        _chart_vuln_type(pre, post, OUT_DIR, TS, source),
        _chart_conversion(conv, OUT_DIR, TS, source),
        _chart_phpstan_iso(analysis, OUT_DIR, TS, source),
    ]

    for p in charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(charts)} charts saved.")


if __name__ == "__main__":
    main()
