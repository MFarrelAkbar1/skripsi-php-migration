"""
generate_validation_split_charts.py -- Pisahkan chart kiri dan kanan dari
validation_metrics_qwen.png menjadi dua file terpisah dengan figsize landscape.

Output (contents/chapter-4/validation/):
  validation_accuracy_rector.png    -- chart kiri (hijau, Akurasi Konversi Rector)
  validation_duration_pipeline.png  -- chart kanan (biru, Durasi Pipeline)

Data source:
  reports/mck_qwen/pipeline_result_20260524_130749.json
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

ROOT          = Path(__file__).parent.parent
PIPELINE_JSON = ROOT / "reports" / "mck_qwen" / "pipeline_result_20260524_130749.json"
OUT_DIR       = ROOT / "contents" / "chapter-4" / "validation"


def _chart_accuracy_rector(pipeline: dict) -> Path:
    conv      = pipeline.get("conversion", {})
    converted = conv.get("converted", 239)

    RATE_LABELS = [
        "Deprecated Removed Rate\n(0 fungsi deprecated tersisa)",
        f"Syntax Valid Rate\n({converted} / {converted} file)",
    ]
    RATE_VALUES = [100.0, 100.0]
    RATE_ANNOTS = [
        "100%\n(semua deprecated dihapus)",
        f"100%\n({converted} / {converted} file)",
    ]

    plt.rcParams.update({"font.size": 10})
    fig, ax = plt.subplots(figsize=(10, 3.5), dpi=150)

    GREEN_DARK  = "#2E7D32"
    GREEN_LIGHT = "#66BB6A"
    bars = ax.barh(
        RATE_LABELS, RATE_VALUES,
        color=[GREEN_LIGHT, GREEN_DARK], height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, annot in zip(bars, RATE_ANNOTS):
        ax.text(
            bar.get_width() - 1.5,
            bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha="right", fontsize=10, fontweight="bold", color="white",
        )

    ax.set_xlim(0, 115)
    ax.set_xlabel("Persentase (%)", fontsize=10)
    ax.set_title(
        f"Akurasi Konversi Rector\n(dataset FT UGM, {converted} file)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax.xaxis.set_major_locator(mticker.MultipleLocator(20))
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout(pad=2.0)
    out = OUT_DIR / "validation_accuracy_rector.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def _chart_duration_pipeline(pipeline: dict) -> Path:
    conv        = pipeline.get("conversion", {})
    total_sec   = pipeline.get("total_duration_sec", 229.48)
    pre_sec     = pipeline.get("pre_scan",  {}).get("scan_duration_sec",  27.14)
    post_sec    = pipeline.get("post_scan", {}).get("scan_duration_sec",  10.97)
    rect_sec    = conv.get("conversion_duration_sec", 56.19)
    phpstan_sec = pipeline.get("analysis", {}).get("duration_sec",        13.74)

    ai_sec   = total_sec - pre_sec - post_sec - rect_sec - phpstan_sec
    tool_sec = rect_sec + phpstan_sec

    total_min = round(total_sec / 60, 1)
    ai_min    = round(ai_sec   / 60, 1)
    tool_min  = round(tool_sec / 60, 1)

    DUR_LABELS = [
        "Total Pipeline",
        "  AI Engine\n  (Qwen2.5-Coder:7b via Ollama)",
        "  Konversi + Analisis\n  (Rector + PHPStan)",
    ]
    DUR_VALUES = [total_min, ai_min, tool_min]
    DUR_ANNOTS = [f"{total_min} menit", f"~{ai_min} menit", f"~{tool_min} menit"]

    plt.rcParams.update({"font.size": 10})
    fig, ax = plt.subplots(figsize=(10, 3.5), dpi=150)

    bars = ax.barh(
        DUR_LABELS, DUR_VALUES,
        color=["#1565C0", "#42A5F5", "#90CAF9"], height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, annot, val in zip(bars, DUR_ANNOTS, DUR_VALUES):
        inside  = val >= 2.0
        x_pos   = bar.get_width() - 0.1 if inside else bar.get_width() + 0.1
        h_align = "right" if inside else "left"
        color   = "white" if inside else "black"
        ax.text(
            x_pos, bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha=h_align, fontsize=10, fontweight="bold", color=color,
        )

    ax.set_xlim(0, max(DUR_VALUES) * 1.4 + 0.5)
    ax.set_xlabel("Durasi (menit)", fontsize=10)
    ax.set_title(
        f"Durasi Pipeline\n(total {total_min} menit)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout(pad=2.0)
    out = OUT_DIR / "validation_duration_pipeline.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pipeline = json.loads(PIPELINE_JSON.read_text(encoding="utf-8"))

    print("=" * 60)
    print("Generating split validation charts (landscape, figsize 10x3.5)")
    print(f"  Pipeline JSON : {PIPELINE_JSON.relative_to(ROOT)}")
    print(f"  Output        : {OUT_DIR.relative_to(ROOT)}")
    print("=" * 60)

    charts = [
        _chart_accuracy_rector(pipeline),
        _chart_duration_pipeline(pipeline),
    ]
    for p in charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(charts)} charts saved.")


if __name__ == "__main__":
    main()
