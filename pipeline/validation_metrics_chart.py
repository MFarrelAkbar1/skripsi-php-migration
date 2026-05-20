"""
validation_metrics_chart.py -- Bar chart horizontal 3 metrik validasi akurasi
hasil konversi Rector pada dataset FT UGM.

Subplot kiri : Syntax Valid Rate + Deprecated Removed Rate (%)
Subplot kanan: Pipeline Duration breakdown (menit)
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

OUT_PATH = Path(
    r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration"
    r"\reports\validation\validation_metrics_chart.png"
)

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

RATE_LABELS = [
    "Deprecated Removed Rate\n(0 fungsi deprecated tersisa)",
    "Syntax Valid Rate\n(241 / 241 file)",
]
RATE_VALUES  = [100.0, 100.0]
RATE_ANNOTS  = ["100%\n(semua deprecated dihapus)", "100%\n(241 / 241 file)"]

DUR_LABELS = [
    "Total Pipeline",
    "  AI Engine\n  (DeepSeek via Ollama)",
    "  Konversi + Analisis\n  (Rector + PHPStan)",
]
DUR_VALUES  = [41, 39, 2]
DUR_ANNOTS  = ["41 menit", "~39 menit", "~2 menit"]


def main() -> None:
    plt.rcParams.update({"font.size": 10})
    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(10, 4), dpi=150)

    # ================================================================== #
    # Subplot kiri -- Rate (%)
    # ================================================================== #
    GREEN_DARK  = "#2E7D32"
    GREEN_LIGHT = "#66BB6A"
    rate_colors = [GREEN_LIGHT, GREEN_DARK]

    bars_l = ax_l.barh(
        RATE_LABELS, RATE_VALUES,
        color=rate_colors, height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )

    for bar, annot in zip(bars_l, RATE_ANNOTS):
        ax_l.text(
            bar.get_width() - 1.5,
            bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha="right",
            fontsize=10, fontweight="bold",
            color="white",
        )

    ax_l.set_xlim(0, 115)
    ax_l.set_xlabel("Persentase (%)", fontsize=10)
    ax_l.set_title(
        "Akurasi Konversi Rector\n(dataset FT UGM, 241 file)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax_l.xaxis.set_major_locator(mticker.MultipleLocator(20))
    ax_l.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax_l.set_axisbelow(True)
    ax_l.spines["top"].set_visible(False)
    ax_l.spines["right"].set_visible(False)

    # ================================================================== #
    # Subplot kanan -- Duration (menit)
    # ================================================================== #
    BLUE_TOTAL  = "#1565C0"
    BLUE_AI     = "#42A5F5"
    BLUE_CONV   = "#90CAF9"
    dur_colors  = [BLUE_TOTAL, BLUE_AI, BLUE_CONV]

    bars_r = ax_r.barh(
        DUR_LABELS, DUR_VALUES,
        color=dur_colors, height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )

    for bar, annot, val in zip(bars_r, DUR_ANNOTS, DUR_VALUES):
        # Place label inside if bar is wide enough, outside otherwise
        inside = val >= 8
        x_pos  = bar.get_width() - 0.8 if inside else bar.get_width() + 0.5
        h_align = "right" if inside else "left"
        color   = "white" if inside else "black"
        ax_r.text(
            x_pos,
            bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha=h_align,
            fontsize=10, fontweight="bold",
            color=color,
        )

    ax_r.set_xlim(0, 52)
    ax_r.set_xlabel("Durasi (menit)", fontsize=10)
    ax_r.set_title(
        "Durasi Pipeline\n(total 41 menit)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax_r.xaxis.set_major_locator(mticker.MultipleLocator(10))
    ax_r.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax_r.set_axisbelow(True)
    ax_r.spines["top"].set_visible(False)
    ax_r.spines["right"].set_visible(False)

    # ================================================================== #
    # Save
    # ================================================================== #
    plt.tight_layout(pad=2.0)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_PATH, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Chart saved -> {OUT_PATH}")


if __name__ == "__main__":
    main()
