"""
validation_chart.py -- Visualisasi hasil accuracy_report.json dalam 3 subplot.

Subplot 1: grouped bar chart (Rector vs Referensi LLM) untuk 3 metrik validasi
Subplot 2: histogram distribusi similarity score (Rector vs Referensi LLM)
Subplot 3: horizontal bar breakdown cakupan file sample
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

REPORT_PATH = Path(
    r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration"
    r"\reports\validation\accuracy_report.json"
)
CHART_OUT = REPORT_PATH.parent / "validation_accuracy_chart.png"

COLOR_RECTOR = "#2979FF"   # biru
COLOR_GT     = "#43A047"   # hijau
COLOR_SYS    = "#EF6C00"   # oranye (system/, out-of-scope)


def _pct(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


def main() -> None:
    data = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    summary = data["summary"]
    files   = data["files"]

    # ------------------------------------------------------------------ #
    # Segmentasi: hanya 12 file yang ada Rector output-nya
    # ------------------------------------------------------------------ #
    rector_files     = [f for f in files if f["rector_file_found"]]
    non_rector_files = [f for f in files if not f["rector_file_found"]]
    n_r  = len(rector_files)
    n_nr = len(non_rector_files)

    # (a) syntax valid %
    rect_syntax_pct = _pct(sum(1 for f in rector_files if f["rector_syntax_valid"]),       n_r)
    gt_syntax_pct   = _pct(sum(1 for f in rector_files if f["ground_truth_syntax_valid"]), n_r)

    # (b) deprecated removed %
    rect_depr_pct = _pct(sum(1 for f in rector_files if f["deprecated_removed_rector"]),        n_r)
    gt_depr_pct   = _pct(sum(1 for f in rector_files if f["deprecated_removed_ground_truth"]),  n_r)

    # (c) avg old-syntax remaining (absolute count)
    rect_old_vals = [f["rector_old_syntax_count"]      for f in rector_files if f["rector_old_syntax_count"]      is not None]
    gt_old_vals   = [f["ground_truth_old_syntax_count"] for f in rector_files if f["ground_truth_old_syntax_count"] is not None]
    rect_old_avg  = sum(rect_old_vals) / len(rect_old_vals) if rect_old_vals else 0.0
    gt_old_avg    = sum(gt_old_vals)   / len(gt_old_vals)   if gt_old_vals   else 0.0

    # (d) similarity scores
    similarities = [
        f["rector_vs_ground_truth_similarity"]
        for f in rector_files
        if f["rector_vs_ground_truth_similarity"] is not None
    ]
    sim_mean = sum(similarities) / len(similarities) if similarities else 0.0

    # ------------------------------------------------------------------ #
    # Figure setup
    # ------------------------------------------------------------------ #
    plt.rcParams.update({"font.size": 10})
    fig, axes = plt.subplots(1, 3, figsize=(15, 5), dpi=150)

    # ================================================================== #
    # Subplot 1 -- Grouped bar (% left axis, count right axis)
    # ================================================================== #
    ax1  = axes[0]
    ax1b = ax1.twinx()

    x_pct = np.array([0.0, 1.0])   # positions for % metrics
    x_abs = np.array([2.0])         # position for count metric
    w = 0.35

    # Percentage bars (left axis, 0-100%)
    bars_r_pct = ax1.bar(x_pct - w / 2, [rect_syntax_pct, rect_depr_pct], w,
                         color=COLOR_RECTOR, label="Rector",       zorder=3)
    bars_g_pct = ax1.bar(x_pct + w / 2, [gt_syntax_pct,   gt_depr_pct],   w,
                         color=COLOR_GT,     label="Referensi LLM", zorder=3)

    # Count bars (right twin axis)
    bars_r_abs = ax1b.bar(x_abs - w / 2, [rect_old_avg], w,
                          color=COLOR_RECTOR, zorder=3)
    bars_g_abs = ax1b.bar(x_abs + w / 2, [gt_old_avg],   w,
                          color=COLOR_GT,     zorder=3)

    # Value labels for % bars
    for bar, val in zip(
        [*bars_r_pct, *bars_g_pct],
        [rect_syntax_pct, rect_depr_pct, gt_syntax_pct, gt_depr_pct],
    ):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{val:.0f}%",
            ha="center", va="bottom", fontsize=9,
        )

    # Value labels for count bars
    for bar, val in zip([bars_r_abs[0], bars_g_abs[0]], [rect_old_avg, gt_old_avg]):
        ax1b.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.06,
            f"{val:.2f}",
            ha="center", va="bottom", fontsize=9,
        )

    old_axis_max = max(rect_old_avg, gt_old_avg, 0.1)
    ax1.set_xlim(-0.6, 2.6)
    ax1.set_xticks([0, 1, 2])
    ax1.set_xticklabels(
        ["Syntax Valid", "Deprecated\nRemoved", "Old Syntax\nTersisa (avg)"],
        fontsize=10,
    )
    ax1.set_ylim(0, 120)
    ax1.set_ylabel("Persentase (%)", fontsize=10)
    ax1b.set_ylim(0, old_axis_max * 4)
    ax1b.set_ylabel("Jumlah rata-rata (count)", fontsize=10)
    ax1b.yaxis.set_major_locator(mticker.MaxNLocator(integer=False, nbins=5))
    ax1.set_title(
        f"Validasi Sampel 10% (24 file, seed=42)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax1.set_axisbelow(True)

    # ================================================================== #
    # Subplot 2 -- Histogram similarity scores
    # ================================================================== #
    ax2 = axes[1]

    bins = np.linspace(0.0, 1.0, 11)   # 10 bins, each 0.1 wide
    ax2.hist(similarities, bins=bins,
             color="#5C6BC0", edgecolor="white", linewidth=0.8, zorder=3)

    ax2.axvline(sim_mean, color="red", linewidth=2.0, linestyle="--",
                zorder=4, label=f"Rata-rata: {sim_mean:.4f}")

    # Bold label pinned at 85% height so it's always visible
    ax2.text(
        sim_mean + 0.018, 0.85,
        f"rata-rata\n{sim_mean:.4f}",
        transform=ax2.get_xaxis_transform(),
        color="red", fontsize=10, fontweight="bold",
        va="top", ha="left",
        bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="red", alpha=0.85),
    )

    ax2.set_xlim(0.0, 1.0)
    ax2.set_xlabel("Similarity Score (line-level SequenceMatcher)", fontsize=10)
    ax2.set_ylabel("Jumlah File", fontsize=10)
    ax2.set_title(
        "Distribusi Similarity Score\n(Rector vs Referensi LLM)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax2.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax2.legend(fontsize=9)
    ax2.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax2.set_axisbelow(True)

    # ================================================================== #
    # Subplot 3 -- Horizontal bar: file coverage breakdown
    # ================================================================== #
    ax3 = axes[2]

    categories = [
        f"system/\n(di luar scope Rector)  ",
        f"application/\n(ada output Rector)  ",
    ]
    counts = [n_nr, n_r]
    colors = [COLOR_SYS, COLOR_RECTOR]

    bars3 = ax3.barh(
        categories, counts,
        color=colors, height=0.4, edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, n in zip(bars3, counts):
        ax3.text(
            bar.get_width() + 0.25,
            bar.get_y() + bar.get_height() / 2,
            str(n),
            va="center", ha="left", fontsize=11, fontweight="bold",
        )

    ax3.set_xlim(0, max(counts) + 4)
    ax3.set_xlabel("Jumlah File", fontsize=10)
    ax3.set_title(
        f"Cakupan File Sample ({summary['total_sampled']} file)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax3.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax3.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax3.set_axisbelow(True)

    # ================================================================== #
    # Save
    # ================================================================== #
    plt.tight_layout()
    CHART_OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(CHART_OUT, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Chart saved -> {CHART_OUT}")


if __name__ == "__main__":
    main()
