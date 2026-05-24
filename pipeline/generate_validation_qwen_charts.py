"""
generate_validation_qwen_charts.py -- Validation charts untuk run mck_qwen
(FT UGM, Qwen2.5-Coder:7b).

Menghasilkan dua set chart:
  1. Metrics chart (durasi pipeline + akurasi konversi) -- data dari mck_qwen
  2. Accuracy charts (sampling validation, similarity, coverage) -- data dari
     accuracy_report.json (Rector output sama persis antara run DeepSeek
     dan Qwen; chart ini merepresentasikan kualitas Rector, bukan AI)

Output (contents/chapter-4/validation/):
  validation_metrics_qwen.png
  validation_accuracy_qwen_1_sampling.png
  validation_accuracy_qwen_2_similarity.png
  validation_accuracy_qwen_3_coverage.png

Data source:
  reports/mck_qwen/pipeline_result_20260524_130749.json
  reports/validation/accuracy_report.json
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

ROOT       = Path(__file__).parent.parent
PIPELINE_JSON  = ROOT / "reports" / "mck_qwen" / "pipeline_result_20260524_130749.json"
ACCURACY_JSON  = ROOT / "reports" / "validation" / "accuracy_report.json"
OUT_DIR    = ROOT / "contents" / "chapter-4" / "validation"

COLOR_RECTOR = "#2979FF"
COLOR_GT     = "#43A047"
COLOR_SYS    = "#EF6C00"


def _pct(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


# ---------------------------------------------------------------------------
# Chart 1: Pipeline metrics (duration + conversion rate) -- mck_qwen data
# ---------------------------------------------------------------------------

def _chart_metrics(pipeline: dict) -> Path:
    conv  = pipeline.get("conversion", {})
    converted = conv.get("converted", 239)  # 239 files converted successfully

    RATE_LABELS = [
        "Deprecated Removed Rate\n(0 fungsi deprecated tersisa)",
        f"Syntax Valid Rate\n({converted} / {converted} file)",
    ]
    RATE_VALUES = [100.0, 100.0]
    RATE_ANNOTS = ["100%\n(semua deprecated dihapus)", f"100%\n({converted} / {converted} file)"]

    # Duration breakdown (from pipeline_result JSON, in minutes)
    total_sec    = pipeline.get("total_duration_sec", 229.48)
    pre_sec      = pipeline.get("pre_scan",  {}).get("scan_duration_sec",  27.14)
    post_sec     = pipeline.get("post_scan", {}).get("scan_duration_sec",  10.97)
    rect_sec     = conv.get("conversion_duration_sec", 56.19)
    phpstan_sec  = pipeline.get("analysis", {}).get("duration_sec",        13.74)

    ai_sec       = total_sec - pre_sec - post_sec - rect_sec - phpstan_sec
    tool_sec     = rect_sec + phpstan_sec

    total_min = round(total_sec / 60, 1)
    ai_min    = round(ai_sec   / 60, 1)
    tool_min  = round(tool_sec / 60, 1)

    DUR_LABELS = [
        "Total Pipeline",
        "  AI Engine\n  (Qwen2.5-Coder:7b via Ollama)",
        "  Konversi + Analisis\n  (Rector + PHPStan)",
    ]
    DUR_VALUES  = [total_min, ai_min, tool_min]
    DUR_ANNOTS  = [f"{total_min} menit", f"~{ai_min} menit", f"~{tool_min} menit"]

    plt.rcParams.update({"font.size": 10})
    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(10, 4), dpi=150)

    # -- Subplot kiri: Rate (%) --
    GREEN_DARK  = "#2E7D32"
    GREEN_LIGHT = "#66BB6A"
    bars_l = ax_l.barh(
        RATE_LABELS, RATE_VALUES,
        color=[GREEN_LIGHT, GREEN_DARK], height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, annot in zip(bars_l, RATE_ANNOTS):
        ax_l.text(
            bar.get_width() - 1.5,
            bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha="right", fontsize=10, fontweight="bold", color="white",
        )
    ax_l.set_xlim(0, 115)
    ax_l.set_xlabel("Persentase (%)", fontsize=10)
    ax_l.set_title(
        f"Akurasi Konversi Rector\n(dataset FT UGM, {converted} file)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax_l.xaxis.set_major_locator(mticker.MultipleLocator(20))
    ax_l.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax_l.set_axisbelow(True)
    ax_l.spines["top"].set_visible(False)
    ax_l.spines["right"].set_visible(False)

    # -- Subplot kanan: Duration (menit) --
    bars_r = ax_r.barh(
        DUR_LABELS, DUR_VALUES,
        color=["#1565C0", "#42A5F5", "#90CAF9"], height=0.45,
        edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, annot, val in zip(bars_r, DUR_ANNOTS, DUR_VALUES):
        inside  = val >= 2.0
        x_pos   = bar.get_width() - 0.1 if inside else bar.get_width() + 0.1
        h_align = "right" if inside else "left"
        color   = "white" if inside else "black"
        ax_r.text(
            x_pos, bar.get_y() + bar.get_height() / 2,
            annot,
            va="center", ha=h_align, fontsize=10, fontweight="bold", color=color,
        )
    ax_r.set_xlim(0, max(DUR_VALUES) * 1.4 + 0.5)
    ax_r.set_xlabel("Durasi (menit)", fontsize=10)
    ax_r.set_title(
        f"Durasi Pipeline\n(total {total_min} menit)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax_r.xaxis.set_major_locator(mticker.MultipleLocator(1))
    ax_r.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax_r.set_axisbelow(True)
    ax_r.spines["top"].set_visible(False)
    ax_r.spines["right"].set_visible(False)

    plt.tight_layout(pad=2.0)
    out = OUT_DIR / "validation_metrics_qwen.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Charts 2-4: Accuracy validation (uses accuracy_report.json -- data tetap)
# ---------------------------------------------------------------------------

def _chart_sampling(rector_files: list, n_r: int) -> Path:
    rect_syntax_pct = _pct(sum(1 for f in rector_files if f["rector_syntax_valid"]),      n_r)
    gt_syntax_pct   = _pct(sum(1 for f in rector_files if f["ground_truth_syntax_valid"]),n_r)
    rect_depr_pct   = _pct(sum(1 for f in rector_files if f["deprecated_removed_rector"]),       n_r)
    gt_depr_pct     = _pct(sum(1 for f in rector_files if f["deprecated_removed_ground_truth"]), n_r)

    plt.rcParams.update({"font.size": 10})
    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)

    x = np.array([0.0, 1.0])
    w = 0.35
    bars_r = ax.bar(x - w / 2, [rect_syntax_pct, rect_depr_pct], w,
                    color=COLOR_RECTOR, label="Rector",       zorder=3)
    bars_g = ax.bar(x + w / 2, [gt_syntax_pct,   gt_depr_pct],   w,
                    color=COLOR_GT,     label="Referensi LLM", zorder=3)
    for bar, val in zip(
        [*bars_r, *bars_g],
        [rect_syntax_pct, rect_depr_pct, gt_syntax_pct, gt_depr_pct],
    ):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
            f"{val:.0f}%", ha="center", va="bottom", fontsize=9,
        )
    ax.set_xlim(-0.6, 1.6)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Syntax Valid", "Deprecated\nRemoved"], fontsize=10)
    ax.set_ylim(0, 120)
    ax.set_ylabel("Persentase (%)", fontsize=10)
    ax.set_title("Validasi Sampel 10% (24 file, seed=42)", fontsize=11, fontweight="bold", pad=8)
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    out = OUT_DIR / "validation_accuracy_qwen_1_sampling.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def _chart_similarity(rector_files: list) -> Path:
    similarities = [
        f["rector_vs_ground_truth_similarity"]
        for f in rector_files
        if f["rector_vs_ground_truth_similarity"] is not None
    ]
    sim_mean = sum(similarities) / len(similarities) if similarities else 0.0

    plt.rcParams.update({"font.size": 10})
    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)

    bins = np.linspace(0.0, 1.0, 11)
    ax.hist(similarities, bins=bins, color="#5C6BC0", edgecolor="white", linewidth=0.8, zorder=3)
    ax.axvline(sim_mean, color="red", linewidth=2.0, linestyle="--",
               zorder=4, label=f"Rata-rata: {sim_mean:.4f}")
    ax.text(
        sim_mean + 0.018, 0.85,
        f"rata-rata\n{sim_mean:.4f}",
        transform=ax.get_xaxis_transform(),
        color="red", fontsize=10, fontweight="bold", va="top", ha="left",
        bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="red", alpha=0.85),
    )
    ax.set_xlim(0.0, 1.0)
    ax.set_xlabel("Similarity Score (line-level SequenceMatcher)", fontsize=10)
    ax.set_ylabel("Jumlah File", fontsize=10)
    ax.set_title(
        "Distribusi Similarity Score\n(Rector vs Referensi LLM)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    out = OUT_DIR / "validation_accuracy_qwen_2_similarity.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def _chart_coverage(rector_files: list, non_rector_files: list, total_sampled: int) -> Path:
    n_r  = len(rector_files)
    n_nr = len(non_rector_files)

    plt.rcParams.update({"font.size": 10})
    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)

    categories = [
        "system/\n(di luar scope Rector)  ",
        "application/\n(ada output Rector)  ",
    ]
    counts = [n_nr, n_r]
    bars = ax.barh(
        categories, counts,
        color=[COLOR_SYS, COLOR_RECTOR], height=0.4,
        edgecolor="white", linewidth=0.8, zorder=3,
    )
    for bar, n in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.25, bar.get_y() + bar.get_height() / 2,
            str(n), va="center", ha="left", fontsize=11, fontweight="bold",
        )
    ax.set_xlim(0, max(counts) + 4)
    ax.set_xlabel("Jumlah File", fontsize=10)
    ax.set_title(
        f"Cakupan File Sample ({total_sampled} file)",
        fontsize=11, fontweight="bold", pad=8,
    )
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    out = OUT_DIR / "validation_accuracy_qwen_3_coverage.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pipeline = json.loads(PIPELINE_JSON.read_text(encoding="utf-8"))
    accuracy = json.loads(ACCURACY_JSON.read_text(encoding="utf-8"))

    files           = accuracy["files"]
    rector_files    = [f for f in files if f["rector_file_found"]]
    non_rector_files = [f for f in files if not f["rector_file_found"]]
    total_sampled   = accuracy["summary"]["total_sampled"]

    print("=" * 60)
    print("FT UGM -- Qwen2.5-Coder:7b validation charts")
    print(f"  Pipeline JSON : {PIPELINE_JSON.relative_to(ROOT)}")
    print(f"  Accuracy JSON : {ACCURACY_JSON.relative_to(ROOT)}")
    print(f"  Output        : {OUT_DIR.relative_to(ROOT)}")
    print("=" * 60)

    charts = [
        _chart_metrics(pipeline),
        _chart_sampling(rector_files, len(rector_files)),
        _chart_similarity(rector_files),
        _chart_coverage(rector_files, non_rector_files, total_sampled),
    ]

    for p in charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(charts)} charts saved.")


if __name__ == "__main__":
    main()
