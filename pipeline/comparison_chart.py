"""
comparison_chart.py -- Grafik perbandingan dua studi kasus pipeline.

Menghasilkan 4 chart perbandingan FT UGM (mck) vs CBT DTI:
  1. Semgrep findings pre-scan (vulnerability type breakdown)
  2. Rector conversion results (stacked bar)
  3. PHPStan errors by ISO 27001:2022 control
  4. Composer dependency PHP 8.x status

Output: reports/comparison/comparison_<N>_<name>.png
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
# Style (consistent with pipeline_result_chart.py)
# ---------------------------------------------------------------------------

MCK_COLOR  = "#2166AC"   # blue  -- FT UGM
CBT_COLOR  = "#D7191C"   # red   -- CBT DTI
OK_COLOR   = "#4DAC26"   # green
SKIP_COLOR = "#E66101"   # orange
FAIL_COLOR = "#D7191C"   # red
SAFE_COLOR = "#4DAC26"
MR_COLOR   = "#E66101"

GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

_RC = {
    "font.family":       "DejaVu Sans",
    "font.size":         9,
    "text.color":        TEXT_C,
    "axes.titlesize":    11,
    "axes.titleweight":  "bold",
    "axes.labelsize":    9,
    "axes.labelcolor":   TEXT_C,
    "xtick.color":       TEXT_C,
    "ytick.color":       TEXT_C,
    "figure.facecolor":  "white",
    "axes.facecolor":    "white",
}


def _style_ax(ax: plt.Axes, orient: str = "v") -> None:
    grid_axis = "y" if orient == "v" else "x"
    ax.grid(axis=grid_axis, linewidth=0.5, color=GRID_C, linestyle="-")
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]:
        ax.spines[sp].set_color(SPINE_C)
        ax.spines[sp].set_linewidth(0.8)


def _footer(fig: plt.Figure) -> None:
    fig.text(
        0.5, 0.01,
        "Source: pipeline_result JSON  |  Skripsi Muhammad Farrel Akbar -- FT UGM vs CBT DTI",
        ha="center", fontsize=7.5, color="#888888",
    )


def _bar_label(ax: plt.Axes, bars, fmt: str = "{:.0f}", offset: int = 3) -> None:
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + offset,
                fmt.format(h),
                ha="center", va="bottom", fontsize=8, color=TEXT_C,
            )


# ---------------------------------------------------------------------------
# Chart 1: Semgrep findings pre-scan by vulnerability type
# ---------------------------------------------------------------------------

def chart1_semgrep(mck: dict, cbt: dict, out_dir: Path) -> Path:
    pre_mck = mck.get("pre_scan") or {}
    pre_cbt = cbt.get("pre_scan") or {}

    vuln_mck = pre_mck.get("by_vuln_type", {})
    vuln_cbt = pre_cbt.get("by_vuln_type", {})

    # All vulnerability types across both datasets
    all_types = sorted(set(list(vuln_mck.keys()) + list(vuln_cbt.keys())))
    if not all_types:
        all_types = ["No Findings"]

    x = np.arange(len(all_types))
    w = 0.35

    vals_mck = [vuln_mck.get(t, 0) for t in all_types]
    vals_cbt = [vuln_cbt.get(t, 0) for t in all_types]

    plt.rcParams.update(_RC)
    fig, ax = plt.subplots(figsize=(8, 4.5))

    bars_mck = ax.bar(x - w/2, vals_mck, w, label="FT UGM (mck)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w, label="CBT DTI",       color=CBT_COLOR, zorder=3)

    _bar_label(ax, bars_mck, offset=0.2)
    _bar_label(ax, bars_cbt, offset=0.2)

    ax.set_title("Semgrep Security Findings (Pre-Conversion) -- by Vulnerability Type")
    ax.set_ylabel("Jumlah Temuan")
    ax.set_xticks(x)
    ax.set_xticklabels(all_types, fontsize=9)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.legend(framealpha=0.85, fontsize=8.5)
    _style_ax(ax)

    # Totals annotation
    total_mck = pre_mck.get("total_findings", 0)
    total_cbt = pre_cbt.get("total_findings", 0)
    ax.text(0.98, 0.96,
            f"Total: FT UGM={total_mck}  CBT DTI={total_cbt}",
            transform=ax.transAxes, ha="right", va="top",
            fontsize=8, color="#555555",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=SPINE_C, linewidth=0.8))

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig)

    out = out_dir / "comparison_1_semgrep_findings.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Chart 2: Rector conversion results (stacked bar)
# ---------------------------------------------------------------------------

def chart2_rector(mck: dict, cbt: dict, out_dir: Path) -> Path:
    def _conv(d: dict) -> tuple[int, int, int]:
        c = d.get("conversion") or {}
        return c.get("converted", 0), c.get("skipped", 0), c.get("failed", 0)

    cv_m, sk_m, fa_m = _conv(mck)
    cv_c, sk_c, fa_c = _conv(cbt)

    labels = ["FT UGM (mck)", "CBT DTI"]
    conv   = [cv_m, cv_c]
    skip   = [sk_m, sk_c]
    fail   = [fa_m, fa_c]
    totals = [cv_m+sk_m+fa_m, cv_c+sk_c+fa_c]

    x = np.arange(len(labels))
    w = 0.45

    plt.rcParams.update(_RC)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    # Left: stacked bar
    ax = axes[0]
    b1 = ax.bar(x, conv, w, label="Converted", color=OK_COLOR,   zorder=3)
    b2 = ax.bar(x, skip, w, label="Skipped",   color=SKIP_COLOR, bottom=conv, zorder=3)
    b3 = ax.bar(x, fail, w, label="Failed",    color=FAIL_COLOR,
                bottom=[c+s for c, s in zip(conv, skip)], zorder=3)

    # Labels inside stacked bars
    for i, (c, s, f, tot) in enumerate(zip(conv, skip, fail, totals)):
        if c:  ax.text(x[i], c/2,       str(c), ha="center", va="center", fontsize=9, color="white", fontweight="bold")
        if s:  ax.text(x[i], c+s/2,     str(s), ha="center", va="center", fontsize=9, color="white", fontweight="bold")
        if f:  ax.text(x[i], c+s+f/2,   str(f), ha="center", va="center", fontsize=9, color="white", fontweight="bold")
        ax.text(x[i], tot+5, f"n={tot}", ha="center", va="bottom", fontsize=8, color=TEXT_C)

    ax.set_title("Rector Conversion Results")
    ax.set_ylabel("Jumlah File")
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.legend(loc="upper right", framealpha=0.85, fontsize=8)
    _style_ax(ax)

    # Right: conversion rate bar
    ax2 = axes[1]
    rates = [round(cv/tot*100, 1) if tot else 0 for cv, tot in zip(conv, totals)]
    colors = [MCK_COLOR, CBT_COLOR]
    bars = ax2.bar(x, rates, w*0.9, color=colors, zorder=3)
    for bar, rate in zip(bars, rates):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 f"{rate}%", ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)

    ax2.set_title("Conversion Rate (%)")
    ax2.set_ylabel("Persentase")
    ax2.set_ylim(0, 110)
    ax2.set_xticks(x); ax2.set_xticklabels(labels)
    ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    _style_ax(ax2)

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig)

    out = out_dir / "comparison_2_rector_conversion.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Chart 3: PHPStan errors by ISO 27001:2022 control
# ---------------------------------------------------------------------------

def chart3_phpstan(mck: dict, cbt: dict, out_dir: Path) -> Path:
    ana_mck = mck.get("analysis") or {}
    ana_cbt = cbt.get("analysis") or {}

    iso_mck = ana_mck.get("by_iso_control", {})
    iso_cbt = ana_cbt.get("by_iso_control", {})
    controls = sorted(set(list(iso_mck.keys()) + list(iso_cbt.keys())))

    x = np.arange(len(controls))
    w = 0.35

    vals_mck = [iso_mck.get(c, 0) for c in controls]
    vals_cbt = [iso_cbt.get(c, 0) for c in controls]

    plt.rcParams.update(_RC)
    fig, ax = plt.subplots(figsize=(8, 4.5))

    bars_mck = ax.bar(x - w/2, vals_mck, w, label="FT UGM (mck)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w, label="CBT DTI",       color=CBT_COLOR, zorder=3)

    _bar_label(ax, bars_mck, offset=10)
    _bar_label(ax, bars_cbt, offset=10)

    ax.set_title("PHPStan Errors by ISO/IEC 27001:2022 Control\n"
                 "(Application code only; CI3 framework noise filtered out)")
    ax.set_ylabel("Jumlah Error")
    ax.set_xticks(x)
    ax.set_xticklabels(controls)
    ax.legend(framealpha=0.85, fontsize=8.5)
    _style_ax(ax)

    # Totals annotation
    total_mck = ana_mck.get("total_errors", 0)
    total_cbt = ana_cbt.get("total_errors", 0)
    ax.text(0.98, 0.96,
            f"Total errors: FT UGM={total_mck:,}  CBT DTI={total_cbt:,}",
            transform=ax.transAxes, ha="right", va="top",
            fontsize=8, color="#555555",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=SPINE_C, linewidth=0.8))

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig)

    out = out_dir / "comparison_3_phpstan_iso.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Chart 4: Composer dependency analysis (FT UGM) + pipeline summary
# ---------------------------------------------------------------------------

def chart4_composer_and_summary(mck: dict, cbt: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

    # Left: Composer dependency status for FT UGM
    ax1 = axes[0]
    # Hard-coded from our run today (composer_analyzer result)
    comp_labels = ["SAFE\n(vlucas/phpdotenv\nphpoffice/phpspreadsheet\nfirebase/php-jwt)",
                   "MANUAL REVIEW\n(ngekoding/google-login\ncodeigniter-restserver)"]
    comp_sizes  = [3, 2]
    comp_colors = [SAFE_COLOR, MR_COLOR]

    wedges, texts, autotexts = ax1.pie(
        comp_sizes, labels=None, colors=comp_colors,
        autopct="%1.0f%%", startangle=90,
        wedgeprops=dict(linewidth=1.5, edgecolor="white"),
        textprops=dict(fontsize=9),
    )
    for at in autotexts:
        at.set_fontsize(11)
        at.set_fontweight("bold")
        at.set_color("white")

    safe_patch = mpatches.Patch(color=SAFE_COLOR, label="SAFE (3 packages)")
    mr_patch   = mpatches.Patch(color=MR_COLOR,   label="MANUAL REVIEW (2 packages)")
    ax1.legend(handles=[safe_patch, mr_patch], loc="lower center",
               bbox_to_anchor=(0.5, -0.22), ncol=1, framealpha=0.85, fontsize=8)
    ax1.set_title("Composer Dependency PHP 8.x Status\nFT UGM (mck) -- 5 Dependencies")

    # CBT DTI annotation
    ax1.text(0.5, -0.38,
             "CBT DTI: Tidak ada application-level\ncomposer dependencies",
             transform=ax1.transAxes, ha="center", va="top",
             fontsize=8, color="#888888", style="italic")

    # Right: overall pipeline summary metrics side-by-side
    ax2 = axes[1]
    ax2.axis("off")

    pre_mck = mck.get("pre_scan") or {}
    pre_cbt = cbt.get("pre_scan") or {}
    conv_mck = mck.get("conversion") or {}
    conv_cbt = cbt.get("conversion") or {}
    ana_mck = mck.get("analysis") or {}
    ana_cbt = cbt.get("analysis") or {}

    cv_m, sk_m, fa_m = conv_mck.get("converted",0), conv_mck.get("skipped",0), conv_mck.get("failed",0)
    cv_c, sk_c, fa_c = conv_cbt.get("converted",0), conv_cbt.get("skipped",0), conv_cbt.get("failed",0)
    tot_m = cv_m + sk_m + fa_m
    tot_c = cv_c + sk_c + fa_c
    rate_m = f"{round(cv_m/tot_m*100,1)}%" if tot_m else "-"
    rate_c = f"{round(cv_c/tot_c*100,1)}%" if tot_c else "-"

    rows = [
        ("Metrik", "FT UGM (mck)", "CBT DTI"),
        ("File PHP (custom)", str(tot_m), str(tot_c)),
        ("Semgrep findings (pre)", str(pre_mck.get("total_findings",0)), str(pre_cbt.get("total_findings",0))),
        ("  -- SQL Injection", str(pre_mck.get("by_vuln_type",{}).get("SQL Injection",0)), "0"),
        ("  -- SSRF", str(pre_mck.get("by_vuln_type",{}).get("SSRF",0)), "0"),
        ("Rector converted", f"{cv_m} ({rate_m})", f"{cv_c} ({rate_c})"),
        ("Rector skipped", str(sk_m), str(sk_c)),
        ("Rector failed", str(fa_m), str(fa_c)),
        ("PHPStan errors*", f"{ana_mck.get('total_errors',0):,}", f"{ana_cbt.get('total_errors',0):,}"),
        ("Composer deps", "5", "0"),
        ("AI recommendations", str(mck.get("ai_recommendations_count",0)), str(cbt.get("ai_recommendations_count",0))),
        ("ISO overall status", "NON-COMPLIANT*", "NON-COMPLIANT*"),
    ]

    col_x   = [0.0, 0.42, 0.72]
    row_h   = 0.073
    start_y = 0.96

    for i, row in enumerate(rows):
        y = start_y - i * row_h
        is_header = (i == 0)
        for j, cell in enumerate(row):
            weight = "bold" if is_header else "normal"
            color  = "#FFFFFF" if is_header else TEXT_C
            if is_header:
                ax2.add_patch(mpatches.FancyBboxPatch(
                    (col_x[j] - 0.01, y - 0.04), 0.38, 0.065,
                    boxstyle="round,pad=0.01",
                    facecolor="#2166AC", edgecolor="none",
                    transform=ax2.transAxes, clip_on=False,
                ))
            elif i % 2 == 0:
                ax2.add_patch(mpatches.FancyBboxPatch(
                    (-0.01, y - 0.04), 1.02, 0.065,
                    boxstyle="square,pad=0",
                    facecolor="#F5F5F5", edgecolor="none",
                    transform=ax2.transAxes, clip_on=False,
                ))
            ax2.text(col_x[j], y, cell,
                     transform=ax2.transAxes,
                     fontsize=8.2, fontweight=weight, color=color, va="center")

    ax2.text(0.0, start_y - len(rows)*row_h - 0.04,
             "* PHPStan errors: application code only; CI3 noise filtered (mck: 740, CBT: 1103)\n"
             "* CBT PHPStan scoped to application/ (excl. libraries) due to TCPDF/PHPExcel memory limit",
             transform=ax2.transAxes, fontsize=7, color="#888888", va="top")

    ax2.set_title("Ringkasan Perbandingan Pipeline", pad=10)

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig)

    out = out_dir / "comparison_4_composer_summary.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    root = Path(__file__).parent.parent
    mck_path = root / "reports" / "mck" / "pipeline_result_20260519_075958.json"
    cbt_path = root / "reports" / "cbt_new" / "pipeline_result_20260519_082600.json"

    mck = json.loads(mck_path.read_text(encoding="utf-8"))
    cbt = json.loads(cbt_path.read_text(encoding="utf-8"))

    out_dir = root / "reports" / "comparison"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating comparison charts...")
    paths = [
        chart1_semgrep(mck, cbt, out_dir),
        chart2_rector(mck, cbt, out_dir),
        chart3_phpstan(mck, cbt, out_dir),
        chart4_composer_and_summary(mck, cbt, out_dir),
    ]
    for p in paths:
        print(f"  Saved: {p}")
    print(f"Done. {len(paths)} charts saved to {out_dir}")


if __name__ == "__main__":
    main()
