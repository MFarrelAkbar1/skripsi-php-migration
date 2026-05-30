"""
generate_comparison_qwen_charts.py -- Perbandingan SK1 (FT UGM) vs SK2 (CBT DTI)
menggunakan hasil pipeline run Qwen2.5-Coder:7b.

Output charts (contents/chapter-4/comparison/):
  comparison_qwen_1_semgrep_findings.png
  comparison_qwen_2_rector_conversion.png
  comparison_qwen_3_phpstan_iso.png
  comparison_qwen_4_summary.png

Data sources:
  SK1 (FT UGM) : reports/mck_qwen/pipeline_result_20260524_130749.json
  SK2 (CBT DTI): reports/cbt_qwen/pipeline_result_20260524_124116.json
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT     = Path(__file__).parent.parent
MCK_JSON = ROOT / "reports" / "mck_qwen" / "pipeline_result_20260524_130749.json"
CBT_JSON = ROOT / "reports" / "cbt_qwen" / "pipeline_result_20260524_124116.json"
OUT_DIR  = ROOT / "contents" / "chapter-4" / "comparison"

# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

MCK_COLOR  = "#2166AC"   # blue  -- FT UGM / SK1
CBT_COLOR  = "#D7191C"   # red   -- CBT DTI / SK2
OK_COLOR   = "#4DAC26"
SKIP_COLOR = "#E66101"
FAIL_COLOR = "#D7191C"

GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

ISO_STATUS_COLORS = {
    "COMPLIANT":     "#4DAC26",
    "NON_COMPLIANT": "#D7191C",
    "PARTIAL":       "#E66101",
}

_RC = {
    "font.family":      "DejaVu Sans",
    "font.size":        9,
    "text.color":       TEXT_C,
    "axes.titlesize":   11,
    "axes.titleweight": "bold",
    "axes.labelsize":   9,
    "axes.labelcolor":  TEXT_C,
    "xtick.color":      TEXT_C,
    "ytick.color":      TEXT_C,
    "figure.facecolor": "white",
    "axes.facecolor":   "white",
}


def _style_ax(ax: plt.Axes, orient: str = "v") -> None:
    ax.grid(axis="y" if orient == "v" else "x",
            linewidth=0.5, color=GRID_C, linestyle="-")
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]:
        ax.spines[sp].set_color(SPINE_C)
        ax.spines[sp].set_linewidth(0.8)


def _footer(fig: plt.Figure) -> None:
    fig.text(
        0.5, 0.01,
        "Source: pipeline_result JSON  |  Skripsi Muhammad Farrel Akbar"
        "  --  FT UGM (SK1) vs CBT DTI (SK2)  |  Model: Qwen2.5-Coder:7b",
        ha="center", fontsize=7.5, color="#888888",
    )


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(fig: plt.Figure, name: str, dpi: int = 180) -> Path:
    out = OUT_DIR / name
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ===========================================================================
# Chart 1 -- Semgrep findings by vulnerability type
# ===========================================================================

def chart1_semgrep(mck: dict, cbt: dict) -> Path:
    plt.rcParams.update(_RC)

    pre_mck = mck.get("pre_scan", {})
    pre_cbt = cbt.get("pre_scan", {})
    vt_mck  = pre_mck.get("by_vuln_type", {})
    vt_cbt  = pre_cbt.get("by_vuln_type", {})
    all_types = sorted(set(list(vt_mck) + list(vt_cbt)))
    if not all_types:
        all_types = ["(no findings)"]

    x = np.arange(len(all_types))
    w = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("white")

    vals_mck = [vt_mck.get(t, 0) for t in all_types]
    vals_cbt = [vt_cbt.get(t, 0) for t in all_types]

    bars_mck = ax.bar(x - w/2, vals_mck, w,
                      label="FT UGM / SK1 (mck_qwen)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w,
                      label="CBT DTI / SK2 (cbt_qwen)", color=CBT_COLOR, zorder=3)

    y_max = max(max(vals_mck), max(vals_cbt)) if (vals_mck and vals_cbt) else 1
    for bar, v in zip(bars_mck, vals_mck):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + y_max * 0.015,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)
    for bar, v in zip(bars_cbt, vals_cbt):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + y_max * 0.015,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)

    total_mck = pre_mck.get("total_findings", 0)
    total_cbt = pre_cbt.get("total_findings", 0)

    ax.set_title("Semgrep Security Findings (Pre-Conversion)\nby Vulnerability Type  --  Qwen2.5-Coder:7b")
    ax.set_ylabel("Jumlah Temuan")
    ax.set_xticks(x)
    ax.set_xticklabels(all_types, fontsize=10)
    ax.set_ylim(0, y_max * 1.30)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.legend(framealpha=0.85, fontsize=9)
    _style_ax(ax)

    fig.tight_layout(rect=[0, 0.20, 1, 1])
    fig.text(0.03, 0.08,
             f"Total: FT UGM = {total_mck}  |  CBT DTI = {total_cbt}\n"
             "Semua findings berasal dari CI3 system/core/Output.php (framework)\n"
             "Kode aplikasi custom kedua dataset = 0 findings  |  Delta post-conversion = 0 (kedua SK)",
             ha="left", va="bottom",
             fontsize=8, color="#555555",
             bbox=dict(boxstyle="round,pad=0.35", facecolor="white",
                       edgecolor=SPINE_C, linewidth=0.7))
    _footer(fig)
    return _save(fig, "comparison_qwen_1_semgrep_findings.png")


# ===========================================================================
# Chart 2 -- Rector conversion results
# ===========================================================================

def chart2_rector(mck: dict, cbt: dict) -> Path:
    plt.rcParams.update(_RC)

    def _conv(d: dict) -> tuple[int, int, int, int]:
        c = d.get("conversion") or {}
        cv = c.get("converted", 0)
        sk = c.get("skipped",   0)
        fa = c.get("failed",    0)
        tot = c.get("total_files", cv + sk + fa)
        return cv, sk, fa, tot

    cv_m, sk_m, fa_m, tot_m = _conv(mck)
    cv_c, sk_c, fa_c, tot_c = _conv(cbt)
    rate_m = cv_m / tot_m * 100 if tot_m else 0
    rate_c = cv_c / tot_c * 100 if tot_c else 0

    labels = [f"FT UGM / SK1\n(mck_qwen, {tot_m} file)",
              f"CBT DTI / SK2\n(cbt_qwen, {tot_c} file)"]
    x = np.arange(2)
    w = 0.45

    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5))
    fig.patch.set_facecolor("white")

    # --- Stacked bar ---
    ax1 = axes[0]
    conv_v = [cv_m, cv_c]
    skip_v = [sk_m, sk_c]
    fail_v = [fa_m, fa_c]
    totals = [tot_m, tot_c]

    ax1.bar(x, conv_v, w, color=OK_COLOR,   label="Converted", zorder=3)
    ax1.bar(x, skip_v, w, color=SKIP_COLOR, label="Skipped",
            bottom=conv_v, zorder=3)
    ax1.bar(x, fail_v, w, color=FAIL_COLOR, label="Failed",
            bottom=[c + s for c, s in zip(conv_v, skip_v)], zorder=3)

    for i, (c, s, f, tot) in enumerate(zip(conv_v, skip_v, fail_v, totals)):
        if c:
            ax1.text(x[i], c/2,      str(c), ha="center", va="center",
                     fontsize=11, color="white", fontweight="bold")
        if s:
            ax1.text(x[i], c + s/2,  str(s), ha="center", va="center",
                     fontsize=11, color="white", fontweight="bold")
        if f:
            ax1.text(x[i], c+s+f/2,  str(f), ha="center", va="center",
                     fontsize=11, color="white", fontweight="bold")
        ax1.text(x[i], tot + 8, f"n={tot}", ha="center", va="bottom",
                 fontsize=9, color=TEXT_C)

    ax1.set_title("Rector Conversion Results")
    ax1.set_ylabel("Jumlah File")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_ylim(0, max(totals) * 1.20)
    ax1.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14), ncol=3,
               framealpha=0.88, fontsize=9, edgecolor=SPINE_C)
    _style_ax(ax1)

    # --- Conversion rate bar ---
    ax2 = axes[1]
    rates  = [rate_m, rate_c]
    colors = [MCK_COLOR, CBT_COLOR]
    bars = ax2.bar(x, rates, w * 0.85, color=colors, zorder=3)
    for bar, rate in zip(bars, rates):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
                 f"{rate:.1f}%", ha="center", va="bottom",
                 fontsize=13, fontweight="bold", color=TEXT_C)

    ax2.set_title("Conversion Rate (%)")
    ax2.set_ylabel("Persentase (%)")
    ax2.set_ylim(0, 115)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=9.5)
    ax2.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax2.axhline(90, color=SPINE_C, linestyle="--", linewidth=0.8, zorder=1)
    ax2.text(1.28, 90.6, "90%", ha="right", fontsize=8, color=SPINE_C)
    _style_ax(ax2)

    fig.suptitle("Rector PHP 8.3 Migration -- FT UGM vs CBT DTI  (Qwen2.5-Coder:7b)",
                 fontsize=12, fontweight="bold", y=1.01)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _footer(fig)
    return _save(fig, "comparison_qwen_2_rector_conversion.png")


# ===========================================================================
# Chart 3 -- PHPStan errors by ISO control
# ===========================================================================

def chart3_phpstan(mck: dict, cbt: dict) -> Path:
    plt.rcParams.update(_RC)

    ana_mck = mck.get("analysis") or {}
    ana_cbt = cbt.get("analysis") or {}

    iso_mck  = ana_mck.get("by_iso_control", {})
    iso_cbt  = ana_cbt.get("by_iso_control", {})
    controls = sorted(set(list(iso_mck) + list(iso_cbt)))

    x = np.arange(len(controls))
    w = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("white")

    vals_mck = [iso_mck.get(c, 0) for c in controls]
    vals_cbt = [iso_cbt.get(c, 0) for c in controls]

    bars_mck = ax.bar(x - w/2, vals_mck, w,
                      label="FT UGM / SK1 (mck_qwen)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w,
                      label="CBT DTI / SK2 (cbt_qwen)", color=CBT_COLOR, zorder=3)

    y_max = max(max(vals_mck), max(vals_cbt)) if (vals_mck and vals_cbt) else 1
    offset = y_max * 0.018
    for bar, v in zip(bars_mck, vals_mck):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + offset,
                    f"{v:,}", ha="center", va="bottom", fontsize=9.5, color=TEXT_C)
    for bar, v in zip(bars_cbt, vals_cbt):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + offset,
                    f"{v:,}", ha="center", va="bottom", fontsize=9.5, color=TEXT_C)

    noise_mck = ana_mck.get("framework_noise_filtered", 0)
    noise_cbt = ana_cbt.get("framework_noise_filtered", 0)
    total_mck = ana_mck.get("total_errors", 0)
    total_cbt = ana_cbt.get("total_errors", 0)

    ax.set_title(
        "PHPStan Errors by ISO/IEC 27001:2022 Control\n"
        "(CI3 framework noise filtered; PHPStan level 5, PHP 8.3  --  Qwen2.5-Coder:7b)"
    )
    ax.set_ylabel("Jumlah Error")
    ax.set_xticks(x)
    ax.set_xticklabels(controls, fontsize=10)
    ax.set_ylim(0, y_max * 1.28)
    ax.legend(framealpha=0.85, fontsize=9)
    _style_ax(ax)

    ax.text(0.02, 0.05,
            f"Total errors: FT UGM = {total_mck:,}  |  CBT DTI = {total_cbt:,}\n"
            f"CI3 noise filtered: FT UGM = {noise_mck:,}  |  CBT DTI = {noise_cbt:,}",
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=8, color="#555555",
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white",
                      edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _footer(fig)
    return _save(fig, "comparison_qwen_3_phpstan_iso.png")


# ===========================================================================
# Chart 4 -- Ringkasan perbandingan (summary table)
# ===========================================================================

def chart4_summary(mck: dict, cbt: dict) -> Path:
    plt.rcParams.update(_RC)

    pre_mck  = mck.get("pre_scan",   {})
    pre_cbt  = cbt.get("pre_scan",   {})
    post_mck = mck.get("post_scan",  {})
    post_cbt = cbt.get("post_scan",  {})
    conv_mck = mck.get("conversion", {})
    conv_cbt = cbt.get("conversion", {})
    ana_mck  = mck.get("analysis",   {})
    ana_cbt  = cbt.get("analysis",   {})

    cv_m = conv_mck.get("converted", 0)
    sk_m = conv_mck.get("skipped",   0)
    fa_m = conv_mck.get("failed",    0)
    tot_m = conv_mck.get("total_files", cv_m + sk_m + fa_m)

    cv_c = conv_cbt.get("converted", 0)
    sk_c = conv_cbt.get("skipped",   0)
    fa_c = conv_cbt.get("failed",    0)
    tot_c = conv_cbt.get("total_files", cv_c + sk_c + fa_c)

    rate_m = f"{cv_m/tot_m*100:.1f}%" if tot_m else "-"
    rate_c = f"{cv_c/tot_c*100:.1f}%" if tot_c else "-"

    pre_tot_m  = pre_mck.get("total_findings", 0)
    pre_tot_c  = pre_cbt.get("total_findings", 0)
    post_tot_m = post_mck.get("total_findings", 0)
    post_tot_c = post_cbt.get("total_findings", 0)
    delta_m    = post_tot_m - pre_tot_m
    delta_c    = post_tot_c - pre_tot_c

    sqli_m = pre_mck.get("by_vuln_type", {}).get("SQL Injection", 0)
    sqli_c = pre_cbt.get("by_vuln_type", {}).get("SQL Injection", 0)
    ssrf_m = pre_mck.get("by_vuln_type", {}).get("SSRF", 0)
    ssrf_c = pre_cbt.get("by_vuln_type", {}).get("SSRF", 0)

    total_err_m = ana_mck.get("total_errors", 0)
    total_err_c = ana_cbt.get("total_errors", 0)
    noise_m     = ana_mck.get("framework_noise_filtered", 0)
    noise_c     = ana_cbt.get("framework_noise_filtered", 0)
    ai_m        = mck.get("ai_recommendations_count", 0)
    ai_c        = cbt.get("ai_recommendations_count", 0)

    rows = [
        ("Metrik",                     "FT UGM / SK1\n(mck_qwen)",      "CBT DTI / SK2\n(cbt_qwen)"),
        ("File PHP dianalisis",         str(tot_m),                       str(tot_c)),
        ("Semgrep findings (pre)",      str(pre_tot_m),                   str(pre_tot_c)),
        ("  -- SQL Injection",          str(sqli_m),                      str(sqli_c) + " (CI3 core)"),
        ("  -- SSRF",                   str(ssrf_m),                      str(ssrf_c) + " (CI3 core)"),
        ("Semgrep delta (post-pre)",    f"{delta_m:+d} (stabil)",         f"{delta_c:+d} (stabil)"),
        ("Rector converted",            f"{cv_m} ({rate_m})",             f"{cv_c} ({rate_c})"),
        ("Rector skipped",              str(sk_m),                        str(sk_c)),
        ("Rector failed",               f"{fa_m} (Fiber bug)",            f"{fa_c} (Fiber bug)"),
        ("PHPStan total errors",        f"{total_err_m:,}",               f"{total_err_c:,}"),
        ("  CI3 noise filtered",        f"{noise_m:,}",                   f"{noise_c:,}"),
        ("AI recommendations",          f"{ai_m} (Qwen2.5-Coder:7b)",    f"{ai_c} (Qwen2.5-Coder:7b)"),
        ("ISO overall status",          "NON-COMPLIANT",                  "NON-COMPLIANT"),
        ("Kode aplikasi custom (Semgrep)", "0 findings",                  "0 findings"),
    ]

    fig, ax = plt.subplots(figsize=(13, 7))
    fig.patch.set_facecolor("white")
    ax.axis("off")

    col_x  = [0.0, 0.38, 0.69]
    row_h  = 0.058
    start_y = 0.94

    for i, row in enumerate(rows):
        y      = start_y - i * row_h
        is_hdr = (i == 0)

        for j, cell in enumerate(row):
            w_col = (col_x[j+1] if j+1 < len(col_x) else 1.01) - col_x[j]

            if is_hdr:
                ax.add_patch(mpatches.FancyBboxPatch(
                    (col_x[j] - 0.005, y - 0.032), w_col + 0.002, 0.058,
                    boxstyle="round,pad=0.01",
                    facecolor=MCK_COLOR if j == 1 else (CBT_COLOR if j == 2 else "#1A1A1A"),
                    edgecolor="none",
                    transform=ax.transAxes, clip_on=False,
                ))
                ax.text(col_x[j] + 0.01, y, cell,
                        transform=ax.transAxes, fontsize=9,
                        fontweight="bold", color="white", va="center",
                        multialignment="center")
            else:
                if i % 2 == 0:
                    ax.add_patch(mpatches.FancyBboxPatch(
                        (-0.005, y - 0.032), 1.01, 0.058,
                        boxstyle="square,pad=0",
                        facecolor="#F5F5F5", edgecolor="none",
                        transform=ax.transAxes, clip_on=False,
                    ))
                is_indent = cell.startswith("  ")
                ax.text(col_x[j] + 0.01, y, cell,
                        transform=ax.transAxes,
                        fontsize=8.5 if not is_indent else 8,
                        color="#555555" if is_indent else TEXT_C,
                        va="center")

    ax.set_title(
        "Ringkasan Perbandingan Pipeline -- FT UGM (SK1) vs CBT DTI (SK2)\n"
        "Model AI: Qwen2.5-Coder:7b  |  PHP 8.3  |  PHPStan Level 5",
        fontsize=12, pad=14,
    )

    note_y = start_y - len(rows) * row_h - 0.015
    ax.text(0.0, note_y,
            "* PHPStan errors: mayoritas CI3 framework false positive (magic props, runtime constants)\n"
            "* Delta Semgrep = 0 untuk kedua SK: Rector tidak memperkenalkan/menghilangkan vulnerability\n"
            "* Semua Semgrep findings berasal dari CI3 system/core/Output.php -- bukan kode aplikasi custom",
            transform=ax.transAxes, fontsize=7.5, color="#888888", va="top")

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig)
    return _save(fig, "comparison_qwen_4_summary.png")


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    mck = _load(MCK_JSON)
    cbt = _load(CBT_JSON)

    print("=" * 62)
    print("Comparison SK1 vs SK2 -- Qwen2.5-Coder:7b charts")
    print(f"  SK1 : {MCK_JSON.relative_to(ROOT)}")
    print(f"  SK2 : {CBT_JSON.relative_to(ROOT)}")
    print(f"  Out : {OUT_DIR.relative_to(ROOT)}")
    print("=" * 62)

    charts = [
        chart1_semgrep(mck, cbt),
        chart2_rector(mck, cbt),
        chart3_phpstan(mck, cbt),
        chart4_summary(mck, cbt),
    ]

    for p in charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(charts)} charts saved.")


if __name__ == "__main__":
    main()
