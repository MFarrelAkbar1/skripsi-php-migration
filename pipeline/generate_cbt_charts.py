"""
generate_cbt_charts.py -- Generate charts untuk Studi Kasus 2 (CBT DTI, cbt_full run)
dan 4 chart perbandingan SK1 (FT UGM) vs SK2 (CBT DTI full).

DTI charts (each split into 2 separate files):
  contents/chapter-4/dti/pipeline_chart_cbt_full_1a_semgrep_severity.png
  contents/chapter-4/dti/pipeline_chart_cbt_full_1b_semgrep_vulntype.png
  contents/chapter-4/dti/pipeline_chart_cbt_full_2a_rector_bar.png
  contents/chapter-4/dti/pipeline_chart_cbt_full_2b_rector_pie.png
  contents/chapter-4/dti/pipeline_chart_cbt_full_3a_phpstan_bar.png
  contents/chapter-4/dti/pipeline_chart_cbt_full_3b_iso_compliance.png

Comparison charts:
  contents/chapter-4/comparison/comparison_1_semgrep_findings.png
  contents/chapter-4/comparison/comparison_2_rector_conversion.png
  contents/chapter-4/comparison/comparison_3_phpstan_iso.png
  contents/chapter-4/comparison/comparison_4_composer_summary.png

Data source:
  SK1 (FT UGM): reports/pipeline_result_20260425_120423.json  (April 25, 245 file, level 5)
  SK2 (CBT DTI): reports/cbt_full/pipeline_result_20260519_220557.json
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

ROOT = Path(__file__).parent.parent
SK1_JSON     = ROOT / "reports" / "pipeline_result_20260425_120423.json"
SK2_JSON     = ROOT / "reports" / "cbt_full" / "pipeline_result_20260519_220557.json"
SK2_ISO_JSON = ROOT / "reports" / "cbt_full" / "iso_report_20260519_220557.json"

OUT_DTI = ROOT / "contents" / "chapter-4" / "dti"
OUT_CMP = ROOT / "contents" / "chapter-4" / "comparison"

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

MCK_COLOR  = "#2166AC"
CBT_COLOR  = "#D7191C"
OK_COLOR   = "#4DAC26"
SKIP_COLOR = "#E66101"
FAIL_COLOR = "#D7191C"
SAFE_COLOR = "#4DAC26"
MR_COLOR   = "#E66101"
PRE_COLOR  = "#2166AC"
POST_COLOR = "#D7191C"

GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

ISO_STATUS_COLORS = {
    "COMPLIANT":     "#4DAC26",
    "NON_COMPLIANT": "#D7191C",
    "PARTIAL":       "#E66101",
}

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


def _footer(fig: plt.Figure, source: str) -> None:
    fig.text(
        0.5, 0.01,
        f"Source: {source}  |  Skripsi Muhammad Farrel Akbar",
        ha="center", fontsize=7.5, color="#888888",
    )


def _cmp_footer(fig: plt.Figure) -> None:
    fig.text(
        0.5, 0.01,
        "Source: pipeline_result JSON  |  Skripsi Muhammad Farrel Akbar  --  FT UGM (SK1) vs CBT DTI (SK2)",
        ha="center", fontsize=7.5, color="#888888",
    )


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(fig: plt.Figure, out: Path, dpi: int = 150) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ===========================================================================
# DTI Charts (each as a single, full-size figure)
# ===========================================================================

# ---------------------------------------------------------------------------
# 1a: Semgrep -- Pre vs Post by Severity
# ---------------------------------------------------------------------------

def dti_1a_semgrep_severity(data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    pre  = data.get("pre_scan",  {})
    post = data.get("post_scan", {})

    pre_total  = pre.get("total_findings", 0)
    post_total = post.get("total_findings", 0)
    delta      = post_total - pre_total

    pre_sev  = pre.get("by_severity", {})
    post_sev = post.get("by_severity", {})
    sev_keys = sorted(set(list(pre_sev) + list(post_sev)),
                      key=lambda s: {"ERROR": 0, "WARNING": 1}.get(s, 9))

    cats      = ["Total"] + sev_keys
    pre_vals  = [pre_total]  + [pre_sev.get(s, 0)  for s in sev_keys]
    post_vals = [post_total] + [post_sev.get(s, 0) for s in sev_keys]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("white")

    x = np.arange(len(cats))
    w = 0.35
    b1 = ax.bar(x - w/2, pre_vals,  w, label="Pre-Conversion",  color=PRE_COLOR,  alpha=0.85, edgecolor="white", zorder=3)
    b2 = ax.bar(x + w/2, post_vals, w, label="Post-Conversion", color=POST_COLOR, alpha=0.85, edgecolor="white", zorder=3)

    for bar, v in zip(b1, pre_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.15,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)
    for bar, v in zip(b2, post_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.15,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)

    delta_str = f"+{delta}" if delta > 0 else str(delta)
    ax.set_title(f"Semgrep Security Findings: Pre vs Post-Conversion\n(CBT DTI -- Delta = {delta_str})", pad=10)
    ax.set_ylabel("Jumlah Temuan")
    ax.set_xticks(x)
    ax.set_xticklabels(cats, fontsize=10)
    ax.set_ylim(0, max(max(pre_vals), max(post_vals)) * 1.25)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C,
              loc="upper left", bbox_to_anchor=(0.01, 0.99))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    _style_ax(ax, "v")

    # Annotation in figure space below axes -- avoids any bar overlap
    fig.text(0.99, 0.07,
             "Semua findings berasal dari system/core/Output.php (CI3 framework)\n"
             "Kode aplikasi CBT custom = 0 Semgrep findings",
             ha="right", va="bottom",
             fontsize=8, color="#555555", style="italic",
             bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.15, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_1a_semgrep_severity.png")


# ---------------------------------------------------------------------------
# 1b: Semgrep -- By Vulnerability Type
# ---------------------------------------------------------------------------

def dti_1b_semgrep_vulntype(data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    pre  = data.get("pre_scan",  {})
    post = data.get("post_scan", {})

    pre_vt  = pre.get("by_vuln_type", {})
    post_vt = post.get("by_vuln_type", {})
    all_types = sorted(set(list(pre_vt) + list(post_vt)))
    if not all_types:
        all_types = ["(no findings)"]

    vals_pre  = [pre_vt.get(t, 0)  for t in all_types]
    vals_post = [post_vt.get(t, 0) for t in all_types]

    fig, ax = plt.subplots(figsize=(8, max(4, len(all_types) * 1.4 + 1.8)))
    fig.patch.set_facecolor("white")

    y = np.arange(len(all_types))
    h = 0.35
    bh1 = ax.barh(y + h/2, vals_pre,  h, label="Pre-Conversion",  color=PRE_COLOR,  alpha=0.85, edgecolor="white", zorder=3)
    bh2 = ax.barh(y - h/2, vals_post, h, label="Post-Conversion", color=POST_COLOR, alpha=0.85, edgecolor="white", zorder=3)

    x_max = max(max(vals_pre), max(vals_post)) if (vals_pre or vals_post) else 1
    for bar, v in zip(bh1, vals_pre):
        if v > 0:
            ax.text(bar.get_width() + x_max * 0.02, bar.get_y() + bar.get_height()/2,
                    str(v), va="center", fontsize=11, fontweight="bold", color=PRE_COLOR)
    for bar, v in zip(bh2, vals_post):
        if v > 0:
            ax.text(bar.get_width() + x_max * 0.02, bar.get_y() + bar.get_height()/2,
                    str(v), va="center", fontsize=11, fontweight="bold", color=POST_COLOR)

    ax.set_yticks(y)
    ax.set_yticklabels(all_types, fontsize=11)
    ax.set_xlabel("Jumlah Temuan")
    ax.set_xlim(0, x_max * 1.25)
    ax.set_title("Semgrep Findings by Vulnerability Type\n(CBT DTI -- Pre vs Post-Conversion)", pad=10)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C, loc="lower right")
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    _style_ax(ax, "h")

    ax.text(0.99, 0.55,
            "Seluruh 11 findings berasal dari\nsystem/core/Output.php (CI3 framework)\nKode aplikasi CBT custom = 0 findings",
            transform=ax.transAxes, ha="right", va="center",
            fontsize=8.5, color="#555555", style="italic",
            bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_1b_semgrep_vulntype.png")


# ---------------------------------------------------------------------------
# 2a: Rector -- Stacked Bar (style matches pipeline_result_chart.py)
# ---------------------------------------------------------------------------

def dti_2a_rector_bar(data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    conv      = data.get("conversion", {})
    converted = conv.get("converted", 0)
    skipped   = conv.get("skipped",   0)
    failed    = conv.get("failed",    0)
    total     = conv.get("total_files", converted + skipped + failed)
    cr_pct    = converted / total * 100 if total else 0.0

    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor("white")

    x = np.array([0.0])
    w = 0.5
    b1 = ax.bar(x, [converted], w, label=f"Converted ({converted})", color=OK_COLOR,   alpha=0.87, edgecolor="white", zorder=3)
    b2 = ax.bar(x, [skipped],   w, label=f"Skipped ({skipped})",     color=SKIP_COLOR, alpha=0.82, edgecolor="white", bottom=[converted], zorder=3)
    b3 = ax.bar(x, [failed],    w, label=f"Failed ({failed})",       color=FAIL_COLOR, alpha=0.82, edgecolor="white", bottom=[converted + skipped], zorder=3)

    # % labels inside each segment
    if converted > 0:
        ax.text(0, converted / 2, f"{cr_pct:.1f}%",
                ha="center", va="center", fontsize=14, color="white", fontweight="bold")
    if skipped > 0:
        ax.text(0, converted + skipped / 2, f"{skipped/total*100:.1f}%",
                ha="center", va="center", fontsize=12, color="white", fontweight="bold")
    if failed > 0:
        ax.text(0, converted + skipped + failed / 2, f"{failed/total*100:.1f}%",
                ha="center", va="center", fontsize=11, color="white", fontweight="bold")

    ax.set_xticks([0])
    ax.set_xticklabels([f"Total: {total} files"], fontsize=11)
    ax.set_ylabel("Number of Files", fontsize=10)
    ax.set_ylim(0, total * 1.18)
    ax.set_title("Rector PHP Migration: Conversion Result Summary\n(CBT DTI, cbt_full -- Target PHP 8.3)", pad=10)
    ax.legend(fontsize=9.5, frameon=True, framealpha=0.9, edgecolor=GRID_C,
              loc="upper right")
    _style_ax(ax, "v")

    ax.text(0.5, 1.005,
            f"Conversion Rate: {cr_pct:.1f}%",
            transform=ax.transAxes, ha="center", va="bottom",
            fontsize=12, fontweight="bold", color=OK_COLOR)

    ax.text(0.5, -0.07,
            "2 failures: captcha_helper.php & form_helper.php\n(known Rector Fiber bug -- bukan error kode CBT)",
            transform=ax.transAxes, ha="center", va="top",
            fontsize=8, color="#888888", style="italic")

    fig.tight_layout(rect=[0, 0.08, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_2a_rector_bar.png")


# ---------------------------------------------------------------------------
# 2b: Rector -- Pie Chart
# ---------------------------------------------------------------------------

def dti_2b_rector_pie(data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    conv      = data.get("conversion", {})
    converted = conv.get("converted", 0)
    skipped   = conv.get("skipped",   0)
    failed    = conv.get("failed",    0)
    total     = conv.get("total_files", converted + skipped + failed)

    fig, ax = plt.subplots(figsize=(7, 8))
    fig.patch.set_facecolor("white")

    sizes   = [converted, skipped, failed]
    colors  = [OK_COLOR, SKIP_COLOR, FAIL_COLOR]
    explode = (0.02, 0.05, 0.10)
    labels  = [
        f"Converted\n({converted} files, {converted/total*100:.1f}%)",
        f"Skipped\n({skipped} files, {skipped/total*100:.1f}%)",
        f"Failed\n({failed} files, {failed/total*100:.1f}%)",
    ]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=None, colors=colors,
        autopct="%1.1f%%", startangle=90,
        explode=explode,
        wedgeprops=dict(linewidth=1.5, edgecolor="white"),
        textprops=dict(fontsize=10),
        pctdistance=0.75,
    )
    for at in autotexts:
        at.set_fontsize(12)
        at.set_fontweight("bold")
        at.set_color("white")

    patches = [mpatches.Patch(color=c, label=l) for c, l in zip(colors, labels)]
    # loc="upper center": the legend's top-center anchor sits just below the axes
    ax.legend(handles=patches, loc="upper center",
              bbox_to_anchor=(0.5, -0.04), ncol=1, framealpha=0.88, fontsize=9.5,
              edgecolor=SPINE_C)

    ax.set_title("Proporsi Hasil Konversi Rector\n(CBT DTI, cbt_full -- Target PHP 8.3)", pad=10)

    # Force pie axes into the upper portion so the legend has clear space below
    fig.subplots_adjust(left=0.05, right=0.95, bottom=0.36, top=0.92)

    fig.text(0.5, 0.05,
             "2 failures: captcha_helper.php & form_helper.php\n"
             "(known Rector Fiber bug -- bukan error kode CBT)",
             ha="center", va="bottom",
             fontsize=8, color="#888888", style="italic")
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_2b_rector_pie.png")


# ---------------------------------------------------------------------------
# 3a: PHPStan -- Errors by ISO Control (horizontal bar)
# ---------------------------------------------------------------------------

def dti_3a_phpstan_bar(data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)
    analysis       = data.get("analysis", {})
    total_errors   = analysis.get("total_errors", 0)
    noise_filtered = analysis.get("framework_noise_filtered", 0)
    net_errors     = total_errors - noise_filtered
    by_iso         = analysis.get("by_iso_control", {})
    php_ver        = analysis.get("php_version", "8.3")
    level          = analysis.get("phpstan_level", 5)

    controls = list(by_iso.keys())
    counts   = [by_iso[c] for c in controls]
    ISO_BAR_COLORS = ["#2166AC", "#7B3294"]
    colors   = [ISO_BAR_COLORS[i % len(ISO_BAR_COLORS)] for i in range(len(controls))]

    fig, ax = plt.subplots(figsize=(9, max(4.5, len(controls) * 1.2 + 2)))
    fig.patch.set_facecolor("white")

    y    = np.arange(len(controls))
    bars = ax.barh(y, counts, 0.5, color=colors, alpha=0.85, edgecolor="white", zorder=3)

    x_max = max(counts) if counts else 1
    for bar, v in zip(bars, counts):
        pct = v / total_errors * 100 if total_errors else 0
        ax.text(bar.get_width() + x_max * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{v:,}  ({pct:.1f}%)",
                va="center", fontsize=10, color=TEXT_C, fontweight="bold")

    ax.set_yticks(y)
    ax.set_yticklabels(controls, fontsize=11)
    ax.set_xlabel("Jumlah Error / Warning", fontsize=10)
    ax.set_xlim(0, x_max * 1.30)
    ax.set_title(
        f"PHPStan Static Analysis by ISO 27001:2022 Control\n"
        f"PHP {php_ver}  |  Level {level}  |  Total: {total_errors:,}  |  Net (CI3 filtered): {net_errors:,}",
        pad=10, fontsize=11,
    )
    _style_ax(ax, "h")

    # Annotation at bottom-left to avoid overlapping bars
    ax.text(0.02, 0.05,
            f"CI3 framework noise filtered: {noise_filtered:,}\n"
            "(false positives: magic props, runtime constants, CI3 helpers)",
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=8.5, color="#555555", style="italic",
            bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_3a_phpstan_bar.png")


# ---------------------------------------------------------------------------
# 3b: ISO 27001:2022 Compliance Status Table
# ---------------------------------------------------------------------------

def dti_3b_iso_compliance(iso_data: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)

    ISO_ORDER  = ["A.5.17", "A.8.24", "A.8.25", "A.8.26", "A.8.28", "A.8.29"]
    ISO_TITLES = {
        "A.5.17": "Authentication Information",
        "A.8.24": "Use of Cryptography",
        "A.8.25": "Secure Development Lifecycle",
        "A.8.26": "Application Security Requirements",
        "A.8.28": "Secure Coding",
        "A.8.29": "Security Testing in Development",
    }
    ISO_STATUS_SYMB = {
        "COMPLIANT":     "COMPLIANT",
        "NON_COMPLIANT": "NON-COMPLIANT",
        "PARTIAL":       "PARTIAL",
    }

    controls_data = iso_data.get("controls", {})

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("white")
    ax.axis("off")

    # Column positions
    col_x = [0.03, 0.17, 0.60, 0.76, 0.88]
    headers = ["Kontrol", "Judul Kontrol", "Temuan", "Status", ""]
    row_h   = 0.115
    start_y = 0.88

    # Header
    for j, hdr in enumerate(headers[:4]):
        ax.add_patch(mpatches.FancyBboxPatch(
            (col_x[j] - 0.01, start_y - 0.045), col_x[j+1] - col_x[j] - 0.005, 0.075,
            boxstyle="round,pad=0.01",
            facecolor="#2166AC", edgecolor="none",
            transform=ax.transAxes, clip_on=False,
        ))
        ax.text(col_x[j] + 0.005, start_y, hdr,
                transform=ax.transAxes,
                fontsize=10, fontweight="bold", color="white", va="center")

    for i, ctrl_id in enumerate(ISO_ORDER):
        ctrl        = controls_data.get(ctrl_id, {})
        status      = ctrl.get("status", "N/A")
        findings    = ctrl.get("findings_count", 0)
        title       = ISO_TITLES.get(ctrl_id, ctrl_id)
        s_color     = ISO_STATUS_COLORS.get(status, "#888888")
        s_label     = ISO_STATUS_SYMB.get(status, status)

        row_y = start_y - (i + 1) * row_h

        # Alternating background
        bg_color = "#F0F4FA" if i % 2 == 0 else "#FFFFFF"
        ax.add_patch(mpatches.FancyBboxPatch(
            (col_x[0] - 0.01, row_y - 0.048), 1.02 - col_x[0], 0.082,
            boxstyle="square,pad=0",
            facecolor=bg_color, edgecolor="none",
            transform=ax.transAxes, clip_on=False,
        ))

        ax.text(col_x[0] + 0.005, row_y, ctrl_id,
                transform=ax.transAxes, fontsize=10, fontweight="bold", va="center", color=TEXT_C)
        ax.text(col_x[1] + 0.005, row_y, title,
                transform=ax.transAxes, fontsize=9.5, va="center", color=TEXT_C)
        ax.text(col_x[2] + 0.005, row_y, f"{findings:,}",
                transform=ax.transAxes, fontsize=10, va="center", color=TEXT_C,
                fontweight="bold" if findings > 0 else "normal")

        # Status badge
        ax.add_patch(mpatches.FancyBboxPatch(
            (col_x[3] - 0.005, row_y - 0.035), 0.31, 0.060,
            boxstyle="round,pad=0.02",
            facecolor=s_color, edgecolor="none", alpha=0.18,
            transform=ax.transAxes, clip_on=False,
        ))
        ax.text(col_x[3] + 0.005, row_y, s_label,
                transform=ax.transAxes, fontsize=9, fontweight="bold",
                va="center", color=s_color)

    ax.set_title(
        "ISO/IEC 27001:2022 Compliance Status\n(CBT DTI -- cbt_full run, PHP 8.3)",
        pad=16, fontsize=12,
    )

    overall = iso_data.get("overall_status", "NON_COMPLIANT")
    o_color = ISO_STATUS_COLORS.get(overall, "#D7191C")
    total_f = iso_data.get("total_findings", 0)
    crit_f  = iso_data.get("critical_findings", 0)
    ax.text(0.5, 0.03,
            f"Overall Status: {overall.replace('_', '-')}  |  Total findings: {total_f:,}  |  Critical: {crit_f:,}",
            transform=ax.transAxes, ha="center", va="bottom",
            fontsize=10.5, fontweight="bold", color=o_color)

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _footer(fig, SK2_ISO_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_full_3b_iso_compliance.png")


# ===========================================================================
# Comparison Charts
# ===========================================================================

# ---------------------------------------------------------------------------
# Comparison 1: Semgrep Findings -- annotation moved to lower-left
# ---------------------------------------------------------------------------

def cmp_chart1_semgrep(mck: dict, cbt: dict, out_dir: Path) -> Path:
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

    bars_mck = ax.bar(x - w/2, vals_mck, w, label="FT UGM / SK1 (mck)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w, label="CBT DTI / SK2 (cbt_full)", color=CBT_COLOR, zorder=3)

    y_max = max(max(vals_mck), max(vals_cbt)) if (vals_mck and vals_cbt) else 1
    for bar, v in zip(bars_mck, vals_mck):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + y_max * 0.015,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)
    for bar, v in zip(bars_cbt, vals_cbt):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + y_max * 0.015,
                    str(v), ha="center", va="bottom", fontsize=10, fontweight="bold", color=TEXT_C)

    ax.set_title("Semgrep Security Findings (Pre-Conversion)\nby Vulnerability Type")
    ax.set_ylabel("Jumlah Temuan")
    ax.set_xticks(x)
    ax.set_xticklabels(all_types, fontsize=10)
    ax.set_ylim(0, y_max * 1.30)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.legend(framealpha=0.85, fontsize=9)
    _style_ax(ax)

    # Annotation at BOTTOM-LEFT to avoid covering bar labels
    total_mck = pre_mck.get("total_findings", 0)
    total_cbt = pre_cbt.get("total_findings", 0)
    ax.text(0.02, 0.05,
            f"Total: FT UGM = {total_mck}  |  CBT DTI = {total_cbt}\n"
            "CBT: semua findings berasal dari CI3 system/core/Output.php",
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=8, color="#555555",
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _cmp_footer(fig)
    return _save(fig, out_dir / "comparison_1_semgrep_findings.png", dpi=180)


# ---------------------------------------------------------------------------
# Comparison 2: Rector Conversion -- legend below stacked bar, no overlap
# ---------------------------------------------------------------------------

def cmp_chart2_rector(mck: dict, cbt: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)

    def _conv(d: dict) -> tuple[int, int, int]:
        c = d.get("conversion") or {}
        return c.get("converted", 0), c.get("skipped", 0), c.get("failed", 0)

    cv_m, sk_m, fa_m = _conv(mck)
    cv_c, sk_c, fa_c = _conv(cbt)
    tot_m = cv_m + sk_m + fa_m
    tot_c = cv_c + sk_c + fa_c
    rate_m = cv_m / tot_m * 100 if tot_m else 0
    rate_c = cv_c / tot_c * 100 if tot_c else 0

    labels = ["FT UGM / SK1\n(mck, 245 file)", "CBT DTI / SK2\n(cbt_full, 326 file)"]
    x = np.arange(len(labels))
    w = 0.45

    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5))
    fig.patch.set_facecolor("white")

    # --- Left: stacked bar ---
    ax1 = axes[0]
    conv_v = [cv_m, cv_c]
    skip_v = [sk_m, sk_c]
    fail_v = [fa_m, fa_c]
    totals = [tot_m, tot_c]

    b1 = ax1.bar(x, conv_v, w, color=OK_COLOR,   label="Converted", zorder=3)
    b2 = ax1.bar(x, skip_v, w, color=SKIP_COLOR, label="Skipped",
                 bottom=conv_v, zorder=3)
    b3 = ax1.bar(x, fail_v, w, color=FAIL_COLOR, label="Failed",
                 bottom=[c+s for c, s in zip(conv_v, skip_v)], zorder=3)

    for i, (c, s, f, tot) in enumerate(zip(conv_v, skip_v, fail_v, totals)):
        if c: ax1.text(x[i], c/2,       str(c), ha="center", va="center", fontsize=11, color="white", fontweight="bold")
        if s: ax1.text(x[i], c+s/2,     str(s), ha="center", va="center", fontsize=11, color="white", fontweight="bold")
        if f: ax1.text(x[i], c+s+f/2,   str(f), ha="center", va="center", fontsize=11, color="white", fontweight="bold")
        ax1.text(x[i], tot + 8, f"n={tot}", ha="center", va="bottom", fontsize=9, color=TEXT_C)

    ax1.set_title("Rector Conversion Results")
    ax1.set_ylabel("Jumlah File")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9.5)
    ax1.set_ylim(0, max(totals) * 1.20)
    # Legend BELOW the plot area -- avoids covering bars
    ax1.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14), ncol=3,
               framealpha=0.88, fontsize=9, edgecolor=SPINE_C)
    _style_ax(ax1)

    # --- Right: conversion rate bar ---
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
    ax2.text(len(labels) - 1 + 0.28, 90.6, "90%", ha="right", fontsize=8, color=SPINE_C)
    _style_ax(ax2)

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _cmp_footer(fig)
    return _save(fig, out_dir / "comparison_2_rector_conversion.png", dpi=180)


# ---------------------------------------------------------------------------
# Comparison 3: PHPStan -- annotation moved to bottom-left
# ---------------------------------------------------------------------------

def cmp_chart3_phpstan(mck: dict, cbt: dict, out_dir: Path) -> Path:
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

    bars_mck = ax.bar(x - w/2, vals_mck, w, label="FT UGM / SK1 (mck)", color=MCK_COLOR, zorder=3)
    bars_cbt = ax.bar(x + w/2, vals_cbt, w, label="CBT DTI / SK2 (cbt_full)", color=CBT_COLOR, zorder=3)

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

    ax.set_title(
        "PHPStan Errors by ISO/IEC 27001:2022 Control\n"
        "(CI3 framework noise filtered; PHPStan level 5, PHP 8.3)"
    )
    ax.set_ylabel("Jumlah Error")
    ax.set_xticks(x)
    ax.set_xticklabels(controls, fontsize=10)
    ax.set_ylim(0, y_max * 1.28)
    ax.legend(framealpha=0.85, fontsize=9)
    _style_ax(ax)

    # Annotation at BOTTOM-LEFT -- no overlap with bar labels at top
    noise_mck = ana_mck.get("framework_noise_filtered", 0)
    noise_cbt = ana_cbt.get("framework_noise_filtered", 0)
    total_mck = ana_mck.get("total_errors", 0)
    total_cbt = ana_cbt.get("total_errors", 0)
    ax.text(0.02, 0.05,
            f"Total errors: FT UGM = {total_mck:,}  |  CBT DTI = {total_cbt:,}\n"
            f"CI3 noise filtered: FT UGM = {noise_mck:,}  |  CBT DTI = {noise_cbt:,}",
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=8, color="#555555",
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _cmp_footer(fig)
    return _save(fig, out_dir / "comparison_3_phpstan_iso.png", dpi=180)


# ---------------------------------------------------------------------------
# Comparison 4: Composer + Summary Table -- bigger, cleaner (like old chart)
# ---------------------------------------------------------------------------

def cmp_chart4_composer_summary(mck: dict, cbt: dict, out_dir: Path) -> Path:
    plt.rcParams.update(_RC)

    fig, axes = plt.subplots(1, 2, figsize=(13, 6))
    fig.patch.set_facecolor("white")

    # --- Left: Composer pie (FT UGM only) ---
    ax1 = axes[0]
    comp_mck = mck.get("composer_analysis", {})
    safe_n = comp_mck.get("safe_count",   3)
    mr_n   = comp_mck.get("issues_count", 2)

    wedges, texts, autotexts = ax1.pie(
        [safe_n, mr_n],
        labels=None,
        colors=[SAFE_COLOR, MR_COLOR],
        autopct="%1.0f%%", startangle=90,
        wedgeprops=dict(linewidth=2.0, edgecolor="white"),
        pctdistance=0.65,
    )
    for at in autotexts:
        at.set_fontsize(14)
        at.set_fontweight("bold")
        at.set_color("white")

    patches_pie = [
        mpatches.Patch(color=SAFE_COLOR, label=f"SAFE ({safe_n} packages)"),
        mpatches.Patch(color=MR_COLOR,   label=f"MANUAL REVIEW ({mr_n} packages)"),
    ]
    ax1.legend(handles=patches_pie, loc="lower center",
               bbox_to_anchor=(0.5, -0.18), ncol=1, framealpha=0.88, fontsize=10,
               edgecolor=SPINE_C)
    ax1.set_title("Composer Dependency PHP 8.x Status\nFT UGM / SK1 (mck) -- 5 Packages", fontsize=11)

    # Package names listed below
    ax1.text(0.5, -0.36,
             "SAFE: vlucas/phpdotenv, phpoffice/phpspreadsheet, firebase/php-jwt\n"
             "MANUAL REVIEW: ngekoding/google-login, chriskacerguis/codeigniter-restserver\n\n"
             "CBT DTI / SK2: composer.json ada (>=7.0)\nRequire block: tidak ada application-level packages",
             transform=ax1.transAxes, ha="center", va="top",
             fontsize=8.5, color="#555555", style="italic")

    # --- Right: Summary comparison table ---
    ax2 = axes[1]
    ax2.axis("off")

    pre_mck  = mck.get("pre_scan",  {})
    pre_cbt  = cbt.get("pre_scan",  {})
    conv_mck = mck.get("conversion", {})
    conv_cbt = cbt.get("conversion", {})
    ana_mck  = mck.get("analysis",  {})
    ana_cbt  = cbt.get("analysis",  {})

    cv_m = conv_mck.get("converted", 0); sk_m = conv_mck.get("skipped", 0); fa_m = conv_mck.get("failed", 0)
    cv_c = conv_cbt.get("converted", 0); sk_c = conv_cbt.get("skipped", 0); fa_c = conv_cbt.get("failed", 0)
    tot_m = cv_m + sk_m + fa_m
    tot_c = cv_c + sk_c + fa_c
    rate_m = f"{cv_m/tot_m*100:.1f}%" if tot_m else "-"
    rate_c = f"{cv_c/tot_c*100:.1f}%" if tot_c else "-"

    rows = [
        ("Metrik",                    "FT UGM (mck)",                  "CBT DTI"),
        ("File PHP (custom)",         str(tot_m),                       str(tot_c)),
        ("Semgrep findings (pre)",    str(pre_mck.get("total_findings", 0)), str(pre_cbt.get("total_findings", 0))),
        ("  -- SQL Injection",        str(pre_mck.get("by_vuln_type",{}).get("SQL Injection",0)), "1 (CI3 core)"),
        ("  -- SSRF",                 str(pre_mck.get("by_vuln_type",{}).get("SSRF",0)),         "10 (CI3 core)"),
        ("Semgrep delta",             "+7 (regresi Rector)",            "0 (stabil)"),
        ("Rector converted",          f"{cv_m} ({rate_m})",             f"{cv_c} ({rate_c})"),
        ("Rector failed",             str(fa_m),                        f"{fa_c} (Reactor bug)"),
        ("PHPStan total errors*",     f"{ana_mck.get('total_errors',0):,}", f"{ana_cbt.get('total_errors',0):,}"),
        ("  CI3 noise filtered",      f"{ana_mck.get('framework_noise_filtered',0):,}", f"{ana_cbt.get('framework_noise_filtered',0):,}"),
        ("Composer deps",             "5 (3 safe, 2 review)",           "0 app-level deps"),
        ("AI recommendations",       str(mck.get("ai_recommendations_count", 0)), str(cbt.get("ai_recommendations_count", 0))),
        ("ISO overall status",        "NON-COMPLIANT",                  "NON-COMPLIANT"),
    ]

    col_x  = [0.0, 0.44, 0.73]
    row_h  = 0.063
    start_y = 0.96

    for i, row in enumerate(rows):
        y = start_y - i * row_h
        is_hdr = (i == 0)
        for j, cell in enumerate(row):
            w_col = (col_x[j+1] if j+1 < len(col_x) else 1.01) - col_x[j]
            if is_hdr:
                ax2.add_patch(mpatches.FancyBboxPatch(
                    (col_x[j] - 0.01, y - 0.036), w_col + 0.005, 0.063,
                    boxstyle="round,pad=0.01",
                    facecolor="#2166AC", edgecolor="none",
                    transform=ax2.transAxes, clip_on=False,
                ))
                ax2.text(col_x[j] + 0.01, y, cell,
                         transform=ax2.transAxes, fontsize=9.5,
                         fontweight="bold", color="white", va="center")
            else:
                if i % 2 == 0:
                    ax2.add_patch(mpatches.FancyBboxPatch(
                        (-0.01, y - 0.036), 1.02, 0.063,
                        boxstyle="square,pad=0",
                        facecolor="#F5F5F5", edgecolor="none",
                        transform=ax2.transAxes, clip_on=False,
                    ))
                ax2.text(col_x[j] + 0.01, y, cell,
                         transform=ax2.transAxes, fontsize=8.5,
                         color=TEXT_C, va="center")

    ax2.text(0.0, start_y - len(rows) * row_h - 0.02,
             "* PHPStan errors: mayoritas false positive CI3 framework (magic props, runtime constants)\n"
             "* SK1 Semgrep +7: Rector menghasilkan findings baru di kode FT UGM; SK2 delta=0 (CI3 framework, tidak disentuh Rector)",
             transform=ax2.transAxes, fontsize=7.5, color="#888888", va="top")

    ax2.set_title("Ringkasan Perbandingan Pipeline", fontsize=12, pad=12)

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _cmp_footer(fig)
    return _save(fig, out_dir / "comparison_4_composer_summary.png", dpi=180)


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    OUT_DTI.mkdir(parents=True, exist_ok=True)
    OUT_CMP.mkdir(parents=True, exist_ok=True)

    mck     = _load(SK1_JSON)
    cbt     = _load(SK2_JSON)
    cbt_iso = _load(SK2_ISO_JSON)

    print("=" * 60)
    print("DTI SK2 charts (each split into 2 files)")
    print(f"  -> {OUT_DTI}")
    print("=" * 60)
    dti_charts = [
        dti_1a_semgrep_severity(cbt, OUT_DTI),
        dti_1b_semgrep_vulntype(cbt, OUT_DTI),
        dti_2a_rector_bar(cbt, OUT_DTI),
        dti_2b_rector_pie(cbt, OUT_DTI),
        dti_3a_phpstan_bar(cbt, OUT_DTI),
        dti_3b_iso_compliance(cbt_iso, OUT_DTI),
    ]
    for p in dti_charts:
        print(f"  [OK] {p.name}")

    print()
    print("=" * 60)
    print("Comparison SK1 vs SK2 charts (overlap fixed)")
    print(f"  -> {OUT_CMP}")
    print("=" * 60)
    cmp_charts = [
        cmp_chart1_semgrep(mck, cbt, OUT_CMP),
        cmp_chart2_rector(mck, cbt, OUT_CMP),
        cmp_chart3_phpstan(mck, cbt, OUT_CMP),
        cmp_chart4_composer_summary(mck, cbt, OUT_CMP),
    ]
    for p in cmp_charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(dti_charts) + len(cmp_charts)} charts saved.")


if __name__ == "__main__":
    main()
