"""
generate_cbt_qwen_charts.py -- Generate charts untuk Studi Kasus 2 (CBT DTI)
menggunakan hasil pipeline run dengan model Qwen2.5-Coder:7b (cbt_qwen run).

Output charts (contents/chapter-4/dti/):
  pipeline_chart_cbt_qwen_1a_semgrep_severity.png
  pipeline_chart_cbt_qwen_1b_semgrep_vulntype.png
  pipeline_chart_cbt_qwen_2a_rector_bar.png
  pipeline_chart_cbt_qwen_2b_rector_pie.png
  pipeline_chart_cbt_qwen_3a_phpstan_bar.png
  pipeline_chart_cbt_qwen_3b_iso_compliance.png

Data source:
  reports/cbt_qwen/pipeline_result_20260524_124116.json
  reports/cbt_qwen/iso_report_20260524_124116.json
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

ROOT        = Path(__file__).parent.parent
SK2_JSON    = ROOT / "reports" / "cbt_qwen" / "pipeline_result_20260524_124116.json"
SK2_ISO_JSON = ROOT / "reports" / "cbt_qwen" / "iso_report_20260524_124116.json"

OUT_DTI = ROOT / "contents" / "chapter-4" / "dti"

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

OK_COLOR   = "#4DAC26"
SKIP_COLOR = "#E66101"
FAIL_COLOR = "#D7191C"
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

RUN_LABEL = "CBT DTI -- Qwen2.5-Coder:7b (cbt_qwen)"


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


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(fig: plt.Figure, out: Path, dpi: int = 150) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ===========================================================================
# Chart 1a: Semgrep -- Pre vs Post by Severity
# ===========================================================================

def chart_1a_semgrep_severity(data: dict, out_dir: Path) -> Path:
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
    ax.set_title(f"Semgrep Security Findings: Pre vs Post-Conversion\n({RUN_LABEL} -- Delta = {delta_str})", pad=10)
    ax.set_ylabel("Jumlah Temuan")
    ax.set_xticks(x)
    ax.set_xticklabels(cats, fontsize=10)
    ax.set_ylim(0, max(max(pre_vals), max(post_vals)) * 1.25)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C,
              loc="upper left", bbox_to_anchor=(0.01, 0.99))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    _style_ax(ax, "v")

    fig.text(0.99, 0.07,
             "Semua findings berasal dari system/core/Output.php (CI3 framework)\n"
             "Kode aplikasi CBT custom = 0 Semgrep findings",
             ha="right", va="bottom",
             fontsize=8, color="#555555", style="italic",
             bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.15, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_1a_semgrep_severity.png")


# ===========================================================================
# Chart 1b: Semgrep -- By Vulnerability Type
# ===========================================================================

def chart_1b_semgrep_vulntype(data: dict, out_dir: Path) -> Path:
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
    ax.set_title(f"Semgrep Findings by Vulnerability Type\n({RUN_LABEL} -- Pre vs Post-Conversion)", pad=10)
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
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_1b_semgrep_vulntype.png")


# ===========================================================================
# Chart 2a: Rector -- Stacked Bar
# ===========================================================================

def chart_2a_rector_bar(data: dict, out_dir: Path) -> Path:
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
    ax.bar(x, [converted], w, label=f"Converted ({converted})", color=OK_COLOR,   alpha=0.87, edgecolor="white", zorder=3)
    ax.bar(x, [skipped],   w, label=f"Skipped ({skipped})",     color=SKIP_COLOR, alpha=0.82, edgecolor="white", bottom=[converted], zorder=3)
    ax.bar(x, [failed],    w, label=f"Failed ({failed})",       color=FAIL_COLOR, alpha=0.82, edgecolor="white", bottom=[converted + skipped], zorder=3)

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
    ax.set_title(f"Rector PHP Migration: Conversion Result Summary\n({RUN_LABEL} -- Target PHP 8.3)", pad=10)
    ax.legend(fontsize=9.5, frameon=True, framealpha=0.9, edgecolor=GRID_C, loc="upper right")
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
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_2a_rector_bar.png")


# ===========================================================================
# Chart 2b: Rector -- Pie Chart
# ===========================================================================

def chart_2b_rector_pie(data: dict, out_dir: Path) -> Path:
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
    ax.legend(handles=patches, loc="upper center",
              bbox_to_anchor=(0.5, -0.04), ncol=1, framealpha=0.88, fontsize=9.5,
              edgecolor=SPINE_C)

    ax.set_title(f"Proporsi Hasil Konversi Rector\n({RUN_LABEL} -- Target PHP 8.3)", pad=10)

    fig.subplots_adjust(left=0.05, right=0.95, bottom=0.36, top=0.92)

    fig.text(0.5, 0.05,
             "2 failures: captcha_helper.php & form_helper.php\n"
             "(known Rector Fiber bug -- bukan error kode CBT)",
             ha="center", va="bottom",
             fontsize=8, color="#888888", style="italic")
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_2b_rector_pie.png")


# ===========================================================================
# Chart 3a: PHPStan -- Errors by ISO Control
# ===========================================================================

def chart_3a_phpstan_bar(data: dict, out_dir: Path) -> Path:
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

    ax.text(0.02, 0.05,
            f"CI3 framework noise filtered: {noise_filtered:,}\n"
            "(false positives: magic props, runtime constants, CI3 helpers)",
            transform=ax.transAxes, ha="left", va="bottom",
            fontsize=8.5, color="#555555", style="italic",
            bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor=SPINE_C, linewidth=0.7))

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    _footer(fig, SK2_JSON.name)
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_3a_phpstan_bar.png")


# ===========================================================================
# Chart 3b: ISO 27001:2022 Compliance Status Table
# ===========================================================================

def chart_3b_iso_compliance(iso_data: dict, out_dir: Path) -> Path:
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

    col_x   = [0.03, 0.17, 0.60, 0.76, 0.88]
    headers = ["Kontrol", "Judul Kontrol", "Temuan", "Status", ""]
    row_h   = 0.115
    start_y = 0.88

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
        ctrl     = controls_data.get(ctrl_id, {})
        status   = ctrl.get("status", "N/A")
        findings = ctrl.get("findings_count", 0)
        title    = ISO_TITLES.get(ctrl_id, ctrl_id)
        s_color  = ISO_STATUS_COLORS.get(status, "#888888")
        s_label  = ISO_STATUS_SYMB.get(status, status)

        row_y    = start_y - (i + 1) * row_h
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
        f"ISO/IEC 27001:2022 Compliance Status\n({RUN_LABEL}, PHP 8.3)",
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
    return _save(fig, out_dir / "pipeline_chart_cbt_qwen_3b_iso_compliance.png")


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    OUT_DTI.mkdir(parents=True, exist_ok=True)

    pr  = _load(SK2_JSON)
    iso = _load(SK2_ISO_JSON)

    print("=" * 60)
    print(f"CBT DTI -- Qwen2.5-Coder:7b charts")
    print(f"  Source : {SK2_JSON.relative_to(ROOT)}")
    print(f"  Output : {OUT_DTI.relative_to(ROOT)}")
    print("=" * 60)

    charts = [
        chart_1a_semgrep_severity(pr, OUT_DTI),
        chart_1b_semgrep_vulntype(pr, OUT_DTI),
        chart_2a_rector_bar(pr, OUT_DTI),
        chart_2b_rector_pie(pr, OUT_DTI),
        chart_3a_phpstan_bar(pr, OUT_DTI),
        chart_3b_iso_compliance(iso, OUT_DTI),
    ]

    for p in charts:
        print(f"  [OK] {p.name}")

    print(f"\nDone. {len(charts)} charts saved.")


if __name__ == "__main__":
    main()
