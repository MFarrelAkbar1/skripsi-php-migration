"""
pipeline_result_chart.py -- Visualisasi hasil pipeline dari pipeline_result JSON.

Chart 1: Pre-scan vs post-scan -- total findings + by severity (grouped bar)
Chart 2: Pre-scan vs post-scan -- by vulnerability type (horizontal grouped bar)
Chart 3: Rector conversion summary (stacked bar)
Chart 4: PHPStan errors by ISO 27001:2022 control (horizontal bar)

Style: academic/publication, white background, consistent with llm_comparison_chart.py
Simpan ke reports/charts/pipeline_chart_<timestamp>_N_<name>.png
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Style constants (consistent with llm_comparison_chart.py)
# ---------------------------------------------------------------------------

PRE_COLOR  = "#2166AC"   # blue  -- pre-scan
POST_COLOR = "#D7191C"   # red   -- post-scan
OK_COLOR   = "#4DAC26"   # green -- converted/valid
SKIP_COLOR = "#E66101"   # orange -- skipped
FAIL_COLOR = "#D7191C"   # red   -- failed/error

SEVERITY_COLORS = {
    "ERROR":   "#D7191C",
    "WARNING": "#E66101",
    "INFO":    "#2166AC",
}
ISO_COLORS = ["#2166AC", "#7B3294", "#4DAC26", "#D7191C", "#E66101"]

GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

_RCPARAMS = {
    "font.family":        "DejaVu Sans",
    "font.size":          9,
    "text.color":         TEXT_C,
    "axes.titlesize":     11,
    "axes.titleweight":   "bold",
    "axes.labelsize":     9,
    "axes.labelcolor":    TEXT_C,
    "xtick.color":        TEXT_C,
    "ytick.color":        TEXT_C,
    "figure.facecolor":   "white",
    "axes.facecolor":     "white",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _find_latest(reports_dir: Path) -> Path | None:
    candidates = sorted(
        reports_dir.glob("pipeline_result_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Chart 1 -- Pre-scan vs Post-scan: Total + By Severity
# ---------------------------------------------------------------------------

def _chart_severity(
    pre: dict, post: dict,
    reports_dir: Path, timestamp: str, source: str,
) -> Path:
    """Grouped bar: total findings + breakdown by severity."""
    plt.rcParams.update(_RCPARAMS)

    pre_sev  = pre.get("by_severity", {})
    post_sev = post.get("by_severity", {})

    all_sev = sorted(
        set(pre_sev) | set(post_sev),
        key=lambda s: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(s, 9),
    )

    categories   = ["Total"] + all_sev
    pre_vals     = [pre.get("total_findings", 0)]  + [pre_sev.get(s, 0) for s in all_sev]
    post_vals    = [post.get("total_findings", 0)] + [post_sev.get(s, 0) for s in all_sev]

    x      = np.arange(len(categories))
    width  = 0.35
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("white")

    bars_pre  = ax.bar(x - width / 2, pre_vals,  width, label="Pre-Conversion",
                       color=PRE_COLOR,  alpha=0.82, edgecolor="white")
    bars_post = ax.bar(x + width / 2, post_vals, width, label="Post-Conversion",
                       color=POST_COLOR, alpha=0.82, edgecolor="white")

    for bar, v in zip(bars_pre, pre_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    str(v), ha="center", va="bottom", fontsize=9, color=TEXT_C, fontweight="bold")

    for bar, v in zip(bars_post, post_vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    str(v), ha="center", va="bottom", fontsize=9, color=TEXT_C, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9)
    ax.set_ylabel("Number of Findings", fontsize=9)
    ax.set_title("Semgrep Security Findings: Pre-Conversion vs Post-Conversion",
                 color=TEXT_C, pad=8)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C)
    _style_ax(ax, "v")
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])

    out = reports_dir / f"pipeline_chart_{timestamp}_1_prescan_postscan_severity.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ---------------------------------------------------------------------------
# Chart 2 -- Pre-scan vs Post-scan: By Vulnerability Type (horizontal)
# ---------------------------------------------------------------------------

def _chart_vuln_type(
    pre: dict, post: dict,
    reports_dir: Path, timestamp: str, source: str,
) -> Path:
    """Horizontal grouped bar: findings per vulnerability type."""
    plt.rcParams.update(_RCPARAMS)

    pre_vt  = pre.get("by_vuln_type", {})
    post_vt = post.get("by_vuln_type", {})

    # Union of all vuln types, sorted by total descending
    all_types = sorted(
        set(pre_vt) | set(post_vt),
        key=lambda t: (pre_vt.get(t, 0) + post_vt.get(t, 0)),
    )

    pre_vals  = [pre_vt.get(t, 0)  for t in all_types]
    post_vals = [post_vt.get(t, 0) for t in all_types]

    y      = np.arange(len(all_types))
    height = 0.35
    fig, ax = plt.subplots(figsize=(9, max(4, len(all_types) * 1.1 + 1.5)))
    fig.patch.set_facecolor("white")

    bars_pre  = ax.barh(y + height / 2, pre_vals,  height, label="Pre-Conversion",
                        color=PRE_COLOR,  alpha=0.82, edgecolor="white")
    bars_post = ax.barh(y - height / 2, post_vals, height, label="Post-Conversion",
                        color=POST_COLOR, alpha=0.82, edgecolor="white")

    for bar, v in zip(bars_pre, pre_vals):
        if v > 0:
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(v), va="center", fontsize=9, color=PRE_COLOR, fontweight="bold")

    for bar, v in zip(bars_post, post_vals):
        if v > 0:
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(v), va="center", fontsize=9, color=POST_COLOR, fontweight="bold")

    # Highlight types that appeared only post-conversion (new regressions)
    for i, t in enumerate(all_types):
        if pre_vt.get(t, 0) == 0 and post_vt.get(t, 0) > 0:
            ax.annotate(
                "new", xy=(post_vt[t], y[i] - height / 2),
                xytext=(post_vt[t] + 1.2, y[i] - height / 2),
                fontsize=7.5, color=POST_COLOR,
                arrowprops={"arrowstyle": "->", "color": POST_COLOR, "lw": 0.8},
                va="center",
            )

    ax.set_yticks(y)
    ax.set_yticklabels(all_types, fontsize=9)
    ax.set_xlabel("Number of Findings", fontsize=9)
    ax.set_title("Security Findings by Vulnerability Type: Pre vs Post-Conversion",
                 color=TEXT_C, pad=8)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C)
    _style_ax(ax, "h")
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])

    out = reports_dir / f"pipeline_chart_{timestamp}_2_prescan_postscan_vulntype.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ---------------------------------------------------------------------------
# Chart 3 -- Rector Conversion Summary
# ---------------------------------------------------------------------------

def _chart_conversion(
    conv: dict,
    reports_dir: Path, timestamp: str, source: str,
) -> Path:
    """Stacked bar chart: converted / skipped / failed per file category."""
    plt.rcParams.update(_RCPARAMS)

    converted = conv.get("converted", 0)
    skipped   = conv.get("skipped",   0)
    failed    = conv.get("failed",    0)
    total     = conv.get("total_files", converted + skipped + failed)

    categories = ["All Files"]
    vals_ok    = [converted]
    vals_skip  = [skipped]
    vals_fail  = [failed]

    x     = np.arange(len(categories))
    width = 0.45
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor("white")

    b1 = ax.bar(x, vals_ok,   width, label=f"Converted ({converted})",
                color=OK_COLOR,   alpha=0.85, edgecolor="white")
    b2 = ax.bar(x, vals_skip, width, bottom=vals_ok,
                label=f"Skipped ({skipped})",
                color=SKIP_COLOR, alpha=0.75, edgecolor="white")
    b3 = ax.bar(x, vals_fail, width, bottom=[v + s for v, s in zip(vals_ok, vals_skip)],
                label=f"Failed ({failed})",
                color=FAIL_COLOR, alpha=0.75, edgecolor="white")

    # Percentage labels inside each segment
    for bar, v in zip(b1, vals_ok):
        if v > 0:
            pct = v / total * 100
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    f"{pct:.1f}%", ha="center", va="center",
                    fontsize=10, color="white", fontweight="bold")
    for bar, v, base in zip(b2, vals_skip, vals_ok):
        if v > 0:
            pct = v / total * 100
            ax.text(bar.get_x() + bar.get_width() / 2,
                    base + v / 2,
                    f"{pct:.1f}%", ha="center", va="center",
                    fontsize=10, color="white", fontweight="bold")
    for bar, v, base1, base2 in zip(b3, vals_fail, vals_ok, vals_skip):
        if v > 0:
            pct = v / total * 100
            ax.text(bar.get_x() + bar.get_width() / 2,
                    base1 + base2 + v / 2,
                    f"{pct:.1f}%", ha="center", va="center",
                    fontsize=10, color="white", fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels([f"Total: {total} files"], fontsize=9)
    ax.set_ylabel("Number of Files", fontsize=9)
    ax.set_ylim(0, total * 1.15)
    ax.set_title("Rector PHP Migration: Conversion Result Summary",
                 color=TEXT_C, pad=8)
    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C,
              loc="upper right")
    _style_ax(ax, "v")
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])

    out = reports_dir / f"pipeline_chart_{timestamp}_3_rector_conversion.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ---------------------------------------------------------------------------
# Chart 4 -- PHPStan Errors by ISO 27001:2022 Control
# ---------------------------------------------------------------------------

def _chart_phpstan_iso(
    analysis: dict,
    reports_dir: Path, timestamp: str, source: str,
) -> Path:
    """Horizontal bar chart: PHPStan error count by ISO control."""
    plt.rcParams.update(_RCPARAMS)

    by_iso  = analysis.get("by_iso_control", {})
    total   = analysis.get("total_errors", 0)
    php_ver = analysis.get("php_version", "8.x")
    level   = analysis.get("phpstan_level", 5)

    if not by_iso:
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.text(0.5, 0.5, "No ISO control data available",
                ha="center", va="center", fontsize=11, color=SPINE_C)
        ax.axis("off")
        out = reports_dir / f"pipeline_chart_{timestamp}_4_phpstan_iso.png"
        fig.savefig(out, dpi=150, facecolor="white")
        plt.close(fig)
        plt.rcdefaults()
        return out

    controls = list(by_iso.keys())
    counts   = [by_iso[c] for c in controls]
    colors   = [ISO_COLORS[i % len(ISO_COLORS)] for i in range(len(controls))]

    y     = np.arange(len(controls))
    fig, ax = plt.subplots(figsize=(9, max(3.5, len(controls) * 0.9 + 1.5)))
    fig.patch.set_facecolor("white")

    bars = ax.barh(y, counts, 0.5, color=colors, alpha=0.82, edgecolor="white")

    for bar, v in zip(bars, counts):
        pct = v / total * 100 if total else 0
        ax.text(bar.get_width() + total * 0.005,
                bar.get_y() + bar.get_height() / 2,
                f"{v:,}  ({pct:.1f}%)",
                va="center", fontsize=9, color=TEXT_C)

    ax.set_yticks(y)
    ax.set_yticklabels(controls, fontsize=9)
    ax.set_xlabel("Number of Errors / Warnings", fontsize=9)
    ax.set_title(
        f"PHPStan Static Analysis: Errors by ISO 27001:2022 Control\n"
        f"PHP {php_ver}  |  Level {level}  |  Total: {total:,}",
        color=TEXT_C, pad=8,
    )
    _style_ax(ax, "h")
    ax.set_xlim(0, max(counts) * 1.2)
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])

    out = reports_dir / f"pipeline_chart_{timestamp}_4_phpstan_iso.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_charts(json_path: Path, reports_dir: Path) -> list[Path]:
    """Load pipeline_result JSON dan generate semua chart."""
    data      = _load(json_path)
    pre_scan  = data.get("pre_scan")
    post_scan = data.get("post_scan")
    conv      = data.get("conversion")
    analysis  = data.get("analysis")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    source    = json_path.name

    reports_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]Pipeline Result Charts[/bold cyan]")
    console.print(f"Source : [dim]{json_path}[/dim]")
    console.print(f"Output : [dim]{reports_dir}[/dim]")

    saved: list[Path] = []

    if pre_scan and post_scan:
        saved.append(_chart_severity(pre_scan, post_scan, reports_dir, timestamp, source))
        saved.append(_chart_vuln_type(pre_scan, post_scan, reports_dir, timestamp, source))
    else:
        console.print("[yellow]pre_scan / post_scan data tidak lengkap -- chart 1 & 2 dilewati.[/yellow]")

    if conv:
        saved.append(_chart_conversion(conv, reports_dir, timestamp, source))
    else:
        console.print("[yellow]conversion data tidak ada -- chart 3 dilewati.[/yellow]")

    if analysis:
        saved.append(_chart_phpstan_iso(analysis, reports_dir, timestamp, source))
    else:
        console.print("[yellow]analysis data tidak ada -- chart 4 dilewati.[/yellow]")

    console.print(f"\n[bold green]{len(saved)} chart disimpan di {reports_dir}:[/bold green]")
    for p in saved:
        console.print(f"  [green]->[/green] {p.name}")

    return saved


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python pipeline/pipeline_result_chart.py",
        description="Generate chart visualisasi hasil pipeline dari pipeline_result JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--json", dest="json_path", type=Path, default=None,
        help="Path ke pipeline_result JSON. Default: otomatis ambil yang terbaru.",
    )
    parser.add_argument(
        "--reports", dest="reports_dir", type=Path, default=Path("reports/charts"),
        help="Folder output chart.",
    )
    return parser.parse_args()


def main() -> None:
    args        = _parse_args()
    reports_dir = args.reports_dir
    json_path   = args.json_path

    if json_path is None:
        # Search one level up from charts/ if the default dir is used
        search_dir = reports_dir.parent if reports_dir.name == "charts" else reports_dir
        json_path  = _find_latest(search_dir)
        if json_path is None:
            json_path = _find_latest(Path("reports"))

    if json_path is None:
        console.print("[red]Tidak ada pipeline_result JSON ditemukan.[/red]")
        raise SystemExit(1)

    generate_charts(json_path, reports_dir)


if __name__ == "__main__":
    main()
