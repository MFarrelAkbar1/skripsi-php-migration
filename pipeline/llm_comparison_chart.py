"""
llm_comparison_chart.py -- Visualisasi perbandingan 5 LLM dari llm_comparison JSON.

Menghasilkan 4 grafik individual:
1. Box plot confidence score per model
2. Bar chart format compliance rate per model
3. Bar chart avg inference time per model
4. Tabel statistik (mean, std, min, max confidence) per model

Style: academic/publication, white background, warna netral formal.
Simpan ke reports/llm_chart_<timestamp>_N_<name>.png
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
# Color palette -- academic, neutral, print-safe (no bright colors)
# ---------------------------------------------------------------------------
# Model colors: 5 distinct but muted tones (ColorBrewer-inspired)
MODEL_COLORS = [
    "#2166AC",  # blue
    "#4DAC26",  # green
    "#D7191C",  # red
    "#7B3294",  # purple
    "#E66101",  # orange
]

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
# Data loading
# ---------------------------------------------------------------------------

def _find_latest(reports_dir: Path) -> Path | None:
    candidates = sorted(
        reports_dir.glob("llm_comparison_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract(data: dict) -> dict[str, dict]:
    """
    Return per-model dict:
      {model_name: {conf_runs, time_runs, fmt_rate, summary}}
    conf_runs = flat list of confidence values from ALL finding runs.
    """
    out: dict[str, dict] = {}
    for model, mdata in data["results"].items():
        conf_runs: list[float] = []
        time_runs: list[float] = []
        for finding in mdata.get("findings", []):
            for run in finding.get("runs", []):
                conf_runs.append(float(run["confidence"]))
                time_runs.append(float(run["inference_time_sec"]))
        out[model] = {
            "conf_runs":  conf_runs,
            "time_runs":  time_runs,
            "fmt_rate":   mdata["summary"]["format_compliance_rate"],
            "available":  mdata["available"],
            "summary":    mdata["summary"],
        }
    return out


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _style_vbar(ax: plt.Axes) -> None:
    ax.grid(axis="y", linewidth=0.5, color=GRID_C, linestyle="-")
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]:
        ax.spines[sp].set_color(SPINE_C)
        ax.spines[sp].set_linewidth(0.8)


def _short(name: str) -> str:
    """Shorten model name for axis labels."""
    return name.split(":")[0].replace("deepseek-coder", "DeepSeek\nCoder") \
               .replace("qwen2.5-coder", "Qwen2.5\nCoder") \
               .replace("codellama", "CodeLlama") \
               .replace("mistral", "Mistral") \
               .replace("llama3.1", "Llama3.1")


def _footer(fig: plt.Figure, source: str) -> None:
    fig.text(
        0.5, 0.01,
        f"Source: {source}  |  Skripsi Muhammad Farrel Akbar",
        ha="center", fontsize=7.5, color="#888888",
    )


# ---------------------------------------------------------------------------
# Chart generators
# ---------------------------------------------------------------------------

def _chart_boxplot(models: list[str], extracted: dict, reports_dir: Path,
                   timestamp: str, source: str) -> Path:
    """Box plot confidence score per model."""
    plt.rcParams.update(_RCPARAMS)

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("white")

    data_series = [extracted[m]["conf_runs"] for m in models]
    short_labels = [_short(m) for m in models]

    bp = ax.boxplot(
        data_series,
        patch_artist=True,
        notch=False,
        widths=0.45,
        medianprops={"color": TEXT_C, "linewidth": 1.8},
        whiskerprops={"color": SPINE_C, "linewidth": 1.0},
        capprops={"color": SPINE_C, "linewidth": 1.0},
        flierprops={
            "marker": "o", "markersize": 4,
            "markerfacecolor": SPINE_C, "markeredgecolor": SPINE_C, "alpha": 0.6,
        },
    )
    for patch, color in zip(bp["boxes"], MODEL_COLORS):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
        patch.set_linewidth(0.8)

    ax.set_xticks(range(1, len(models) + 1))
    ax.set_xticklabels(short_labels, fontsize=9)
    ax.set_ylim(-0.05, 1.10)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1.0))
    ax.set_ylabel("Confidence Score", fontsize=9)
    ax.set_title("Confidence Score Distribution per LLM Model (Box Plot)",
                 color=TEXT_C, pad=8)
    _style_vbar(ax)
    ax.axhline(0.5, color=SPINE_C, linestyle="--", linewidth=0.8, alpha=0.7)
    ax.text(len(models) + 0.5, 0.51, "0.5 ref", fontsize=7.5, color=SPINE_C, va="bottom")

    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    out = reports_dir / f"llm_chart_{timestamp}_1_boxplot_confidence.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


def _chart_fmt_compliance(models: list[str], extracted: dict, reports_dir: Path,
                          timestamp: str, source: str) -> Path:
    """Bar chart format compliance rate per model."""
    plt.rcParams.update(_RCPARAMS)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.patch.set_facecolor("white")

    rates  = [extracted[m]["fmt_rate"] * 100 for m in models]
    x_pos  = np.arange(len(models))
    bars   = ax.bar(x_pos, rates, color=MODEL_COLORS, alpha=0.82,
                    width=0.55, edgecolor="white", linewidth=0.5)

    ax.set_xticks(x_pos)
    ax.set_xticklabels([_short(m) for m in models], fontsize=9)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Compliance Rate (%)", fontsize=9)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    ax.set_title("Format Compliance Rate per LLM Model", color=TEXT_C, pad=8)
    _style_vbar(ax)

    for bar, v in zip(bars, rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{v:.0f}%",
            ha="center", va="bottom", fontsize=9.5, color=TEXT_C, fontweight="bold",
        )

    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    out = reports_dir / f"llm_chart_{timestamp}_2_format_compliance.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


def _chart_inference_time(models: list[str], extracted: dict, reports_dir: Path,
                          timestamp: str, source: str) -> Path:
    """Bar chart avg inference time per model with error bars (std)."""
    plt.rcParams.update(_RCPARAMS)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.patch.set_facecolor("white")

    means  = [float(np.mean(extracted[m]["time_runs"])) if extracted[m]["time_runs"] else 0.0
              for m in models]
    stds   = [float(np.std(extracted[m]["time_runs"]))  if extracted[m]["time_runs"] else 0.0
              for m in models]
    x_pos  = np.arange(len(models))

    bars = ax.bar(
        x_pos, means, color=MODEL_COLORS, alpha=0.82,
        width=0.55, edgecolor="white", linewidth=0.5,
        yerr=stds, error_kw={"ecolor": SPINE_C, "capsize": 4, "linewidth": 1.0},
    )
    ax.set_xticks(x_pos)
    ax.set_xticklabels([_short(m) for m in models], fontsize=9)
    ax.set_ylabel("Avg Inference Time (seconds)", fontsize=9)
    ax.set_title("Average Inference Time per LLM Model (with Std Dev)",
                 color=TEXT_C, pad=8)
    _style_vbar(ax)

    for bar, v in zip(bars, means):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(means) * 0.015,
            f"{v:.1f}s",
            ha="center", va="bottom", fontsize=9, color=TEXT_C,
        )

    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    out = reports_dir / f"llm_chart_{timestamp}_3_inference_time.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


def _short_model(name: str) -> str:
    """Shorten model name for table cell (multiline, fits narrow column)."""
    mapping = {
        "deepseek-coder": "DeepSeek\nCoder 6.7b",
        "qwen2.5-coder":  "Qwen2.5\nCoder 7b",
        "codellama":      "CodeLlama\n7b",
        "mistral":        "Mistral\n7b",
        "llama3.1":       "Llama 3.1\n8b",
    }
    base = name.split(":")[0]
    return mapping.get(base, name)


def _chart_stats_table(models: list[str], extracted: dict, reports_dir: Path,
                       timestamp: str, source: str) -> Path:
    """Tabel statistik confidence: mean, std, min, max per model."""
    plt.rcParams.update(_RCPARAMS)

    # Narrower figure: 7.5 in wide fits A4 text block comfortably at 150 dpi.
    fig, ax = plt.subplots(figsize=(7.5, 3.0))
    fig.patch.set_facecolor("white")
    ax.axis("off")

    col_labels = ["Model", "Mean", "Std Dev", "Min", "Max",
                  "Fmt OK", "Avg Time\n(s)"]
    rows = []
    for m in models:
        conf = extracted[m]["conf_runs"]
        if conf:
            mean_c = np.mean(conf)
            std_c  = np.std(conf)
            min_c  = np.min(conf)
            max_c  = np.max(conf)
        else:
            mean_c = std_c = min_c = max_c = 0.0

        time_runs = extracted[m]["time_runs"]
        avg_t = np.mean(time_runs) if time_runs else 0.0

        rows.append([
            _short_model(m),
            f"{mean_c:.2f}",
            f"{std_c:.2f}",
            f"{min_c:.2f}",
            f"{max_c:.2f}",
            f"{extracted[m]['fmt_rate'] * 100:.0f}%",
            f"{avg_t:.1f}",
        ])

    tbl = ax.table(
        cellText=rows,
        colLabels=col_labels,
        cellLoc="center",
        loc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.0, 1.9)

    # Explicit column widths: model col wider, numeric cols narrower.
    col_widths = [0.22, 0.11, 0.11, 0.11, 0.11, 0.11, 0.13]
    for col_idx, w in enumerate(col_widths):
        for row_idx in range(len(rows) + 1):
            tbl[row_idx, col_idx].set_width(w)

    # Header row styling
    for col in range(len(col_labels)):
        cell = tbl[0, col]
        cell.set_facecolor("#2166AC")
        cell.set_text_props(color="white", fontweight="bold", fontsize=9)
        cell.set_edgecolor("white")

    # Data rows: alternate shading
    for row in range(1, len(rows) + 1):
        bg = "#F2F2F2" if row % 2 == 0 else "white"
        for col in range(len(col_labels)):
            cell = tbl[row, col]
            cell.set_facecolor(bg)
            cell.set_edgecolor(GRID_C)
        tbl[row, 0].set_text_props(color=MODEL_COLORS[row - 1], fontweight="bold")

    ax.set_title(
        "LLM Model Comparison -- Confidence Score Statistics",
        color=TEXT_C, fontsize=11, fontweight="bold", pad=12,
    )
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 0.96])
    out = reports_dir / f"llm_chart_{timestamp}_4_stats_table.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_charts(json_path: Path, reports_dir: Path) -> list[Path]:
    """Load llm_comparison JSON dan generate 4 grafik individual."""
    data      = _load(json_path)
    extracted = _extract(data)
    models    = data["models_compared"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    source    = json_path.name

    console.print(f"[bold cyan]LLM Comparison Charts[/bold cyan]")
    console.print(f"Source  : [dim]{json_path}[/dim]")
    console.print(f"Models  : {', '.join(models)}")
    console.print(
        f"Findings: {data['findings_count']}  |  "
        f"Runs/finding: {data['runs_per_finding']}  |  "
        f"Strategy: {data['prompt_strategy']}"
    )

    saved: list[Path] = []
    saved.append(_chart_boxplot(models, extracted, reports_dir, timestamp, source))
    saved.append(_chart_fmt_compliance(models, extracted, reports_dir, timestamp, source))
    saved.append(_chart_inference_time(models, extracted, reports_dir, timestamp, source))
    saved.append(_chart_stats_table(models, extracted, reports_dir, timestamp, source))

    console.print(f"\n[bold green]4 grafik disimpan di {reports_dir}:[/bold green]")
    for p in saved:
        console.print(f"  [green]->[/green] {p.name}")

    return saved


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python pipeline/llm_comparison_chart.py",
        description="Generate grafik perbandingan 5 LLM dari llm_comparison JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--json", dest="json_path", type=Path, default=None,
        help="Path ke llm_comparison JSON. Default: otomatis ambil yang terbaru.",
    )
    parser.add_argument(
        "--reports", dest="reports_dir", type=Path, default=Path("reports"),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    reports_dir = args.reports_dir
    json_path   = args.json_path

    if json_path is None:
        json_path = _find_latest(reports_dir)
    if json_path is None:
        console.print("[red]Tidak ada llm_comparison JSON ditemukan.[/red]")
        raise SystemExit(1)

    generate_charts(json_path, reports_dir)


if __name__ == "__main__":
    main()
