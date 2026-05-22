"""
generate_condition_b_charts.py -- Generate 4 LLM comparison charts for Condition B.

Source: reports/llm_comparison_20260427_130844.json (prompt_strategy=optimized-per-model)
Output: reports/charts/llm_chart_20260427_130844_*.png
        contents/chapter-4/llm_chart_20260427_130844_*.png
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

BASE_DIR    = Path(r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration")
JSON_PATH   = BASE_DIR / "reports" / "llm_comparison_20260427_130844.json"
REPORTS_DIR = BASE_DIR / "reports" / "charts"
CHAPTER4_DIR = BASE_DIR / "contents" / "chapter-4"
TIMESTAMP   = "20260427_130844"

MODEL_COLORS = ["#2166AC", "#4DAC26", "#D7191C", "#7B3294", "#E66101"]
GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

_RCPARAMS = {
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


def _short(name: str) -> str:
    return (name.split(":")[0]
            .replace("deepseek-coder", "DeepSeek\nCoder")
            .replace("qwen2.5-coder", "Qwen2.5\nCoder")
            .replace("codellama", "CodeLlama")
            .replace("mistral", "Mistral")
            .replace("llama3.1", "Llama3.1"))


def _short_model(name: str) -> str:
    mapping = {
        "deepseek-coder": "DeepSeek\nCoder 6.7b",
        "qwen2.5-coder":  "Qwen2.5\nCoder 7b",
        "codellama":      "CodeLlama\n7b",
        "mistral":        "Mistral\n7b",
        "llama3.1":       "Llama 3.1\n8b",
    }
    return mapping.get(name.split(":")[0], name)


def _style_vbar(ax: plt.Axes) -> None:
    ax.grid(axis="y", linewidth=0.5, color=GRID_C, linestyle="-")
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]:
        ax.spines[sp].set_color(SPINE_C)
        ax.spines[sp].set_linewidth(0.8)


def _footer(fig: plt.Figure, source: str) -> None:
    fig.text(0.5, 0.01, f"Source: {source}  |  Skripsi Muhammad Farrel Akbar",
             ha="center", fontsize=7.5, color="#888888")


def _extract(data: dict) -> dict:
    out: dict[str, dict] = {}
    for model, mdata in data["results"].items():
        conf_runs: list[float] = []
        time_runs: list[float] = []
        for finding in mdata.get("findings", []):
            for run in finding.get("runs", []):
                conf_runs.append(float(run["confidence"]))
                t = run.get("inference_time_sec") or run.get("inference_time_s") or 0.0
                time_runs.append(float(t))
        out[model] = {
            "conf_runs": conf_runs,
            "time_runs": time_runs,
            "fmt_rate":  mdata["summary"]["format_compliance_rate"],
            "summary":   mdata["summary"],
        }
    return out


def _save(fig: plt.Figure, name: str) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CHAPTER4_DIR.mkdir(parents=True, exist_ok=True)
    for d in [REPORTS_DIR, CHAPTER4_DIR]:
        out = d / name
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
        print(f"  Saved -> {out}")


def chart_boxplot(models: list[str], extracted: dict, source: str) -> None:
    plt.rcParams.update(_RCPARAMS)
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("white")

    data_series = [extracted[m]["conf_runs"] for m in models]
    bp = ax.boxplot(
        data_series, patch_artist=True, notch=False, widths=0.45,
        medianprops={"color": TEXT_C, "linewidth": 1.8},
        whiskerprops={"color": SPINE_C, "linewidth": 1.0},
        capprops={"color": SPINE_C, "linewidth": 1.0},
        flierprops={"marker": "o", "markersize": 4,
                    "markerfacecolor": SPINE_C, "markeredgecolor": SPINE_C, "alpha": 0.6},
    )
    for patch, color in zip(bp["boxes"], MODEL_COLORS):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
        patch.set_linewidth(0.8)

    ax.set_xticks(range(1, len(models) + 1))
    ax.set_xticklabels([_short(m) for m in models], fontsize=9)
    ax.set_ylim(-0.05, 1.10)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1.0))
    ax.set_ylabel("Confidence Score", fontsize=9)
    ax.set_title("Confidence Score Distribution per LLM Model -- Condition B (Box Plot)",
                 color=TEXT_C, pad=8)
    _style_vbar(ax)
    ax.axhline(0.5, color=SPINE_C, linestyle="--", linewidth=0.8, alpha=0.7)
    ax.text(len(models) + 0.5, 0.51, "0.5 ref", fontsize=7.5, color=SPINE_C, va="bottom")
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _save(fig, f"llm_chart_{TIMESTAMP}_1_boxplot_confidence.png")
    plt.close(fig)
    plt.rcdefaults()


def chart_fmt_compliance(models: list[str], extracted: dict, source: str) -> None:
    plt.rcParams.update(_RCPARAMS)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.patch.set_facecolor("white")

    rates = [extracted[m]["fmt_rate"] * 100 for m in models]
    x_pos = np.arange(len(models))
    bars  = ax.bar(x_pos, rates, color=MODEL_COLORS, alpha=0.82,
                   width=0.55, edgecolor="white", linewidth=0.5)
    ax.set_xticks(x_pos)
    ax.set_xticklabels([_short(m) for m in models], fontsize=9)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Compliance Rate (%)", fontsize=9)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    ax.set_title("Format Compliance Rate per LLM Model -- Condition B", color=TEXT_C, pad=8)
    _style_vbar(ax)

    for bar, v in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.5,
                f"{v:.0f}%",
                ha="center", va="bottom", fontsize=9.5, color=TEXT_C, fontweight="bold")

    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _save(fig, f"llm_chart_{TIMESTAMP}_2_format_compliance.png")
    plt.close(fig)
    plt.rcdefaults()


def chart_inference_time(models: list[str], extracted: dict, source: str) -> None:
    plt.rcParams.update(_RCPARAMS)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.patch.set_facecolor("white")

    means = [float(np.mean(extracted[m]["time_runs"])) if extracted[m]["time_runs"] else 0.0
             for m in models]
    stds  = [float(np.std(extracted[m]["time_runs"]))  if extracted[m]["time_runs"] else 0.0
             for m in models]
    x_pos = np.arange(len(models))

    bars = ax.bar(x_pos, means, color=MODEL_COLORS, alpha=0.82,
                  width=0.55, edgecolor="white", linewidth=0.5,
                  yerr=stds, error_kw={"ecolor": SPINE_C, "capsize": 4, "linewidth": 1.0})
    ax.set_xticks(x_pos)
    ax.set_xticklabels([_short(m) for m in models], fontsize=9)
    ax.set_ylabel("Avg Inference Time (seconds)", fontsize=9)
    ax.set_title("Average Inference Time per LLM Model -- Condition B (with Std Dev)",
                 color=TEXT_C, pad=8)
    _style_vbar(ax)

    for bar, v in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(means) * 0.015,
                f"{v:.1f}s",
                ha="center", va="bottom", fontsize=9, color=TEXT_C)

    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    _save(fig, f"llm_chart_{TIMESTAMP}_3_inference_time.png")
    plt.close(fig)
    plt.rcdefaults()


def chart_stats_table(models: list[str], extracted: dict, source: str) -> None:
    plt.rcParams.update(_RCPARAMS)
    fig, ax = plt.subplots(figsize=(7.5, 3.0))
    fig.patch.set_facecolor("white")
    ax.axis("off")

    col_labels = ["Model", "Mean", "Std Dev", "Min", "Max", "Fmt OK", "Avg Time\n(s)"]
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
            f"{mean_c:.2f}", f"{std_c:.2f}", f"{min_c:.2f}", f"{max_c:.2f}",
            f"{extracted[m]['fmt_rate'] * 100:.0f}%",
            f"{avg_t:.1f}",
        ])

    tbl = ax.table(cellText=rows, colLabels=col_labels,
                   cellLoc="center", loc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.0, 1.9)

    col_widths = [0.22, 0.11, 0.11, 0.11, 0.11, 0.11, 0.13]
    for col_idx, w in enumerate(col_widths):
        for row_idx in range(len(rows) + 1):
            tbl[row_idx, col_idx].set_width(w)

    for col in range(len(col_labels)):
        cell = tbl[0, col]
        cell.set_facecolor("#2166AC")
        cell.set_text_props(color="white", fontweight="bold", fontsize=9)
        cell.set_edgecolor("white")

    for row in range(1, len(rows) + 1):
        bg = "#F2F2F2" if row % 2 == 0 else "white"
        for col in range(len(col_labels)):
            cell = tbl[row, col]
            cell.set_facecolor(bg)
            cell.set_edgecolor(GRID_C)
        tbl[row, 0].set_text_props(color=MODEL_COLORS[row - 1], fontweight="bold")

    ax.set_title("LLM Model Comparison -- Condition B (Optimized Per-Model Prompt)",
                 color=TEXT_C, fontsize=11, fontweight="bold", pad=12)
    _footer(fig, source)
    fig.tight_layout(rect=[0, 0.06, 1, 0.96])
    _save(fig, f"llm_chart_{TIMESTAMP}_4_stats_table.png")
    plt.close(fig)
    plt.rcdefaults()


def main() -> None:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    models = data["models_compared"]
    extracted = _extract(data)
    source = JSON_PATH.name

    print(f"Condition B: {data['prompt_strategy']}")
    print(f"Models: {', '.join(models)}")
    print(f"Findings: {data['findings_count']} x {data['runs_per_finding']} runs = {data['findings_count'] * data['runs_per_finding']} runs/model")
    print()

    print("Chart 1: Boxplot confidence...")
    chart_boxplot(models, extracted, source)

    print("Chart 2: Format compliance...")
    chart_fmt_compliance(models, extracted, source)

    print("Chart 3: Inference time...")
    chart_inference_time(models, extracted, source)

    print("Chart 4: Stats table...")
    chart_stats_table(models, extracted, source)

    print("\nDone. 4 charts generated.")


if __name__ == "__main__":
    main()
