"""
llm_quality_checker.py -- Metrik kualitas output AI: syntax validity per model.

Untuk setiap saran perbaikan kode dari AI (semua 5 model):
1. Ekstrak blok kode PHP dari response AI
2. Jalankan php -l ke kode tersebut
3. Catat: valid (1) atau syntax error (0)
4. Hitung syntax validity rate per model

Menghasilkan:
- reports/llm_quality_<timestamp>.json  -- data mentah + ringkasan per model
- reports/llm_quality_chart_<timestamp>.png  -- bar chart perbandingan 5 model

ISO/IEC 27001:2022 relevance:
  A.8.29 -- Security Testing in Development (validasi kualitas output AI)
  A.8.28 -- Secure Coding (output AI harus valid secara sintaks sebelum dipakai)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

try:
    from pipeline.ai_engine import (
        PHPAIEngine,
        COMPARISON_MODELS,
        COMPARISON_RUNS,
        OLLAMA_BASE_URL,
        PRIORITY_THRESHOLD,
        MAX_CODE_CHARS,
    )
    from pipeline.scanner import ScanFinding
except ModuleNotFoundError:
    from ai_engine import (  # type: ignore[no-redef]
        PHPAIEngine,
        COMPARISON_MODELS,
        COMPARISON_RUNS,
        OLLAMA_BASE_URL,
        PRIORITY_THRESHOLD,
        MAX_CODE_CHARS,
    )
    from scanner import ScanFinding  # type: ignore[no-redef]

console = Console()

# ---------------------------------------------------------------------------
# Chart style (consistent with llm_comparison_chart.py)
# ---------------------------------------------------------------------------

MODEL_COLORS = [
    "#2166AC",  # blue   -- deepseek-coder
    "#4DAC26",  # green  -- qwen2.5-coder
    "#D7191C",  # red    -- codellama
    "#7B3294",  # purple -- mistral
    "#E66101",  # orange -- llama3.1
]
GRID_C  = "#EBEBEB"
TEXT_C  = "#1A1A1A"
SPINE_C = "#AAAAAA"

_RCPARAMS: dict = {
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


# ---------------------------------------------------------------------------
# PHP syntax checking
# ---------------------------------------------------------------------------


def _check_php_available() -> bool:
    """Return True jika php tersedia di PATH."""
    try:
        subprocess.run(["php", "--version"], capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_php_lint(code: str) -> bool | None:
    """
    Jalankan php -l pada kode yang diberikan.

    Returns
    -------
    True  -- sintaks PHP valid
    False -- sintaks error
    None  -- php tidak tersedia di PATH
    """
    stripped = code.strip()
    if not stripped.startswith("<?"):
        stripped = "<?php\n" + stripped

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".php", encoding="utf-8", delete=False
        ) as f:
            f.write(stripped)
            tmp_path = f.name

        proc = subprocess.run(
            ["php", "-l", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except FileNotFoundError:
        return None  # php tidak ada di PATH
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _extract_php_code(raw_text: str) -> str:
    """Ekstrak blok kode PHP pertama dari teks respons model."""
    match = re.search(r"```php\s*([\s\S]*?)```", raw_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    match = re.search(r"```\s*([\s\S]*?)```", raw_text)
    if match:
        candidate = match.group(1).strip()
        if candidate and not candidate.upper().startswith("FIXED"):
            return candidate

    match = re.search(r"(<\?php[\s\S]*?\?>)", raw_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return ""


# ---------------------------------------------------------------------------
# Quality check runner
# ---------------------------------------------------------------------------


def run_llm_quality_check(
    findings: list[ScanFinding],
    models: list[str] | None = None,
    runs_per_finding: int = COMPARISON_RUNS,
    ollama_base_url: str = OLLAMA_BASE_URL,
    reports_dir: Path | None = None,
) -> dict:
    """
    Jalankan inferensi AI dan ukur syntax validity kode PHP yang dihasilkan.

    Untuk setiap model x finding x run:
    - Kirim prompt identik ke semua model via /api/chat (zero-shot)
    - Ekstrak blok kode PHP dari respons
    - Jalankan php -l, catat valid=1 / invalid=0
    - Hitung syntax_validity_rate = valid / total_extracted per model

    Parameters
    ----------
    findings:
        List ScanFinding dari scanner. Hanya finding priority <= PRIORITY_THRESHOLD.
    models:
        List model Ollama. Default: COMPARISON_MODELS (5 model thesis).
    runs_per_finding:
        Jumlah run per model per finding. Default: COMPARISON_RUNS (3).
    ollama_base_url:
        URL Ollama lokal.
    reports_dir:
        Jika diberikan, laporan disimpan ke reports_dir/llm_quality_<timestamp>.json.

    Returns
    -------
    dict
        Laporan kualitas JSON-serializable dengan syntax_validity_rate per model.
    """
    if models is None:
        models = COMPARISON_MODELS

    eligible = [f for f in findings if f.priority <= PRIORITY_THRESHOLD]
    if not eligible:
        console.print("[dim]LLM Quality Check: tidak ada findings eligible (priority <= 3).[/dim]")
        return _empty_report(models, runs_per_finding)

    php_available = _check_php_available()
    if not php_available:
        console.print(
            "[yellow]LLM Quality Check: php tidak tersedia di PATH. "
            "Syntax check dilewati (syntax_valid = null).[/yellow]"
        )

    # Prompt builder (model name tidak mempengaruhi isi prompt)
    _builder = PHPAIEngine(ollama_base_url=ollama_base_url)

    # Bangun chat messages per finding -- konten IDENTIK untuk semua model (zero-shot constraint)
    chat_prompts: list[tuple[ScanFinding, list[dict[str, str]]]] = []
    for finding in eligible:
        truncated = finding.code_snippet[:MAX_CODE_CHARS]
        context_str = (
            f"File: {finding.file_path}, "
            f"line {finding.line_start}. "
            f"Semgrep rule: {finding.rule_id}. "
            f"Finding: {finding.message}"
        )
        messages = _builder._build_chat_messages(
            truncated, finding.vuln_type, context_str, finding.iso_controls
        )
        chat_prompts.append((finding, messages))

    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    report: dict = {
        "generated_at": now.isoformat(),
        "timestamp": timestamp,
        "models_compared": list(models),
        "runs_per_finding": runs_per_finding,
        "findings_count": len(eligible),
        "php_available": php_available,
        "results": {},
    }

    for model_idx, model_name in enumerate(models, start=1):
        console.print(
            f"\n[bold cyan]Model {model_idx}/{len(models)}:[/bold cyan] {model_name}"
        )
        engine = PHPAIEngine(model=model_name, ollama_base_url=ollama_base_url)

        if not engine._check_ollama_alive():
            console.print(
                f"[yellow]  Ollama tidak merespons -- skip {model_name}[/yellow]"
            )
            report["results"][model_name] = {
                "model": model_name,
                "available": False,
                "findings": [],
                "summary": None,
            }
            continue

        finding_results: list[dict] = []
        agg_total_runs    = 0
        agg_extracted     = 0
        agg_valid         = 0
        agg_invalid       = 0
        agg_no_block      = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            total_ops = len(chat_prompts) * runs_per_finding
            task = progress.add_task(f"[cyan]{model_name}...", total=total_ops)

            for finding, messages in chat_prompts:
                runs_data: list[dict] = []

                for run_i in range(1, runs_per_finding + 1):
                    progress.update(
                        task,
                        description=(
                            f"[cyan]{model_name} | "
                            f"{Path(finding.file_path).name} "
                            f"run {run_i}/{runs_per_finding}..."
                        ),
                    )

                    raw_text, elapsed = engine._call_ollama_chat_timed(messages)
                    code_block = _extract_php_code(raw_text)

                    if not code_block:
                        syntax_valid: bool | None = None  # tidak ada blok kode
                        agg_no_block += 1
                    else:
                        syntax_valid = _run_php_lint(code_block)
                        agg_extracted += 1
                        if syntax_valid is True:
                            agg_valid += 1
                        elif syntax_valid is False:
                            agg_invalid += 1
                        # syntax_valid == None: php tidak tersedia, tidak dihitung

                    agg_total_runs += 1
                    runs_data.append({
                        "run_index": run_i,
                        "code_block_extracted": bool(code_block),
                        "syntax_valid": syntax_valid,
                        "inference_time_sec": elapsed,
                    })
                    progress.advance(task)

                finding_results.append({
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "vuln_type": finding.vuln_type,
                    "runs": runs_data,
                })

        # Syntax validity rate: valid / total_extracted (hanya run yg punya blok kode)
        if agg_extracted > 0:
            syntax_validity_rate: float | None = round(agg_valid / agg_extracted, 4)
        elif not php_available:
            syntax_validity_rate = None
        else:
            syntax_validity_rate = 0.0  # ada run tapi tak satupun menghasilkan kode

        extraction_rate = round(agg_extracted / agg_total_runs, 4) if agg_total_runs > 0 else 0.0

        summary: dict = {
            "total_runs": agg_total_runs,
            "code_blocks_extracted": agg_extracted,
            "no_code_block": agg_no_block,
            "syntax_valid": agg_valid,
            "syntax_invalid": agg_invalid,
            "extraction_rate": extraction_rate,
            "syntax_validity_rate": syntax_validity_rate,
        }

        report["results"][model_name] = {
            "model": model_name,
            "available": True,
            "findings": finding_results,
            "summary": summary,
        }

        rate_str = f"{syntax_validity_rate:.1%}" if syntax_validity_rate is not None else "N/A"
        console.print(
            f"  [green]Done:[/green] "
            f"extracted={agg_extracted}/{agg_total_runs} ({extraction_rate:.0%})  "
            f"valid={agg_valid}/{agg_extracted if agg_extracted else 0}  "
            f"syntax_validity_rate={rate_str}"
        )

    if reports_dir is not None:
        save_quality_report(report, reports_dir)

    _print_quality_summary(report)
    return report


def _empty_report(models: list[str], runs_per_finding: int) -> dict:
    now = datetime.now()
    return {
        "generated_at": now.isoformat(),
        "timestamp": now.strftime("%Y%m%d_%H%M%S"),
        "models_compared": list(models),
        "runs_per_finding": runs_per_finding,
        "findings_count": 0,
        "php_available": False,
        "results": {},
    }


# ---------------------------------------------------------------------------
# Report saving
# ---------------------------------------------------------------------------


def save_quality_report(report: dict, reports_dir: Path) -> Path:
    """Simpan laporan ke reports_dir/llm_quality_<timestamp>.json."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = report.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
    path = reports_dir / f"llm_quality_{ts}.json"
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"[dim]LLM quality report saved -> {path}[/dim]")
    return path


# ---------------------------------------------------------------------------
# Terminal summary table
# ---------------------------------------------------------------------------


def _print_quality_summary(report: dict) -> None:
    results = report.get("results", {})
    if not results:
        return

    tbl = Table(
        title="LLM Output Quality -- Syntax Validity Rate",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    tbl.add_column("Model", no_wrap=True)
    tbl.add_column("Avail.", justify="center", width=7)
    tbl.add_column("Total Runs", justify="right", width=11)
    tbl.add_column("Extracted", justify="right", width=10)
    tbl.add_column("Valid", justify="right", width=7)
    tbl.add_column("Invalid", justify="right", width=9)
    tbl.add_column("Validity Rate", justify="center", width=14)

    for model_name, data in results.items():
        if not data.get("available", False):
            tbl.add_row(
                model_name, "[red]no[/red]", "-", "-", "-", "-", "-"
            )
            continue
        s = data.get("summary") or {}
        rate = s.get("syntax_validity_rate")
        if rate is None:
            rate_str = "[dim]N/A[/dim]"
        else:
            style = "green" if rate >= 0.8 else "yellow" if rate >= 0.5 else "red"
            rate_str = f"[{style}]{rate:.1%}[/{style}]"

        tbl.add_row(
            model_name,
            "[green]yes[/green]",
            str(s.get("total_runs", 0)),
            str(s.get("code_blocks_extracted", 0)),
            str(s.get("syntax_valid", 0)),
            str(s.get("syntax_invalid", 0)),
            rate_str,
        )

    console.print(tbl)


# ---------------------------------------------------------------------------
# Bar chart: syntax validity rate per model
# ---------------------------------------------------------------------------


def generate_quality_chart(report: dict, reports_dir: Path) -> Path:
    """
    Generate bar chart syntax_validity_rate per model.

    Dua bar per model (grouped):
    - Bar solid   : Syntax Validity Rate  (valid / extracted)
    - Bar hatch   : Code Block Extraction Rate  (extracted / total_runs)

    Simpan ke reports_dir/llm_quality_chart_<timestamp>.png.
    """
    plt.rcParams.update(_RCPARAMS)

    results   = report.get("results", {})
    models    = report.get("models_compared", list(results.keys()))
    timestamp = report.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
    php_avail = report.get("php_available", True)

    labels:     list[str]   = []
    rates:      list[float] = []
    extractions:list[float] = []
    colors:     list[str]   = []

    for i, model in enumerate(models):
        data = results.get(model, {})
        s    = data.get("summary") or {}
        rate = s.get("syntax_validity_rate")
        ext  = s.get("extraction_rate", 0.0)

        labels.append(model)
        rates.append((rate * 100) if isinstance(rate, float) else 0.0)
        extractions.append(float(ext) * 100)
        colors.append(MODEL_COLORS[i % len(MODEL_COLORS)])

    if not labels:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=12)
        ax.axis("off")
        out = reports_dir / f"llm_quality_chart_{timestamp}.png"
        reports_dir.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, dpi=150, facecolor="white")
        plt.close(fig)
        plt.rcdefaults()
        return out

    x_pos = np.arange(len(labels))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 5.5))
    fig.patch.set_facecolor("white")

    bars_validity = ax.bar(
        x_pos - width / 2, rates, width,
        label="Syntax Validity Rate",
        color=colors, alpha=0.88,
        edgecolor="white", linewidth=0.5,
    )
    bars_extract = ax.bar(
        x_pos + width / 2, extractions, width,
        label="Code Block Extraction Rate",
        color=colors, alpha=0.40, hatch="//",
        edgecolor="white", linewidth=0.5,
    )

    # Value labels on validity bars
    for bar, v in zip(bars_validity, rates):
        h = bar.get_height()
        label_txt = f"{v:.1f}%" if v > 0 else "N/A"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + 1.5,
            label_txt,
            ha="center", va="bottom",
            fontsize=9, color=TEXT_C, fontweight="bold",
        )

    # Value labels on extraction bars
    for bar, v in zip(bars_extract, extractions):
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + 1.5,
            f"{v:.0f}%",
            ha="center", va="bottom",
            fontsize=8.5, color=TEXT_C,
        )

    def _short(name: str) -> str:
        return (
            name.split(":")[0]
            .replace("deepseek-coder", "DeepSeek\nCoder")
            .replace("qwen2.5-coder", "Qwen2.5\nCoder")
            .replace("codellama", "CodeLlama")
            .replace("mistral", "Mistral")
            .replace("llama3.1", "Llama 3.1")
        )

    ax.set_xticks(x_pos)
    ax.set_xticklabels([_short(m) for m in labels], fontsize=9)
    ax.set_ylim(0, 118)
    ax.set_ylabel("Rate (%)", fontsize=9)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())

    # Threshold line at 80%
    ax.axhline(
        80, color="#27AE60", linestyle="--", linewidth=0.9, alpha=0.6,
        label="80% threshold",
    )

    ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C, loc="upper right")
    ax.grid(axis="y", linewidth=0.5, color=GRID_C, linestyle="-")
    ax.set_axisbelow(True)
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]:
        ax.spines[sp].set_color(SPINE_C)
        ax.spines[sp].set_linewidth(0.8)

    php_note = "" if php_avail else "  [php -l unavailable -- validity = 0]"
    ax.set_title(
        f"LLM Output Quality: PHP Syntax Validity Rate per Model{php_note}",
        color=TEXT_C, pad=10,
    )

    fig.text(
        0.5, 0.01,
        f"Generated: {report.get('generated_at', '')[:19]}  |  "
        f"Findings: {report.get('findings_count', 0)}  |  "
        f"Runs/model: {report.get('runs_per_finding', 0)}  |  "
        "Skripsi Muhammad Farrel Akbar",
        ha="center", fontsize=7.5, color="#888888",
    )

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / f"llm_quality_chart_{timestamp}.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    plt.rcdefaults()

    console.print(f"[dim]Quality chart saved -> {out}[/dim]")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _find_latest_quality_report(reports_dir: Path) -> Path | None:
    candidates = sorted(
        reports_dir.glob("llm_quality_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python pipeline/llm_quality_checker.py",
        description=(
            "Ukur syntax validity rate output PHP dari 5 LLM model. "
            "Ekstrak blok kode dari respons AI, jalankan php -l, generate laporan + grafik."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input", dest="input_dir", type=Path, default=Path("input"),
        help="Folder PHP sumber (untuk diambil findings-nya).",
    )
    parser.add_argument(
        "--reports", dest="reports_dir", type=Path, default=Path("reports"),
        help="Folder output laporan dan grafik.",
    )
    parser.add_argument(
        "--runs", dest="runs", type=int, default=COMPARISON_RUNS,
        help="Jumlah run per model per finding.",
    )
    parser.add_argument(
        "--chart-only", dest="chart_only", action="store_true", default=False,
        help="Hanya generate chart dari llm_quality JSON yang sudah ada (tidak jalankan inferensi).",
    )
    parser.add_argument(
        "--json", dest="json_path", type=Path, default=None,
        help="Path ke llm_quality JSON (untuk --chart-only). Default: otomatis ambil terbaru.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point CLI."""
    args = _parse_args()

    if args.chart_only:
        json_path = args.json_path
        if json_path is None:
            json_path = _find_latest_quality_report(args.reports_dir)
        if json_path is None:
            console.print("[red]Tidak ada llm_quality JSON ditemukan.[/red]")
            raise SystemExit(1)
        report = json.loads(json_path.read_text(encoding="utf-8"))
        generate_quality_chart(report, args.reports_dir)
        return

    # Full run: scan input dir, then run quality check
    try:
        from pipeline.scanner import run_scan
    except ModuleNotFoundError:
        from scanner import run_scan  # type: ignore[no-redef]

    input_dir = args.input_dir
    if not input_dir.exists():
        console.print(f"[red]Input dir tidak ada: {input_dir}[/red]")
        raise SystemExit(1)

    console.print(
        Panel(
            f"[bold cyan]LLM Quality Checker[/bold cyan]\n"
            f"Input   : [green]{input_dir.resolve()}[/green]\n"
            f"Reports : [green]{args.reports_dir.resolve()}[/green]\n"
            f"Runs    : {args.runs} per finding per model",
            border_style="cyan",
        )
    )

    scan_result = run_scan(input_dir)
    if not scan_result.findings:
        console.print("[yellow]Tidak ada findings dari scanner -- quality check tidak bisa dijalankan.[/yellow]")
        return

    report = run_llm_quality_check(
        findings=scan_result.findings,
        runs_per_finding=args.runs,
        reports_dir=args.reports_dir,
    )
    generate_quality_chart(report, args.reports_dir)


if __name__ == "__main__":
    main()
