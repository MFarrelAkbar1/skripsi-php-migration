"""
main.py -- Entry point utama pipeline migrasi PHP 7.4 -> PHP 8.x.

Mengorkestrasi modul scanner, converter, analyzer, ai_engine, dan iso_mapper
secara berurutan untuk menghasilkan kode PHP target yang aman dan laporan ISO 27001.

Pipeline order
--------------
1. PRE-SCAN    -- Semgrep security scan on input/ (original code)
2. CONVERT     -- Rector PHP 5/7 -> target version migration (writes to output/)
3. POST-SCAN   -- Semgrep security scan on output/ (converted code)
4. ANALYZE     -- PHPStan static analysis on output/ (target PHP validation)
5. AI REVIEW   -- Ollama / Stable Code 3B fix recommendations (skippable)
6. ISO MAP     -- ISO/IEC 27001:2022 compliance report + JSON export

Exit codes
----------
0 -- ISO 27001 overall_status is COMPLIANT
1 -- NON_COMPLIANT, PARTIAL, or any pipeline stage failed to produce a report
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Sibling-module imports  (handle both run-from-root and run-from-pipeline/)
# ---------------------------------------------------------------------------

try:
    from pipeline.scanner import ScanResult, run_scan
    from pipeline.converter import ConversionResult, run_conversion
    from pipeline.analyzer import AnalysisResult, run_analysis
    from pipeline.ai_engine import (
        AIRecommendation,
        COMPARISON_MODELS,
        OLLAMA_MODEL,
        run_ai_analysis,
        run_llm_comparison,
    )
    from pipeline.iso_mapper import ISOReport, run_iso_mapping
    from pipeline.llm_quality_checker import (
        generate_quality_chart,
        run_llm_quality_check,
    )
except ModuleNotFoundError:
    from scanner import ScanResult, run_scan                    # type: ignore[no-redef]
    from converter import ConversionResult, run_conversion      # type: ignore[no-redef]
    from analyzer import AnalysisResult, run_analysis          # type: ignore[no-redef]
    from ai_engine import (                                     # type: ignore[no-redef]
        AIRecommendation,
        COMPARISON_MODELS,
        OLLAMA_MODEL,
        run_ai_analysis,
        run_llm_comparison,
    )
    from iso_mapper import ISOReport, run_iso_mapping          # type: ignore[no-redef]
    from llm_quality_checker import (                          # type: ignore[no-redef]
        generate_quality_chart,
        run_llm_quality_check,
    )

console = Console()

# ---------------------------------------------------------------------------
# PipelineResult dataclass
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """
    Aggregated result of a complete pipeline run.

    Populated sequentially as each stage completes.  A stage that raises an
    exception leaves its field as ``None`` (or ``[]`` for ai_recommendations);
    the pipeline continues rather than aborting so later stages can still run.

    Fields
    ------
    pre_scan:           ScanResult from scanning input/ before conversion.
    conversion:         ConversionResult from Rector migration.
    post_scan:          ScanResult from scanning output/ after conversion.
    analysis:           AnalysisResult from PHPStan static analysis.
    ai_recommendations: list[AIRecommendation] from Ollama (empty if skipped).
    iso_report:         ISOReport with per-control compliance status.
    total_duration_sec: Wall-clock seconds for the entire run.
    started_at:         Timestamp when run_pipeline() was called.
    """

    pre_scan: ScanResult | None
    conversion: ConversionResult | None
    post_scan: ScanResult | None
    analysis: AnalysisResult | None
    ai_recommendations: list[AIRecommendation]
    iso_report: ISOReport | None
    total_duration_sec: float
    started_at: datetime

    @property
    def is_compliant(self) -> bool:
        """True only when the ISO report status is COMPLIANT (no findings)."""
        return (
            self.iso_report is not None
            and self.iso_report.overall_status.value == "COMPLIANT"
        )


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    """Build and return the parsed CLI argument namespace."""
    parser = argparse.ArgumentParser(
        prog="python pipeline/main.py",
        description=(
            "PHP legacy migration pipeline: "
            "Semgrep -> Rector -> PHPStan -> AI -> ISO 27001:2022 report"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input",
        dest="input_dir",
        type=Path,
        default=Path("input"),
        metavar="DIR",
        help="Directory containing original PHP source files.",
    )
    parser.add_argument(
        "--output",
        dest="output_dir",
        type=Path,
        default=Path("output"),
        metavar="DIR",
        help="Destination for converted PHP 8.x files (created if absent).",
    )
    parser.add_argument(
        "--reports",
        dest="reports_dir",
        type=Path,
        default=Path("reports"),
        metavar="DIR",
        help="Directory for generated JSON reports (created if absent).",
    )
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        default=False,
        help="Skip the Ollama AI-analysis step (useful when Ollama is not running).",
    )
    parser.add_argument(
        "--model",
        dest="model",
        default="deepseek-coder:6.7b",
        metavar="MODEL",
        help=(
            "Ollama model identifier for the single-model AI analysis step. "
            "E.g.: deepseek-coder:6.7b, qwen2.5-coder:7b, codellama:7b. "
            "Ignored when --compare-all is used."
        ),
    )
    parser.add_argument(
        "--compare-all",
        dest="compare_all",
        action="store_true",
        default=False,
        help=(
            "Run zero-shot comparison across all 5 LLMs "
            "(deepseek-coder:6.7b, qwen2.5-coder:7b, codellama:7b, "
            "mistral:7b, llama3.1:8b). "
            "Each finding is run 3x per model. "
            "Results saved to reports/llm_comparison_<timestamp>.json. "
            "Overrides --model."
        ),
    )
    parser.add_argument(
        "--quality-check",
        dest="quality_check",
        action="store_true",
        default=False,
        help=(
            "Jalankan LLM quality check: ekstrak blok PHP dari output semua 5 model, "
            "cek sintaks via php -l, hitung syntax_validity_rate per model. "
            "Simpan ke reports/llm_quality_<timestamp>.json dan generate bar chart. "
            "Bisa dikombinasikan dengan --compare-all."
        ),
    )
    parser.add_argument(
        "--target-php",
        dest="target_php",
        choices=["7.4", "8.0", "8.1", "8.2", "8.3"],
        default="8.3",
        metavar="VERSION",
        help=(
            "Target PHP version for Rector migration and PHPStan validation. "
            "Choices: 7.4, 8.0, 8.1, 8.2, 8.3  (default: 8.3). "
            "Example: --target-php 8.1"
        ),
    )
    parser.add_argument(
        "--php-version",
        dest="php_version",
        choices=["5", "7", "auto"],
        default="auto",
        help=(
            "Hint for the source PHP version. "
            "'auto' lets Rector detect per-file; "
            "'5' / '7' forces the corresponding Rector level-set chain "
            "(overrides per-file auto-detection)."
        ),
    )
    parser.add_argument(
        "--prompt-mode",
        dest="prompt_mode",
        choices=["standard", "optimized"],
        default="standard",
        help=(
            "Prompt strategy for --compare-all (LLM comparison experiment). "
            "'standard' = Condition A: identical prompt for every model (default, unchanged). "
            "'optimized' = Condition B: per-model optimized prompt via "
            "PHPAIEngine._build_optimized_chat_messages(). "
            "Ignored when --compare-all is not set."
        ),
    )
    parser.add_argument(
        "--save-raw-responses",
        dest="save_raw_responses",
        action="store_true",
        default=False,
        help=(
            "Save full raw model response text in the llm_comparison JSON report. "
            "Off by default (keeps reports compact). "
            "Enable for qualitative analysis or Bab 4 case study documentation. "
            "Only applies when --compare-all is set."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


def run_pipeline(
    input_dir: Path,
    output_dir: Path,
    reports_dir: Path,
    skip_ai: bool = False,
    php_version_hint: str = "auto",
    target_version: str = "8.3",
    model: str = "deepseek-coder:6.7b",
    compare_all: bool = False,
    quality_check: bool = False,
    prompt_mode: str = "standard",
    save_raw_responses: bool = False,
) -> PipelineResult:
    """
    Execute all six pipeline stages in order and return a ``PipelineResult``.

    Individual stage failures are caught and logged; later stages continue
    where possible.  Both ``pre_scan`` and ``analysis`` are passed to
    ``iso_mapper`` regardless of which stages succeeded.

    Parameters
    ----------
    input_dir:
        Directory containing original PHP 5.x / 7.x source files.
    output_dir:
        Destination for Rector-converted PHP files.
    reports_dir:
        Directory where JSON reports are written.
    skip_ai:
        When ``True``, the Ollama step is skipped entirely.
    php_version_hint:
        ``"5"`` or ``"7"`` to force a specific Rector level-set chain;
        ``"auto"`` lets Rector detect each file individually (default).
    target_version:
        Target PHP version string passed to Rector (level-set chain) and
        PHPStan (``--php-version``).  Defaults to ``"8.3"``.
    model:
        Ollama model identifier for single-model AI analysis.
        Only used when ``compare_all`` is ``False`` and ``skip_ai`` is ``False``.
    compare_all:
        When ``True``, runs LLM comparison across all 5 thesis models
        (``COMPARISON_MODELS``) with 3 runs per finding each, and saves a
        ``reports/llm_comparison_<timestamp>.json``.  Overrides ``model``.
    prompt_mode:
        ``"standard"`` (Condition A) or ``"optimized"`` (Condition B).
        Only used when ``compare_all`` is ``True``.  Defaults to
        ``"standard"`` (original unchanged behaviour).
    quality_check:
        When ``True``, runs LLM quality check across all 5 models: extracts
        PHP code blocks from each response, runs ``php -l``, and records
        syntax validity per model.  Saves
        ``reports/llm_quality_<timestamp>.json`` and a bar chart PNG.
        Can be combined with ``compare_all``.

    Returns
    -------
    PipelineResult
        Fully populated result; stages that failed have ``None`` fields.
    """
    started_at = datetime.now()
    t_start = time.perf_counter()
    reports_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Step 1 -- PRE-SCAN                                                    #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold cyan]Step 1 / 6 -- Pre-Conversion Security Scan (Semgrep)[/bold cyan]\n"
            f"[dim]Target: {input_dir.resolve()}[/dim]",
            border_style="cyan",
        )
    )
    pre_scan: ScanResult | None = None
    try:
        pre_scan = run_scan(input_dir)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Pre-scan failed:[/bold red] {exc}")

    # ------------------------------------------------------------------ #
    # Step 2 -- CONVERT                                                     #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold green]Step 2 / 6 -- PHP Migration (Rector)[/bold green]\n"
            f"[dim]{input_dir.resolve()} -> {output_dir.resolve()}[/dim]",
            border_style="green",
        )
    )
    conversion: ConversionResult | None = None
    try:
        conversion = run_conversion(
            input_path=input_dir,
            output_path=output_dir,
            target_version=target_version,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Conversion failed:[/bold red] {exc}")

    # ------------------------------------------------------------------ #
    # Step 3 -- POST-SCAN                                                   #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold cyan]Step 3 / 6 -- Post-Conversion Security Scan (Semgrep)[/bold cyan]\n"
            f"[dim]Target: {output_dir.resolve()}[/dim]",
            border_style="cyan",
        )
    )
    post_scan: ScanResult | None = None
    if conversion is not None:
        try:
            post_scan = run_scan(output_dir)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[bold red]Post-scan failed:[/bold red] {exc}")
    else:
        console.print(
            "[yellow]Conversion did not complete -- post-scan skipped.[/yellow]"
        )

    # ------------------------------------------------------------------ #
    # Step 4 -- ANALYZE                                                     #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold blue]Step 4 / 6 -- Static Analysis (PHPStan)[/bold blue]\n"
            f"[dim]Target: {output_dir.resolve()}  |  PHP {target_version}  |  Level 5[/dim]",
            border_style="blue",
        )
    )
    analysis: AnalysisResult | None = None
    if conversion is not None:
        try:
            analysis = run_analysis(target_path=output_dir, php_version=target_version)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
    else:
        console.print(
            "[yellow]Conversion did not complete -- PHPStan analysis skipped.[/yellow]"
        )

    # ------------------------------------------------------------------ #
    # Step 5 -- AI REVIEW                                                   #
    # ------------------------------------------------------------------ #
    ai_recs: list[AIRecommendation] = []
    if skip_ai:
        console.print(
            Panel(
                "[dim]Skipped via --skip-ai flag.[/dim]",
                title="[bold]Step 5 / 6 -- AI-Assisted Review[/bold]",
                border_style="dim",
            )
        )
    elif compare_all:
        models_str = ", ".join(COMPARISON_MODELS)
        _prompt_label = (
            "identical for all models (Condition A)"
            if prompt_mode == "standard"
            else "per-model optimized (Condition B)"
        )
        console.print(
            Panel(
                "[bold magenta]Step 5 / 6 -- LLM Comparison "
                "(5 models x 3 runs each)[/bold magenta]\n"
                f"[dim]Models : {models_str}[/dim]\n"
                f"[dim]Temperature : 0.1 (locked) | Prompt : {_prompt_label}[/dim]",
                border_style="magenta",
            )
        )
        if pre_scan and pre_scan.findings:
            try:
                run_llm_comparison(
                    findings=pre_scan.findings,
                    reports_dir=reports_dir,
                    prompt_mode=prompt_mode,
                    save_raw_responses=save_raw_responses,
                )
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red]LLM comparison failed:[/bold red] {exc}")
        else:
            console.print(
                "[dim]No pre-scan findings -- LLM comparison skipped.[/dim]"
            )
    else:
        console.print(
            Panel(
                f"[bold magenta]Step 5 / 6 -- AI-Assisted Security Review "
                f"({model})[/bold magenta]\n"
                "[dim]Processing pre-scan findings with priority <= 3[/dim]",
                border_style="magenta",
            )
        )
        if pre_scan and pre_scan.findings:
            try:
                ai_recs = run_ai_analysis(pre_scan.findings, model=model)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red]AI analysis failed:[/bold red] {exc}")
        else:
            console.print(
                "[dim]No pre-scan findings -- AI review step skipped.[/dim]"
            )

    # ------------------------------------------------------------------ #
    # Step 5b -- LLM QUALITY CHECK  (optioneel, --quality-check flag)      #
    # ------------------------------------------------------------------ #
    if quality_check and not skip_ai:
        console.print(
            Panel(
                "[bold magenta]Step 5b -- LLM Quality Check (Syntax Validity)[/bold magenta]\n"
                "[dim]Ekstrak blok PHP dari output semua 5 model, jalankan php -l per blok[/dim]",
                border_style="magenta",
            )
        )
        if pre_scan and pre_scan.findings:
            try:
                quality_report = run_llm_quality_check(
                    findings=pre_scan.findings,
                    reports_dir=reports_dir,
                )
                generate_quality_chart(quality_report, reports_dir)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red]LLM quality check failed:[/bold red] {exc}")
        else:
            console.print(
                "[dim]No pre-scan findings -- LLM quality check skipped.[/dim]"
            )
    elif quality_check and skip_ai:
        console.print(
            "[dim]--quality-check ignored because --skip-ai is set.[/dim]"
        )

    # ------------------------------------------------------------------ #
    # Step 6 -- ISO MAP                                                     #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold yellow]Step 6 / 6 -- ISO/IEC 27001:2022 Compliance Mapping[/bold yellow]",
            border_style="yellow",
        )
    )
    timestamp = started_at.strftime("%Y%m%d_%H%M%S")
    iso_output = reports_dir / f"iso_report_{timestamp}.json"
    iso_report: ISOReport | None = None
    try:
        iso_report = run_iso_mapping(
            scan_result=pre_scan,
            analysis_result=analysis,
            ai_recommendations=ai_recs,
            output_path=iso_output,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ISO mapping failed:[/bold red] {exc}")

    total_duration = time.perf_counter() - t_start

    result = PipelineResult(
        pre_scan=pre_scan,
        conversion=conversion,
        post_scan=post_scan,
        analysis=analysis,
        ai_recommendations=ai_recs,
        iso_report=iso_report,
        total_duration_sec=round(total_duration, 2),
        started_at=started_at,
    )

    _print_final_summary(result)
    _save_pipeline_result(result, reports_dir, timestamp)
    return result


# ---------------------------------------------------------------------------
# Final Rich summary
# ---------------------------------------------------------------------------


def _print_final_summary(result: PipelineResult) -> None:
    """
    Print a pre-scan vs post-scan comparison table and an overall summary panel.
    """

    # --- Comparison table -------------------------------------------------
    cmp_tbl = Table(
        title="Security Findings: Pre-Conversion vs Post-Conversion",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
    )
    cmp_tbl.add_column("Metric", width=32)
    cmp_tbl.add_column("Pre-Conversion", justify="right", width=17)
    cmp_tbl.add_column("Post-Conversion", justify="right", width=17)
    cmp_tbl.add_column("Delta", justify="right", width=10)

    def _delta(pre: int, post: int) -> str:
        diff = post - pre
        if diff < 0:
            return f"[green]{diff}[/green]"
        if diff > 0:
            return f"[red]+{diff}[/red]"
        return "[dim]±0[/dim]"

    def _pre(key: str) -> int:
        return (result.pre_scan.summary.by_severity.get(key, 0)
                if result.pre_scan else 0)

    def _post(key: str) -> int:
        return (result.post_scan.summary.by_severity.get(key, 0)
                if result.post_scan else 0)

    pre_total = result.pre_scan.summary.total_findings if result.pre_scan else 0
    post_total = result.post_scan.summary.total_findings if result.post_scan else 0

    cmp_tbl.add_row(
        "Total findings",
        str(pre_total), str(post_total), _delta(pre_total, post_total),
    )
    cmp_tbl.add_row(
        "[red]ERROR[/red] severity",
        str(_pre("ERROR")), str(_post("ERROR")),
        _delta(_pre("ERROR"), _post("ERROR")),
    )
    cmp_tbl.add_row(
        "[yellow]WARNING[/yellow] severity",
        str(_pre("WARNING")), str(_post("WARNING")),
        _delta(_pre("WARNING"), _post("WARNING")),
    )
    cmp_tbl.add_row(
        "[cyan]INFO[/cyan] severity",
        str(_pre("INFO")), str(_post("INFO")),
        _delta(_pre("INFO"), _post("INFO")),
    )

    console.print(cmp_tbl)

    # --- ISO / overall status panel --------------------------------------
    iso_style = "dim"
    iso_status_str = "[dim]N/A[/dim]"
    if result.iso_report:
        _style_map = {
            "COMPLIANT":     ("green",  "COMPLIANT"),
            "PARTIAL":       ("yellow", "PARTIAL"),
            "NON_COMPLIANT": ("red",    "NON-COMPLIANT"),
        }
        iso_style, label = _style_map.get(
            result.iso_report.overall_status.value, ("white", "UNKNOWN")
        )
        iso_status_str = (
            f"[{iso_style}][bold]{label}[/bold][/{iso_style}]"
        )

    def _conv_str() -> str:
        if not result.conversion:
            return "[dim]N/A[/dim]"
        s = result.conversion.summary
        parts = []
        if s.converted:
            parts.append(f"[green]{s.converted} converted[/green]")
        if s.skipped:
            parts.append(f"[dim]{s.skipped} skipped[/dim]")
        if s.failed:
            parts.append(f"[red]{s.failed} failed[/red]")
        return "  ".join(parts) if parts else "[dim]0 files[/dim]"

    def _phpstan_str() -> str:
        if not result.analysis:
            return "[dim]N/A[/dim]"
        n = result.analysis.summary.total_errors
        colour = "red" if n else "green"
        return f"[{colour}]{n} error(s)[/{colour}]"

    ai_str = (
        f"{len(result.ai_recommendations)} recommendation(s)"
        if result.ai_recommendations
        else "[dim]0 / skipped[/dim]"
    )

    console.print(
        Panel(
            f"[bold]ISO 27001:2022 Status  :[/bold]  {iso_status_str}\n"
            f"[bold]Rector Conversion      :[/bold]  {_conv_str()}\n"
            f"[bold]PHPStan Errors         :[/bold]  {_phpstan_str()}\n"
            f"[bold]AI Recommendations     :[/bold]  {ai_str}\n"
            f"[bold]Total Duration         :[/bold]  {result.total_duration_sec}s\n"
            f"[bold]Started At             :[/bold]  "
            f"{result.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            title="[bold]Pipeline Complete -- Summary[/bold]",
            border_style=iso_style,
        )
    )


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


def _save_pipeline_result(
    result: PipelineResult,
    reports_dir: Path,
    timestamp: str,
) -> None:
    """
    Serialise ``PipelineResult`` to ``reports/pipeline_result_{timestamp}.json``.

    Only lightweight summary data is written (not raw Semgrep / PHPStan JSON,
    which can be very large).  The full ISO report is in a separate file written
    by ``iso_mapper.export_json()``.
    """
    output_path = reports_dir / f"pipeline_result_{timestamp}.json"

    payload: dict = {
        "started_at": result.started_at.isoformat(),
        "total_duration_sec": result.total_duration_sec,
        "pre_scan": _scan_summary_to_dict(result.pre_scan),
        "post_scan": _scan_summary_to_dict(result.post_scan),
        "conversion": _conversion_summary_to_dict(result.conversion),
        "analysis": _analysis_summary_to_dict(result.analysis),
        "ai_recommendations_count": len(result.ai_recommendations),
        "iso_report": (
            {
                "overall_status": result.iso_report.overall_status.value,
                "total_findings": result.iso_report.total_findings,
                "critical_findings": result.iso_report.critical_findings,
                "generated_at": result.iso_report.generated_at.isoformat(),
            }
            if result.iso_report
            else None
        ),
    }

    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"[dim]Pipeline result saved -> {output_path}[/dim]")


def _scan_summary_to_dict(scan: ScanResult | None) -> dict | None:
    if scan is None:
        return None
    s = scan.summary
    return {
        "total_findings": s.total_findings,
        "scanned_files": s.scanned_files,
        "by_severity": s.by_severity,
        "by_vuln_type": s.by_vuln_type,
        "scan_duration_sec": s.scan_duration_sec,
        "rulesets_used": s.rulesets_used,
    }


def _conversion_summary_to_dict(conv: ConversionResult | None) -> dict | None:
    if conv is None:
        return None
    s = conv.summary
    return {
        "total_files": s.total_files,
        "converted": s.converted,
        "skipped": s.skipped,
        "failed": s.failed,
        "php5_files": s.php5_files,
        "php7_files": s.php7_files,
        "unknown_files": s.unknown_files,
        "level_sets_used": s.level_sets_used,
        "conversion_duration_sec": s.conversion_duration_sec,
        "errors": s.errors,
    }


def _analysis_summary_to_dict(analysis: AnalysisResult | None) -> dict | None:
    if analysis is None:
        return None
    s = analysis.summary
    return {
        "total_errors": s.total_errors,
        "total_files_analysed": s.total_files_analysed,
        "by_severity": s.by_severity,
        "by_iso_control": s.by_iso_control,
        "phpstan_level": s.phpstan_level,
        "php_version": s.php_version,
        "duration_sec": s.duration_sec,
        "phpstan_parse_errors": s.phpstan_parse_errors,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments and run the full migration pipeline."""
    args = _parse_args()

    ai_mode = (
        "compare-all (5 models x 3 runs)"
        if args.compare_all
        else "skip"
        if args.skip_ai
        else args.model
    )
    quality_str = "[green]yes[/green]" if args.quality_check else "[dim]no[/dim]"
    prompt_mode_str = (
        "[dim]standard (Condition A)[/dim]"
        if args.prompt_mode == "standard"
        else "[bold yellow]optimized (Condition B)[/bold yellow]"
    )
    console.print(
        Panel(
            f"[bold green]PHP Legacy Migration Pipeline[/bold green]\n"
            f"Input         : [cyan]{args.input_dir.resolve()}[/cyan]\n"
            f"Output        : [cyan]{args.output_dir.resolve()}[/cyan]\n"
            f"Reports       : [cyan]{args.reports_dir.resolve()}[/cyan]\n"
            f"AI mode       : [yellow]{ai_mode}[/yellow]\n"
            f"Prompt mode   : {prompt_mode_str}\n"
            f"Quality check : {quality_str}\n"
            f"PHP hint      : [yellow]{args.php_version}[/yellow]\n"
            f"Target PHP    : [bold yellow]{args.target_php}[/bold yellow]",
            title="[bold]Skripsi -- Muhammad Farrel Akbar[/bold]",
            border_style="green",
        )
    )

    result = run_pipeline(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        reports_dir=args.reports_dir,
        skip_ai=args.skip_ai,
        php_version_hint=args.php_version,
        target_version=args.target_php,
        model=args.model,
        compare_all=args.compare_all,
        quality_check=args.quality_check,
        prompt_mode=args.prompt_mode,
        save_raw_responses=args.save_raw_responses,
    )

    sys.exit(0 if result.is_compliant else 1)


if __name__ == "__main__":
    main()
