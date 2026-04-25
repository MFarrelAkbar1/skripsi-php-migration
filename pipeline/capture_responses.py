"""
capture_responses.py -- Ad-hoc script to capture raw LLM responses for Bab 4.

Re-runs the SQL Injection finding from Output.php:768 (from the 25 Apr 2026
mck/ scan) against a configurable set of models and saves the full raw
response text to reports/raw_responses_<timestamp>.json.

Usage
-----
    # All 5 models, 1 run each (fast, for documentation)
    python pipeline/capture_responses.py

    # Specific models only
    python pipeline/capture_responses.py --models codellama:7b qwen2.5-coder:7b

    # More runs for variance check
    python pipeline/capture_responses.py --runs 3

    # Custom output path
    python pipeline/capture_responses.py --output reports/my_responses.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box

# ---------------------------------------------------------------------------
# Sibling-module imports
# ---------------------------------------------------------------------------

try:
    from pipeline.ai_engine import (
        COMPARISON_MODELS,
        OLLAMA_BASE_URL,
        PHPAIEngine,
        _OLLAMA_OPTIONS,
    )
    from pipeline.scanner import ScanFinding
except ModuleNotFoundError:
    from ai_engine import (  # type: ignore[no-redef]
        COMPARISON_MODELS,
        OLLAMA_BASE_URL,
        PHPAIEngine,
        _OLLAMA_OPTIONS,
    )
    from scanner import ScanFinding  # type: ignore[no-redef]

console = Console()

# ---------------------------------------------------------------------------
# SQL Injection finding reconstructed from the 25 Apr 2026 mck/ scan
# (Output.php line 768 -- taint source: $_SERVER['QUERY_STRING'] at line 759)
# ---------------------------------------------------------------------------

# Exact code context captured by Semgrep (lines 759-770 of Output.php).
# Semgrep reports the taint sink line; we include surrounding lines so the
# model has enough context to give a meaningful recommendation.
_SQLI_FINDING = ScanFinding(
    rule_id="php.lang.security.injection.tainted-sql-string.tainted-sql-string",
    file_path=(
        r"C:\Users\HP VICTUS\Documents\GitHub\mck\system\core\Output.php"
    ),
    line_start=768,
    line_end=768,
    col_start=4,
    col_end=61,
    message=(
        "User data flows into this manually-constructed SQL string. "
        "User data can be safely incorporated into SQL strings using "
        "prepared statements or an escape function like "
        "mysqli_real_escape_string. Value `$uri` originates from "
        "user-controlled source: $_SERVER['QUERY_STRING'] (line 759)."
    ),
    severity="ERROR",
    code_snippet=(
        "\t\t\t\t$uri .= '?'.$_SERVER['QUERY_STRING'];\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\t\t$cache_path .= md5($CI->config->item('base_url')"
        ".$CI->config->item('index_page').ltrim($uri, '/'));\n"
        "\n"
        "\t\tif ( ! @unlink($cache_path))\n"
        "\t\t{\n"
        "\t\t\tlog_message('error', 'Unable to delete cache file for '.$uri);\n"
        "\t\t\treturn FALSE;\n"
        "\t\t}"
    ),
    vuln_type="SQL Injection",
    iso_controls=["A.8.28", "A.8.26"],
    priority=1,
)


def _check_php_syntax(code: str) -> tuple[bool, str]:
    """
    Run ``php -l`` on *code* and return ``(is_valid, stderr_output)``.

    Returns ``(False, "php not found")`` when PHP is not in PATH.
    """
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".php", delete=False, encoding="utf-8"
        ) as tmp:
            if not code.strip().startswith("<?php"):
                tmp.write("<?php\n" + code)
            else:
                tmp.write(code)
            tmp_path = tmp.name

        result = subprocess.run(
            ["php", "-l", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        Path(tmp_path).unlink(missing_ok=True)
        is_valid = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return is_valid, output

    except FileNotFoundError:
        return False, "php not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "php -l timed out"


def _extract_php_block(text: str) -> str:
    """Extract the first ```php ... ``` block from model output."""
    import re
    match = re.search(r"```php\s*([\s\S]*?)```", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match = re.search(r"```\s*([\s\S]*?)```", text)
    if match:
        candidate = match.group(1).strip()
        if candidate and not candidate.upper().startswith("FIXED"):
            return candidate
    match = re.search(r"(<\?php[\s\S]*?\?>)", text)
    if match:
        return match.group(1).strip()
    return ""


def run_capture(
    models: list[str],
    runs: int,
    ollama_base_url: str,
    output_path: Path,
) -> None:
    """Run inference on the SQL Injection finding and save raw responses."""
    finding = _SQLI_FINDING
    engine_builder = PHPAIEngine(ollama_base_url=ollama_base_url)

    # Build the prompt once (same as Condition A / run_llm_comparison standard)
    truncated = finding.code_snippet[:2000]
    context_str = (
        f"File: {finding.file_path}, "
        f"line {finding.line_start}. "
        f"Semgrep rule: {finding.rule_id}. "
        f"Finding: {finding.message}"
    )
    messages = engine_builder._build_chat_messages(
        truncated, finding.vuln_type, context_str, finding.iso_controls
    )

    console.print(
        Panel(
            "[bold cyan]capture_responses.py[/bold cyan]\n"
            f"Finding : [yellow]{finding.vuln_type}[/yellow] "
            f"in [cyan]{Path(finding.file_path).name}:{finding.line_start}[/cyan]\n"
            f"Models  : {', '.join(models)}\n"
            f"Runs    : {runs} per model\n"
            f"Output  : [green]{output_path}[/green]",
            title="Raw Response Capture",
            border_style="cyan",
        )
    )

    console.print("\n[bold]Prompt sent to all models:[/bold]")
    console.print(f"[dim]System:[/dim] {messages[0]['content']}\n")
    console.print(Syntax(messages[1]["content"], "text", theme="monokai", word_wrap=True))

    now = datetime.now()
    report: dict = {
        "generated_at": now.isoformat(),
        "timestamp": now.strftime("%Y%m%d_%H%M%S"),
        "finding": {
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "vuln_type": finding.vuln_type,
            "severity": finding.severity,
            "iso_controls": finding.iso_controls,
            "message": finding.message,
            "code_snippet": finding.code_snippet,
        },
        "prompt": {
            "system": messages[0]["content"],
            "user": messages[1]["content"],
        },
        "models": {},
    }

    for model_name in models:
        console.print(f"\n[bold magenta]--- {model_name} ---[/bold magenta]")
        engine = PHPAIEngine(model=model_name, ollama_base_url=ollama_base_url)

        if not engine._check_ollama_alive():
            console.print(f"[yellow]  Ollama not reachable -- skipping {model_name}[/yellow]")
            report["models"][model_name] = {"available": False, "runs": []}
            continue

        model_runs: list[dict] = []

        for run_i in range(1, runs + 1):
            console.print(f"  Run {run_i}/{runs}...", end="", highlight=False)
            t0 = time.perf_counter()
            raw_text = engine._call_ollama_chat(messages)
            elapsed = round(time.perf_counter() - t0, 3)

            confidence = engine._extract_confidence(raw_text)
            fmt_valid = engine._check_format_valid(raw_text)
            code_block = _extract_php_block(raw_text)
            syntax_valid, php_lint_output = (
                _check_php_syntax(code_block) if code_block else (False, "no code block")
            )

            console.print(
                f" {elapsed:.1f}s | conf={confidence:.0%} | "
                f"fmt={'[green]ok[/green]' if fmt_valid else '[red]miss[/red]'} | "
                f"block={'[green]yes[/green]' if code_block else '[red]no[/red]'} | "
                f"php-l={'[green]ok[/green]' if syntax_valid else '[red]fail[/red]'}"
            )

            model_runs.append({
                "run_index": run_i,
                "inference_time_sec": elapsed,
                "confidence": confidence,
                "format_valid": fmt_valid,
                "code_block_extracted": bool(code_block),
                "syntax_valid": syntax_valid,
                "php_lint_output": php_lint_output,
                "extracted_code": code_block,
                "raw_response": raw_text,
            })

            # Print the raw response inline
            console.print(f"\n[dim]  Run {run_i} raw response:[/dim]")
            console.print(
                Panel(raw_text or "[dim](empty)[/dim]", border_style="dim", padding=(0, 1))
            )

        report["models"][model_name] = {
            "available": True,
            "runs": model_runs,
        }

    # Save to JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[green]Saved:[/green] {output_path}")

    # Summary table
    tbl = Table(
        title="Capture Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    tbl.add_column("Model")
    tbl.add_column("Run", justify="center")
    tbl.add_column("Conf.", justify="center")
    tbl.add_column("Fmt", justify="center")
    tbl.add_column("Block", justify="center")
    tbl.add_column("php -l", justify="center")
    tbl.add_column("Time(s)", justify="right")

    for model_name, mdata in report["models"].items():
        if not mdata.get("available", False):
            tbl.add_row(model_name, "-", "-", "-", "-", "-", "-")
            continue
        for run in mdata["runs"]:
            tbl.add_row(
                model_name,
                str(run["run_index"]),
                f"{run['confidence']:.0%}",
                "[green]ok[/green]" if run["format_valid"] else "[red]miss[/red]",
                "[green]yes[/green]" if run["code_block_extracted"] else "[red]no[/red]",
                "[green]ok[/green]" if run["syntax_valid"] else "[red]fail[/red]",
                str(run["inference_time_sec"]),
            )

    console.print(tbl)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture raw LLM responses for the SQL Injection finding (Bab 4)."
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=COMPARISON_MODELS,
        metavar="MODEL",
        help="Ollama model identifiers to query. Default: all 5 thesis models.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of independent runs per model. Default: 1.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output JSON path. Default: "
            "reports/raw_responses_<timestamp>.json"
        ),
    )
    parser.add_argument(
        "--ollama-url",
        default=OLLAMA_BASE_URL,
        help=f"Ollama base URL. Default: {OLLAMA_BASE_URL}",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path: Path = args.output or (
        Path(__file__).parent.parent / "reports" / f"raw_responses_{timestamp}.json"
    )

    run_capture(
        models=args.models,
        runs=args.runs,
        ollama_base_url=args.ollama_url,
        output_path=output_path,
    )


if __name__ == "__main__":
    main()
