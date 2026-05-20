"""
accuracy_validator.py -- Validator akurasi migrasi PHP via ground-truth dari Claude API.

Membandingkan hasil Rector dengan ground-truth dari claude-sonnet-4-20250514:
1. Sampling 10% file dari dataset mck (seed=42) yang lolos php -l
2. Kirim ke Anthropic API untuk mendapat migrated PHP 8.3 ground-truth
3. Bandingkan ground-truth dengan output Rector di output/mck/
4. Hasilkan reports/validation/accuracy_report.json + ringkasan konsol
"""

from __future__ import annotations

import difflib
import json
import os
import random
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import anthropic
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MCK_DIR = Path(r"C:\Users\HP VICTUS\Documents\GitHub\mck")
OUTPUT_MCK_DIR = Path(
    r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration\output\mck"
)
REPORTS_VALIDATION_DIR = Path(
    r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration\reports\validation"
)

ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
SAMPLE_SEED = 42
SAMPLE_FRACTION = 0.10
MAX_FILE_SIZE_BYTES = 50 * 1024  # 50 KB

MIGRATE_PROMPT = (
    "Migrate this PHP code to PHP 8.3. Apply all modern PHP 8.x syntax: "
    "short array syntax, null coalescing, str_contains/str_starts_with, "
    "match expressions where appropriate, typed properties. "
    "Return ONLY the migrated PHP code, no explanation."
)

# Patterns for deprecated functions
_DEPRECATED_RE = re.compile(
    r"\b(mysql_\w+|ereg\w*|create_function\s*\()",
    re.IGNORECASE,
)

# Old syntax indicators that modern PHP 8.x should replace
_OLD_ARRAY_RE = re.compile(r"\barray\s*\(", re.IGNORECASE)
_ISSET_TERNARY_RE = re.compile(r"isset\s*\([^)]*\)\s*\?", re.DOTALL)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FileValidationResult:
    """Per-file comparison result between Rector output and Claude ground-truth."""

    rel_path: str
    input_path: str
    rector_output_path: str | None
    ground_truth_path: str | None

    # (a) php -l validity
    input_syntax_valid: bool
    rector_syntax_valid: bool | None
    ground_truth_syntax_valid: bool | None

    # (b) deprecated removal
    input_deprecated_count: int
    rector_deprecated_count: int | None
    ground_truth_deprecated_count: int | None
    deprecated_removed_rector: bool | None
    deprecated_removed_ground_truth: bool | None

    # (c) modern syntax remaining in output (lower = better)
    input_old_syntax_count: int
    rector_old_syntax_count: int | None
    ground_truth_old_syntax_count: int | None

    # (d) line-level similarity between Rector output and ground-truth
    rector_vs_ground_truth_similarity: float | None

    file_size_bytes: int
    rector_file_found: bool
    api_skipped: bool
    api_skip_reason: str
    error: str


@dataclass
class ValidationSummary:
    """Aggregate statistics across all sampled files."""

    total_sampled: int
    api_calls_made: int
    api_skipped: int
    rector_file_found: int
    syntax_valid_rector: int
    syntax_valid_ground_truth: int
    deprecated_removed_rector: int
    deprecated_removed_ground_truth: int
    files_with_old_syntax_in_input: int
    avg_old_syntax_remaining_rector: float
    avg_old_syntax_remaining_ground_truth: float
    avg_similarity_score: float
    generated_at: str


# ---------------------------------------------------------------------------
# Utilities: php -l, pattern counts, similarity
# ---------------------------------------------------------------------------


def _php_lint(path: Path) -> bool:
    """Return True if `php -l <path>` exits 0 (no syntax errors)."""
    try:
        r = subprocess.run(
            ["php", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _count_deprecated(code: str) -> int:
    return len(_DEPRECATED_RE.findall(code))


def _count_old_syntax(code: str) -> int:
    """Count old-style array() calls and isset()-ternary patterns still present."""
    return len(_OLD_ARRAY_RE.findall(code)) + len(_ISSET_TERNARY_RE.findall(code))


def _similarity(text_a: str, text_b: str) -> float:
    """Line-level SequenceMatcher ratio between two text strings."""
    return round(
        difflib.SequenceMatcher(None, text_a.splitlines(), text_b.splitlines()).ratio(),
        4,
    )


# ---------------------------------------------------------------------------
# Step 1: collect valid PHP files and sample
# ---------------------------------------------------------------------------


def _collect_valid_files(mck_dir: Path) -> list[Path]:
    """Return all .php files under mck_dir that pass `php -l`.

    Excludes paths that contain a 'validation' component so that any
    ground-truth files accidentally stored inside mck_dir are ignored.
    """
    all_php = [
        f for f in sorted(mck_dir.rglob("*.php"))
        if "validation" not in f.parts
    ]
    console.print(f"[dim]Found {len(all_php)} PHP files in {mck_dir} (validation/ excluded)[/dim]")

    valid: list[Path] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("php -l validation...", total=len(all_php))
        for f in all_php:
            if _php_lint(f):
                valid.append(f)
            progress.advance(task)

    console.print(
        f"[green]{len(valid)}/{len(all_php)} files pass php -l[/green]"
    )
    return valid


def _sample(files: list[Path]) -> list[Path]:
    rng = random.Random(SAMPLE_SEED)
    k = max(1, round(len(files) * SAMPLE_FRACTION))
    return sorted(rng.sample(files, k))


# ---------------------------------------------------------------------------
# Step 2: map mck input path -> Rector output path
# ---------------------------------------------------------------------------


def _find_rector_output(
    input_path: Path,
    mck_dir: Path,
    output_mck_dir: Path,
) -> Path | None:
    """
    Locate the Rector-converted counterpart of input_path.

    Rector was run on mck/application/ as source, so output/mck/ mirrors
    that sub-tree without the leading 'application/' segment.
    Falls back to a direct relative mapping if the stripped path isn't found.
    """
    rel = input_path.relative_to(mck_dir)
    parts = rel.parts

    if parts and parts[0].lower() == "application":
        stripped = Path(*parts[1:])
        candidate = output_mck_dir / stripped
        if candidate.exists():
            return candidate

    # Direct mapping fallback
    direct = output_mck_dir / rel
    if direct.exists():
        return direct

    return None


# ---------------------------------------------------------------------------
# Step 3: Anthropic API call
# ---------------------------------------------------------------------------


def _call_api(client: anthropic.Anthropic, php_code: str) -> str:
    """Send php_code to the model and return the response text."""
    msg = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=8192,
        messages=[
            {
                "role": "user",
                "content": f"{MIGRATE_PROMPT}\n\n```php\n{php_code}\n```",
            }
        ],
    )
    return msg.content[0].text


def _extract_code(raw: str) -> str:
    """Strip markdown code fences that the model may wrap around its output."""
    m = re.search(r"```php\s*\n(.*?)```", raw, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).rstrip()
    m2 = re.search(r"```\s*\n(.*?)```", raw, re.DOTALL)
    if m2:
        return m2.group(1).rstrip()
    return raw.strip()


def _save_ground_truth(code: str, rel_path: Path, gt_dir: Path) -> Path:
    """
    Write migrated code to gt_dir preserving the relative sub-directory tree
    so filenames with the same basename (e.g. index.php) never collide.
    """
    out = gt_dir / rel_path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_validation(
    mck_dir: Path = MCK_DIR,
    output_mck_dir: Path = OUTPUT_MCK_DIR,
    reports_dir: Path = REPORTS_VALIDATION_DIR,
) -> list[FileValidationResult]:
    """
    Execute the full accuracy-validation workflow and return per-file results.

    Side effects:
    - Writes reports_dir/sample_files.txt
    - Writes reports_dir/ground_truth/<rel_path> for each API call
    - Writes reports_dir/accuracy_report.json
    """
    gt_dir = reports_dir / "ground_truth"
    sample_txt = reports_dir / "sample_files.txt"
    accuracy_json = reports_dir / "accuracy_report.json"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Step 1 -- php -l + 10% sample                                       #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold cyan]Step 1 -- Collecting PHP files that pass php -l[/bold cyan]\n"
            f"[dim]Source: {mck_dir}[/dim]",
            border_style="cyan",
        )
    )
    valid_files = _collect_valid_files(mck_dir)
    sample = _sample(valid_files)

    sample_txt.write_text(
        "\n".join(str(p) for p in sample), encoding="utf-8"
    )
    console.print(
        f"[green]Sampled {len(sample)} files "
        f"({SAMPLE_FRACTION * 100:.0f}% of {len(valid_files)} valid)[/green]\n"
        f"[dim]Sample list -> {sample_txt}[/dim]"
    )

    # ------------------------------------------------------------------ #
    # Step 2 -- Anthropic client (optional — skipped gracefully if absent) #
    # ------------------------------------------------------------------ #
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    client: anthropic.Anthropic | None = None
    if api_key:
        client = anthropic.Anthropic(api_key=api_key)
    else:
        console.print(
            "[yellow]ANTHROPIC_API_KEY not set -- API calls will be skipped; "
            "cached ground-truth files will still be used.[/yellow]"
        )

    # ------------------------------------------------------------------ #
    # Steps 3-4 -- Process files sequentially                             #
    # ------------------------------------------------------------------ #
    console.print(
        Panel(
            "[bold cyan]Steps 2-4 -- Ground-truth generation + comparison[/bold cyan]\n"
            f"[dim]Model: {ANTHROPIC_MODEL} | {len(sample)} files | sequential[/dim]",
            border_style="cyan",
        )
    )

    results: list[FileValidationResult] = []

    for idx, input_path in enumerate(sample, 1):
        rel_path = input_path.relative_to(mck_dir)
        file_size = input_path.stat().st_size
        console.rule(
            f"[dim][{idx}/{len(sample)}][/dim] [cyan]{rel_path}[/cyan] "
            f"({file_size // 1024} KB)"
        )

        # Read input
        try:
            input_code = input_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results.append(_error_result(str(rel_path), input_path, file_size, str(exc)))
            continue

        input_deprecated = _count_deprecated(input_code)
        input_old_syntax = _count_old_syntax(input_code)

        # --- Rector output --------------------------------------------------
        rector_path = _find_rector_output(input_path, mck_dir, output_mck_dir)
        rector_code: str | None = None
        rector_syntax: bool | None = None
        rector_deprecated: int | None = None
        rector_old_syntax: int | None = None

        if rector_path:
            try:
                rector_code = rector_path.read_text(encoding="utf-8", errors="replace")
                rector_syntax = _php_lint(rector_path)
                rector_deprecated = _count_deprecated(rector_code)
                rector_old_syntax = _count_old_syntax(rector_code)
                status = "[green]OK[/green]" if rector_syntax else "[red]FAIL[/red]"
                console.print(
                    f"  Rector : {rector_path.name} | php -l {status} | "
                    f"deprecated={rector_deprecated} | old_syntax={rector_old_syntax}"
                )
            except OSError as exc:
                console.print(f"  [yellow]Rector read error: {exc}[/yellow]")
        else:
            console.print("  [yellow]Rector output not found[/yellow]")

        # --- Anthropic API (with cache-hit shortcut) ------------------------
        api_skipped = False
        api_skip_reason = ""
        gt_code: str | None = None
        gt_path_result: Path | None = None
        gt_syntax: bool | None = None
        gt_deprecated: int | None = None
        gt_old_syntax: int | None = None

        cached_gt = gt_dir / rel_path
        if cached_gt.exists():
            # Ground-truth already generated in a previous run — reuse it.
            try:
                gt_code = cached_gt.read_text(encoding="utf-8", errors="replace")
                gt_path_result = cached_gt
                gt_syntax = _php_lint(cached_gt)
                gt_deprecated = _count_deprecated(gt_code)
                gt_old_syntax = _count_old_syntax(gt_code)
                gt_status = "[green]OK[/green]" if gt_syntax else "[red]FAIL[/red]"
                console.print(
                    f"  GT     : {cached_gt.name} | [dim](cached)[/dim] php -l {gt_status} | "
                    f"deprecated={gt_deprecated} | old_syntax={gt_old_syntax}"
                )
            except OSError as exc:
                console.print(f"  [yellow]Cached GT read error: {exc} -- will re-call API[/yellow]")
                gt_code = None
                gt_path_result = None

        if gt_code is None and client is None:
            api_skipped = True
            api_skip_reason = "no API key configured"
            console.print(f"  [dim]API skipped: {api_skip_reason}[/dim]")
        elif gt_code is None and file_size > MAX_FILE_SIZE_BYTES:
            api_skipped = True
            api_skip_reason = f"file too large ({file_size // 1024} KB > 50 KB limit)"
            console.print(f"  [yellow]API skipped: {api_skip_reason}[/yellow]")
        elif gt_code is None:
            try:
                console.print(f"  [dim]Calling {ANTHROPIC_MODEL}...[/dim]")
                raw = _call_api(client, input_code)
                gt_code = _extract_code(raw)
                gt_path_result = _save_ground_truth(gt_code, rel_path, gt_dir)
                gt_syntax = _php_lint(gt_path_result)
                gt_deprecated = _count_deprecated(gt_code)
                gt_old_syntax = _count_old_syntax(gt_code)
                gt_status = "[green]OK[/green]" if gt_syntax else "[red]FAIL[/red]"
                console.print(
                    f"  GT     : {gt_path_result.name} | php -l {gt_status} | "
                    f"deprecated={gt_deprecated} | old_syntax={gt_old_syntax}"
                )
            except anthropic.RateLimitError:
                api_skipped = True
                api_skip_reason = "rate limit -- sleeping 60s"
                console.print(f"  [yellow]Rate limit hit, sleeping 60s...[/yellow]")
                time.sleep(60)
                # Retry once after sleep
                try:
                    raw = _call_api(client, input_code)
                    gt_code = _extract_code(raw)
                    gt_path_result = _save_ground_truth(gt_code, rel_path, gt_dir)
                    gt_syntax = _php_lint(gt_path_result)
                    gt_deprecated = _count_deprecated(gt_code)
                    gt_old_syntax = _count_old_syntax(gt_code)
                    api_skipped = False
                    api_skip_reason = ""
                    console.print("  [green]Retry succeeded.[/green]")
                except Exception as exc2:  # noqa: BLE001
                    api_skip_reason = f"retry failed: {exc2}"
                    console.print(f"  [red]{api_skip_reason}[/red]")
            except anthropic.APIError as exc:
                api_skipped = True
                api_skip_reason = str(exc)
                console.print(f"  [red]API error: {exc}[/red]")
            except Exception as exc:  # noqa: BLE001
                api_skipped = True
                api_skip_reason = str(exc)
                console.print(f"  [red]Unexpected error: {exc}[/red]")

        # --- Similarity -----------------------------------------------------
        similarity: float | None = None
        if rector_code is not None and gt_code is not None:
            similarity = _similarity(rector_code, gt_code)
            console.print(f"  Similarity (Rector vs GT): {similarity:.4f}")

        results.append(
            FileValidationResult(
                rel_path=str(rel_path),
                input_path=str(input_path),
                rector_output_path=str(rector_path) if rector_path else None,
                ground_truth_path=str(gt_path_result) if gt_path_result else None,
                input_syntax_valid=True,  # already passed php -l in sampling
                rector_syntax_valid=rector_syntax,
                ground_truth_syntax_valid=gt_syntax,
                input_deprecated_count=input_deprecated,
                rector_deprecated_count=rector_deprecated,
                ground_truth_deprecated_count=gt_deprecated,
                deprecated_removed_rector=(
                    rector_deprecated == 0 if rector_deprecated is not None else None
                ),
                deprecated_removed_ground_truth=(
                    gt_deprecated == 0 if gt_deprecated is not None else None
                ),
                input_old_syntax_count=input_old_syntax,
                rector_old_syntax_count=rector_old_syntax,
                ground_truth_old_syntax_count=gt_old_syntax,
                rector_vs_ground_truth_similarity=similarity,
                file_size_bytes=file_size,
                rector_file_found=rector_path is not None,
                api_skipped=api_skipped,
                api_skip_reason=api_skip_reason,
                error="",
            )
        )

    _save_and_print(results, accuracy_json)
    return results


def _error_result(
    rel_path: str,
    input_path: Path,
    file_size: int,
    error: str,
) -> FileValidationResult:
    return FileValidationResult(
        rel_path=rel_path,
        input_path=str(input_path),
        rector_output_path=None,
        ground_truth_path=None,
        input_syntax_valid=False,
        rector_syntax_valid=None,
        ground_truth_syntax_valid=None,
        input_deprecated_count=0,
        rector_deprecated_count=None,
        ground_truth_deprecated_count=None,
        deprecated_removed_rector=None,
        deprecated_removed_ground_truth=None,
        input_old_syntax_count=0,
        rector_old_syntax_count=None,
        ground_truth_old_syntax_count=None,
        rector_vs_ground_truth_similarity=None,
        file_size_bytes=file_size,
        rector_file_found=False,
        api_skipped=True,
        api_skip_reason="read error",
        error=error,
    )


# ---------------------------------------------------------------------------
# Report: JSON + Rich console table
# ---------------------------------------------------------------------------


def _save_and_print(
    results: list[FileValidationResult],
    out_path: Path,
) -> None:
    """Compute aggregate summary, write JSON, and print a Rich summary table."""
    total = len(results)
    api_calls = sum(
        1 for r in results if not r.api_skipped and r.ground_truth_path
    )
    api_skipped = sum(1 for r in results if r.api_skipped)
    rector_found = sum(1 for r in results if r.rector_file_found)

    # (a) syntax_valid counts (denominator = files where output exists)
    syntax_rector = sum(1 for r in results if r.rector_syntax_valid is True)
    syntax_gt = sum(1 for r in results if r.ground_truth_syntax_valid is True)

    # (b) deprecated_removed (all outputs, not just those that had deprecated in input)
    dep_rector = sum(1 for r in results if r.deprecated_removed_rector is True)
    dep_gt = sum(1 for r in results if r.deprecated_removed_ground_truth is True)

    # (c) old syntax remaining counts
    old_syntax_inputs = sum(
        1 for r in results if r.input_old_syntax_count > 0
    )
    rector_remaining = [
        r.rector_old_syntax_count
        for r in results
        if r.rector_old_syntax_count is not None
    ]
    gt_remaining = [
        r.ground_truth_old_syntax_count
        for r in results
        if r.ground_truth_old_syntax_count is not None
    ]

    avg_rector_old = (
        round(sum(rector_remaining) / len(rector_remaining), 2)
        if rector_remaining
        else 0.0
    )
    avg_gt_old = (
        round(sum(gt_remaining) / len(gt_remaining), 2)
        if gt_remaining
        else 0.0
    )

    # (d) similarity
    sims = [
        r.rector_vs_ground_truth_similarity
        for r in results
        if r.rector_vs_ground_truth_similarity is not None
    ]
    avg_sim = round(sum(sims) / len(sims), 4) if sims else 0.0

    summary = ValidationSummary(
        total_sampled=total,
        api_calls_made=api_calls,
        api_skipped=api_skipped,
        rector_file_found=rector_found,
        syntax_valid_rector=syntax_rector,
        syntax_valid_ground_truth=syntax_gt,
        deprecated_removed_rector=dep_rector,
        deprecated_removed_ground_truth=dep_gt,
        files_with_old_syntax_in_input=old_syntax_inputs,
        avg_old_syntax_remaining_rector=avg_rector_old,
        avg_old_syntax_remaining_ground_truth=avg_gt_old,
        avg_similarity_score=avg_sim,
        generated_at=datetime.now().isoformat(),
    )

    payload = {
        "summary": asdict(summary),
        "files": [asdict(r) for r in results],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- Rich table ---------------------------------------------------------
    def _pct(n: int, d: int) -> str:
        if d == 0:
            return "N/A"
        return f"{n}/{d} ({100 * n // d}%)"

    tbl = Table(
        title="Accuracy Validation Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
    )
    tbl.add_column("Metric", width=44)
    tbl.add_column("Rector (tool)", justify="right", width=16)
    tbl.add_column("Claude GT (ref)", justify="right", width=16)

    tbl.add_row(
        "(a) Syntax valid via php -l",
        _pct(syntax_rector, rector_found),
        _pct(syntax_gt, api_calls),
    )
    tbl.add_row(
        "(b) Deprecated patterns removed",
        _pct(dep_rector, rector_found),
        _pct(dep_gt, api_calls),
    )
    tbl.add_row(
        "(c) Avg old-syntax remaining (lower = better)",
        str(avg_rector_old),
        str(avg_gt_old),
    )
    tbl.add_row(
        "(d) Avg Rector-vs-GT similarity (0-1)",
        f"{avg_sim:.4f}",
        "[dim]ref[/dim]",
    )

    console.print(tbl)
    console.print(
        Panel(
            f"Files sampled          : {total}\n"
            f"API calls made         : {api_calls}  (skipped: {api_skipped})\n"
            f"Rector output found    : {rector_found}/{total}\n"
            f"Files w/ old syntax    : {old_syntax_inputs}/{total}\n"
            f"Report                 : {out_path}",
            title="[bold green]Validation Complete[/bold green]",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_validation()
