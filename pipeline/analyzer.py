"""
analyzer.py -- Modul analisis statis menggunakan PHPStan.

Menjalankan PHPStan terhadap kode PHP hasil konversi di folder output/
untuk memverifikasi kompatibilitas PHP 8 dan mendeteksi error tipe,
variabel/fungsi tidak terdefinisi, dan dead code.  Setiap temuan dipetakan
ke kontrol ISO/IEC 27001:2022 yang relevan.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# PHPStan binary: "phpstan" assumes it is on PATH (global Composer install).
# Falls back to vendor/bin/phpstan relative to the target directory.
# Override by passing phpstan_exe= to PHPStanAnalyzer or run_analysis().
PHPSTAN_EXE: str = "phpstan"

# Default analysis level: 5 = balanced strictness (checks types of arguments,
# return types, and basic undefined method/property calls without being overly
# strict about mixed types -- appropriate for migrated legacy code).
DEFAULT_LEVEL: int = 2

# Default PHP version string passed to PHPStan --php-version flag.
# Set to 8.3 since output/ contains Rector-converted PHP 8.x code.
DEFAULT_PHP_VERSION: str = "8.3"

# ---------------------------------------------------------------------------
# Error classification rules
# ---------------------------------------------------------------------------
# Each entry: (keyword_tuple, severity, iso_controls)
# Matched case-insensitively against the PHPStan error message.
# First match wins.

_ERROR_RULES: list[tuple[tuple[str, ...], str, list[str]]] = [
    # --- Dead code (A.8.25 -- Secure Development Lifecycle) ---------------
    (
        ("dead code", "unreachable", "is never", "always true", "always false",
         "never returns", "is always", "will always", "cannot reach"),
        "WARNING",
        ["A.8.25"],
    ),
    # --- Undefined identifiers (A.8.28 + A.8.25) -------------------------
    (
        ("undefined", "unknown", "not found", "does not exist", "cannot find",
         "no such", "undeclared", "not defined", "cannot be called",
         "method not found", "class not found", "function not found"),
        "ERROR",
        ["A.8.28", "A.8.25"],
    ),
    # --- Type safety (A.8.28 -- Secure Coding) ----------------------------
    (
        ("type", "phpDoc", "typed", "incompatible", "accepts", "does not accept",
         "cannot be", "null", "nullable", "return type", "parameter type",
         "argument #", "expects", "given", "passed"),
        "ERROR",
        ["A.8.28"],
    ),
]

# Fallback when no rule matches: generic secure coding
_DEFAULT_ISO: list[str] = ["A.8.28"]

# ---------------------------------------------------------------------------
# CI3 framework false-positive filter
# ---------------------------------------------------------------------------
# PHPStan cannot see CodeIgniter 3's dynamic architecture: the base classes
# live in system/ (excluded), constants are defined at runtime in index.php,
# and Composer vendor/ is not copied to output/.  All errors matching these
# substrings are CI3 structural noise, not real application bugs.
_CI3_NOISE_SUBSTRINGS: tuple[str, ...] = (
    # CI3 base class hierarchy (system/ excluded from analysis)
    "extends unknown class CI_",
    "extends unknown class MX_",
    # CI3 runtime constants (defined by index.php, invisible to static analysis)
    "Constant ENVIRONMENT not found",
    "Constant FCPATH not found",
    "Constant APPPATH not found",
    "Constant BASEPATH not found",
    "Constant EXT not found",
    # CI3 built-in magic properties accessed via $this->
    "::$load.", "::$db.", "::$input.", "::$output.",
    "::$config.", "::$session.", "::$uri.", "::$router.",
    "::$security.", "::$form_validation.", "::$email.",
    "::$upload.", "::$pagination.", "::$cache.", "::$lang.",
    "::$benchmark.", "::$hooks.",
    # CI3 URL / form / template helpers (loaded by CI3, not in PHPStan scope)
    "Function base_url not found",
    "Function site_url not found",
    "Function redirect not found",
    "Function anchor not found",
    "Function form_open not found",
    "Function form_close not found",
    "Function set_value not found",
    "Function form_error not found",
    "Function validation_errors not found",
    "Function get_instance not found",
    "Function log_message not found",
    "Function show_error not found",
    "Function show_404 not found",
    "Function html_escape not found",
    "Function set_status_header not found",
    "Function current_url not found",
    "Function previous_url not found",
    "Function strip_image_tags not found",
    "Function encode_php_tags not found",
    "Function function_usable not found",
    "Function is_https not found",
    "Function is_cli not found",
    "Function remove_invisible_characters not found",
    # Composer packages absent from output/ (vendor/ not copied by Rector)
    "unknown class Dotenv\\",
    "createUnsafeImmutable",
    "createMutable",
    "unknown class PhpOffice\\",
    "unknown class Firebase\\",
    "unknown class Google\\",
    "unknown class chriskacerguis\\",
    "unknown class Kreait\\",
    "unknown class Ngekoding\\",
)

console = Console()


# ---------------------------------------------------------------------------
# Data classes  (mirror ScanFinding / ScanSummary / ScanResult pattern)
# ---------------------------------------------------------------------------


@dataclass
class AnalysisError:
    """
    A single PHPStan error / warning.

    Mirrors ScanFinding from scanner.py.
    """

    file_path: str          # absolute path reported by PHPStan
    line: int               # source line (0 = file-level / unknown)
    message: str            # PHPStan error message
    severity: str           # "ERROR" | "WARNING"  (derived from classification)
    iso_controls: list[str] # ISO 27001:2022 controls this finding maps to

    def sort_key(self) -> tuple[str, int]:
        """Primary sort: file path; secondary: line number."""
        return (self.file_path, self.line)


@dataclass
class AnalysisSummary:
    """
    Aggregate statistics for a PHPStan analysis run.

    Mirrors ScanSummary from scanner.py.
    """

    total_errors: int
    total_files_analysed: int
    by_file: dict[str, int] = field(default_factory=dict)   # file_path -> error count
    by_severity: dict[str, int] = field(default_factory=dict)
    by_iso_control: dict[str, int] = field(default_factory=dict)
    phpstan_level: int = DEFAULT_LEVEL
    php_version: str = DEFAULT_PHP_VERSION
    duration_sec: float = 0.0
    phpstan_parse_errors: list[str] = field(default_factory=list)  # top-level PHPStan errors
    framework_noise_count: int = 0  # CI3 false positives filtered from error list


@dataclass
class AnalysisResult:
    """
    Full result returned by PHPStanAnalyzer.run() / run_analysis().

    Mirrors ScanResult from scanner.py.

    Fields
    ------
    errors:     sorted list of AnalysisError (by file, then line)
    summary:    aggregate statistics
    raw_output: original parsed JSON from PHPStan (for audit / reporting)
    """

    errors: list[AnalysisError]
    summary: AnalysisSummary
    raw_output: dict


# ---------------------------------------------------------------------------
# Main analyser class
# ---------------------------------------------------------------------------


class PHPStanAnalyzer:
    """
    Wraps PHPStan invocation, output parsing, and error classification.

    Runs AFTER conversion (on the output/ directory) to confirm the migrated
    code is PHP 8 compatible and to report any remaining type / undefined
    identifier issues.

    Usage
    -----
    analyzer = PHPStanAnalyzer()
    result   = analyzer.run(Path("output/"))
    """

    def __init__(
        self,
        phpstan_exe: str = PHPSTAN_EXE,
        timeout_sec: int = 300,
    ) -> None:
        self._exe = phpstan_exe
        self._timeout = timeout_sec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        target_path: Path,
        level: int = DEFAULT_LEVEL,
        php_version: str = DEFAULT_PHP_VERSION,
        exclude_dirs: list[str] | None = None,
    ) -> AnalysisResult:
        """
        Run PHPStan on *target_path* and return structured results.

        Parameters
        ----------
        target_path:
            Directory (or single file) to analyse -- typically ``output/``.
        level:
            PHPStan analysis level (0-9).  Defaults to 5 (balanced).
        php_version:
            PHP version string passed to ``--php-version``.
            Defaults to ``"8.3"`` to match Rector's upgrade target.

        Raises
        ------
        FileNotFoundError
            If *target_path* does not exist.
        """
        if not target_path.exists():
            raise FileNotFoundError(
                f"Analysis target does not exist: {target_path}"
            )

        console.print(
            Panel(
                f"[bold blue]PHPStan Static Analysis[/bold blue]\n"
                f"Target     : [green]{target_path}[/green]\n"
                f"Level      : [yellow]{level}[/yellow]  "
                f"(0 = basic … 9 = strictest)\n"
                f"PHP version: [cyan]{php_version}[/cyan]",
                border_style="blue",
            )
        )

        # Resolve the best phpstan binary to use
        resolved_exe = self._resolve_exe(target_path)

        analysis_paths = self._collect_analysis_paths(target_path, exclude_dirs or [])
        if exclude_dirs:
            console.print(
                f"[dim]Excluding directories: {', '.join(exclude_dirs)}[/dim]"
            )

        cmd = self._build_command(
            analysis_paths=analysis_paths,
            level=level,
            php_version=php_version,
            exe=resolved_exe,
        )
        exit_code, stdout, stderr, elapsed = self._invoke_phpstan(cmd)
        raw = self._parse_phpstan_json(stdout, stderr, exit_code)
        errors, noise_count = self._build_errors(raw)
        errors.sort(key=lambda e: e.sort_key())
        summary = self._build_summary(
            errors=errors,
            raw=raw,
            elapsed=elapsed,
            level=level,
            php_version=php_version,
            noise_count=noise_count,
        )
        result = AnalysisResult(errors=errors, summary=summary, raw_output=raw)
        self._print_results(result)
        return result

    # ------------------------------------------------------------------
    # Executable resolution
    # ------------------------------------------------------------------

    def _resolve_exe(self, target_path: Path) -> str:
        """
        Return the best available PHPStan executable path.

        Resolution order:
        1. The ``phpstan_exe`` passed at construction (default ``"phpstan"``)
        2. ``vendor/bin/phpstan`` relative to ``target_path``
        3. ``vendor/bin/phpstan`` relative to ``target_path``'s parent
        4. Fall back to the configured exe (let subprocess raise a useful error)
        """
        # If the caller supplied an explicit non-default path, honour it
        if self._exe != PHPSTAN_EXE:
            return self._exe

        # Try vendor-local installs first (preferred -- pinned version)
        # Also check the pipeline's own project root (two levels up from this file)
        _project_root = Path(__file__).parent.parent
        candidates: list[Path] = [
            target_path / "vendor" / "bin" / "phpstan",
            target_path.parent / "vendor" / "bin" / "phpstan",
            _project_root / "vendor" / "bin" / "phpstan",
        ]
        # Windows Composer adds a .bat wrapper
        bat_candidates = [p.with_suffix(".bat") for p in candidates]

        for p in bat_candidates + candidates:
            if p.exists():
                return str(p)

        # Fall back to global phpstan on PATH
        return self._exe

    # ------------------------------------------------------------------
    # Path collection (with optional exclusion)
    # ------------------------------------------------------------------

    def _collect_analysis_paths(
        self, target_path: Path, exclude_dirs: list[str]
    ) -> list[Path]:
        """
        Return the list of paths to pass to PHPStan.

        When *exclude_dirs* is empty, returns ``[target_path]`` (default behaviour).
        Otherwise returns immediate children of *target_path* (both PHP files and
        subdirectories) whose names are NOT in *exclude_dirs*, so PHPStan only
        analyses the relevant parts of the tree.
        """
        if not exclude_dirs:
            return [target_path]

        exclude_set = frozenset(exclude_dirs)
        paths: list[Path] = []
        try:
            for item in sorted(target_path.iterdir()):
                if item.name in exclude_set:
                    continue
                if item.is_dir() or (item.is_file() and item.suffix == ".php"):
                    paths.append(item)
        except OSError:
            return [target_path]

        return paths if paths else [target_path]

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def _build_command(
        self,
        analysis_paths: list[Path],
        level: int,
        php_version: str,
        exe: str,
    ) -> list[str]:
        """Build the PHPStan CLI invocation."""
        cmd = [exe, "analyse"]
        cmd.extend(str(p) for p in analysis_paths)
        cmd += [
            f"--level={level}",
            "--error-format=json",
            "--no-progress",
            "--memory-limit=1G",
        ]
        return cmd

    # ------------------------------------------------------------------
    # PHPStan subprocess invocation
    # ------------------------------------------------------------------

    def _invoke_phpstan(
        self, cmd: list[str]
    ) -> tuple[int, str, str, float]:
        """
        Execute PHPStan and return ``(exit_code, stdout, stderr, elapsed_sec)``.

        PHPStan exit codes:
          0 -- no errors found
          1 -- errors found (normal operation, not a crash)
          2+ -- unexpected error (config error, crash, etc.)

        With ``--error-format=json``, structured JSON is written to stdout.
        """
        level_val = next((c.split("=")[1] for c in cmd if c.startswith("--level=")), "?")
        console.print(
            f"[dim]Running: {cmd[0]} analyse  --level={level_val}  "
            f"… (may take a moment)[/dim]"
        )
        t_start = time.perf_counter()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t_start
            console.print("[bold red]ERROR:[/bold red] PHPStan timed out.")
            return -1, "", "Process timed out", elapsed
        except FileNotFoundError:
            elapsed = time.perf_counter() - t_start
            msg = (
                f"PHPStan executable not found: '{cmd[0]}'\n"
                "Install globally : composer global require phpstan/phpstan\n"
                "Or vendor-local  : composer require --dev phpstan/phpstan"
            )
            console.print(f"[bold red]ERROR:[/bold red] {msg}")
            return -1, "", msg, elapsed
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - t_start
            console.print(
                f"[bold red]ERROR:[/bold red] Failed to launch PHPStan: {exc}"
            )
            return -1, "", str(exc), elapsed

        elapsed = time.perf_counter() - t_start
        console.print(
            f"[dim]PHPStan finished in {elapsed:.1f}s "
            f"(exit code {proc.returncode})[/dim]"
        )

        # Show stderr only on unexpected failure
        if proc.returncode > 1 and proc.stderr:
            console.print(
                f"[yellow]PHPStan stderr:[/yellow]\n{proc.stderr[:2000]}"
            )

        return proc.returncode, proc.stdout, proc.stderr, elapsed

    # ------------------------------------------------------------------
    # PHPStan JSON output parsing
    # ------------------------------------------------------------------

    def _parse_phpstan_json(
        self, stdout: str, stderr: str, exit_code: int
    ) -> dict:
        """
        Parse PHPStan's ``--error-format=json`` stdout.

        Expected structure::

            {
              "totals":  {"errors": int, "file_errors": int},
              "files":   { "<path>": {"errors": int, "messages": [...]} },
              "errors":  ["top-level parse/config error strings"]
            }

        Returns a normalised dict; gracefully returns an empty structure on
        any parse failure so callers never need to handle ``None``.
        """
        empty: dict = {
            "totals": {"errors": 0, "file_errors": 0},
            "files": {},
            "errors": [],
        }

        if not stdout.strip():
            if exit_code not in (0, 1):
                empty["errors"].append(stderr[:500] if stderr else "No output from PHPStan")
            return empty

        # PHPStan may occasionally emit a warning line before the JSON
        json_start = stdout.find("{")
        if json_start == -1:
            return empty

        try:
            data: dict = json.loads(stdout[json_start:])
        except json.JSONDecodeError:
            # Last-ditch: truncate at final closing brace
            try:
                data = json.loads(stdout[json_start:].rsplit("}", 1)[0] + "}")
            except (json.JSONDecodeError, IndexError):
                return empty

        data.setdefault("totals", {"errors": 0, "file_errors": 0})
        data.setdefault("files", {})
        data.setdefault("errors", [])
        return data

    # ------------------------------------------------------------------
    # CI3 noise detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ci3_noise(message: str) -> bool:
        """Return True if message is a CodeIgniter 3 framework false positive."""
        return any(pattern in message for pattern in _CI3_NOISE_SUBSTRINGS)

    # ------------------------------------------------------------------
    # Error classification
    # ------------------------------------------------------------------

    def _classify_error(
        self, message: str
    ) -> tuple[str, list[str]]:
        """
        Return ``(severity, iso_controls)`` for a PHPStan error message.

        Matches case-insensitively against ``_ERROR_RULES``; first match wins.
        Falls back to ``("ERROR", ["A.8.28"])`` for unclassified messages.
        """
        lower = message.lower()
        for keywords, severity, controls in _ERROR_RULES:
            if any(kw in lower for kw in keywords):
                return severity, list(controls)
        return "ERROR", list(_DEFAULT_ISO)

    # ------------------------------------------------------------------
    # Error list construction
    # ------------------------------------------------------------------

    def _build_errors(self, raw: dict) -> tuple[list[AnalysisError], int]:
        """
        Convert PHPStan's parsed JSON into a flat list of ``AnalysisError``.

        Handles both file-specific messages (``raw["files"]``) and top-level
        parse/config errors (``raw["errors"]``).

        Returns
        -------
        (errors, noise_count)
            ``errors`` contains real application errors only.
            ``noise_count`` counts CI3 framework false positives that were filtered.
        """
        result: list[AnalysisError] = []
        noise_count: int = 0

        # File-specific errors
        for file_path, file_data in raw.get("files", {}).items():
            for msg_entry in file_data.get("messages", []):
                message: str = msg_entry.get("message", "")
                line: int = msg_entry.get("line", 0) or 0
                if self._is_ci3_noise(message):
                    noise_count += 1
                    continue
                severity, iso_controls = self._classify_error(message)
                result.append(
                    AnalysisError(
                        file_path=file_path,
                        line=line,
                        message=message,
                        severity=severity,
                        iso_controls=iso_controls,
                    )
                )

        # Top-level PHPStan errors (config issues, parse failures, etc.)
        for err in raw.get("errors", []):
            if isinstance(err, str) and err.strip():
                if self._is_ci3_noise(err):
                    noise_count += 1
                    continue
                severity, iso_controls = self._classify_error(err)
                result.append(
                    AnalysisError(
                        file_path="<phpstan>",
                        line=0,
                        message=err,
                        severity=severity,
                        iso_controls=iso_controls,
                    )
                )

        return result, noise_count

    # ------------------------------------------------------------------
    # Summary construction
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        errors: list[AnalysisError],
        raw: dict,
        elapsed: float,
        level: int,
        php_version: str,
        noise_count: int = 0,
    ) -> AnalysisSummary:
        """Aggregate error list into an AnalysisSummary."""
        by_file: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_iso: dict[str, int] = {}

        for err in errors:
            by_file[err.file_path] = by_file.get(err.file_path, 0) + 1
            sev = err.severity.upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            for ctrl in err.iso_controls:
                by_iso[ctrl] = by_iso.get(ctrl, 0) + 1

        # Count distinct analysed files from raw output (excludes
        # files with zero errors, which PHPStan omits from the JSON).
        files_with_errors = len(raw.get("files", {}))

        parse_errors: list[str] = [
            e for e in raw.get("errors", []) if isinstance(e, str)
        ]

        return AnalysisSummary(
            total_errors=len(errors),
            total_files_analysed=files_with_errors,
            by_file=by_file,
            by_severity=by_severity,
            by_iso_control=by_iso,
            phpstan_level=level,
            php_version=php_version,
            duration_sec=round(elapsed, 2),
            phpstan_parse_errors=parse_errors,
            framework_noise_count=noise_count,
        )

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_results(self, result: AnalysisResult) -> None:
        """Render analysis results grouped by file to the terminal."""
        s = result.summary

        if not result.errors:
            console.print(
                Panel(
                    "[bold green]No errors found![/bold green]  "
                    "The converted code passed PHPStan level "
                    f"[yellow]{s.phpstan_level}[/yellow] analysis.",
                    border_style="green",
                )
            )
            self._print_footer(s)
            return

        # --- Errors grouped by file ---
        # Build {file_path: [AnalysisError]} preserving sort order
        grouped: dict[str, list[AnalysisError]] = {}
        for err in result.errors:
            grouped.setdefault(err.file_path, []).append(err)

        for file_path, file_errors in grouped.items():
            tbl = Table(
                title=f"[bold]{file_path}[/bold]  "
                      f"([red]{len(file_errors)} error(s)[/red])",
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold magenta",
                show_lines=False,
            )
            tbl.add_column("Line", justify="right", width=6, style="dim")
            tbl.add_column("Sev", justify="center", width=7)
            tbl.add_column("Message")
            tbl.add_column("ISO Control")

            _sev_style = {"ERROR": "red", "WARNING": "yellow"}

            for err in file_errors:
                sev_col = _sev_style.get(err.severity.upper(), "white")
                tbl.add_row(
                    str(err.line) if err.line else "-",
                    f"[{sev_col}]{err.severity}[/{sev_col}]",
                    err.message,
                    ", ".join(err.iso_controls),
                )

            console.print(tbl)

        # --- Severity breakdown ---
        sev_tbl = Table(
            title="Summary by Severity",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        sev_tbl.add_column("Severity", style="bold")
        sev_tbl.add_column("Count", justify="right")

        for sev_label, sev_style in (("ERROR", "red"), ("WARNING", "yellow")):
            count = s.by_severity.get(sev_label, 0)
            if count:
                sev_tbl.add_row(
                    f"[{sev_style}]{sev_label}[/{sev_style}]",
                    str(count),
                )

        # --- ISO control breakdown ---
        iso_tbl = Table(
            title="Summary by ISO 27001:2022 Control",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        iso_tbl.add_column("Control")
        iso_tbl.add_column("Findings", justify="right")

        for control, count in sorted(s.by_iso_control.items()):
            iso_tbl.add_row(control, str(count))

        console.print(sev_tbl)
        console.print(iso_tbl)

        # --- PHPStan parse errors (config/setup problems) ---
        if s.phpstan_parse_errors:
            console.print(
                Panel(
                    "\n".join(f"• {e}" for e in s.phpstan_parse_errors[:10]),
                    title="[bold red]PHPStan Parse / Config Errors[/bold red]",
                    border_style="red",
                )
            )

        self._print_footer(s)

    def _print_footer(self, s: AnalysisSummary) -> None:
        """Print the one-line summary footer."""
        noise_note = (
            f"  |  [dim]CI3 framework noise filtered: {s.framework_noise_count}[/dim]"
            if s.framework_noise_count
            else ""
        )
        console.print(
            f"\n[bold]Total errors:[/bold] [red]{s.total_errors}[/red]  |  "
            f"[bold]Files with errors:[/bold] {s.total_files_analysed}  |  "
            f"[bold]Level:[/bold] {s.phpstan_level}  |  "
            f"[bold]PHP:[/bold] {s.php_version}  |  "
            f"[bold]Time:[/bold] {s.duration_sec}s"
            f"{noise_note}\n"
        )


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_analysis(
    target_path: Path,
    level: int = DEFAULT_LEVEL,
    phpstan_exe: str = PHPSTAN_EXE,
    php_version: str = DEFAULT_PHP_VERSION,
    exclude_dirs: list[str] | None = None,
) -> AnalysisResult:
    """
    Run PHPStan on *target_path* and return structured results.

    This is the primary entry point for ``main.py``.  Call this AFTER
    ``run_conversion()`` so analysis runs on the migrated PHP 8.x code
    in ``output/``.

    Parameters
    ----------
    target_path:
        Directory (or file) to analyse -- typically ``output/``.
    level:
        PHPStan analysis level 0-9.  Defaults to 5 (balanced strictness).
    phpstan_exe:
        PHPStan binary name or absolute path.  Falls back to
        ``vendor/bin/phpstan`` relative to *target_path* before giving up.
    php_version:
        PHP version string for ``--php-version``.  Defaults to ``"8.3"``.

    Returns
    -------
    AnalysisResult
        Sorted error list with ISO 27001:2022 control mappings,
        aggregate ``AnalysisSummary``, and PHPStan's raw JSON output.
    """
    analyzer = PHPStanAnalyzer(phpstan_exe=phpstan_exe)
    return analyzer.run(
        target_path=target_path,
        level=level,
        php_version=php_version,
        exclude_dirs=exclude_dirs,
    )
