"""
converter.py -- Modul konversi PHP menggunakan Rector.

Menyalin file PHP dari input/ ke output/ (TIDAK pernah memodifikasi input/),
mendeteksi versi PHP per-file secara otomatis, menghasilkan konfigurasi
rector.php sementara yang sesuai, dan menjalankan Rector via subprocess.
Mendokumentasikan setiap perubahan dan memetakan ke kontrol ISO/IEC 27001:2022
A.8.25 (Secure Development Lifecycle).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Project root directory (used to resolve Composer-local Rector install).
PROJECT_ROOT: Path = Path(r"C:\Users\HP VICTUS\Documents\GitHub\skripsi-php-migration")

# Rector binary: defaults to the Composer-local install inside this project.
# Override by passing rector_exe= to RectorConverter or run_conversion().
RECTOR_EXE: Path = PROJECT_ROOT / "vendor" / "bin" / "rector.bat"

# Fallback candidates tried in order when the primary path raises FileNotFoundError.
_RECTOR_FALLBACKS: list[Path | str] = [
    PROJECT_ROOT / "vendor" / "bin" / "rector.bat",  # Composer-local (.bat)
    PROJECT_ROOT / "vendor" / "bin" / "rector",       # Composer-local (no ext)
    "rector",                                          # global PATH
]

# ISO 27001:2022 controls relevant to all conversion activity
ISO_CONTROLS_CONVERSION: list[str] = ["A.8.25"]

# ---------------------------------------------------------------------------
# PHP version detection patterns  (compiled once at import time)
# ---------------------------------------------------------------------------

# PHP 5.x syntactic / API indicators -- scanned in the first 8 KB of each file.
_PHP5_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bmysql_connect\b"),
    re.compile(r"\bmysql_query\b"),
    re.compile(r"\bmysql_\w+\s*\("),        # any mysql_* function call
    re.compile(r"\bereg\s*\("),
    re.compile(r"\beregi\s*\("),
    re.compile(r"\bsplit\s*\("),
    re.compile(r"\bmagic_quotes\b"),
    re.compile(r"\bset_magic_quotes_runtime\b"),
    re.compile(r"\bsession_register\s*\("),
    re.compile(r"\bsession_unregister\s*\("),
    re.compile(r"\bsession_is_registered\s*\("),
    re.compile(r"\bcall_user_method\s*\("),
    re.compile(r"\bdefine_syslog_variables\s*\("),
    re.compile(r"\bimport_request_variables\s*\("),
]

# PHP 7.x syntactic indicators (not found in plain PHP 5 code).
_PHP7_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bintdiv\s*\("),              # PHP 7.0 function
    re.compile(r"\?\?="),                       # null coalescing assignment PHP 7.4
    re.compile(r"\blist\s*\([^)]*\)\s+as\b"),  # list() in foreach PHP 7.1+
    re.compile(r"\bfn\s*\("),                  # arrow functions PHP 7.4
    re.compile(r"\?\?"),                        # null coalescing operator PHP 7.0
]

# ---------------------------------------------------------------------------
# Rector level-set chains
# ---------------------------------------------------------------------------

# Full chain for PHP 5 -> PHP 8.3 upgrade
_LEVEL_SETS_FROM_PHP5: list[str] = [
    "LevelSetList::UP_TO_PHP_53",
    "LevelSetList::UP_TO_PHP_54",
    "LevelSetList::UP_TO_PHP_55",
    "LevelSetList::UP_TO_PHP_56",
    "LevelSetList::UP_TO_PHP_70",
    "LevelSetList::UP_TO_PHP_71",
    "LevelSetList::UP_TO_PHP_72",
    "LevelSetList::UP_TO_PHP_73",
    "LevelSetList::UP_TO_PHP_74",
    "LevelSetList::UP_TO_PHP_80",
    "LevelSetList::UP_TO_PHP_81",
    "LevelSetList::UP_TO_PHP_82",
    "LevelSetList::UP_TO_PHP_83",
    "LevelSetList::UP_TO_PHP_85",
]

# Shorter chain for PHP 7 -> PHP 8.5 upgrade
_LEVEL_SETS_FROM_PHP7: list[str] = [
    "LevelSetList::UP_TO_PHP_70",
    "LevelSetList::UP_TO_PHP_71",
    "LevelSetList::UP_TO_PHP_72",
    "LevelSetList::UP_TO_PHP_73",
    "LevelSetList::UP_TO_PHP_74",
    "LevelSetList::UP_TO_PHP_80",
    "LevelSetList::UP_TO_PHP_81",
    "LevelSetList::UP_TO_PHP_82",
    "LevelSetList::UP_TO_PHP_83",
    "LevelSetList::UP_TO_PHP_85",
]

# Mapping from --target-php version string to the final Rector level-set constant
_TARGET_VERSION_TO_LEVEL_SET: dict[str, str] = {
    "7.4": "LevelSetList::UP_TO_PHP_74",
    "8.0": "LevelSetList::UP_TO_PHP_80",
    "8.1": "LevelSetList::UP_TO_PHP_81",
    "8.2": "LevelSetList::UP_TO_PHP_82",
    "8.3": "LevelSetList::UP_TO_PHP_83",
    "8.5": "LevelSetList::UP_TO_PHP_85",
}

# Code quality sets always appended after the level chain
_QUALITY_SETS: list[str] = [
    "SetList::CODE_QUALITY",
    "SetList::DEAD_CODE",
    "SetList::EARLY_RETURN",
    "SetList::TYPE_DECLARATION",
]

# ---------------------------------------------------------------------------
# rector.php template  (uses fluent Rector 1.x+ API)
# ---------------------------------------------------------------------------

_RECTOR_CONFIG_TEMPLATE = """\
<?php

declare(strict_types=1);

use Rector\\Config\\RectorConfig;
use Rector\\Set\\ValueObject\\LevelSetList;
use Rector\\Set\\ValueObject\\SetList;

return RectorConfig::configure()
    ->withPaths([
        '{TARGET_PATH}',
    ])
    ->withSets([
{SETS_BLOCK}
    ]);
"""

console = Console()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PHPVersion(Enum):
    """Auto-detected source PHP version for a single file."""

    PHP5 = auto()     # PHP 5.x indicator pattern matched
    PHP7 = auto()     # PHP 7.x indicator matched (and no PHP 5 indicator)
    UNKNOWN = auto()  # No version-specific indicator detected


class ConversionStatus(Enum):
    """Outcome of Rector's run on a single file."""

    CONVERTED = auto()  # Rector applied at least one rule (file hash changed)
    SKIPPED = auto()    # Rector ran but made no changes (already modern)
    FAILED = auto()     # Rector reported an error for this file


# ---------------------------------------------------------------------------
# Data classes  (mirror pattern from scanner.py ScanFinding/Summary/Result)
# ---------------------------------------------------------------------------


@dataclass
class ConversionFile:
    """
    Result for a single PHP file that passed through Rector.

    Mirrors ScanFinding from scanner.py.
    """

    source_path: Path           # original location in input/
    output_path: Path           # copy in output/ (edited by Rector in-place)
    php_version: PHPVersion     # auto-detected source version
    status: ConversionStatus    # CONVERTED | SKIPPED | FAILED
    changes_count: int          # number of Rector rules applied (0 when SKIPPED)
    applied_rectors: list[str]  # Rector rule class-names applied to this file
    applied_sets: list[str]     # level-set + quality-set constants used
    iso_controls: list[str]     # always ["A.8.25"]
    error_message: str = ""     # populated only when status == FAILED

    def sort_key(self) -> tuple[int, str]:
        """Sort FAILED -> CONVERTED -> SKIPPED; within group by filename."""
        order = {
            ConversionStatus.FAILED: 0,
            ConversionStatus.CONVERTED: 1,
            ConversionStatus.SKIPPED: 2,
        }
        return (order[self.status], str(self.source_path))


@dataclass
class ConversionSummary:
    """
    Aggregate statistics for a conversion run.

    Mirrors ScanSummary from scanner.py.
    """

    total_files: int
    converted: int
    skipped: int
    failed: int
    php5_files: int
    php7_files: int
    unknown_files: int
    level_sets_used: list[str] = field(default_factory=list)
    quality_sets_used: list[str] = field(default_factory=lambda: list(_QUALITY_SETS))
    conversion_duration_sec: float = 0.0
    iso_controls: list[str] = field(default_factory=lambda: list(ISO_CONTROLS_CONVERSION))
    errors: list[str] = field(default_factory=list)


@dataclass
class ConversionResult:
    """
    Full result returned by RectorConverter.run() / run_conversion().

    Mirrors ScanResult from scanner.py.

    Fields
    ------
    files:              per-file results sorted FAILED -> CONVERTED -> SKIPPED
    summary:            aggregate statistics
    rector_raw_output:  raw stdout from Rector (JSON string) for audit purposes
    """

    files: list[ConversionFile]
    summary: ConversionSummary
    rector_raw_output: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*'s byte contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot_dir(root: Path) -> dict[Path, str]:
    """
    Walk *root* recursively and return a {resolved_Path: sha256} mapping
    for every .php file found.
    """
    return {p.resolve(): _hash_file(p) for p in root.rglob("*.php")}


def _collect_php_files(
    root: Path, exclude_dirs: frozenset[str] = frozenset()
) -> list[Path]:
    """Return a sorted list of all .php files under *root*, skipping excluded dirs."""
    if root.is_file() and root.suffix == ".php":
        return [root]
    if not exclude_dirs:
        return sorted(root.rglob("*.php"))
    return sorted(
        p for p in root.rglob("*.php")
        if not any(part in exclude_dirs for part in p.relative_to(root).parts)
    )


# ---------------------------------------------------------------------------
# Main converter class
# ---------------------------------------------------------------------------


class RectorConverter:
    """
    Orchestrates the full PHP migration pipeline step.

    Workflow
    --------
    1. Collect .php files from ``input_path``
    2. Detect PHP version (5 / 7 / UNKNOWN) for each file
    3. Choose Rector level-set chain from detected versions
    4. Copy ``input_path`` -> ``output_path`` (input/ is never touched)
    5. Write a temporary rector.php config to a system temp directory
    6. Invoke ``rector process`` via subprocess on ``output_path``
    7. Compare SHA-256 hashes before/after to detect per-file changes
    8. Parse Rector's ``--output-format=json`` for applied-rule detail
    9. Return a structured ``ConversionResult``

    Usage
    -----
    converter = RectorConverter()
    result = converter.run(Path("input/"), Path("output/"))
    """

    def __init__(
        self,
        rector_exe: Path | str = RECTOR_EXE,
        timeout_sec: int = 600,
    ) -> None:
        self._rector_exe = rector_exe
        self._timeout = timeout_sec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        input_path: Path,
        output_path: Path,
        target_version: str = "8.3",
        exclude_dirs: list[str] | None = None,
    ) -> ConversionResult:
        """
        Convert PHP files from *input_path* and write results to *output_path*.

        Parameters
        ----------
        input_path:
            Directory containing the original PHP source files.  This
            directory is never modified (read-only access).
        output_path:
            Destination directory for converted files (created if absent).
        target_version:
            Target PHP version string, e.g. ``"8.3"`` or ``"7.4"``.
            Determines which Rector level-set chain is generated.

        Raises
        ------
        FileNotFoundError
            If *input_path* does not exist.
        RuntimeError
            If no .php files are found in *input_path*.
        """
        if not input_path.exists():
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        console.print(
            Panel(
                f"[bold green]PHP Migration -- Rector Converter[/bold green]\n"
                f"Input   : [cyan]{input_path}[/cyan]\n"
                f"Output  : [cyan]{output_path}[/cyan]\n"
                f"Target  : [yellow]PHP {target_version}[/yellow]",
                border_style="green",
            )
        )

        t_start = time.perf_counter()
        _exclude: frozenset[str] = frozenset(exclude_dirs) if exclude_dirs else frozenset()

        if _exclude:
            console.print(
                f"[dim]Excluding directories: {', '.join(sorted(_exclude))}[/dim]"
            )

        # 1. Collect source files
        source_files = _collect_php_files(input_path, _exclude)
        if not source_files:
            raise RuntimeError(f"No .php files found in: {input_path}")
        console.print(f"[dim]Found {len(source_files)} PHP file(s) in input.[/dim]")

        # 2. Detect PHP version per file
        version_map: dict[Path, PHPVersion] = {
            f: self._detect_php_version(f) for f in source_files
        }
        self._print_version_table(version_map)

        # 3. Choose level sets based on detected versions and target
        detected_versions = set(version_map.values())
        level_sets = self._choose_level_sets(detected_versions, target_version)
        all_sets = level_sets + _QUALITY_SETS
        console.print(
            f"[dim]Level sets: "
            f"{level_sets[0]} … {level_sets[-1]} "
            f"(+{len(_QUALITY_SETS)} quality sets)[/dim]"
        )

        # 4. Copy input -> output (never touch input/)
        output_path.mkdir(parents=True, exist_ok=True)
        self._copy_tree(input_path, output_path, _exclude)
        console.print(f"[dim]Copied {len(source_files)} file(s) -> {output_path}[/dim]")

        # 5. Snapshot SHA-256 hashes BEFORE Rector
        pre_hashes = _snapshot_dir(output_path)

        # 6. Write temporary rector.php to system temp dir
        config_path = self._write_rector_config(output_path, all_sets)
        console.print(f"[dim]Rector config: {config_path}[/dim]")

        # 7. Invoke Rector
        exit_code, stdout, stderr, rector_elapsed = self._invoke_rector(config_path)

        # 8. Snapshot SHA-256 hashes AFTER Rector
        post_hashes = _snapshot_dir(output_path)

        # 9. Clean up temporary config
        try:
            config_path.unlink()
        except OSError:
            pass  # non-fatal; temp dir will eventually be cleaned by the OS

        # 10. Parse Rector JSON output
        rector_data = self._parse_rector_json(stdout, stderr, exit_code)

        # 11. Build per-file ConversionFile list
        files = self._build_file_results(
            source_files=source_files,
            input_path=input_path,
            output_path=output_path,
            version_map=version_map,
            pre_hashes=pre_hashes,
            post_hashes=post_hashes,
            rector_data=rector_data,
            all_sets=all_sets,
        )
        files.sort(key=lambda f: f.sort_key())

        # 12. Build summary
        total_elapsed = time.perf_counter() - t_start
        summary = self._build_summary(
            files=files,
            level_sets=level_sets,
            elapsed=total_elapsed,
            rector_data=rector_data,
        )

        result = ConversionResult(
            files=files,
            summary=summary,
            rector_raw_output=stdout,
        )
        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # PHP version detection
    # ------------------------------------------------------------------

    def _detect_php_version(self, file_path: Path) -> PHPVersion:
        """
        Scan the first 8 KB of *file_path* for version indicator patterns.

        PHP 5 takes absolute priority: if any PHP 5 pattern matches, the file
        is classified as PHP5 even if PHP 7 patterns also appear (mixed
        codebases exist during partial migrations).
        """
        try:
            raw = file_path.read_bytes()[:8192]
            content = raw.decode("utf-8", errors="replace")
        except OSError:
            return PHPVersion.UNKNOWN

        # PHP 5 indicators (highest priority)
        for pattern in _PHP5_PATTERNS:
            if pattern.search(content):
                return PHPVersion.PHP5

        # PHP 7 indicators
        for pattern in _PHP7_PATTERNS:
            if pattern.search(content):
                return PHPVersion.PHP7

        # Inline version hint in file header (e.g. `<?php // PHP 5`)
        if re.search(r"<\?php\s+//\s*PHP\s*5", content, re.IGNORECASE):
            return PHPVersion.PHP5
        if re.search(r"<\?php\s+//\s*PHP\s*7", content, re.IGNORECASE):
            return PHPVersion.PHP7

        return PHPVersion.UNKNOWN

    # ------------------------------------------------------------------
    # Level-set selection
    # ------------------------------------------------------------------

    def _choose_level_sets(
        self, versions: set[PHPVersion], target_version: str = "8.3"
    ) -> list[str]:
        """
        Return the ordered Rector LevelSetList chain appropriate for the
        set of detected source versions and the requested target version.

        Parameters
        ----------
        versions:
            Set of detected source PHP versions across all input files.
        target_version:
            Target PHP version string (e.g. ``"8.3"``, ``"7.4"``).  The chain
            is truncated after the corresponding ``UP_TO_PHP_*`` level set.

        Examples
        --------
        PHP 5 source, target 7.4 -> UP_TO_PHP_53 … UP_TO_PHP_74
        PHP 5 source, target 8.x -> UP_TO_PHP_53 … UP_TO_PHP_8x
        PHP 7 source, target 7.4 -> UP_TO_PHP_70 … UP_TO_PHP_74
        PHP 7 source, target 8.x -> UP_TO_PHP_70 … UP_TO_PHP_8x
        """
        target_set = _TARGET_VERSION_TO_LEVEL_SET.get(
            target_version, "LevelSetList::UP_TO_PHP_83"
        )

        if PHPVersion.PHP5 in versions:
            console.print(
                f"[yellow]PHP 5.x detected -- applying full upgrade chain "
                f"(PHP 5 -> PHP {target_version})[/yellow]"
            )
            full_chain = list(_LEVEL_SETS_FROM_PHP5)
        else:
            console.print(
                f"[cyan]PHP 7.x source -- applying PHP 7 -> PHP {target_version} "
                f"upgrade chain[/cyan]"
            )
            full_chain = list(_LEVEL_SETS_FROM_PHP7)

        # Truncate chain at (and including) the target level set
        if target_set in full_chain:
            return full_chain[: full_chain.index(target_set) + 1]
        return full_chain

    # ------------------------------------------------------------------
    # rector.php config generation
    # ------------------------------------------------------------------

    def _write_rector_config(self, output_path: Path, all_sets: list[str]) -> Path:
        """
        Write a temporary ``rector.php`` using the fluent Rector 1.x+ API and
        return its ``Path``.

        The config targets *output_path* so Rector edits the copies;
        input/ is never mentioned and never touched.
        """
        # Forward-slash paths are valid inside PHP string literals on Windows
        target = output_path.resolve().as_posix()

        indent = " " * 8
        sets_block = "\n".join(f"{indent}{s}," for s in all_sets)

        config_content = _RECTOR_CONFIG_TEMPLATE.format(
            TARGET_PATH=target,
            SETS_BLOCK=sets_block,
        )

        # NamedTemporaryFile so Rector can open it by path; delete=False for
        # compatibility with Windows (which cannot open a file opened by another
        # process under delete=True).
        tmp_fd, tmp_path_str = tempfile.mkstemp(
            suffix="_rector.php", prefix="pipeline_"
        )
        config_path = Path(tmp_path_str)
        try:
            import os
            os.close(tmp_fd)
            config_path.write_text(config_content, encoding="utf-8")
        except OSError as exc:
            console.print(
                f"[bold red]ERROR:[/bold red] Could not write rector config: {exc}"
            )
            raise

        return config_path

    # ------------------------------------------------------------------
    # File copying
    # ------------------------------------------------------------------

    def _copy_tree(
        self, src: Path, dst: Path, exclude_dirs: frozenset[str] = frozenset()
    ) -> None:
        """
        Recursively copy all .php files from *src* into *dst*, preserving
        the relative directory structure.

        Only .php files are copied -- non-PHP assets are excluded so that
        output/ stays focused on code under conversion.
        """
        for source_file in src.rglob("*.php"):
            relative = source_file.relative_to(src)
            if exclude_dirs and any(part in exclude_dirs for part in relative.parts):
                continue
            dest_file = dst / relative
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(source_file), str(dest_file))

    # ------------------------------------------------------------------
    # Rector subprocess invocation
    # ------------------------------------------------------------------

    def _invoke_rector(
        self, config_path: Path
    ) -> tuple[int, str, str, float]:
        """
        Run ``rector process`` and return ``(exit_code, stdout, stderr, elapsed)``.

        Candidates are tried in order until one succeeds (does not raise
        ``FileNotFoundError``):
          1. ``self._rector_exe``          -- primary path (default: vendor\\bin\\rector.bat)
          2. ``vendor\\bin\\rector.bat``   -- Composer-local, with .bat extension
          3. ``vendor\\bin\\rector``       -- Composer-local, no extension
          4. ``rector``                    -- global PATH

        Rector exit codes:
          0 -- completed, no changes applied
          1 -- completed, changes were applied  (also returned on some errors)
          2 -- configuration / fatal error

        With ``--output-format=json``, Rector writes structured JSON to stdout
        and progress text to stderr.
        """
        # Build a deduplicated ordered candidate list.
        candidates: list[Path | str] = []
        seen: set[str] = set()
        for candidate in [self._rector_exe, *_RECTOR_FALLBACKS]:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                candidates.append(candidate)

        last_error: str = ""
        t_start = time.perf_counter()

        for exe in candidates:
            cmd: list[str] = [
                str(exe),
                "process",
                "--config", str(config_path),
                "--output-format=json",
                "--no-diffs",   # suppress inline diff blocks; keep stdout as clean JSON
            ]

            console.print(
                f"[dim]Running Rector via '{exe}' (config: {config_path.name}, "
                f"timeout: {self._timeout}s) …[/dim]"
            )

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except subprocess.TimeoutExpired:
                elapsed = time.perf_counter() - t_start
                console.print("[bold red]ERROR:[/bold red] Rector timed out.")
                return -1, "", "Process timed out", elapsed
            except FileNotFoundError:
                last_error = f"Rector executable not found: '{exe}'"
                console.print(f"[dim]{last_error} -- trying next candidate …[/dim]")
                continue
            except Exception as exc:  # noqa: BLE001
                elapsed = time.perf_counter() - t_start
                console.print(
                    f"[bold red]ERROR:[/bold red] Failed to launch Rector: {exc}"
                )
                return -1, "", str(exc), elapsed

            # Rector launched successfully -- return its result immediately.
            elapsed = time.perf_counter() - t_start
            console.print(
                f"[dim]Rector finished in {elapsed:.1f}s "
                f"(exit code {proc.returncode})[/dim]"
            )

            # Show stderr only for unexpected exit codes
            if proc.returncode not in (0, 1) and proc.stderr:
                console.print(
                    f"[yellow]Rector stderr (first 2000 chars):[/yellow]\n"
                    f"{proc.stderr[:2000]}"
                )

            return proc.returncode, proc.stdout, proc.stderr, elapsed

        # All candidates exhausted without a successful launch.
        elapsed = time.perf_counter() - t_start
        msg = (
            f"{last_error}\n"
            "All Rector candidate paths failed. To install Rector locally run:\n"
            "  composer require rector/rector --dev\n"
            "Or globally: composer global require rector/rector"
        )
        console.print(f"[bold red]ERROR:[/bold red] {msg}")
        return -1, "", msg, elapsed

    # ------------------------------------------------------------------
    # Rector JSON output parsing
    # ------------------------------------------------------------------

    def _parse_rector_json(
        self, stdout: str, stderr: str, exit_code: int
    ) -> dict:
        """
        Parse Rector's ``--output-format=json`` stdout.

        Returns a normalised dict:
          ``file_diffs``  -- list of ``{file, applied_rectors}``
          ``errors``      -- list of error dicts or strings
          ``totals``      -- ``{changed_files, errors}``

        Gracefully returns an empty structure on any parse failure so that
        callers never need to handle ``None``.
        """
        empty: dict = {
            "file_diffs": [],
            "errors": [],
            "totals": {"changed_files": 0, "errors": 0},
        }

        if not stdout.strip():
            if exit_code not in (0, 1):
                msg = stderr[:500] if stderr else "No output from Rector"
                empty["errors"].append(msg)
            return empty

        # Rector may prefix stdout with ANSI progress lines before the JSON blob
        json_start = stdout.find("{")
        if json_start == -1:
            return empty

        try:
            data: dict = json.loads(stdout[json_start:])
        except json.JSONDecodeError:
            # Last-ditch attempt: truncate at the last closing brace
            try:
                trimmed = stdout[json_start:].rsplit("}", 1)
                data = json.loads(trimmed[0] + "}")
            except (json.JSONDecodeError, IndexError):
                return empty

        data.setdefault("file_diffs", [])
        data.setdefault("errors", [])
        data.setdefault("totals", {"changed_files": 0, "errors": 0})
        return data

    # ------------------------------------------------------------------
    # Per-file result construction
    # ------------------------------------------------------------------

    def _build_file_results(
        self,
        source_files: list[Path],
        input_path: Path,
        output_path: Path,
        version_map: dict[Path, PHPVersion],
        pre_hashes: dict[Path, str],
        post_hashes: dict[Path, str],
        rector_data: dict,
        all_sets: list[str],
    ) -> list[ConversionFile]:
        """
        Build a ``ConversionFile`` for every source file.

        Conversion status is derived from SHA-256 hash comparison (before/after
        Rector).  Rector's JSON ``file_diffs`` provides the list of applied rule
        class-names when available.
        """
        # Index Rector per-file detail by lower-cased posix path string
        diff_index: dict[str, dict] = {}
        for diff in rector_data.get("file_diffs", []):
            raw = diff.get("file", "")
            if raw:
                diff_index[Path(raw).resolve().as_posix().lower()] = diff

        # Index Rector-reported errors by file path
        error_index: dict[str, str] = {}
        for err in rector_data.get("errors", []):
            if isinstance(err, dict):
                raw = err.get("file_path", err.get("file", ""))
                msg = err.get("message", str(err))
            else:
                raw, msg = "", str(err)
            if raw:
                error_index[Path(raw).resolve().as_posix().lower()] = msg

        results: list[ConversionFile] = []

        for src in source_files:
            relative = src.relative_to(input_path)
            out = (output_path / relative).resolve()
            out_key = out.as_posix().lower()

            pre = pre_hashes.get(out, "")
            post = post_hashes.get(out, "")

            if out_key in error_index:
                status = ConversionStatus.FAILED
                error_msg = error_index[out_key]
            elif pre and post and pre != post:
                status = ConversionStatus.CONVERTED
                error_msg = ""
            else:
                status = ConversionStatus.SKIPPED
                error_msg = ""

            diff_entry = diff_index.get(out_key, {})
            raw_rectors = diff_entry.get("applied_rectors", [])
            applied_rectors = [str(r) for r in raw_rectors] if isinstance(raw_rectors, list) else []

            results.append(
                ConversionFile(
                    source_path=src,
                    output_path=output_path / relative,
                    php_version=version_map.get(src, PHPVersion.UNKNOWN),
                    status=status,
                    changes_count=len(applied_rectors),
                    applied_rectors=applied_rectors,
                    applied_sets=list(all_sets),
                    iso_controls=list(ISO_CONTROLS_CONVERSION),
                    error_message=error_msg,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Summary construction
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        files: list[ConversionFile],
        level_sets: list[str],
        elapsed: float,
        rector_data: dict,
    ) -> ConversionSummary:
        """Aggregate per-file results into a ConversionSummary."""
        converted = sum(1 for f in files if f.status == ConversionStatus.CONVERTED)
        skipped = sum(1 for f in files if f.status == ConversionStatus.SKIPPED)
        failed = sum(1 for f in files if f.status == ConversionStatus.FAILED)
        php5 = sum(1 for f in files if f.php_version == PHPVersion.PHP5)
        php7 = sum(1 for f in files if f.php_version == PHPVersion.PHP7)
        unknown = sum(1 for f in files if f.php_version == PHPVersion.UNKNOWN)

        errors: list[str] = []
        for err in rector_data.get("errors", []):
            errors.append(err.get("message", str(err)) if isinstance(err, dict) else str(err))
        # Append per-file error messages not already captured
        for f in files:
            if f.status == ConversionStatus.FAILED and f.error_message:
                entry = f"{f.source_path.name}: {f.error_message}"
                if entry not in errors:
                    errors.append(entry)

        return ConversionSummary(
            total_files=len(files),
            converted=converted,
            skipped=skipped,
            failed=failed,
            php5_files=php5,
            php7_files=php7,
            unknown_files=unknown,
            level_sets_used=list(level_sets),
            quality_sets_used=list(_QUALITY_SETS),
            conversion_duration_sec=round(elapsed, 2),
            iso_controls=list(ISO_CONTROLS_CONVERSION),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_version_table(self, version_map: dict[Path, PHPVersion]) -> None:
        """Print a compact per-file PHP version detection table."""
        tbl = Table(
            title="PHP Version Detection",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("File")
        tbl.add_column("Detected Version", justify="center")

        _ver_label = {
            PHPVersion.PHP5: "[bold red]PHP 5.x[/bold red]",
            PHPVersion.PHP7: "[bold yellow]PHP 7.x[/bold yellow]",
            PHPVersion.UNKNOWN: "[dim]Unknown[/dim]",
        }
        for path, ver in version_map.items():
            tbl.add_row(path.name, _ver_label[ver])

        console.print(tbl)

    def _print_summary(self, result: ConversionResult) -> None:
        """Render a conversion summary to the terminal."""
        s = result.summary

        # Status breakdown table
        status_tbl = Table(
            title="Conversion Results",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        status_tbl.add_column("Status", style="bold")
        status_tbl.add_column("Files", justify="right")

        if s.converted:
            status_tbl.add_row("[green]CONVERTED[/green]", str(s.converted))
        if s.skipped:
            status_tbl.add_row("[dim]SKIPPED[/dim]", str(s.skipped))
        if s.failed:
            status_tbl.add_row("[bold red]FAILED[/bold red]", str(s.failed))

        # Per-file detail (CONVERTED and FAILED only; SKIPPED is noise)
        detail_tbl = Table(
            title="Per-File Detail (CONVERTED / FAILED)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        detail_tbl.add_column("File")
        detail_tbl.add_column("PHP Ver", justify="center")
        detail_tbl.add_column("Status", justify="center")
        detail_tbl.add_column("Rules", justify="right")
        detail_tbl.add_column("ISO Control")

        _ver_badge = {
            PHPVersion.PHP5: "[red]PHP5[/red]",
            PHPVersion.PHP7: "[yellow]PHP7[/yellow]",
            PHPVersion.UNKNOWN: "[dim]?[/dim]",
        }
        _status_badge = {
            ConversionStatus.CONVERTED: "[green]CONVERTED[/green]",
            ConversionStatus.SKIPPED: "[dim]SKIPPED[/dim]",
            ConversionStatus.FAILED: "[bold red]FAILED[/bold red]",
        }

        has_detail = False
        for cf in result.files:
            if cf.status == ConversionStatus.SKIPPED:
                continue
            has_detail = True
            detail_tbl.add_row(
                cf.source_path.name,
                _ver_badge[cf.php_version],
                _status_badge[cf.status],
                str(cf.changes_count) if cf.changes_count else "-",
                ", ".join(cf.iso_controls),
            )

        console.print(status_tbl)
        if has_detail:
            console.print(detail_tbl)

        if s.errors:
            console.print(
                Panel(
                    "\n".join(f"• {e}" for e in s.errors[:10]),
                    title="[bold red]Rector Errors[/bold red]",
                    border_style="red",
                )
            )

        console.print(
            f"\n[bold]Total:[/bold] {s.total_files}  "
            f"[green]Converted: {s.converted}[/green]  "
            f"[dim]Skipped: {s.skipped}[/dim]  "
            f"[red]Failed: {s.failed}[/red]  |  "
            f"[bold]Time:[/bold] {s.conversion_duration_sec}s  |  "
            f"[bold]ISO:[/bold] {', '.join(s.iso_controls)}\n"
        )


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_conversion(
    input_path: Path,
    output_path: Path,
    rector_exe: Path | str = RECTOR_EXE,
    target_version: str = "8.3",
    exclude_dirs: list[str] | None = None,
) -> ConversionResult:
    """
    Copy PHP files from *input_path* to *output_path* and run Rector.

    This is the primary entry point for ``main.py``.  It guarantees that
    files in *input_path* are never modified -- all Rector edits happen on
    the copies in *output_path*.

    Parameters
    ----------
    input_path:
        Directory containing original PHP 5.x / 7.x source files.
    output_path:
        Destination for converted PHP files (created if absent).
    rector_exe:
        Rector binary name or absolute path.  Defaults to the Composer-local
        install inside this project.
    target_version:
        Target PHP version string, e.g. ``"8.3"`` (default) or ``"7.4"``.
        Passed to ``_choose_level_sets()`` to select the appropriate Rector
        level-set chain.

    Returns
    -------
    ConversionResult
        Per-file results with ``ConversionStatus``, applied Rector rules,
        aggregate ``ConversionSummary``, and Rector's raw JSON stdout.
        ISO control ``A.8.25`` is recorded on every file entry.
    """
    converter = RectorConverter(rector_exe=rector_exe)
    return converter.run(
        input_path=input_path,
        output_path=output_path,
        target_version=target_version,
        exclude_dirs=exclude_dirs,
    )
