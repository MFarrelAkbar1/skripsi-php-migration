"""
scanner.py -- Modul pemindaian keamanan menggunakan Semgrep.

Menjalankan Semgrep dengan ruleset p/php dan p/owasp-top-ten terhadap
kode PHP di folder input/, lalu mengembalikan temuan terstruktur yang
dipetakan ke prioritas kerentanan dan kontrol ISO/IEC 27001:2022.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def _find_semgrep_exe() -> Path:
    """Locate the Semgrep executable via shutil.which (searches PATH)."""
    found = shutil.which("semgrep")
    if found:
        return Path(found)
    raise FileNotFoundError(
        "Semgrep executable not found on PATH.\n"
        "Install it with: pip install semgrep\n"
        "Then ensure 'semgrep' is accessible in your PATH and restart your terminal."
    )


RULESETS: list[str] = ["p/php", "p/owasp-top-ten"]

# Project root is one level above pipeline/ (i.e. the repo root).
_PROJECT_ROOT: Path = Path(__file__).parent.parent
_LOCAL_RULES_DIR: Path = _PROJECT_ROOT / "rules"

# ---------------------------------------------------------------------------
# Local Ruleset Setup (for reproducible scans)
# ---------------------------------------------------------------------------
# By default, Semgrep downloads p/php and p/owasp-top-ten from the online
# registry at runtime, so results can differ if Semgrep updates those rulesets.
#
# To pin rulesets locally:
#
#   mkdir rules
#
#   # Unix / macOS / Git Bash:
#   semgrep --config p/php --dump-rules > rules/php.yaml
#   semgrep --config p/owasp-top-ten --dump-rules > rules/owasp-top-ten.yaml
#
#   # Windows PowerShell:
#   semgrep --config p/php --dump-rules | Out-File -Encoding utf8 rules/php.yaml
#   semgrep --config p/owasp-top-ten --dump-rules | Out-File -Encoding utf8 rules/owasp-top-ten.yaml
#
# Once rules/ is populated, the scanner auto-detects it and uses the local files
# instead of the online registry -- no code changes needed.
# ---------------------------------------------------------------------------


def _resolve_rulesets() -> tuple[list[str], bool]:
    """
    Return (configs, is_local).

    Checks for a non-empty rules/ directory at the project root.
    If found, returns a single --config pointing to that directory so Semgrep
    uses all YAML files inside it (pinned, reproducible).
    Otherwise falls back to the online registry rulesets (RULESETS constant).
    """
    if _LOCAL_RULES_DIR.is_dir() and any(_LOCAL_RULES_DIR.iterdir()):
        return [str(_LOCAL_RULES_DIR)], True
    return list(RULESETS), False


# Vulnerability classification: maps keyword patterns (substring of rule_id or
# message, lower-cased) -> (vuln_type_label, iso_controls, priority)
# Priority follows CLAUDE.md ordering (lower number = higher priority).
_VULN_RULES: list[tuple[tuple[str, ...], str, list[str], int]] = [
    (
        ("sql-injection", "sqli", "mysql_query", "mysql_connect", "mysql_real_escape",
         "sql_injection", "unsanitized-input-into-sql", "injection.php",
         "manually-constructed sql", "user data flows into", "sql string"),
        "SQL Injection",
        ["A.8.28", "A.8.26"],
        1,
    ),
    (
        ("xss", "cross-site-scripting", "reflected-xss", "stored-xss",
         "htmlspecialchars", "htmlentities", "echo-unescaped", "print-unescaped"),
        "XSS",
        ["A.8.28", "A.8.26"],
        2,
    ),
    (
        ("deprecated", "mysql_", "ereg", "split(", "eregi", "magic_quotes",
         "php7-deprecated", "removed-function"),
        "Deprecated Function",
        ["A.8.25", "A.8.28"],
        3,
    ),
    (
        ("hardcoded", "hardcode", "credentials", "password", "secret", "api-key",
         "private-key", "token", "auth"),
        "Hardcoded Credentials",
        ["A.5.17", "A.8.28"],
        4,
    ),
    (
        ("ssrf", "server-side-request-forgery", "server_side_request",
         "file name based on user input", "user-controlled-filename",
         "user input risks server-side"),
        "SSRF",
        ["A.8.28", "A.8.29"],
        5,
    ),
    (
        ("path-traversal", "directory-traversal", "file-inclusion", "lfi", "rfi",
         "include", "require", "fopen", "file_get_contents"),
        "Path Traversal",
        ["A.8.28", "A.8.29"],
        5,
    ),
    (
        ("md5", "sha1", "weak-crypto", "weak-hash", "insecure-hash",
         "crc32", "base64", "rot13"),
        "Weak Cryptography",
        ["A.8.24", "A.8.28"],
        6,
    ),
]

_SEVERITY_ORDER: dict[str, int] = {
    "ERROR": 1,
    "WARNING": 2,
    "INFO": 3,
}

console = Console()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanFinding:
    """Represents a single Semgrep finding."""

    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    col_start: int
    col_end: int
    message: str
    severity: str          # ERROR | WARNING | INFO
    code_snippet: str
    vuln_type: str         # Classified label (e.g. "SQL Injection")
    iso_controls: list[str]
    priority: int          # 1-6 per CLAUDE.md, 99 = unclassified

    # Convenience: sort key
    def sort_key(self) -> tuple[int, int, str, int]:
        return (
            self.priority,
            _SEVERITY_ORDER.get(self.severity.upper(), 99),
            self.file_path,
            self.line_start,
        )


@dataclass
class ScanSummary:
    """Aggregate statistics for a completed scan."""

    scanned_files: int
    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    by_vuln_type: dict[str, int] = field(default_factory=dict)
    by_priority: dict[int, int] = field(default_factory=dict)
    scan_duration_sec: float = 0.0
    rulesets_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """
    Full result returned by SemgrepScanner.run().

    Fields
    ------
    findings:  sorted list of ScanFinding (highest priority first)
    summary:   aggregate statistics
    raw_output: original parsed JSON from Semgrep
    """

    findings: list[ScanFinding]
    summary: ScanSummary
    raw_output: dict


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------


class SemgrepScanner:
    """
    Wraps Semgrep invocation, output parsing, and finding classification.

    Usage
    -----
    scanner = SemgrepScanner()
    result  = scanner.run(Path("input/"))
    """

    def __init__(
        self,
        semgrep_exe: Path | None = None,
        rulesets: list[str] | None = None,
        timeout_sec: int = 300,
    ) -> None:
        self._exe = semgrep_exe if semgrep_exe is not None else _find_semgrep_exe()
        if rulesets is not None:
            self._rulesets = rulesets
            self._using_local_rules = True
        else:
            self._rulesets, self._using_local_rules = _resolve_rulesets()
        self._timeout = timeout_sec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target_path: Path) -> ScanResult:
        """
        Run Semgrep against *target_path* and return a structured ScanResult.

        Parameters
        ----------
        target_path:
            Directory (or single file) containing PHP source to scan.

        Raises
        ------
        FileNotFoundError
            If the Semgrep executable does not exist.
        FileNotFoundError
            If *target_path* does not exist.
        """
        if not self._exe.exists():
            raise FileNotFoundError(
                f"Semgrep executable not found: {self._exe}\n"
                "Ensure Semgrep is installed: pip install semgrep"
            )
        if not target_path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {target_path}")

        rules_label = "local (pinned)" if self._using_local_rules else "online registry"
        console.print(
            Panel(
                f"[bold cyan]Semgrep Security Scan[/bold cyan]\n"
                f"Target : [green]{target_path}[/green]\n"
                f"Rules  : [yellow]{', '.join(self._rulesets)}[/yellow]  "
                f"[dim]({rules_label})[/dim]",
                border_style="cyan",
            )
        )
        if not self._using_local_rules:
            console.print(
                "[yellow]WARNING:[/yellow] Semgrep rulesets loaded from online registry "
                "(p/php, p/owasp-top-ten). Scan results may differ between runs if "
                "Semgrep updates those rulesets.\n"
                "[dim]For reproducible scans: create rules/ and run "
                "'semgrep --config p/php --dump-rules > rules/php.yaml' "
                "(see pipeline/scanner.py for full instructions).[/dim]"
            )

        cmd = self._build_command(target_path)
        raw = self._invoke_semgrep(cmd)
        findings = self._parse_findings(raw)
        summary = self._build_summary(raw, findings)
        result = ScanResult(findings=findings, summary=summary, raw_output=raw)

        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def _build_command(self, target_path: Path) -> list[str]:
        """Build the Semgrep CLI invocation as a list of arguments."""
        cmd: list[str] = [str(self._exe)]
        for ruleset in self._rulesets:
            cmd += ["--config", ruleset]
        cmd += [
            "--json",
            "--no-git-ignore",         # scan all files regardless of .gitignore
            "--timeout", "60",         # per-file timeout (seconds)
            "--max-memory", "2048",    # MB; safe for 16 GB RAM system
            "--metrics=off",           # no telemetry
            "--include", "*.php",      # scan only PHP files (skip JS, Vue, etc.)
            str(target_path),
        ]
        return cmd

    # ------------------------------------------------------------------
    # Semgrep invocation
    # ------------------------------------------------------------------

    def _invoke_semgrep(self, cmd: list[str]) -> dict:
        """
        Execute Semgrep and return the parsed JSON output.

        Semgrep always exits with code 1 when it finds vulnerabilities, so we
        only treat non-zero exit codes as fatal when stdout is empty / not JSON.
        """
        console.print(f"[dim]Running: {' '.join(cmd[:4])} … (may take a moment)[/dim]")
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
            console.print("[bold red]ERROR:[/bold red] Semgrep timed out.")
            return {"results": [], "errors": ["Process timed out"], "stats": {}}
        except Exception as exc:  # noqa: BLE001
            console.print(f"[bold red]ERROR:[/bold red] Failed to launch Semgrep: {exc}")
            return {"results": [], "errors": [str(exc)], "stats": {}}

        elapsed = time.perf_counter() - t_start
        console.print(f"[dim]Semgrep finished in {elapsed:.1f}s (exit code {proc.returncode})[/dim]")

        if proc.stderr:
            # Semgrep writes progress / warnings to stderr; only show on non-zero
            if proc.returncode not in (0, 1):
                console.print(f"[yellow]Semgrep stderr:[/yellow]\n{proc.stderr[:2000]}")

        if not proc.stdout.strip():
            console.print("[bold red]ERROR:[/bold red] Semgrep produced no output.")
            return {"results": [], "errors": ["No output from Semgrep"], "stats": {}}

        try:
            data: dict = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            console.print(f"[bold red]ERROR:[/bold red] Could not parse Semgrep JSON: {exc}")
            return {"results": [], "errors": [f"JSON parse error: {exc}"], "stats": {}}

        # Inject elapsed time so summary can report it
        data.setdefault("stats", {})["pipeline_elapsed"] = elapsed
        return data

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_findings(self, raw: dict) -> list[ScanFinding]:
        """Convert raw Semgrep JSON results into ScanFinding objects."""
        findings: list[ScanFinding] = []

        for item in raw.get("results", []):
            rule_id: str = item.get("check_id", "unknown")
            path: str = item.get("path", "unknown")

            start = item.get("start", {})
            end = item.get("end", {})
            extra = item.get("extra", {})

            severity: str = extra.get("severity", "WARNING").upper()
            message: str = extra.get("message", "No message provided.")
            snippet: str = extra.get("lines", "").rstrip()

            vuln_type, iso_controls, priority = self._classify(rule_id, message)

            findings.append(
                ScanFinding(
                    rule_id=rule_id,
                    file_path=path,
                    line_start=start.get("line", 0),
                    line_end=end.get("line", 0),
                    col_start=start.get("col", 0),
                    col_end=end.get("col", 0),
                    message=message,
                    severity=severity,
                    code_snippet=snippet,
                    vuln_type=vuln_type,
                    iso_controls=iso_controls,
                    priority=priority,
                )
            )

        findings.sort(key=lambda f: f.sort_key())
        return findings

    # ------------------------------------------------------------------
    # Vulnerability classification
    # ------------------------------------------------------------------

    def _classify(
        self, rule_id: str, message: str
    ) -> tuple[str, list[str], int]:
        """
        Return (vuln_type, iso_controls, priority) for a given rule/message.

        Matching is case-insensitive against both the rule_id and the first
        100 characters of the message.
        """
        haystack = (rule_id + " " + message[:100]).lower()

        for keywords, label, controls, priority in _VULN_RULES:
            if any(kw in haystack for kw in keywords):
                return label, controls, priority

        # Unclassified -- still assign generic secure-coding control
        return "Other", ["A.8.28"], 99

    # ------------------------------------------------------------------
    # Summary construction
    # ------------------------------------------------------------------

    def _build_summary(self, raw: dict, findings: list[ScanFinding]) -> ScanSummary:
        """Aggregate findings into a ScanSummary."""
        stats: dict = raw.get("stats", {})

        by_severity: dict[str, int] = {}
        by_vuln_type: dict[str, int] = {}
        by_priority: dict[int, int] = {}

        for f in findings:
            sev = f.severity.upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_vuln_type[f.vuln_type] = by_vuln_type.get(f.vuln_type, 0) + 1
            by_priority[f.priority] = by_priority.get(f.priority, 0) + 1

        errors: list[str] = [
            e.get("message", str(e)) if isinstance(e, dict) else str(e)
            for e in raw.get("errors", [])
        ]

        return ScanSummary(
            scanned_files=len(raw.get("paths", {}).get("scanned", [])),
            total_findings=len(findings),
            by_severity=by_severity,
            by_vuln_type=by_vuln_type,
            by_priority=by_priority,
            scan_duration_sec=round(stats.get("pipeline_elapsed", 0.0), 2),
            rulesets_used=list(self._rulesets),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_summary(self, result: ScanResult) -> None:
        """Render a findings summary table to the terminal."""
        s = result.summary

        # --- Severity breakdown table ---
        sev_table = Table(
            title="Findings by Severity",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")

        _sev_styles = {"ERROR": "red", "WARNING": "yellow", "INFO": "cyan"}
        for sev in ("ERROR", "WARNING", "INFO"):
            count = s.by_severity.get(sev, 0)
            if count:
                sev_table.add_row(
                    f"[{_sev_styles[sev]}]{sev}[/{_sev_styles[sev]}]",
                    str(count),
                )

        # --- Vulnerability type table ---
        vuln_table = Table(
            title="Findings by Vulnerability Type",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        vuln_table.add_column("Priority", justify="center")
        vuln_table.add_column("Vulnerability Type")
        vuln_table.add_column("Count", justify="right")
        vuln_table.add_column("ISO 27001 Controls")

        # Build a priority->label map for display
        _priority_label: dict[int, tuple[str, list[str]]] = {
            r[3]: (r[1], r[2]) for r in _VULN_RULES
        }
        _priority_label[99] = ("Other", ["A.8.28"])

        seen_types: set[str] = set()
        for finding in result.findings:
            if finding.vuln_type in seen_types:
                continue
            seen_types.add(finding.vuln_type)
            count = s.by_vuln_type.get(finding.vuln_type, 0)
            pri = finding.priority
            iso = ", ".join(finding.iso_controls)
            pri_display = str(pri) if pri != 99 else "-"
            vuln_table.add_row(pri_display, finding.vuln_type, str(count), iso)

        console.print(sev_table)
        console.print(vuln_table)

        # --- Errors from Semgrep ---
        if s.errors:
            console.print(
                Panel(
                    "\n".join(f"• {e}" for e in s.errors[:10]),
                    title="[bold red]Semgrep Errors[/bold red]",
                    border_style="red",
                )
            )

        # --- Footer ---
        console.print(
            f"\n[bold]Total findings:[/bold] [red]{s.total_findings}[/red]  |  "
            f"[bold]Files scanned:[/bold] {s.scanned_files}  |  "
            f"[bold]Scan time:[/bold] {s.scan_duration_sec}s\n"
        )


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_scan(
    target_path: Path,
    semgrep_exe: Path | None = None,
    rulesets: list[str] | None = None,
) -> ScanResult:
    """
    Run a Semgrep security scan and return structured results.

    Parameters
    ----------
    target_path:
        Directory or file to scan (typically ``input/``).
    semgrep_exe:
        Absolute path to the Semgrep executable.
    rulesets:
        List of Semgrep config identifiers, e.g. ``["p/php", "p/owasp-top-ten"]``.
        Defaults to :data:`RULESETS`.

    Returns
    -------
    ScanResult
        Structured findings with ISO 27001 control mappings.
    """
    scanner = SemgrepScanner(semgrep_exe=semgrep_exe, rulesets=rulesets)
    return scanner.run(target_path)
