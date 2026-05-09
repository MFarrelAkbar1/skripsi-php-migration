"""
composer_analyzer.py -- Analisis kompatibilitas PHP 8.x pada composer.json.

Membaca composer.json dari direktori input, memeriksa setiap dependency
terhadap daftar mapping yang diketahui, dan menghasilkan rekomendasi upgrade
yang dipetakan ke kontrol ISO/IEC 27001:2022 A.8.25 (Secure Development
Lifecycle).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# Compatibility mapping: package -> (action, replacement_or_note, php8_safe)
#
# php8_safe=True  -> package is known to support PHP 8.x without replacement
# php8_safe=False -> package needs action (replace or manual review)
# ---------------------------------------------------------------------------

_KNOWN_MAPPINGS: dict[str, tuple[str, str, bool]] = {
    # action           suggestion / note                     php8_safe
    "phpoffice/phpexcel": (
        "replace",
        "phpoffice/phpspreadsheet",
        False,
    ),
    "dompdf/dompdf": (
        "upgrade",
        "dompdf/dompdf >=2.0 (supports PHP 8.x); update version constraint",
        False,
    ),
    "swiftmailer/swiftmailer": (
        "replace",
        "symfony/mailer",
        False,
    ),
    "ezyang/htmlpurifier": (
        "upgrade",
        "ezyang/htmlpurifier >=4.16 (supports PHP 8.x); verify version constraint",
        False,
    ),
    "doctrine/common": (
        "upgrade",
        "doctrine/common >=3.0 (supports PHP 8.x); update version constraint",
        False,
    ),
    "monolog/monolog": (
        "safe",
        "monolog/monolog >=2.0 fully supports PHP 8.x",
        True,
    ),
    "guzzlehttp/guzzle": (
        "upgrade",
        "guzzlehttp/guzzle >=7.0 required for PHP 8.x; update version constraint",
        False,
    ),
    "symfony/http-foundation": (
        "safe",
        "symfony/http-foundation >=5.0 fully supports PHP 8.x",
        True,
    ),
    "symfony/console": (
        "safe",
        "symfony/console >=5.0 fully supports PHP 8.x",
        True,
    ),
    "phpmailer/phpmailer": (
        "upgrade",
        "phpmailer/phpmailer >=6.5 required for PHP 8.x; update version constraint",
        False,
    ),
    "codeigniter/framework": (
        "replace",
        "codeigniter4/framework (CodeIgniter 4 rewrites CI3 for PHP 8.x)",
        False,
    ),
    "laravel/framework": (
        "upgrade",
        "laravel/framework >=9.0 required for PHP 8.x; update version constraint",
        False,
    ),
    "vlucas/phpdotenv": (
        "safe",
        "vlucas/phpdotenv >=5.0 fully supports PHP 8.x",
        True,
    ),
    "phpoffice/phpspreadsheet": (
        "safe",
        "phpoffice/phpspreadsheet >=1.18 supports PHP 8.x; ^1.12 constraint will resolve to a compatible version",
        True,
    ),
    "firebase/php-jwt": (
        "safe",
        "firebase/php-jwt >=6.0 fully supports PHP 8.x",
        True,
    ),
}

# ISO control relevant to dependency management / secure dev lifecycle
_ISO_CONTROL: str = "A.8.25"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DependencyRecommendation:
    """Single dependency analysis result."""

    package: str
    current_version_constraint: str
    status: str          # "safe" | "replace" | "upgrade" | "manual_review"
    suggestion: str
    iso_control: str = _ISO_CONTROL


@dataclass
class ComposerAnalysisResult:
    """Aggregated result of a composer.json analysis run."""

    composer_found: bool
    php_constraint: str                        # e.g. ">=7.4"
    recommendations: list[DependencyRecommendation] = field(default_factory=list)
    duration_sec: float = 0.0
    composer_path: str = ""

    @property
    def issues_count(self) -> int:
        return sum(1 for r in self.recommendations if r.status != "safe")

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.recommendations if r.status == "safe")


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------


class ComposerAnalyzer:
    """
    Parses composer.json, checks PHP 8.x compatibility per dependency,
    and produces structured upgrade recommendations.
    """

    def __init__(self, target_php: str = "8.3") -> None:
        self._target_php = target_php

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, input_dir: Path) -> ComposerAnalysisResult:
        """
        Analyse composer.json inside *input_dir*.

        Returns a ComposerAnalysisResult.  When no composer.json is present,
        ``composer_found`` is False and the recommendation list is empty.
        """
        t_start = time.perf_counter()

        composer_path = input_dir / "composer.json"
        if not composer_path.exists():
            console.print(
                f"[dim]composer.json not found in {input_dir} -- step skipped.[/dim]"
            )
            return ComposerAnalysisResult(
                composer_found=False,
                php_constraint="",
                duration_sec=round(time.perf_counter() - t_start, 2),
            )

        console.print(
            Panel(
                f"[bold green]Composer Dependency Analyzer[/bold green]\n"
                f"File   : [cyan]{composer_path.resolve()}[/cyan]\n"
                f"Target : PHP [yellow]{self._target_php}[/yellow]",
                border_style="green",
            )
        )

        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[bold red]Failed to parse composer.json:[/bold red] {exc}")
            return ComposerAnalysisResult(
                composer_found=True,
                php_constraint="",
                composer_path=str(composer_path.resolve()),
                duration_sec=round(time.perf_counter() - t_start, 2),
            )

        php_constraint: str = (
            data.get("require", {}).get("php", "")
            or data.get("require-dev", {}).get("php", "")
        )

        all_deps: dict[str, str] = {}
        all_deps.update(data.get("require", {}))
        all_deps.update(data.get("require-dev", {}))
        # Remove the bare "php" and "ext-*" meta entries
        deps = {
            pkg: ver
            for pkg, ver in all_deps.items()
            if pkg != "php" and not pkg.startswith("ext-")
        }

        recommendations = [self._evaluate(pkg, ver) for pkg, ver in deps.items()]

        result = ComposerAnalysisResult(
            composer_found=True,
            php_constraint=php_constraint,
            recommendations=recommendations,
            composer_path=str(composer_path.resolve()),
            duration_sec=round(time.perf_counter() - t_start, 2),
        )

        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # Per-dependency evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, package: str, version: str) -> DependencyRecommendation:
        """Return a DependencyRecommendation for one composer dependency."""
        pkg_lower = package.lower()

        if pkg_lower in _KNOWN_MAPPINGS:
            action, suggestion, php8_safe = _KNOWN_MAPPINGS[pkg_lower]
            status = "safe" if php8_safe else action
        else:
            status = "manual_review"
            suggestion = (
                f"No known PHP 8.x compatibility data for '{package}'. "
                "Verify the library's changelog and test with PHP "
                f"{self._target_php}."
            )

        return DependencyRecommendation(
            package=package,
            current_version_constraint=version,
            status=status,
            suggestion=suggestion,
        )

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_summary(self, result: ComposerAnalysisResult) -> None:
        """Render the dependency table and a brief summary panel."""

        tbl = Table(
            title="Composer Dependency PHP 8.x Compatibility",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        tbl.add_column("Package", min_width=30)
        tbl.add_column("Current Constraint", justify="center", width=18)
        tbl.add_column("Status", justify="center", width=14)
        tbl.add_column("Recommendation / Note", min_width=38)

        _status_styles: dict[str, str] = {
            "safe":          "green",
            "upgrade":       "yellow",
            "replace":       "red",
            "manual_review": "cyan",
        }

        for rec in result.recommendations:
            style = _status_styles.get(rec.status, "white")
            status_label = {
                "safe":          "SAFE",
                "upgrade":       "UPGRADE",
                "replace":       "REPLACE",
                "manual_review": "MANUAL REVIEW",
            }.get(rec.status, rec.status.upper())

            tbl.add_row(
                rec.package,
                rec.current_version_constraint,
                f"[{style}]{status_label}[/{style}]",
                rec.suggestion,
            )

        console.print(tbl)

        php_str = (
            f"  PHP constraint in composer.json: [yellow]{result.php_constraint}[/yellow]\n"
            if result.php_constraint
            else ""
        )
        issues_style = "red" if result.issues_count else "green"
        console.print(
            Panel(
                f"{php_str}"
                f"  Total dependencies checked : [bold]{len(result.recommendations)}[/bold]\n"
                f"  Issues requiring action    : [{issues_style}]{result.issues_count}[/{issues_style}]\n"
                f"  Already PHP 8.x safe       : [green]{result.safe_count}[/green]\n"
                f"  Duration                   : {result.duration_sec}s",
                title="[bold]Composer Analysis Summary[/bold]",
                border_style=issues_style,
            )
        )


# ---------------------------------------------------------------------------
# Serialisation helpers (used by main.py)
# ---------------------------------------------------------------------------


def composer_result_to_dict(result: ComposerAnalysisResult) -> dict:
    """Convert a ComposerAnalysisResult to a JSON-serialisable dict."""
    return {
        "composer_found": result.composer_found,
        "php_constraint": result.php_constraint,
        "composer_path": result.composer_path,
        "duration_sec": result.duration_sec,
        "issues_count": result.issues_count,
        "safe_count": result.safe_count,
        "recommendations": [
            {
                "package": r.package,
                "current_version_constraint": r.current_version_constraint,
                "status": r.status,
                "suggestion": r.suggestion,
                "iso_control": r.iso_control,
            }
            for r in result.recommendations
        ],
    }


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_composer_analysis(
    input_dir: Path,
    target_php: str = "8.3",
) -> ComposerAnalysisResult:
    """
    Run composer.json compatibility analysis and return structured results.

    Parameters
    ----------
    input_dir:
        Directory that may contain a composer.json file.
    target_php:
        Target PHP version string (e.g. "8.3") for display purposes.

    Returns
    -------
    ComposerAnalysisResult
        ``composer_found=False`` when no composer.json is present.
    """
    analyzer = ComposerAnalyzer(target_php=target_php)
    return analyzer.run(input_dir)
