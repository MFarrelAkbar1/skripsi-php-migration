"""
accuracy_checker.py -- Modul pengecekan keakuratan hasil migrasi PHP.

Mengukur keakuratan konversi Rector dari 5 dimensi:
1. Conversion Rate       -- file berhasil / gagal / skip
2. Syntax Validity       -- php -l per file di output/
3. Deprecated Removal    -- jumlah pola deprecated sebelum vs sesudah
4. Security Findings     -- Semgrep pre-scan vs post-scan delta
5. PHPStan Distribution  -- distribusi error severity

Menghasilkan:
- 6 grafik PNG individual di reports/accuracy_<timestamp>_N_<name>.png
- Ringkasan skor akurasi di terminal
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend, aman untuk Windows tanpa display
import matplotlib.pyplot as plt
import numpy as np
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ---------------------------------------------------------------------------
# Deprecated PHP patterns yang dicari di file sumber
# ---------------------------------------------------------------------------

_DEPRECATED_PATTERNS: dict[str, re.Pattern[str]] = {
    "mysql_connect":    re.compile(r"\bmysql_connect\s*\(", re.IGNORECASE),
    "mysql_query":      re.compile(r"\bmysql_query\s*\(", re.IGNORECASE),
    "mysql_*":          re.compile(r"\bmysql_\w+\s*\(", re.IGNORECASE),
    "ereg()":           re.compile(r"\bereg\s*\(", re.IGNORECASE),
    "eregi()":          re.compile(r"\beregi\s*\(", re.IGNORECASE),
    "split()":          re.compile(r"\bsplit\s*\(", re.IGNORECASE),
    "magic_quotes":     re.compile(r"\bmagic_quotes\b", re.IGNORECASE),
    "session_register": re.compile(r"\bsession_register\s*\(", re.IGNORECASE),
    "call_user_method": re.compile(r"\bcall_user_method\s*\(", re.IGNORECASE),
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SyntaxResult:
    """Hasil php -l per file."""
    valid: int = 0
    invalid: int = 0
    skipped: int = 0          # php tidak tersedia
    invalid_files: list[str] = field(default_factory=list)


@dataclass
class DeprecatedCount:
    """Jumlah kemunculan pola deprecated di suatu folder."""
    counts: dict[str, int] = field(default_factory=dict)  # pattern -> count

    @property
    def total(self) -> int:
        return sum(self.counts.values())


@dataclass
class AccuracyReport:
    """Laporan keakuratan lengkap."""
    # dimensi 1 -- dari pipeline report
    conversion_total: int = 0
    conversion_converted: int = 0
    conversion_skipped: int = 0
    conversion_failed: int = 0

    # dimensi 2 -- php -l
    syntax: SyntaxResult = field(default_factory=SyntaxResult)

    # dimensi 3 -- deprecated removal
    deprecated_input: DeprecatedCount = field(default_factory=DeprecatedCount)
    deprecated_output: DeprecatedCount = field(default_factory=DeprecatedCount)

    # dimensi 4 -- semgrep delta (dari pipeline report)
    pre_findings: dict[str, int] = field(default_factory=dict)
    post_findings: dict[str, int] = field(default_factory=dict)

    # dimensi 5 -- phpstan (dari pipeline report)
    phpstan_errors: int = 0
    phpstan_warnings: int = 0
    phpstan_files: int = 0

    # skor
    scores: dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0

    # metadata
    generated_at: datetime = field(default_factory=datetime.now)
    pipeline_report_path: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_latest_report(reports_dir: Path) -> Path | None:
    """Cari pipeline_result terbaru di reports_dir."""
    candidates = sorted(
        reports_dir.glob("pipeline_result_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load_pipeline_report(report_path: Path) -> dict:
    """Load JSON pipeline report."""
    return json.loads(report_path.read_text(encoding="utf-8"))


def _check_php_available() -> bool:
    """Return True jika php tersedia di PATH."""
    try:
        subprocess.run(
            ["php", "--version"],
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_syntax_check(output_dir: Path) -> SyntaxResult:
    """Jalankan php -l pada setiap .php di output_dir."""
    result = SyntaxResult()

    if not _check_php_available():
        console.print("[yellow]php tidak tersedia di PATH -- syntax check dilewati.[/yellow]")
        result.skipped = len(list(output_dir.rglob("*.php")))
        return result

    php_files = list(output_dir.rglob("*.php"))
    console.print(f"[dim]Syntax check: {len(php_files)} file ...[/dim]")

    for php_file in php_files:
        try:
            proc = subprocess.run(
                ["php", "-l", str(php_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                result.valid += 1
            else:
                result.invalid += 1
                result.invalid_files.append(str(php_file))
        except (subprocess.TimeoutExpired, Exception):
            result.invalid += 1
            result.invalid_files.append(str(php_file))

    return result


def _count_deprecated(folder: Path) -> DeprecatedCount:
    """Hitung kemunculan pola deprecated di seluruh .php dalam folder."""
    result = DeprecatedCount(counts={k: 0 for k in _DEPRECATED_PATTERNS})

    for php_file in folder.rglob("*.php"):
        try:
            content = php_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for name, pattern in _DEPRECATED_PATTERNS.items():
            result.counts[name] += len(pattern.findall(content))

    return result


def _compute_scores(report: AccuracyReport) -> None:
    """
    Hitung skor akurasi per dimensi (0-100) dan overall.

    Dimensi dan bobotnya:
    - Conversion Rate    : 25%
    - Syntax Validity    : 30%
    - Deprecated Removal : 20%
    - Security Delta     : 15%
    - PHPStan (proxy)    : 10%
    """
    scores: dict[str, float] = {}

    # 1. Conversion Rate
    if report.conversion_total > 0:
        scores["Conversion Rate"] = round(
            report.conversion_converted / report.conversion_total * 100, 1
        )
    else:
        scores["Conversion Rate"] = 0.0

    # 2. Syntax Validity
    total_syntax = report.syntax.valid + report.syntax.invalid
    if total_syntax > 0:
        scores["Syntax Validity"] = round(
            report.syntax.valid / total_syntax * 100, 1
        )
    elif report.syntax.skipped > 0:
        scores["Syntax Validity"] = scores["Conversion Rate"]  # fallback
    else:
        scores["Syntax Validity"] = 0.0

    # 3. Deprecated Removal
    input_total = report.deprecated_input.total
    output_total = report.deprecated_output.total
    if input_total > 0:
        removed = max(0, input_total - output_total)
        scores["Deprecated Removal"] = round(removed / input_total * 100, 1)
    else:
        scores["Deprecated Removal"] = 100.0  # tidak ada yg deprecated = sempurna

    # 4. Security Delta (post < pre = bagus)
    pre_total = sum(report.pre_findings.values())
    post_total = sum(report.post_findings.values())
    if pre_total > 0:
        delta_ratio = (pre_total - post_total) / pre_total
        scores["Security Delta"] = round(max(0.0, min(100.0, 50 + delta_ratio * 50)), 1)
    else:
        scores["Security Delta"] = 100.0  # tidak ada finding = clean

    # 5. PHPStan proxy (skor berdasarkan rasio error terhadap file)
    if report.phpstan_files > 0:
        err_per_file = report.phpstan_errors / report.phpstan_files
        # heuristic: 0 err/file = 100, >= 20 err/file = 0
        scores["PHPStan Quality"] = round(max(0.0, 100 - err_per_file * 5), 1)
    else:
        scores["PHPStan Quality"] = 0.0  # PHPStan tidak jalan

    # Overall (weighted average)
    weights = {
        "Conversion Rate":    0.25,
        "Syntax Validity":    0.30,
        "Deprecated Removal": 0.20,
        "Security Delta":     0.15,
        "PHPStan Quality":    0.10,
    }
    overall = sum(scores[k] * weights[k] for k in weights)
    report.scores = scores
    report.overall_score = round(overall, 1)


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------


class AccuracyChecker:
    """
    Orchestrates all accuracy checks and generates the report + graphs.

    Usage
    -----
    checker = AccuracyChecker()
    report  = checker.run(input_dir, output_dir, reports_dir)
    """

    def run(
        self,
        input_dir: Path,
        output_dir: Path,
        reports_dir: Path,
        pipeline_report_path: Path | None = None,
    ) -> AccuracyReport:
        """
        Jalankan semua pengecekan dan hasilkan laporan + grafik individual.

        Parameters
        ----------
        input_dir:
            Folder PHP asli (sebelum konversi).
        output_dir:
            Folder hasil konversi Rector.
        reports_dir:
            Folder laporan -- output grafik PNG disimpan di sini.
        pipeline_report_path:
            Path ke pipeline_result JSON. Jika None, pakai yang terbaru.
        """
        report = AccuracyReport()

        # --- Load pipeline report ---
        if pipeline_report_path is None:
            pipeline_report_path = _find_latest_report(reports_dir)
        if pipeline_report_path is None:
            console.print("[red]Tidak ada pipeline_result JSON ditemukan. Jalankan pipeline dulu.[/red]")
            sys.exit(1)

        report.pipeline_report_path = str(pipeline_report_path)
        pipeline_data = _load_pipeline_report(pipeline_report_path)

        console.print(
            Panel(
                f"[bold cyan]Accuracy Checker[/bold cyan]\n"
                f"Input   : [green]{input_dir}[/green]\n"
                f"Output  : [green]{output_dir}[/green]\n"
                f"Report  : [dim]{pipeline_report_path.name}[/dim]",
                border_style="cyan",
            )
        )

        # --- Dimensi 1: Conversion rate (dari pipeline report) ---
        console.print("[bold]1/5[/bold] Membaca data konversi ...")
        conv = pipeline_data.get("conversion") or {}
        report.conversion_total = conv.get("total_files", 0)
        report.conversion_converted = conv.get("converted", 0)
        report.conversion_skipped = conv.get("skipped", 0)
        report.conversion_failed = conv.get("failed", 0)

        # --- Dimensi 2: Syntax validity ---
        console.print("[bold]2/5[/bold] Menjalankan php -l syntax check ...")
        if output_dir.exists():
            report.syntax = _run_syntax_check(output_dir)
        else:
            console.print(f"[yellow]output_dir tidak ada: {output_dir}[/yellow]")

        # --- Dimensi 3: Deprecated pattern removal ---
        console.print("[bold]3/5[/bold] Menghitung deprecated patterns ...")
        if input_dir.exists():
            report.deprecated_input = _count_deprecated(input_dir)
        if output_dir.exists():
            report.deprecated_output = _count_deprecated(output_dir)

        # --- Dimensi 4: Security findings delta ---
        console.print("[bold]4/5[/bold] Membaca Semgrep findings ...")
        pre = pipeline_data.get("pre_scan") or {}
        post = pipeline_data.get("post_scan") or {}
        report.pre_findings = pre.get("by_vuln_type", {})
        report.post_findings = post.get("by_vuln_type", {})

        # --- Dimensi 5: PHPStan ---
        console.print("[bold]5/5[/bold] Membaca PHPStan data ...")
        analysis = pipeline_data.get("analysis") or {}
        by_sev = analysis.get("by_severity", {})
        report.phpstan_errors = by_sev.get("ERROR", 0)
        report.phpstan_warnings = by_sev.get("WARNING", 0)
        report.phpstan_files = analysis.get("total_files_analysed", 0)

        # --- Hitung skor ---
        _compute_scores(report)

        # --- Print ke terminal ---
        self._print_summary(report)

        # --- Generate grafik individual ---
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._generate_graphs(report, reports_dir, timestamp)

        return report

    # ------------------------------------------------------------------
    # Terminal output
    # ------------------------------------------------------------------

    def _print_summary(self, report: AccuracyReport) -> None:
        """Tampilkan ringkasan skor ke terminal."""
        tbl = Table(
            title="Accuracy Score per Dimensi",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        tbl.add_column("Dimensi", width=24)
        tbl.add_column("Skor", justify="right", width=10)
        tbl.add_column("Detail", width=40)

        def _bar(score: float) -> str:
            filled = int(score / 10)
            return "[" + "#" * filled + "-" * (10 - filled) + "]"

        details = {
            "Conversion Rate": (
                f"{report.conversion_converted}/{report.conversion_total} converted, "
                f"{report.conversion_failed} failed"
            ),
            "Syntax Validity": (
                f"{report.syntax.valid} valid, {report.syntax.invalid} invalid"
                if report.syntax.skipped == 0
                else f"php -l dilewati ({report.syntax.skipped} files)"
            ),
            "Deprecated Removal": (
                f"{report.deprecated_input.total} -> {report.deprecated_output.total} occurrences"
            ),
            "Security Delta": (
                f"pre={sum(report.pre_findings.values())} "
                f"post={sum(report.post_findings.values())}"
            ),
            "PHPStan Quality": (
                f"{report.phpstan_errors} errors, {report.phpstan_warnings} warnings, "
                f"{report.phpstan_files} files"
            ),
        }

        for dim, score in report.scores.items():
            colour = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
            tbl.add_row(
                dim,
                f"[{colour}]{score:.1f}%[/{colour}]  {_bar(score)}",
                details.get(dim, ""),
            )

        console.print(tbl)

        overall_colour = (
            "green" if report.overall_score >= 70
            else ("yellow" if report.overall_score >= 40 else "red")
        )
        console.print(
            Panel(
                f"[bold]Overall Accuracy Score: "
                f"[{overall_colour}]{report.overall_score:.1f}%[/{overall_colour}][/bold]\n"
                f"[dim]Weighted: Syntax 30% | Conversion 25% | Deprecated 20% | "
                f"Security 15% | PHPStan 10%[/dim]",
                border_style=overall_colour,
            )
        )

    # ------------------------------------------------------------------
    # Graph generation -- 6 individual PNGs, academic/IEEE style
    # ------------------------------------------------------------------

    def _generate_graphs(
        self, report: AccuracyReport, reports_dir: Path, timestamp: str
    ) -> list[Path]:
        """Generate 6 grafik PNG individual dan simpan ke reports_dir."""

        # ---- Color palette (print-safe, no gray for data variables) ----
        C_PRIMARY   = "#2166AC"   # blue   -- converted, valid, pre-scan
        C_SECONDARY = "#D6604D"   # red    -- failed, invalid, post-scan
        C_NEUTRAL   = "#CC79A7"   # purple -- skipped
        C_INPUT     = "#E69F00"   # orange -- deprecated input (PHP 7.4)
        C_OUTPUT    = "#009E73"   # teal   -- deprecated output (PHP 8.x)
        C_ERROR     = "#B2182B"   # dark red -- phpstan errors
        C_WARNING   = "#F5A623"   # amber  -- phpstan warnings
        GRID_C      = "#E8E8E8"   # thin grid lines
        TEXT_C      = "#1A1A1A"   # primary text (near-black)
        SPINE_C     = "#AAAAAA"   # axis spine color

        plt.rcParams.update({
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
        })

        def _style_vbar_ax(ax: plt.Axes) -> None:
            ax.grid(axis="y", linewidth=0.5, color=GRID_C, linestyle="-")
            ax.set_axisbelow(True)
            for sp in ["top", "right"]:
                ax.spines[sp].set_visible(False)
            for sp in ["left", "bottom"]:
                ax.spines[sp].set_color(SPINE_C)
                ax.spines[sp].set_linewidth(0.8)

        def _style_hbar_ax(ax: plt.Axes) -> None:
            ax.grid(axis="x", linewidth=0.5, color=GRID_C, linestyle="-")
            ax.set_axisbelow(True)
            for sp in ["top", "right"]:
                ax.spines[sp].set_visible(False)
            for sp in ["left", "bottom"]:
                ax.spines[sp].set_color(SPINE_C)
                ax.spines[sp].set_linewidth(0.8)

        def _footer(fig: plt.Figure) -> None:
            fig.text(
                0.5, 0.01,
                f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  |  "
                f"Pipeline: {Path(report.pipeline_report_path).name}  |  "
                "Skripsi Muhammad Farrel Akbar",
                ha="center", fontsize=8, color="#888888",
            )

        saved: list[Path] = []

        # ----------------------------------------------------------------
        # Chart 1 -- Score Summary (horizontal bar per dimensi)
        # ----------------------------------------------------------------
        p1 = reports_dir / f"accuracy_{timestamp}_1_scorecard.png"
        fig1, ax = plt.subplots(figsize=(8, 4))
        fig1.patch.set_facecolor("white")

        dims  = list(report.scores.keys())
        vals  = list(report.scores.values())
        clrs  = [
            "#27AE60" if v >= 70 else ("#E67E22" if v >= 40 else "#C0392B")
            for v in vals
        ]
        y_pos = np.arange(len(dims))
        bars  = ax.barh(y_pos, vals, color=clrs, alpha=0.87,
                        edgecolor="white", linewidth=0.5)
        ax.set_xlim(0, 115)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(dims, fontsize=10)
        ax.set_xlabel("Score (%)", fontsize=9)
        ax.axvline(70, color="#27AE60", linestyle="--", linewidth=0.9, alpha=0.5,
                   label="70% threshold")
        for bar, v in zip(bars, vals):
            ax.text(
                bar.get_width() + 1.5,
                bar.get_y() + bar.get_height() / 2,
                f"{v:.1f}%", va="center", fontsize=9, color=TEXT_C,
            )
        overall_clr = (
            "#27AE60" if report.overall_score >= 70
            else ("#E67E22" if report.overall_score >= 40 else "#C0392B")
        )
        ax.text(
            0.99, 0.02,
            f"Overall: {report.overall_score:.1f}%",
            ha="right", va="bottom", transform=ax.transAxes,
            fontsize=13, fontweight="bold", color=overall_clr,
        )
        ax.set_title("PHP Migration -- Accuracy Score per Dimension", color=TEXT_C, pad=8)
        _style_hbar_ax(ax)
        _footer(fig1)
        fig1.tight_layout(rect=[0, 0.06, 1, 1])
        fig1.savefig(p1, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig1)
        saved.append(p1)

        # ----------------------------------------------------------------
        # Chart 2 -- Conversion Results (pie)
        # ----------------------------------------------------------------
        p2 = reports_dir / f"accuracy_{timestamp}_2_conversion.png"
        fig2, ax = plt.subplots(figsize=(6, 5))
        fig2.patch.set_facecolor("white")

        conv_vals   = [
            report.conversion_converted,
            report.conversion_skipped,
            report.conversion_failed,
        ]
        conv_labels = [
            f"Converted ({report.conversion_converted})",
            f"Skipped ({report.conversion_skipped})",
            f"Failed ({report.conversion_failed})",
        ]
        conv_colors = [C_PRIMARY, C_NEUTRAL, C_SECONDARY]
        non_zero = [
            (v, l, c) for v, l, c in zip(conv_vals, conv_labels, conv_colors) if v > 0
        ]
        if non_zero:
            vs, ls, cs = zip(*non_zero)
            wedges, _, autotexts = ax.pie(
                vs, labels=None, colors=cs,
                autopct="%1.1f%%", startangle=90,
                pctdistance=0.72,
                wedgeprops={"linewidth": 0.8, "edgecolor": "white"},
            )
            for at in autotexts:
                at.set_fontsize(9)
                at.set_color("white")
            ax.legend(
                wedges, ls,
                loc="lower center", bbox_to_anchor=(0.5, -0.12),
                fontsize=9, frameon=False,
            )
        ax.set_title(
            f"Conversion Results ({report.conversion_total} files)",
            color=TEXT_C, pad=10,
        )
        _footer(fig2)
        fig2.tight_layout(rect=[0, 0.06, 1, 1])
        fig2.savefig(p2, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig2)
        saved.append(p2)

        # ----------------------------------------------------------------
        # Chart 3 -- Security Findings Pre vs Post (grouped bar)
        # ----------------------------------------------------------------
        p3 = reports_dir / f"accuracy_{timestamp}_3_security.png"
        fig3, ax = plt.subplots(figsize=(8, 5))
        fig3.patch.set_facecolor("white")

        all_types = sorted(
            set(list(report.pre_findings.keys()) + list(report.post_findings.keys()))
        )
        if all_types:
            x         = np.arange(len(all_types))
            pre_vals  = [report.pre_findings.get(t, 0)  for t in all_types]
            post_vals = [report.post_findings.get(t, 0) for t in all_types]
            width = 0.35
            ax.bar(x - width / 2, pre_vals, width, label="Pre-conversion",
                   color=C_PRIMARY,   alpha=0.85, edgecolor="white", linewidth=0.5)
            ax.bar(x + width / 2, post_vals, width, label="Post-conversion",
                   color=C_SECONDARY, alpha=0.85, edgecolor="white", linewidth=0.5)
            ax.set_xticks(x)
            ax.set_xticklabels([t.replace(" ", "\n") for t in all_types], fontsize=9)
            ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C)
            ax.set_ylabel("Count", fontsize=9)
            _style_vbar_ax(ax)
        else:
            ax.text(0.5, 0.5, "No findings data",
                    ha="center", va="center", fontsize=11, color=TEXT_C)
            ax.axis("off")
        ax.set_title("Security Findings: Pre vs Post Conversion", color=TEXT_C, pad=8)
        _footer(fig3)
        fig3.tight_layout(rect=[0, 0.06, 1, 1])
        fig3.savefig(p3, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig3)
        saved.append(p3)

        # ----------------------------------------------------------------
        # Chart 4 -- PHP Syntax Validity (pie)
        # ----------------------------------------------------------------
        p4 = reports_dir / f"accuracy_{timestamp}_4_syntax.png"
        fig4, ax = plt.subplots(figsize=(6, 5))
        fig4.patch.set_facecolor("white")

        if report.syntax.skipped == 0:
            syn_vals   = [report.syntax.valid, report.syntax.invalid]
            syn_labels = [
                f"Valid ({report.syntax.valid})",
                f"Invalid ({report.syntax.invalid})",
            ]
            syn_colors = [C_PRIMARY, C_SECONDARY]
            non_zero_syn = [
                (v, l, c) for v, l, c in zip(syn_vals, syn_labels, syn_colors) if v > 0
            ]
            if non_zero_syn:
                vs, ls, cs = zip(*non_zero_syn)
                wedges, _, autotexts = ax.pie(
                    vs, labels=None, colors=cs,
                    autopct="%1.1f%%", startangle=90,
                    pctdistance=0.72,
                    wedgeprops={"linewidth": 0.8, "edgecolor": "white"},
                )
                for at in autotexts:
                    at.set_fontsize(9)
                    at.set_color("white")
                ax.legend(
                    wedges, ls,
                    loc="lower center", bbox_to_anchor=(0.5, -0.12),
                    fontsize=9, frameon=False,
                )
        else:
            ax.text(0.5, 0.5, "php -l skipped\n(php not in PATH)",
                    ha="center", va="center", color=TEXT_C, fontsize=11)
            ax.axis("off")
        ax.set_title("PHP Syntax Validity (php -l)", color=TEXT_C, pad=10)
        _footer(fig4)
        fig4.tight_layout(rect=[0, 0.06, 1, 1])
        fig4.savefig(p4, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig4)
        saved.append(p4)

        # ----------------------------------------------------------------
        # Chart 5 -- Deprecated Pattern Removal (grouped bar)
        # ----------------------------------------------------------------
        p5 = reports_dir / f"accuracy_{timestamp}_5_deprecated.png"
        fig5, ax = plt.subplots(figsize=(9, 5))
        fig5.patch.set_facecolor("white")

        dep_keys = [
            k for k in _DEPRECATED_PATTERNS
            if report.deprecated_input.counts.get(k, 0) > 0
            or report.deprecated_output.counts.get(k, 0) > 0
        ]
        if dep_keys:
            x        = np.arange(len(dep_keys))
            in_vals  = [report.deprecated_input.counts.get(k, 0)  for k in dep_keys]
            out_vals = [report.deprecated_output.counts.get(k, 0) for k in dep_keys]
            width = 0.35
            bars_in = ax.bar(
                x - width / 2, in_vals, width,
                label="Input (PHP 7.4)",
                color=C_INPUT, alpha=0.85, edgecolor="white", linewidth=0.5,
            )
            bars_out = ax.bar(
                x + width / 2, out_vals, width,
                label="Output (PHP 8.x)",
                color=C_OUTPUT, alpha=0.85, edgecolor="white", linewidth=0.5,
            )
            ax.set_xticks(x)
            ax.set_xticklabels(dep_keys, rotation=30, ha="right", fontsize=9)
            ax.legend(fontsize=9, frameon=True, framealpha=0.9, edgecolor=GRID_C)
            ax.set_ylabel("Occurrences", fontsize=9)
            _style_vbar_ax(ax)
            for bar in bars_in:
                h = bar.get_height()
                if h > 0:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2, h + 0.1,
                        str(int(h)), ha="center", va="bottom",
                        fontsize=7.5, color=TEXT_C,
                    )
            for bar in bars_out:
                h = bar.get_height()
                if h > 0:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2, h + 0.1,
                        str(int(h)), ha="center", va="bottom",
                        fontsize=7.5, color=TEXT_C,
                    )
        else:
            ax.text(
                0.5, 0.5,
                "No deprecated patterns found\nin input or output",
                ha="center", va="center", color=TEXT_C, fontsize=11,
            )
            ax.axis("off")
        ax.set_title(
            f"Deprecated Pattern Removal  "
            f"(input: {report.deprecated_input.total} -> "
            f"output: {report.deprecated_output.total})",
            color=TEXT_C, pad=8,
        )
        _footer(fig5)
        fig5.tight_layout(rect=[0, 0.06, 1, 1])
        fig5.savefig(p5, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig5)
        saved.append(p5)

        # ----------------------------------------------------------------
        # Chart 6 -- PHPStan Error Distribution (bar)
        # ----------------------------------------------------------------
        p6 = reports_dir / f"accuracy_{timestamp}_6_phpstan.png"
        fig6, ax = plt.subplots(figsize=(7, 5))
        fig6.patch.set_facecolor("white")

        if report.phpstan_files > 0:
            php_labels = ["ERROR", "WARNING"]
            php_vals   = [report.phpstan_errors, report.phpstan_warnings]
            php_colors = [C_ERROR, C_WARNING]
            non_zero_php = [
                (v, l, c) for v, l, c in zip(php_vals, php_labels, php_colors) if v > 0
            ]
            if non_zero_php:
                vs, ls, cs = zip(*non_zero_php)
                x_pos = np.arange(len(ls))
                bars = ax.bar(
                    x_pos, vs, color=list(cs), alpha=0.85, width=0.4,
                    edgecolor="white", linewidth=0.5,
                )
                ax.set_xticks(x_pos)
                ax.set_xticklabels(list(ls), fontsize=11)
                for bar, v in zip(bars, vs):
                    h = bar.get_height()
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        h + max(vs) * 0.01,
                        f"{int(h):,}",
                        ha="center", va="bottom",
                        fontsize=10, color=TEXT_C, fontweight="bold",
                    )
                ax.set_ylabel("Count", fontsize=9)
                _style_vbar_ax(ax)
                total_php = report.phpstan_errors + report.phpstan_warnings
                ax.text(
                    0.98, 0.97,
                    f"Total: {total_php:,}\n{report.phpstan_files} files analysed",
                    ha="right", va="top", transform=ax.transAxes,
                    fontsize=9, color=TEXT_C,
                )
        else:
            ax.text(0.5, 0.5, "PHPStan not run\n(0 files analysed)",
                    ha="center", va="center", color=TEXT_C, fontsize=11)
            ax.axis("off")
        ax.set_title("PHPStan Static Analysis (Level 5)", color=TEXT_C, pad=8)
        _footer(fig6)
        fig6.tight_layout(rect=[0, 0.06, 1, 1])
        fig6.savefig(p6, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close(fig6)
        saved.append(p6)

        plt.rcdefaults()

        console.print(f"\n[bold green]6 grafik individual disimpan di {reports_dir}:[/bold green]")
        for p in saved:
            console.print(f"  [green]->[/green] {p.name}")

        return saved


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python pipeline/accuracy_checker.py",
        description="Cek keakuratan hasil migrasi PHP dan generate grafik.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input",   dest="input_dir",   type=Path, default=Path("input"))
    parser.add_argument("--output",  dest="output_dir",  type=Path, default=Path("output"))
    parser.add_argument("--reports", dest="reports_dir", type=Path, default=Path("reports"))
    parser.add_argument(
        "--report-file", dest="report_file", type=Path, default=None,
        help="Path ke pipeline_result JSON tertentu (default: otomatis cari yang terbaru)",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point CLI."""
    args = _parse_args()
    checker = AccuracyChecker()
    checker.run(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        reports_dir=args.reports_dir,
        pipeline_report_path=args.report_file,
    )


if __name__ == "__main__":
    main()
