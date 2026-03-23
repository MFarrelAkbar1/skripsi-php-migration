"""
iso_mapper.py -- Modul pemetaan temuan ke kontrol ISO/IEC 27001:2022.

Mengagregasi temuan dari Semgrep (scanner), PHPStan (analyzer), dan
rekomendasi AI (ai_engine) ke enam kontrol ISO/IEC 27001:2022 Annex A
yang relevan, menentukan status kepatuhan per-kontrol, dan mengekspor
laporan terstruktur sebagai JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Sibling-module imports  (handle both run-from-root and run-from-pipeline/)
# ---------------------------------------------------------------------------

try:
    from pipeline.scanner import ScanResult
    from pipeline.analyzer import AnalysisResult
    from pipeline.ai_engine import AIRecommendation
except ModuleNotFoundError:
    from scanner import ScanResult       # type: ignore[no-redef]
    from analyzer import AnalysisResult  # type: ignore[no-redef]
    from ai_engine import AIRecommendation  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A control registry
# ---------------------------------------------------------------------------
# Ordered dict preserves display order (insertion order in Python 3.7+).

_CONTROL_REGISTRY: dict[str, tuple[str, str]] = {
    "A.5.17": (
        "Authentication Information",
        "Secure management of authentication information including passwords, "
        "tokens, and cryptographic keys.  Prohibits hardcoded credentials and "
        "requires secure storage mechanisms.",
    ),
    "A.8.24": (
        "Use of Cryptography",
        "Rules governing the selection and use of cryptographic controls.  "
        "Prohibits weak algorithms (MD5, SHA-1 for passwords) and requires "
        "appropriate key lengths and modern, vetted cipher suites.",
    ),
    "A.8.25": (
        "Secure Development Lifecycle",
        "Security integrated throughout the software development lifecycle.  "
        "Includes maintaining up-to-date language versions, removal of "
        "deprecated APIs, and maintaining secure-by-default configurations.",
    ),
    "A.8.26": (
        "Application Security Requirements",
        "Identification and specification of information security requirements "
        "for application development and procurement.  Covers protection "
        "against OWASP Top 10 vulnerabilities (SQL Injection, XSS, etc.).",
    ),
    "A.8.28": (
        "Secure Coding",
        "Application of secure coding principles across the development process.  "
        "Covers input validation, output encoding, parameterised queries, type "
        "safety, and elimination of insecure constructs.",
    ),
    "A.8.29": (
        "Security Testing in Development",
        "Security testing activities during development and pre-deployment, "
        "including static analysis, code review, and path-traversal checks.  "
        "Validates that security requirements are met before release.",
    ),
}

# Maximum evidence items stored per control to keep JSON files manageable
_MAX_EVIDENCE: int = 30

console = Console()


# ---------------------------------------------------------------------------
# Enums and data classes
# ---------------------------------------------------------------------------


class ControlStatus(Enum):
    """Compliance status for a single ISO 27001:2022 control."""

    COMPLIANT = "COMPLIANT"           # no findings mapped to this control
    PARTIAL = "PARTIAL"               # only WARNING-severity findings
    NON_COMPLIANT = "NON_COMPLIANT"   # at least one ERROR-severity finding

    # Severity ordering: NON_COMPLIANT > PARTIAL > COMPLIANT
    def __lt__(self, other: ControlStatus) -> bool:  # type: ignore[override]
        order = {
            ControlStatus.COMPLIANT: 0,
            ControlStatus.PARTIAL: 1,
            ControlStatus.NON_COMPLIANT: 2,
        }
        return order[self] < order[other]


@dataclass
class ISOControl:
    """
    Compliance posture for a single ISO/IEC 27001:2022 Annex A control.
    """

    control_id: str           # e.g. "A.8.28"
    title: str                # e.g. "Secure Coding"
    description: str          # brief description of the control
    status: ControlStatus     # COMPLIANT | PARTIAL | NON_COMPLIANT
    findings_count: int       # number of scan/analysis findings mapped here
    evidence: list[str]       # human-readable evidence strings (capped at 30)


@dataclass
class ISOReport:
    """
    Full ISO/IEC 27001:2022 compliance report produced by ISOMapper.

    Fields
    ------
    controls:          per-control assessment, keyed by control ID
    overall_status:    worst status among all assessed controls
    total_findings:    sum of Semgrep + PHPStan findings (unique, not per-control)
    critical_findings: subset of total_findings with ERROR severity
    generated_at:      timestamp of report creation
    """

    controls: dict[str, ISOControl]
    overall_status: ControlStatus
    total_findings: int
    critical_findings: int
    generated_at: datetime


# ---------------------------------------------------------------------------
# Main mapper class
# ---------------------------------------------------------------------------


class ISOMapper:
    """
    Aggregates findings from all pipeline stages and produces an
    ``ISOReport`` showing compliance posture per ISO 27001:2022 control.

    Status logic
    ------------
    NON_COMPLIANT -- at least one ERROR-severity finding maps to this control
    PARTIAL       -- only WARNING-severity findings mapped (no ERROR)
    COMPLIANT     -- no findings mapped to this control

    AI recommendations (``AIRecommendation``) are recorded as "fix available"
    evidence strings but do NOT affect status determination -- they represent
    remediation actions, not new violations.

    Usage
    -----
    mapper = ISOMapper()
    report = mapper.generate_report(scan_result, analysis_result, ai_recs)
    mapper.export_json(report, Path("reports/iso_report.json"))
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        scan_result: ScanResult | None,
        analysis_result: AnalysisResult | None,
        ai_recommendations: list[AIRecommendation] | None,
    ) -> ISOReport:
        """
        Build an ``ISOReport`` from the three pipeline result objects.

        Any argument may be ``None`` (e.g. if a pipeline step was skipped);
        the mapper handles missing data gracefully.

        Parameters
        ----------
        scan_result:
            Output of ``scanner.run_scan()``.
        analysis_result:
            Output of ``analyzer.run_analysis()``.
        ai_recommendations:
            Output of ``ai_engine.run_ai_analysis()``.

        Returns
        -------
        ISOReport
            Fully populated compliance report -- also printed to the terminal.
        """
        ai_recs: list[AIRecommendation] = ai_recommendations or []

        # 1. Collect (severity, evidence_str) pairs per control from scan + phpstan
        findings_map = self._collect_findings(scan_result, analysis_result)

        # 2. Collect AI "fix available" evidence strings per control (INFO only)
        ai_evidence_map = self._collect_ai_evidence(ai_recs)

        # 3. Build per-control ISOControl objects
        controls: dict[str, ISOControl] = {}
        for ctrl_id, (title, description) in _CONTROL_REGISTRY.items():
            entries = findings_map.get(ctrl_id, [])
            ai_evs = ai_evidence_map.get(ctrl_id, [])

            status = self._determine_status(entries)
            findings_count = sum(
                1 for sev, _ in entries if sev in ("ERROR", "WARNING")
            )

            # Merge evidence: ERROR first, then WARNING, then AI fixes
            error_ev = [ev for sev, ev in entries if sev == "ERROR"]
            warn_ev = [ev for sev, ev in entries if sev == "WARNING"]
            evidence = (error_ev + warn_ev + ai_evs)[:_MAX_EVIDENCE]

            controls[ctrl_id] = ISOControl(
                control_id=ctrl_id,
                title=title,
                description=description,
                status=status,
                findings_count=findings_count,
                evidence=evidence,
            )

        # 4. Overall status: worst among all controls
        all_statuses = [ctrl.status for ctrl in controls.values()]
        overall_status = max(all_statuses)  # uses __lt__ defined above

        # 5. Totals from source summaries (avoid double-counting per-control)
        total_findings, critical_findings = self._compute_totals(
            scan_result, analysis_result
        )

        report = ISOReport(
            controls=controls,
            overall_status=overall_status,
            total_findings=total_findings,
            critical_findings=critical_findings,
            generated_at=datetime.now(),
        )

        self._print_report(report)
        return report

    def export_json(self, report: ISOReport, output_path: Path) -> None:
        """
        Serialise *report* to a JSON file at *output_path*.

        The parent directory is created if it does not exist.
        Enums are written as their string values; ``datetime`` as ISO 8601.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._report_to_dict(report)
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[dim]ISO report saved -> {output_path}[/dim]")

    # ------------------------------------------------------------------
    # Finding collection
    # ------------------------------------------------------------------

    def _collect_findings(
        self,
        scan_result: ScanResult | None,
        analysis_result: AnalysisResult | None,
    ) -> dict[str, list[tuple[str, str]]]:
        """
        Build a mapping of control_id -> [(severity, evidence_str)] by
        iterating over Semgrep findings and PHPStan errors.

        Only controls in ``_CONTROL_REGISTRY`` are populated; controls
        referenced by a finding but absent from the registry are silently
        skipped.
        """
        data: dict[str, list[tuple[str, str]]] = {
            ctrl: [] for ctrl in _CONTROL_REGISTRY
        }

        # ---- Semgrep findings ----
        if scan_result:
            for finding in scan_result.findings:
                sev = finding.severity.upper()
                # Normalise to ERROR or WARNING; treat INFO as WARNING
                if sev not in ("ERROR", "WARNING"):
                    sev = "WARNING"
                filename = Path(finding.file_path).name
                evidence = (
                    f"[Semgrep][{finding.vuln_type}] "
                    f"{filename}:{finding.line_start} -- "
                    f"{finding.message[:80]}"
                )
                for ctrl in finding.iso_controls:
                    if ctrl in data:
                        data[ctrl].append((sev, evidence))

        # ---- PHPStan errors ----
        if analysis_result:
            for error in analysis_result.errors:
                # Skip top-level config errors (no file association)
                if error.file_path == "<phpstan>":
                    continue
                sev = error.severity.upper()
                if sev not in ("ERROR", "WARNING"):
                    sev = "ERROR"
                filename = Path(error.file_path).name
                evidence = (
                    f"[PHPStan] "
                    f"{filename}:{error.line} -- "
                    f"{error.message[:80]}"
                )
                for ctrl in error.iso_controls:
                    if ctrl in data:
                        data[ctrl].append((sev, evidence))

        return data

    def _collect_ai_evidence(
        self,
        ai_recs: list[AIRecommendation],
    ) -> dict[str, list[str]]:
        """
        Build a mapping of control_id -> [evidence_str] for AI fix suggestions.

        AI recommendations represent attempted remediation, not new violations.
        They are stored here for evidence / auditability but never affect
        status determination.
        """
        data: dict[str, list[str]] = {ctrl: [] for ctrl in _CONTROL_REGISTRY}

        for rec in ai_recs:
            filename = Path(rec.file_path).name
            evidence = (
                f"[AI/{rec.model_used}][{rec.vuln_type}] "
                f"{filename}:{rec.line_start} -- "
                f"fix suggested (confidence: {rec.confidence:.0%})"
            )
            for ctrl in rec.iso_controls:
                if ctrl in data:
                    data[ctrl].append(evidence)

        return data

    # ------------------------------------------------------------------
    # Status determination
    # ------------------------------------------------------------------

    def _determine_status(
        self, entries: list[tuple[str, str]]
    ) -> ControlStatus:
        """
        Map a severity set to a ``ControlStatus``.

        NON_COMPLIANT -- any ERROR present
        PARTIAL       -- only WARNINGs (no ERROR)
        COMPLIANT     -- empty list or all INFO
        """
        severities = {sev for sev, _ in entries}
        if "ERROR" in severities:
            return ControlStatus.NON_COMPLIANT
        if "WARNING" in severities:
            return ControlStatus.PARTIAL
        return ControlStatus.COMPLIANT

    # ------------------------------------------------------------------
    # Total finding counts
    # ------------------------------------------------------------------

    def _compute_totals(
        self,
        scan_result: ScanResult | None,
        analysis_result: AnalysisResult | None,
    ) -> tuple[int, int]:
        """
        Return ``(total_findings, critical_findings)`` as a simple sum of
        Semgrep and PHPStan counts -- no per-control double-counting.
        """
        total = 0
        critical = 0

        if scan_result:
            total += scan_result.summary.total_findings
            critical += scan_result.summary.by_severity.get("ERROR", 0)

        if analysis_result:
            total += analysis_result.summary.total_errors
            critical += analysis_result.summary.by_severity.get("ERROR", 0)

        return total, critical

    # ------------------------------------------------------------------
    # JSON serialisation
    # ------------------------------------------------------------------

    def _report_to_dict(self, report: ISOReport) -> dict:
        """Convert an ``ISOReport`` to a plain JSON-serialisable dict."""
        return {
            "generated_at": report.generated_at.isoformat(),
            "overall_status": report.overall_status.value,
            "total_findings": report.total_findings,
            "critical_findings": report.critical_findings,
            "controls": {
                ctrl_id: {
                    "control_id": ctrl.control_id,
                    "title": ctrl.title,
                    "description": ctrl.description,
                    "status": ctrl.status.value,
                    "findings_count": ctrl.findings_count,
                    "evidence": ctrl.evidence,
                }
                for ctrl_id, ctrl in report.controls.items()
            },
        }

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_report(self, report: ISOReport) -> None:
        """Render the ISO compliance table to the terminal."""

        tbl = Table(
            title="ISO/IEC 27001:2022 -- Annex A Control Mapping",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        tbl.add_column("Control", justify="center", width=9, style="bold")
        tbl.add_column("Title", width=28)
        tbl.add_column("Status", justify="center", width=16)
        tbl.add_column("Findings", justify="right", width=9)
        tbl.add_column("Top Evidence", no_wrap=False)

        _status_style: dict[ControlStatus, tuple[str, str]] = {
            ControlStatus.COMPLIANT:     ("green",  "COMPLIANT"),
            ControlStatus.PARTIAL:       ("yellow", "PARTIAL"),
            ControlStatus.NON_COMPLIANT: ("red",    "NON-COMPLIANT"),
        }

        for ctrl_id in _CONTROL_REGISTRY:          # preserve intended display order
            if ctrl_id not in report.controls:
                continue
            ctrl = report.controls[ctrl_id]
            style, label = _status_style[ctrl.status]
            # Show the first evidence item as a preview
            preview = (
                ctrl.evidence[0][:65] + "…"
                if ctrl.evidence and len(ctrl.evidence[0]) > 65
                else ctrl.evidence[0] if ctrl.evidence
                else "[dim]-[/dim]"
            )
            count_display = str(ctrl.findings_count) if ctrl.findings_count else "[dim]-[/dim]"

            tbl.add_row(
                ctrl_id,
                ctrl.title,
                f"[{style}]{label}[/{style}]",
                count_display,
                f"[dim]{preview}[/dim]",
            )

        console.print(tbl)

        # ---- Overall status panel ----
        overall_style, overall_label = _status_style[report.overall_status]
        console.print(
            Panel(
                f"[bold]Overall status  :[/bold]  "
                f"[{overall_style}][bold]{overall_label}[/bold][/{overall_style}]\n"
                f"[bold]Total findings  :[/bold]  {report.total_findings}\n"
                f"[bold]Critical (ERROR):[/bold]  [red]{report.critical_findings}[/red]\n"
                f"[bold]Generated at    :[/bold]  "
                f"{report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
                title="[bold]ISO/IEC 27001:2022 Compliance Summary[/bold]",
                border_style=overall_style,
            )
        )


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_iso_mapping(
    scan_result: ScanResult | None,
    analysis_result: AnalysisResult | None,
    ai_recommendations: list[AIRecommendation] | None,
    output_path: Path,
) -> ISOReport:
    """
    Aggregate all pipeline findings, assess ISO 27001:2022 compliance,
    and export a JSON report.

    This is the primary entry point for ``main.py`` -- call it as the
    final step after scan -> convert -> analyse -> AI analysis.

    Parameters
    ----------
    scan_result:
        Output of ``scanner.run_scan()``, or ``None`` if step was skipped.
    analysis_result:
        Output of ``analyzer.run_analysis()``, or ``None`` if skipped.
    ai_recommendations:
        Output of ``ai_engine.run_ai_analysis()``, or ``None`` / ``[]``.
    output_path:
        Destination path for the JSON report
        (e.g. ``Path("reports/iso_report.json")``).
        Parent directories are created automatically.

    Returns
    -------
    ISOReport
        Compliance report with per-control status and evidence.
        Also written as JSON to *output_path*.
    """
    mapper = ISOMapper()
    report = mapper.generate_report(scan_result, analysis_result, ai_recommendations)
    mapper.export_json(report, output_path)
    return report
