"""
ai_engine.py -- Modul AI berbasis DeepSeek Coder 6.7B via Ollama (lokal/offline).

Menggunakan prompt engineering (bukan fine-tuning) untuk menganalisis temuan
keamanan PHP yang TIDAK bisa diperbaiki otomatis oleh Rector, lalu memberikan
saran perbaikan terstruktur.  Semua inferensi berjalan lokal via Ollama --
tidak ada kode yang dikirim ke API eksternal.

ISO/IEC 27001:2022 relevance:
  A.8.28 -- Secure Coding  (rekomendasi perbaikan)
  A.8.29 -- Security Testing in Development (validasi temuan AI)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import requests

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

# Lazy import: ScanFinding lives in scanner.py -- handle both execution contexts
# (run from project root as `python pipeline/main.py` or from pipeline/ directly).
try:
    from pipeline.scanner import ScanFinding
except ModuleNotFoundError:
    from scanner import ScanFinding  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL: str = "http://localhost:11434"
OLLAMA_MODEL: str = "deepseek-coder:6.7b"

# Maximum characters of PHP code sent per request (context-window budget)
MAX_CODE_CHARS: int = 2000

# Only process ScanFindings with priority <= this value.
# Priorities 1-3 = SQL Injection, XSS, Deprecated Function.
PRIORITY_THRESHOLD: int = 3

# Ollama generation parameters
_OLLAMA_OPTIONS: dict = {
    "temperature": 0.1,   # low = deterministic security advice
    "num_ctx": 4096,      # context window (prompt + response)
    "num_predict": 1024,  # max output tokens
    "stop": ["```\n\n", "---"],  # stop at end of last code block
}

# Mapping priority -> human label (for display)
_PRIORITY_LABELS: dict[int, str] = {
    1: "SQL Injection",
    2: "XSS",
    3: "Deprecated Function",
}

# Lines-per-snippet threshold: <= this -> use FIM prompt, else regular prompt
_FIM_LINE_THRESHOLD: int = 3

# Returned by _extract_confidence() when no parseable value is found.
# 0.0 is used instead of an arbitrary mid-range value so that downstream
# colour-coding and report thresholds see "no data" rather than fake data.
_CONFIDENCE_FALLBACK: float = 0.0

console = Console()


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class AIRecommendation:
    """
    AI-generated security fix recommendation for a single ScanFinding.

    Produced by ``PHPAIEngine.analyze_snippet()`` or as part of the batch
    result from ``PHPAIEngine.analyze_findings()``.
    """

    original_code: str       # vulnerable code snippet (as-found by Semgrep)
    suggested_fix: str       # AI-generated replacement code
    explanation: str         # AI's description of the vulnerability & fix
    confidence: float        # AI self-rated confidence: 0.0 (none) - 1.0 (certain)
    iso_controls: list[str]  # ISO 27001:2022 controls from the parent ScanFinding
    vuln_type: str           # e.g. "SQL Injection"
    file_path: str           # source file that contains the finding
    line_start: int          # line number in source file
    model_used: str          # Ollama model identifier
    fim_used: bool = False   # True when FIM-style prompt was used


# ---------------------------------------------------------------------------
# Main AI engine class
# ---------------------------------------------------------------------------


class PHPAIEngine:
    """
    Sends PHP code snippets to DeepSeek Coder 6.7B (via local Ollama) and returns
    structured security fix recommendations.

    Design constraints (per CLAUDE.md):
    - Prompt engineering only -- no fine-tuning
    - All inference local -- no external API calls
    - Max 2 000 chars of code per request
    - FIM tokens for partial-patch prompts (<= 3 source lines)
    - Plain-text output format: prose explanation + ```php block + CONFIDENCE: N

    Usage
    -----
    engine = PHPAIEngine()
    result = engine.analyze_snippet(code, vuln_type="SQL Injection",
                                    context="login form -- db query")
    results = engine.analyze_findings(scan_result.findings)
    """

    def __init__(
        self,
        model: str = OLLAMA_MODEL,
        ollama_base_url: str = OLLAMA_BASE_URL,
        timeout_sec: int = 120,
    ) -> None:
        self._model = model
        self._base_url = ollama_base_url.rstrip("/")
        self._timeout = timeout_sec
        self._generate_url = f"{self._base_url}/api/generate"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_snippet(
        self,
        code: str,
        vuln_type: str,
        context: str = "",
        iso_controls: list[str] | None = None,
        file_path: str = "<unknown>",
        line_start: int = 0,
    ) -> AIRecommendation:
        """
        Ask the AI model to explain and fix a single vulnerable PHP snippet.

        Parameters
        ----------
        code:
            PHP source code containing the vulnerability.  Truncated to
            ``MAX_CODE_CHARS`` (2 000) before sending to the model.
        vuln_type:
            Human-readable vulnerability category, e.g. ``"SQL Injection"``.
        context:
            Free-form description of where/how the code is used -- helps the
            model produce more accurate suggestions.
        iso_controls:
            ISO 27001:2022 control IDs from the parent finding.  Included in
            the prompt so the model can tailor advice to the control.
        file_path:
            Source file path -- stored in the returned dataclass for traceability.
        line_start:
            Line number -- stored in the returned dataclass for traceability.

        Returns
        -------
        AIRecommendation
            Populated recommendation, or a placeholder with ``confidence=0.0``
            if the model was unreachable or produced no parseable output.
        """
        controls = iso_controls or ["A.8.28"]
        truncated = code[:MAX_CODE_CHARS]

        use_fim = self._should_use_fim(truncated)
        prompt = (
            self._build_fim_prompt(truncated, vuln_type, context, controls)
            if use_fim
            else self._build_prompt(truncated, vuln_type, context, controls)
        )

        raw_text = self._call_ollama(prompt)
        return self._parse_response(
            raw_text=raw_text,
            original_code=truncated,
            iso_controls=controls,
            vuln_type=vuln_type,
            file_path=file_path,
            line_start=line_start,
            fim_used=use_fim,
        )

    def analyze_findings(
        self,
        findings: list[ScanFinding],
    ) -> list[AIRecommendation]:
        """
        Batch-process a list of Semgrep findings through the AI engine.

        Findings with ``priority > PRIORITY_THRESHOLD`` (> 3) are skipped to
        conserve compute -- only SQL Injection (1), XSS (2), and Deprecated
        Functions (3) are processed.

        Parameters
        ----------
        findings:
            List of ``ScanFinding`` objects from ``scanner.run_scan()``.

        Returns
        -------
        list[AIRecommendation]
            One entry per processed finding, in the same order as the filtered
            input.  Returns an empty list if Ollama is unreachable.
        """
        eligible = [f for f in findings if f.priority <= PRIORITY_THRESHOLD]
        skipped_count = len(findings) - len(eligible)

        if not eligible:
            console.print(
                "[dim]AI Engine: no high-priority findings to process "
                f"(all {len(findings)} finding(s) have priority > {PRIORITY_THRESHOLD}).[/dim]"
            )
            return []

        if skipped_count:
            console.print(
                f"[dim]AI Engine: skipping {skipped_count} lower-priority "
                f"finding(s) (priority > {PRIORITY_THRESHOLD}).[/dim]"
            )

        # Quick Ollama connectivity check before starting the batch
        if not self._check_ollama_alive():
            console.print(
                Panel(
                    "[bold yellow]WARNING:[/bold yellow] Ollama is not reachable at "
                    f"[cyan]{self._base_url}[/cyan].\n"
                    "AI-assisted recommendations are skipped.\n"
                    "Start Ollama with: [green]ollama serve[/green]",
                    title="[yellow]AI Engine -- Offline[/yellow]",
                    border_style="yellow",
                )
            )
            return []

        recommendations: list[AIRecommendation] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]AI analysis ({self._model})…", total=len(eligible)
            )

            for finding in eligible:
                label = _PRIORITY_LABELS.get(finding.priority, finding.vuln_type)
                progress.update(
                    task,
                    description=f"[cyan]AI: {label} in {Path(finding.file_path).name}…",
                )

                context_str = (
                    f"File: {finding.file_path}, "
                    f"line {finding.line_start}. "
                    f"Semgrep rule: {finding.rule_id}. "
                    f"Finding: {finding.message}"
                )

                rec = self.analyze_snippet(
                    code=finding.code_snippet,
                    vuln_type=finding.vuln_type,
                    context=context_str,
                    iso_controls=finding.iso_controls,
                    file_path=finding.file_path,
                    line_start=finding.line_start,
                )
                recommendations.append(rec)
                progress.advance(task)

        self._print_batch_summary(recommendations)
        return recommendations

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _should_use_fim(self, code: str) -> bool:
        """Return True when the code snippet is short enough to warrant FIM."""
        non_empty_lines = [ln for ln in code.splitlines() if ln.strip()]
        return len(non_empty_lines) <= _FIM_LINE_THRESHOLD

    def _build_prompt(
        self,
        code: str,
        vuln_type: str,
        context: str,
        iso_controls: list[str],
    ) -> str:
        """
        Build an instruct prompt for a multi-line code snippet.

        Format:
        - Starts with PHP security expert persona
        - Includes vuln_type and ISO control context
        - Asks for prose explanation + ```php fix block
        - Last line must be: CONFIDENCE: <0-100>
        - Output language: English
        """
        controls_str = ", ".join(iso_controls)
        context_block = f"Context: {context}\n" if context else ""

        return (
            "You are a PHP security expert and migration specialist.\n\n"
            f"TASK: Analyze the following PHP code for a [{vuln_type}] vulnerability "
            f"and provide a secure PHP 8.x replacement.\n"
            f"ISO/IEC 27001:2022 Controls: {controls_str}\n"
            f"{context_block}"
            "\nVULNERABLE CODE:\n"
            "```php\n"
            f"{code}\n"
            "```\n\n"
            "Respond in English:\n"
            "1. Explain the vulnerability and its security risk.\n"
            "2. Provide the corrected PHP 8.x code in a ```php code block.\n\n"
            "After your explanation and code fix, write exactly this on the last line:\n"
            "CONFIDENCE: [number between 0 and 100]\n\n"
            "Example last line: CONFIDENCE: 85\n"
        )

    def _build_fim_prompt(
        self,
        code: str,
        vuln_type: str,
        context: str,
        iso_controls: list[str],
    ) -> str:
        """
        Build a FIM-style prompt for short / partial code snippets.

        Uses ``<FIM_PREFIX>``, ``<FIM_SUFFIX>``, ``<FIM_MIDDLE>`` tokens to
        suggest a partial patch.  The vulnerable line(s) are placed in the
        PREFIX; the model generates the secure replacement in MIDDLE.
        The MIDDLE is seeded with a comment so the model continues with
        explanation, fix, and a trailing CONFIDENCE: <n> line.
        """
        controls_str = ", ".join(iso_controls)
        context_note = f"// Context: {context}\n" if context else ""

        return (
            "<FIM_PREFIX>\n"
            "<?php\n"
            "// You are a PHP security expert and migration specialist.\n"
            f"// TASK: Replace the [{vuln_type}] vulnerability with secure PHP 8.x code.\n"
            f"// ISO/IEC 27001:2022 Controls: {controls_str}\n"
            f"{context_note}"
            "// Respond:\n"
            "// 1. Explain the vulnerability and its security risk.\n"
            "// 2. Provide the fixed PHP 8.x code.\n"
            "// After explanation and code, write on the last line:\n"
            "// CONFIDENCE: [number between 0 and 100]\n"
            "// Example: CONFIDENCE: 85\n"
            "// --- VULNERABLE CODE ---\n"
            f"{code}\n"
            "<FIM_SUFFIX>\n"
            "// end\n"
            "<FIM_MIDDLE>\n"
            "// 1. Explanation:"
        )

    # ------------------------------------------------------------------
    # Ollama HTTP calls
    # ------------------------------------------------------------------

    def _check_ollama_alive(self) -> bool:
        """Return True if Ollama's health endpoint responds within 3 seconds."""
        try:
            resp = requests.get(
                f"{self._base_url}/api/tags", timeout=3
            )
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _call_ollama(self, prompt: str) -> str:
        """
        POST *prompt* to Ollama's ``/api/generate`` endpoint.

        Returns the model's raw text response, or an empty string on any
        error (connection refused, timeout, non-200 status, JSON parse
        failure).  Never raises -- callers rely on an empty string as a
        sentinel for failure.
        """
        payload: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": _OLLAMA_OPTIONS,
        }

        try:
            resp = requests.post(
                self._generate_url,
                json=payload,
                timeout=self._timeout,
            )
        except requests.exceptions.ConnectionError:
            console.print(
                f"[yellow]AI Engine:[/yellow] Ollama not reachable at {self._base_url}"
            )
            return ""
        except requests.exceptions.Timeout:
            console.print(
                f"[yellow]AI Engine:[/yellow] Ollama timed out after {self._timeout}s"
            )
            return ""
        except requests.exceptions.RequestException as exc:
            console.print(f"[yellow]AI Engine:[/yellow] HTTP error: {exc}")
            return ""

        if resp.status_code != 200:
            console.print(
                f"[yellow]AI Engine:[/yellow] Ollama returned HTTP {resp.status_code}: "
                f"{resp.text[:200]}"
            )
            return ""

        try:
            data = resp.json()
        except ValueError:
            console.print(
                "[yellow]AI Engine:[/yellow] Could not parse Ollama JSON response"
            )
            return ""

        return data.get("response", "")

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        raw_text: str,
        original_code: str,
        iso_controls: list[str],
        vuln_type: str,
        file_path: str,
        line_start: int,
        fim_used: bool,
    ) -> AIRecommendation:
        """
        Convert the model's raw text into an ``AIRecommendation``.

        Parsing strategy (most specific -> least specific):
        1. XML tags  (``<explanation>``, ``<fix>``, ``<confidence>``) — legacy format
        2. Numbered sections (``1. EXPLANATION``, ``2. FIXED CODE``) — current format fallback
        3. PHP code fences (` ```php … ``` `) — code extraction fallback
        4. Natural-language confidence expressions — confidence fallback
        """
        if not raw_text.strip():
            return self._placeholder(
                original_code, iso_controls, vuln_type, file_path, line_start, fim_used,
                reason="No response from model",
            )

        # 1. Try XML-tag format (new prompt structure)
        explanation = self._extract_xml_tag(raw_text, "explanation")
        fix_xml = self._extract_xml_tag(raw_text, "fix")
        # Code block may be inside the <fix> tag or at the top level
        suggested_fix = (
            self._extract_code_block(fix_xml) or fix_xml
            if fix_xml
            else self._extract_code_block(raw_text)
        )
        confidence = self._extract_confidence(raw_text)

        # 2. Legacy fallback: numbered sections
        if not explanation:
            explanation = self._extract_section(raw_text, section_num=1, label="EXPLANATION")
        if not suggested_fix:
            suggested_fix = self._extract_section(raw_text, section_num=2, label="FIXED CODE")

        # 3. Strip FIM comment prefix that can bleed into the fix text
        if fim_used and suggested_fix.startswith("// 1. EXPLANATION:"):
            suggested_fix = ""

        # 4. Final explanation fallback: whole response minus code fences
        if not explanation:
            explanation = re.sub(r"```[\s\S]*?```", "", raw_text).strip()[:800]

        return AIRecommendation(
            original_code=original_code,
            suggested_fix=suggested_fix or "// Manual review required -- model produced no code.",
            explanation=explanation or raw_text[:500],
            confidence=confidence,
            iso_controls=list(iso_controls),
            vuln_type=vuln_type,
            file_path=file_path,
            line_start=line_start,
            model_used=self._model,
            fim_used=fim_used,
        )

    def _extract_xml_tag(self, text: str, tag: str) -> str:
        """
        Extract content from ``<tag>...</tag>`` in the model response.

        Also handles FIM-style responses where the model prefixes each line
        with ``//``, e.g. ``// <explanation>...</explanation>``.

        Returns an empty string when the tag is absent.
        """
        # Direct XML form: <tag>content</tag>
        match = re.search(rf"<{tag}>([\s\S]*?)</{tag}>", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # FIM comment form: // <tag>content</tag>
        # Strip leading "// " from each line before returning.
        match = re.search(
            rf"//\s*<{tag}>([\s\S]*?)//\s*</{tag}>", text, re.IGNORECASE
        )
        if match:
            lines = match.group(1).splitlines()
            cleaned = "\n".join(ln.lstrip("/ ").rstrip() for ln in lines)
            return cleaned.strip()

        return ""

    def _extract_section(self, text: str, section_num: int, label: str) -> str:
        """
        Extract the body of a numbered section from the model's response.

        Matches patterns like::

            1. EXPLANATION: ...
            2. FIXED CODE: ...

        Returns the text between this section's header and the next
        numbered header (or end of string), stripped of leading/trailing
        whitespace.
        """
        # Pattern: "<num>. [LABEL]:  <content>  [\n<num+1>. ...]"
        pattern = rf"(?:^|\n)\s*{section_num}\.\s*{re.escape(label)}[:\-]?\s*([\s\S]*?)(?=\n\s*{section_num + 1}\.\s|\Z)"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # Looser: just find the label anywhere
        loose = rf"{re.escape(label)}[:\-]?\s*([\s\S]*?)(?=\n\s*\d+\.\s|\Z)"
        match = re.search(loose, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        return ""

    def _extract_code_block(self, text: str) -> str:
        """
        Extract the first PHP code block from markdown-fenced output.

        Tries ` ```php … ``` ` first, then any ` ``` … ``` `, then
        ``<?php … ?>`` inline blocks.
        """
        # Fenced php block
        match = re.search(r"```php\s*([\s\S]*?)```", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # Any fenced block
        match = re.search(r"```\s*([\s\S]*?)```", text)
        if match:
            candidate = match.group(1).strip()
            # Skip if it looks like a section label, not code
            if candidate and not candidate.upper().startswith("FIXED"):
                return candidate

        # Inline PHP tags
        match = re.search(r"(<\?php[\s\S]*?\?>)", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        return ""

    def _extract_confidence(self, text: str) -> float:
        """
        Parse a confidence value (0.0-1.0) from the model's response text.

        Patterns are tried in priority order:

        0. **XML tag** ``<confidence>85</confidence>`` -- new format.
        1. **Integer 0-100** near the "confidence" keyword -- legacy format,
           e.g. ``3. CONFIDENCE: 85``.
        2. **Decimal 0.x / 1.0** near "confidence" -- e.g. ``confidence: 0.85``.
        3. **Percentage** near "confidence" -- e.g. ``confidence: 85%``.
        4. **Bare decimal** anywhere in the text -- e.g. ``I am 0.7 confident``.
        5. **Natural-language expressions** -- mapped to fixed scores when the
           model ignores the structured format entirely and uses prose.

        Returns ``_CONFIDENCE_FALLBACK`` (0.0) when none of the above succeed.
        """
        # 0. XML tag — highest priority, matches new prompt format.
        #    Also handles FIM comment variant: // <confidence>85</confidence>
        for xml_pat in (
            r"<confidence>\s*(\d{1,3})\s*</confidence>",
            r"//\s*<confidence>\s*(\d{1,3})\s*</confidence>",
        ):
            match = re.search(xml_pat, text, re.IGNORECASE)
            if match:
                try:
                    val = int(match.group(1))
                    if 0 <= val <= 100:
                        return round(val / 100.0, 2)
                except ValueError:
                    pass

        # 1. Integer 0-100 near the "confidence" keyword.
        #    (?!\.\d) prevents matching the leading digit of a decimal like "0.85".
        match = re.search(
            r"confidence[^0-9\n]*?(\d{1,3})(?!\.\d)",
            text,
            re.IGNORECASE,
        )
        if match:
            try:
                val = int(match.group(1))
                if 0 <= val <= 100:
                    return round(val / 100.0, 2)
            except ValueError:
                pass

        # 2. Decimal 0.0-1.0 near "confidence".
        match = re.search(
            r"confidence[^0-9\n]*?([01]\.\d{1,2})",
            text,
            re.IGNORECASE,
        )
        if match:
            try:
                val = float(match.group(1))
                return max(0.0, min(1.0, val))
            except ValueError:
                pass

        # 3. Percentage near "confidence", e.g. "confidence: 85%".
        match = re.search(r"confidence[^0-9\n]*?(\d{1,3})\s*%", text, re.IGNORECASE)
        if match:
            try:
                val = float(match.group(1)) / 100.0
                return max(0.0, min(1.0, val))
            except ValueError:
                pass

        # 4. Bare decimal anywhere in text (last numeric resort).
        match = re.search(r"\b([01]\.\d{1,2})\b", text)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass

        # 5. Natural-language confidence expressions.
        #    Ordered most-specific first so "fairly confident" wins over "confident".
        _NL_PATTERNS: list[tuple[str, int]] = [
            (r"\bnot\s+sure\b|\bmay\s+not\b|\bunsure\b", 30),
            (r"\bshould\s+(?:work|resolve|fix)\b", 60),
            (r"\bfairly\s+confident\b", 70),
            (r"\b(?:straightforward|simple\s+fix)\b", 80),
            (r"\bconfident\b", 75),
        ]
        for pattern, score in _NL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return round(score / 100.0, 2)

        # No parseable confidence found -- return explicit zero rather than a
        # magic number that would masquerade as a genuine model rating.
        return _CONFIDENCE_FALLBACK

    def _placeholder(
        self,
        original_code: str,
        iso_controls: list[str],
        vuln_type: str,
        file_path: str,
        line_start: int,
        fim_used: bool,
        reason: str = "",
    ) -> AIRecommendation:
        """Return a zero-confidence placeholder when AI analysis fails."""
        return AIRecommendation(
            original_code=original_code,
            suggested_fix="// AI analysis unavailable -- manual review required.",
            explanation=f"AI analysis could not complete. {reason}".strip(),
            confidence=0.0,
            iso_controls=list(iso_controls),
            vuln_type=vuln_type,
            file_path=file_path,
            line_start=line_start,
            model_used=self._model,
            fim_used=fim_used,
        )

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------

    def _print_batch_summary(self, recommendations: list[AIRecommendation]) -> None:
        """Render a summary table of all AI recommendations."""
        if not recommendations:
            return

        tbl = Table(
            title=f"AI Recommendations  ({self._model})",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("File", no_wrap=False)
        tbl.add_column("Line", justify="right", width=6)
        tbl.add_column("Vulnerability", width=18)
        tbl.add_column("Confidence", justify="center", width=11)
        tbl.add_column("FIM", justify="center", width=5)
        tbl.add_column("ISO Controls")

        for rec in recommendations:
            conf_pct = f"{rec.confidence * 100:.0f}%"
            conf_style = (
                "green" if rec.confidence >= 0.7
                else "yellow" if rec.confidence >= 0.4
                else "red"
            )
            tbl.add_row(
                Path(rec.file_path).name,
                str(rec.line_start),
                rec.vuln_type,
                f"[{conf_style}]{conf_pct}[/{conf_style}]",
                "yes" if rec.fim_used else "no",
                ", ".join(rec.iso_controls),
            )

        console.print(tbl)
        avg_conf = sum(r.confidence for r in recommendations) / len(recommendations)
        console.print(
            f"\n[bold]AI processed:[/bold] {len(recommendations)} finding(s)  |  "
            f"[bold]Avg confidence:[/bold] {avg_conf * 100:.0f}%  |  "
            f"[bold]Model:[/bold] {self._model}\n"
        )


# ---------------------------------------------------------------------------
# Convenience top-level function (used by main.py)
# ---------------------------------------------------------------------------


def run_ai_analysis(
    findings: list[ScanFinding],
    model: str = OLLAMA_MODEL,
    ollama_base_url: str = OLLAMA_BASE_URL,
) -> list[AIRecommendation]:
    """
    Run AI-assisted analysis on high-priority Semgrep findings.

    Sends findings with ``priority <= 3`` (SQL Injection, XSS, Deprecated
    Functions) to DeepSeek Coder 6.7B via local Ollama and returns structured
    fix recommendations.

    This function is safe to call even when Ollama is not running -- it
    returns an empty list with a warning rather than crashing the pipeline.

    Parameters
    ----------
    findings:
        Output of ``scanner.run_scan().findings``.  Only findings with
        ``priority <= PRIORITY_THRESHOLD`` are sent to the model.
    model:
        Ollama model identifier.  Defaults to ``"deepseek-coder:6.7b"``.
    ollama_base_url:
        Base URL for the local Ollama server.
        Defaults to ``"http://localhost:11434"``.

    Returns
    -------
    list[AIRecommendation]
        One ``AIRecommendation`` per eligible finding, in priority order.
        Empty list if Ollama is unreachable or no eligible findings exist.
    """
    engine = PHPAIEngine(model=model, ollama_base_url=ollama_base_url)
    return engine.analyze_findings(findings)
