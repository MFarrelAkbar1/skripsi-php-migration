"""
Regenerate T1 packet content using a wider source-code context window.

Background
----------
The original T1 explanations (built by generate_b0_t1_packets.py) reuse
Qwen2.5-Coder responses from reports/llm_comparison_20260430_083613.json,
where the model only saw a +-5 line snippet (the zero-shot comparison
experiment's MAX_CODE_CHARS / context budget). For the 10 SSRF findings in
Output.php this produced near-identical "code snippet is incomplete"
explanations, weakening the B0 vs T1 comparison.

This script re-queries Ollama for a *fresh* AI explanation per finding,
feeding it a wider context window (the enclosing function, or +-30 lines
when no function boundary is found -- see scanner.extract_context_window())
read directly from the FT UGM source file. It only replaces the T1
("--- Vulnerability Explanation ---" / "--- Suggested Remediation ---")
section -- B0 packet content, the displayed code snippet, and the A/B
blinding/order are left untouched, so the existing experimental design
stays valid.

It does NOT touch reports/llm_comparison_*.json or any chapter-4 charts:
those still report results from the original MAX_CODE_CHARS=2000 zero-shot
comparison. ai_engine.PHPAIEngine.analyze_snippet()'s new max_chars
parameter defaults to None (-> MAX_CODE_CHARS), so this script is the only
caller that opts into a wider budget.

Usage:
    ollama serve            (separate terminal, must already be running)
    python validation/regenerate_t1_wide_context.py
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Sibling module in validation/ -- Python puts this script's own directory
# on sys.path, so this import works without extra path setup.
from generate_b0_t1_packets import (
    OUTPUT_DIR,
    SOURCE_FILE,
    Finding,
    Packet,
    build_t1_content,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.ai_engine import PHPAIEngine  # noqa: E402
from pipeline.scanner import extract_context_window  # noqa: E402

WIDE_CONTEXT_LINES = 30
WIDE_MAX_CHARS = 6000


def main() -> None:
    packets_path = OUTPUT_DIR / "packets_full.json"
    csv_path = OUTPUT_DIR / "rating_sheet_rater.csv"

    backup = json.loads(packets_path.read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in backup["findings"]]
    packets = [Packet(**p) for p in backup["packets"]]

    engine = PHPAIEngine()
    if not engine._check_ollama_alive():
        raise SystemExit(
            "Ollama is not reachable at http://localhost:11434 -- "
            "start it with `ollama serve` and re-run this script."
        )

    print(f"Regenerating T1 explanations for {len(findings)} findings "
          f"(model={engine._model}, max_chars={WIDE_MAX_CHARS})\n")

    context_log: list[dict] = []

    for f in findings:
        wide_snippet, ctx_start, ctx_end = extract_context_window(
            SOURCE_FILE, f.line_start, context_lines=WIDE_CONTEXT_LINES,
        )
        context_str = (
            f"File: {f.file_path}, line {f.line_start}. "
            f"Semgrep rule: {f.rule_id}. "
            f"Finding: {f.semgrep_message[:200]}"
        )

        rec = engine.analyze_snippet(
            code=wide_snippet,
            vuln_type=f.vuln_type,
            context=context_str,
            iso_controls=f.iso_controls,
            file_path=f.file_path,
            line_start=f.line_start,
            max_chars=WIDE_MAX_CHARS,
        )

        print(
            f"[{f.id}] line {f.line_start} | context {ctx_start}-{ctx_end} "
            f"({ctx_end - ctx_start + 1} lines, {len(wide_snippet)} chars) | "
            f"confidence={rec.confidence:.0%}"
        )

        f.ai_explanation = rec.explanation
        f.ai_suggested_fix = rec.suggested_fix
        context_log.append({
            "finding_id": f.id,
            "context_line_start": ctx_start,
            "context_line_end": ctx_end,
            "context_chars": len(wide_snippet),
            "confidence": rec.confidence,
        })

    # Rebuild T1 packet content only -- B0 packets, order, and A/B labels
    # are left exactly as generate_b0_t1_packets.py originally produced them.
    findings_by_id = {f.id: f for f in findings}
    for p in packets:
        if p.condition == "T1":
            p.content = build_t1_content(findings_by_id[p.finding_id])

    backup["findings"] = [asdict(f) for f in findings]
    backup["packets"] = [asdict(p) for p in packets]
    backup["t1_context_regeneration"] = {
        "description": (
            "T1 explanations regenerated with a wider source context "
            "window (enclosing function, or +-N lines fallback) instead "
            "of the +-5 line snippet used by the original zero-shot "
            "comparison experiment. B0 content and A/B blinding are "
            "unchanged."
        ),
        "context_window_lines": WIDE_CONTEXT_LINES,
        "max_chars": WIDE_MAX_CHARS,
        "model": engine._model,
        "log": context_log,
    }
    packets_path.write_text(
        json.dumps(backup, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\nUpdated -> {packets_path}")

    # Rewrite the rater CSV with the same row order/labels -- only the T1
    # packet text changes; score columns stay empty (template).
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "id_temuan", "paket_label", "konten_paket",
            "skor_akurasi", "skor_kejelasan", "skor_actionability",
            "skor_ketepatan_iso", "komentar",
        ])
        for p in packets:
            writer.writerow([p.finding_id, p.blinded_label, p.content, "", "", "", "", ""])
    print(f"Updated -> {csv_path}")


if __name__ == "__main__":
    main()
