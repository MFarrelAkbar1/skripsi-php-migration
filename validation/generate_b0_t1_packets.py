"""
Generate blinded B0 vs T1 rating packets for the baseline experiment.

Reads existing pipeline data (llm_comparison JSON + original source file)
and produces:
  1. rating_sheet_rater.csv   -- blinded CSV for raters (A/B labels, empty scores)
  2. mapping_b0_t1.json       -- secret mapping (finding -> B0/T1 -> A/B)
  3. instruksi_rater.txt      -- rater briefing document
  4. packets_full.json        -- complete data backup (all fields, unblinded)

Usage:
    python validation/generate_b0_t1_packets.py

Requires no external dependencies beyond Python 3.11+ stdlib.
"""

from __future__ import annotations

import csv
import json
import random
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "validation" / "output"

LLM_COMPARISON_FILE = (
    PROJECT_ROOT
    / "reports"
    / "llm_comparison_20260430_083613.json"
)

SOURCE_FILE = Path(
    r"C:\Users\HP VICTUS\Documents\GitHub\mck\system\core\Output.php"
)

SNIPPET_CONTEXT_LINES = 5

SEED = 42

# ---------------------------------------------------------------------------
# Semgrep rule metadata (deterministic, from scanner.py _VULN_RULES)
# ---------------------------------------------------------------------------

SEMGREP_RULES: dict[str, dict] = {
    "SQL Injection": {
        "rule_id": (
            "php.lang.security.injection."
            "tainted-sql-string.tainted-sql-string"
        ),
        "severity": "ERROR",
        "message": (
            "User data flows into this manually-constructed SQL string. "
            "User data can be safely inserted into SQL strings using "
            "prepared statements or an object-relational mapper (ORM). "
            "Manually-constructed SQL strings is a possible indicator of "
            "SQL injection, which could let an attacker steal or "
            "manipulate data from the database. Instead, use prepared "
            'statements (`$mysqli->prepare("INSERT INTO test(id, label) '
            'VALUES (?, ?)");`) or a safe library.'
        ),
        "cwe": "CWE-89: Improper Neutralization of Special Elements "
               "used in an SQL Command ('SQL Injection')",
        "owasp": "A03:2021 - Injection",
        "iso_controls": ["A.8.28", "A.8.26"],
    },
    "SSRF": {
        "rule_id": (
            "php.lang.security.injection."
            "tainted-filename.tainted-filename"
        ),
        "severity": "WARNING",
        "message": (
            "File name based on user input risks server-side request "
            "forgery."
        ),
        "cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "iso_controls": ["A.8.28", "A.8.29"],
    },
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    id: str
    file_path: str
    line_start: int
    vuln_type: str
    rule_id: str
    severity: str
    semgrep_message: str
    cwe: str
    owasp: str
    iso_controls: list[str]
    code_snippet: str
    ai_explanation: str
    ai_suggested_fix: str


@dataclass
class Packet:
    finding_id: str
    condition: str          # "B0" or "T1"
    blinded_label: str      # "A" or "B"
    content: str


@dataclass
class MappingEntry:
    finding_id: str
    vuln_type: str
    line_start: int
    b0_label: str
    t1_label: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_source_snippet(
    source_path: Path, line: int, context: int = SNIPPET_CONTEXT_LINES
) -> str:
    """Extract lines [line-context .. line+context] from a source file."""
    if not source_path.exists():
        return f"[Source file not found: {source_path}]"

    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    numbered = []
    for i in range(start, end):
        marker = " >> " if i == line - 1 else "    "
        numbered.append(f"{i + 1:4d}{marker}{lines[i]}")
    return "\n".join(numbered)


def extract_ai_parts(raw_response: str) -> tuple[str, str]:
    """
    Split a Qwen2.5-Coder raw_response into (explanation, suggested_fix).

    The model typically produces:
      ### Explanation of Vulnerability
      ... prose ...
      ### Corrected PHP 8.x Code
      ... prose + ```php block ...
    """
    explanation_parts: list[str] = []
    code_parts: list[str] = []

    in_code_block = False
    past_code_header = False

    for line in raw_response.splitlines():
        lower = line.lower().strip()

        if any(
            kw in lower
            for kw in [
                "corrected php",
                "secure php",
                "corrected code",
                "secure code",
                "php 8.x code",
            ]
        ):
            past_code_header = True
            continue

        if line.strip().startswith("```php"):
            in_code_block = True
            code_parts.append(line)
            continue

        if in_code_block:
            code_parts.append(line)
            if line.strip() == "```":
                in_code_block = False
            continue

        if past_code_header:
            code_parts.append(line)
        else:
            explanation_parts.append(line)

    explanation = "\n".join(explanation_parts).strip()
    suggested_fix = "\n".join(code_parts).strip()

    if not explanation:
        explanation = raw_response.strip()
    if not suggested_fix:
        suggested_fix = "[No code block extracted]"

    return explanation, suggested_fix


def build_b0_content(f: Finding) -> str:
    """Compose the B0 (baseline, no AI) packet text."""
    sections = [
        f"Rule ID    : {f.rule_id}",
        f"File       : {Path(f.file_path).name}",
        f"Line       : {f.line_start}",
        f"Severity   : {f.severity}",
        f"Vuln Type  : {f.vuln_type}",
        "",
        "--- Semgrep Rule Description ---",
        f"{f.semgrep_message}",
        "",
        f"CWE  : {f.cwe}",
        f"OWASP: {f.owasp}",
        "",
        "--- Code Snippet ---",
        f"{f.code_snippet}",
        "",
        "--- ISO/IEC 27001:2022 Controls ---",
        ", ".join(f.iso_controls),
    ]
    return "\n".join(sections)


def build_t1_content(f: Finding) -> str:
    """Compose the T1 (full AI) packet text = B0 + AI output."""
    b0 = build_b0_content(f)
    ai_section = "\n".join([
        "",
        "============================================================",
        "AI Engine Analysis (model: qwen2.5-coder:7b)",
        "============================================================",
        "",
        "--- Vulnerability Explanation ---",
        f"{f.ai_explanation}",
        "",
        "--- Suggested Remediation ---",
        f"{f.ai_suggested_fix}",
    ])
    return b0 + ai_section


def generate_rater_briefing() -> str:
    """Generate the rater instruction document."""
    return textwrap.dedent("""\
        ================================================================
        INSTRUKSI PENILAIAN PAKET TEMUAN KEAMANAN
        ================================================================

        Terima kasih atas kesediaan Anda menjadi rater dalam eksperimen
        ini. Dokumen ini menjelaskan tugas Anda dan definisi dimensi
        penilaian.

        ----------------------------------------------------------------
        KONTEKS
        ----------------------------------------------------------------
        Anda akan menilai paket-paket temuan keamanan dari pemindaian
        kode PHP menggunakan alat analisis statis. Setiap temuan
        disajikan dalam dua versi (Paket A dan Paket B) yang mungkin
        berbeda dalam tingkat detail dan kelengkapan informasinya.

        Tugas Anda adalah menilai SETIAP paket secara INDEPENDEN pada
        empat dimensi menggunakan skala Likert 1-7. Jangan
        membandingkan Paket A dan Paket B secara langsung -- nilai
        masing-masing berdasarkan kualitas intrinsiknya.

        ----------------------------------------------------------------
        SKALA PENILAIAN: 1-7
        ----------------------------------------------------------------
        1 = Sangat buruk / tidak memenuhi sama sekali
        2 = Buruk
        3 = Di bawah rata-rata
        4 = Cukup / rata-rata
        5 = Di atas rata-rata
        6 = Baik
        7 = Sangat baik / memenuhi sepenuhnya

        ----------------------------------------------------------------
        DIMENSI PENILAIAN
        ----------------------------------------------------------------

        1. AKURASI (skor_akurasi)
           Seberapa tepat dan benar informasi yang disajikan dalam
           paket ini?
           - Apakah identifikasi jenis kerentanan sudah tepat?
           - Apakah penjelasan penyebab kerentanan (jika ada) sesuai
             dengan kode yang ditampilkan?
           - Apakah ada informasi yang salah atau menyesatkan?

           1 = Informasi salah/menyesatkan
           4 = Sebagian besar benar, ada minor inaccuracy
           7 = Sepenuhnya akurat dan tepat

        2. KEJELASAN (skor_kejelasan)
           Seberapa mudah dipahami informasi dalam paket ini oleh
           seorang pengembang dengan pengetahuan PHP dasar?
           - Apakah bahasa yang digunakan jelas dan tidak ambigu?
           - Apakah alur penjelasan logis?
           - Apakah pengembang bisa memahami APA masalahnya dan
             MENGAPA itu berbahaya?

           1 = Tidak bisa dipahami tanpa riset tambahan
           4 = Bisa dipahami dengan sedikit usaha
           7 = Langsung jelas tanpa interpretasi tambahan

        3. ACTIONABILITY (skor_actionability)
           Seberapa mudah seorang pengembang dapat mengambil tindakan
           perbaikan berdasarkan informasi dalam paket ini?
           - Apakah ada panduan langkah perbaikan yang spesifik?
           - Apakah contoh kode perbaikan (jika ada) bisa langsung
             diterapkan atau diadaptasi?
           - Apakah pengembang tahu apa yang harus dilakukan
             SELANJUTNYA setelah membaca paket ini?

           1 = Tidak ada petunjuk tindakan sama sekali
           4 = Ada arah umum tapi perlu riset tambahan
           7 = Langkah perbaikan jelas dan spesifik

        4. KETEPATAN PEMETAAN ISO (skor_ketepatan_iso)
           Seberapa tepat kontrol ISO/IEC 27001:2022 yang dipetakan
           terhadap temuan ini?
           - Apakah kontrol yang dicantumkan relevan dengan jenis
             kerentanan yang ditemukan?
           - Apakah pemetaan masuk akal dari perspektif kepatuhan
             keamanan informasi?

           Referensi singkat kontrol:
           * A.8.26 - Application Security Requirements:
             perlindungan terhadap OWASP Top 10 (SQLi, XSS, dll.)
           * A.8.28 - Secure Coding: aturan pengkodean aman,
             validasi input, parameterised queries
           * A.8.29 - Security Testing in Development: pengujian
             keamanan sebagai bagian proses pengembangan

           1 = Kontrol yang dipetakan tidak relevan
           4 = Kontrol relevan tapi bisa lebih tepat
           7 = Pemetaan sangat tepat dan lengkap

        ----------------------------------------------------------------
        PETUNJUK TEKNIS
        ----------------------------------------------------------------
        - Isi skor pada kolom yang tersedia di file CSV.
        - Gunakan angka bulat 1-7 saja.
        - Jika Anda merasa tidak cukup kompeten menilai dimensi
          tertentu, beri nilai 0 (nol) dan beri catatan di kolom
          komentar.
        - Boleh menambahkan catatan kualitatif di kolom 'komentar'
          jika ada observasi yang ingin disampaikan.

        ----------------------------------------------------------------
        PENTING
        ----------------------------------------------------------------
        - Nilai setiap paket secara mandiri. Hindari anchoring effect
          dari paket sebelumnya.
        - Tidak ada jawaban benar atau salah -- kami menilai kualitas
          informasi, bukan pengetahuan Anda.
        - Urutan penyajian paket sudah diacak.

        ================================================================
    """)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # --- Load llm_comparison data ---
    with open(LLM_COMPARISON_FILE, encoding="utf-8") as fh:
        comparison = json.load(fh)

    qwen_data = comparison["results"]["qwen2.5-coder:7b"]
    raw_findings = qwen_data["findings"]

    print(f"Loaded {len(raw_findings)} findings from {LLM_COMPARISON_FILE.name}")

    # --- Build Finding objects ---
    findings: list[Finding] = []
    for idx, rf in enumerate(raw_findings, start=1):
        vuln_type = rf["vuln_type"]
        rule_meta = SEMGREP_RULES[vuln_type]

        raw_response = rf["runs"][0]["raw_response"]
        explanation, suggested_fix = extract_ai_parts(raw_response)

        snippet = read_source_snippet(SOURCE_FILE, rf["line_start"])

        f = Finding(
            id=f"FT-{idx:02d}",
            file_path=rf["file_path"],
            line_start=rf["line_start"],
            vuln_type=vuln_type,
            rule_id=rule_meta["rule_id"],
            severity=rule_meta["severity"],
            semgrep_message=rule_meta["message"],
            cwe=rule_meta["cwe"],
            owasp=rule_meta["owasp"],
            iso_controls=rule_meta["iso_controls"],
            code_snippet=snippet,
            ai_explanation=explanation,
            ai_suggested_fix=suggested_fix,
        )
        findings.append(f)

    print(f"Built {len(findings)} Finding objects")

    # --- Generate packets with randomized A/B labels ---
    # Use stratified shuffle to ensure roughly half B0->A and half B0->B,
    # preventing raters from inferring a pattern (e.g. "A is always shorter").
    rng = random.Random(SEED)
    packets: list[Packet] = []
    mappings: list[MappingEntry] = []

    n = len(findings)
    half = n // 2
    assignments = [True] * half + [False] * (n - half)
    rng.shuffle(assignments)

    for f, assign_b0_to_a in zip(findings, assignments):
        b0_content = build_b0_content(f)
        t1_content = build_t1_content(f)

        if assign_b0_to_a:
            b0_label, t1_label = "A", "B"
        else:
            b0_label, t1_label = "B", "A"

        packets.append(Packet(
            finding_id=f.id,
            condition="B0",
            blinded_label=b0_label,
            content=b0_content,
        ))
        packets.append(Packet(
            finding_id=f.id,
            condition="T1",
            blinded_label=t1_label,
            content=t1_content,
        ))

        mappings.append(MappingEntry(
            finding_id=f.id,
            vuln_type=f.vuln_type,
            line_start=f.line_start,
            b0_label=b0_label,
            t1_label=t1_label,
        ))

    # Shuffle packet presentation order (but keep pairs grouped by finding)
    packet_pairs = [
        (packets[i], packets[i + 1]) for i in range(0, len(packets), 2)
    ]
    rng.shuffle(packet_pairs)
    ordered_packets: list[Packet] = []
    for p_a, p_b in packet_pairs:
        if p_a.blinded_label == "A":
            ordered_packets.extend([p_a, p_b])
        else:
            ordered_packets.extend([p_b, p_a])

    # --- Write CSV for raters ---
    csv_path = OUTPUT_DIR / "rating_sheet_rater.csv"
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "id_temuan",
            "paket_label",
            "konten_paket",
            "skor_akurasi",
            "skor_kejelasan",
            "skor_actionability",
            "skor_ketepatan_iso",
            "komentar",
        ])
        for pkt in ordered_packets:
            writer.writerow([
                pkt.finding_id,
                pkt.blinded_label,
                pkt.content,
                "",  # skor_akurasi
                "",  # skor_kejelasan
                "",  # skor_actionability
                "",  # skor_ketepatan_iso
                "",  # komentar
            ])

    print(f"Rating sheet saved -> {csv_path}")

    # --- Write secret mapping ---
    mapping_path = OUTPUT_DIR / "mapping_b0_t1.json"
    mapping_payload = {
        "description": (
            "Secret mapping: finding -> B0/T1 -> blinded A/B label. "
            "DO NOT share with raters. Used for analysis after ratings "
            "are collected."
        ),
        "seed": SEED,
        "source_file": str(LLM_COMPARISON_FILE),
        "ai_model": "qwen2.5-coder:7b",
        "ai_run_used": 1,
        "mappings": [asdict(m) for m in mappings],
    }
    mapping_path.write_text(
        json.dumps(mapping_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Mapping saved -> {mapping_path}")

    # --- Write rater briefing ---
    briefing_path = OUTPUT_DIR / "instruksi_rater.txt"
    briefing_path.write_text(generate_rater_briefing(), encoding="utf-8")
    print(f"Rater briefing saved -> {briefing_path}")

    # --- Write full data backup ---
    backup_path = OUTPUT_DIR / "packets_full.json"
    backup_payload = {
        "description": "Complete unblinded packet data for archival.",
        "findings": [asdict(f) for f in findings],
        "packets": [asdict(p) for p in ordered_packets],
        "mappings": [asdict(m) for m in mappings],
    }
    backup_path.write_text(
        json.dumps(backup_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Full backup saved -> {backup_path}")

    # --- Summary ---
    b0_a = sum(1 for m in mappings if m.b0_label == "A")
    b0_b = sum(1 for m in mappings if m.b0_label == "B")
    sqli_count = sum(1 for m in mappings if m.vuln_type == "SQL Injection")
    ssrf_count = sum(1 for m in mappings if m.vuln_type == "SSRF")

    print("\n--- Summary ---")
    print(f"Total findings : {len(findings)}")
    print(f"  SQL Injection: {sqli_count}")
    print(f"  SSRF         : {ssrf_count}")
    print(f"Total packets  : {len(ordered_packets)}")
    print(f"B0 -> A: {b0_a}, B0 -> B: {b0_b}  (randomized)")
    print(f"Output dir     : {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
