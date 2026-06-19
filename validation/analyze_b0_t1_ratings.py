"""
Analyze B0 vs T1 ratings after human raters have completed scoring.

Reads the completed rating CSV(s), maps blinded A/B labels back to B0/T1,
and performs:
  - Wilcoxon signed-rank test (paired, B0 vs T1) per dimension
  - Cohen's kappa for inter-rater agreement (when multiple raters)
  - Separate analysis for SQLi (n=1, descriptive only) and SSRF (n=10)
  - Combined analysis (n=11) with caveat about SSRF dominance

Usage:
    python validation/analyze_b0_t1_ratings.py

    By default reads from validation/output/. Override with --ratings-dir.

DO NOT run this script until human ratings have been collected.
"""

from __future__ import annotations

import argparse
import json
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import numpy as np
    from scipy import stats
except ImportError:
    print(
        "This script requires numpy and scipy.\n"
        "Install with: pip install numpy scipy\n"
        "DO NOT run until rating data has been collected.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "validation" / "output"

DIMENSIONS = [
    "skor_akurasi",
    "skor_kejelasan",
    "skor_actionability",
    "skor_ketepatan_iso",
]

DIMENSION_LABELS = {
    "skor_akurasi": "Akurasi",
    "skor_kejelasan": "Kejelasan",
    "skor_actionability": "Actionability",
    "skor_ketepatan_iso": "Ketepatan ISO",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RatedPacket:
    finding_id: str
    blinded_label: str  # A or B
    condition: str      # B0 or T1 (resolved from mapping)
    vuln_type: str      # SQL Injection or SSRF (resolved from mapping)
    scores: dict[str, float]
    rater_id: str


@dataclass
class PairedScore:
    finding_id: str
    vuln_type: str
    dimension: str
    b0_score: float
    t1_score: float
    rater_id: str


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_mapping(output_dir: Path) -> dict:
    mapping_path = output_dir / "mapping_b0_t1.json"
    with open(mapping_path, encoding="utf-8") as fh:
        return json.load(fh)


def resolve_condition(
    finding_id: str, blinded_label: str, mappings: list[dict]
) -> tuple[str, str]:
    """Return (condition, vuln_type) for a given finding_id + blinded_label."""
    for m in mappings:
        if m["finding_id"] == finding_id:
            if blinded_label == m["b0_label"]:
                return "B0", m["vuln_type"]
            elif blinded_label == m["t1_label"]:
                return "T1", m["vuln_type"]
    raise ValueError(
        f"No mapping found for {finding_id} label={blinded_label}"
    )


def load_ratings(
    csv_path: Path, mappings: list[dict], rater_id: str
) -> list[RatedPacket]:
    """Load a single rater's completed CSV."""
    packets: list[RatedPacket] = []
    with open(csv_path, encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            scores = {}
            skip = False
            for dim in DIMENSIONS:
                val = row.get(dim, "").strip()
                if val == "" or val == "0":
                    skip = True
                    break
                scores[dim] = float(val)
            if skip:
                continue

            condition, vuln_type = resolve_condition(
                row["id_temuan"], row["paket_label"], mappings
            )
            packets.append(RatedPacket(
                finding_id=row["id_temuan"],
                blinded_label=row["paket_label"],
                condition=condition,
                vuln_type=vuln_type,
                scores=scores,
                rater_id=rater_id,
            ))
    return packets


def pair_scores(
    packets: list[RatedPacket],
) -> list[PairedScore]:
    """Pair B0 and T1 scores for the same finding+rater+dimension."""
    by_key: dict[tuple[str, str], dict[str, dict[str, float]]] = {}
    for p in packets:
        key = (p.finding_id, p.rater_id)
        if key not in by_key:
            by_key[key] = {}
        by_key[key][p.condition] = p.scores

    pairs: list[PairedScore] = []
    for (fid, rid), cond_scores in by_key.items():
        if "B0" not in cond_scores or "T1" not in cond_scores:
            continue
        vuln_type = next(
            p.vuln_type for p in packets
            if p.finding_id == fid and p.rater_id == rid
        )
        for dim in DIMENSIONS:
            if dim in cond_scores["B0"] and dim in cond_scores["T1"]:
                pairs.append(PairedScore(
                    finding_id=fid,
                    vuln_type=vuln_type,
                    dimension=dim,
                    b0_score=cond_scores["B0"][dim],
                    t1_score=cond_scores["T1"][dim],
                    rater_id=rid,
                ))
    return pairs


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------


def wilcoxon_test(
    b0_scores: list[float], t1_scores: list[float]
) -> dict:
    """Run Wilcoxon signed-rank test. Returns dict with stat, p, n, etc."""
    b0 = np.array(b0_scores)
    t1 = np.array(t1_scores)
    diff = t1 - b0

    n = len(diff)
    non_zero = np.count_nonzero(diff)

    if non_zero < 2:
        return {
            "test": "wilcoxon_signed_rank",
            "n_total": n,
            "n_non_zero_diff": non_zero,
            "statistic": None,
            "p_value": None,
            "note": (
                "Cannot run Wilcoxon: fewer than 2 non-zero differences."
            ),
            "b0_mean": float(b0.mean()),
            "b0_median": float(np.median(b0)),
            "t1_mean": float(t1.mean()),
            "t1_median": float(np.median(t1)),
            "diff_mean": float(diff.mean()),
            "diff_median": float(np.median(diff)),
        }

    stat, p = stats.wilcoxon(b0, t1, alternative="two-sided")
    return {
        "test": "wilcoxon_signed_rank",
        "n_total": n,
        "n_non_zero_diff": non_zero,
        "statistic": float(stat),
        "p_value": float(p),
        "significant_at_005": bool(p < 0.05),
        "b0_mean": float(b0.mean()),
        "b0_median": float(np.median(b0)),
        "t1_mean": float(t1.mean()),
        "t1_median": float(np.median(t1)),
        "diff_mean": float(diff.mean()),
        "diff_median": float(np.median(diff)),
    }


def cohens_kappa_pairwise(
    rater_a_scores: list[float],
    rater_b_scores: list[float],
    k: int = 7,
) -> dict:
    """
    Cohen's kappa for ordinal ratings.

    Discretizes scores into integer bins [1..k] and computes kappa
    on the resulting contingency matrix.
    """
    a = np.array(rater_a_scores, dtype=int)
    b = np.array(rater_b_scores, dtype=int)

    a = np.clip(a, 1, k)
    b = np.clip(b, 1, k)

    n = len(a)
    matrix = np.zeros((k, k), dtype=int)
    for i in range(n):
        matrix[a[i] - 1, b[i] - 1] += 1

    po = np.trace(matrix) / n

    row_sums = matrix.sum(axis=1)
    col_sums = matrix.sum(axis=0)
    pe = np.sum(row_sums * col_sums) / (n * n)

    if pe == 1.0:
        kappa = 1.0
    else:
        kappa = (po - pe) / (1.0 - pe)

    return {
        "test": "cohens_kappa",
        "n_items": n,
        "kappa": float(kappa),
        "p_observed": float(po),
        "p_expected": float(pe),
        "interpretation": interpret_kappa(kappa),
    }


def interpret_kappa(kappa: float) -> str:
    if kappa < 0:
        return "Less than chance agreement"
    elif kappa < 0.21:
        return "Slight agreement"
    elif kappa < 0.41:
        return "Fair agreement"
    elif kappa < 0.61:
        return "Moderate agreement"
    elif kappa < 0.81:
        return "Substantial agreement"
    else:
        return "Almost perfect agreement"


# ---------------------------------------------------------------------------
# Analysis groups
# ---------------------------------------------------------------------------


def analyze_group(
    pairs: list[PairedScore],
    group_name: str,
) -> dict:
    """Analyze a group of paired scores across all dimensions."""
    result: dict = {"group": group_name, "dimensions": {}}

    for dim in DIMENSIONS:
        dim_pairs = [p for p in pairs if p.dimension == dim]
        if not dim_pairs:
            continue

        b0 = [p.b0_score for p in dim_pairs]
        t1 = [p.t1_score for p in dim_pairs]
        n = len(dim_pairs)

        dim_result: dict = {"n": n}

        if n == 1:
            dim_result["analysis_type"] = "descriptive_only"
            dim_result["note"] = (
                "n=1: Wilcoxon not applicable. Reporting raw scores."
            )
            dim_result["b0_score"] = b0[0]
            dim_result["t1_score"] = t1[0]
            dim_result["difference"] = t1[0] - b0[0]
        elif n < 6:
            dim_result["analysis_type"] = "descriptive_with_caveat"
            dim_result["note"] = (
                f"n={n}: sample too small for reliable Wilcoxon. "
                "Reporting descriptive stats + attempting test."
            )
            dim_result["wilcoxon"] = wilcoxon_test(b0, t1)
        else:
            dim_result["analysis_type"] = "wilcoxon"
            dim_result["wilcoxon"] = wilcoxon_test(b0, t1)

        result["dimensions"][DIMENSION_LABELS[dim]] = dim_result

    return result


def analyze_inter_rater(
    all_packets: list[RatedPacket],
    rater_ids: list[str],
) -> dict:
    """Compute Cohen's kappa for each pair of raters, per dimension."""
    if len(rater_ids) < 2:
        return {
            "note": "Only 1 rater; inter-rater agreement not applicable.",
            "n_raters": len(rater_ids),
        }

    results: dict = {"n_raters": len(rater_ids), "pairwise": {}}

    for i in range(len(rater_ids)):
        for j in range(i + 1, len(rater_ids)):
            ra, rb = rater_ids[i], rater_ids[j]
            pair_key = f"{ra}_vs_{rb}"
            results["pairwise"][pair_key] = {}

            for dim in DIMENSIONS:
                a_by_item: dict[tuple[str, str], float] = {}
                b_by_item: dict[tuple[str, str], float] = {}

                for p in all_packets:
                    item_key = (p.finding_id, p.condition)
                    if p.rater_id == ra and dim in p.scores:
                        a_by_item[item_key] = p.scores[dim]
                    elif p.rater_id == rb and dim in p.scores:
                        b_by_item[item_key] = p.scores[dim]

                common = sorted(set(a_by_item) & set(b_by_item))
                if len(common) < 2:
                    results["pairwise"][pair_key][DIMENSION_LABELS[dim]] = {
                        "note": "Insufficient overlapping items.",
                        "n_common": len(common),
                    }
                    continue

                a_scores = [a_by_item[k] for k in common]
                b_scores = [b_by_item[k] for k in common]
                results["pairwise"][pair_key][DIMENSION_LABELS[dim]] = (
                    cohens_kappa_pairwise(a_scores, b_scores)
                )

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(
    combined: dict,
    sqli_group: dict,
    ssrf_group: dict,
    inter_rater: dict,
    rater_ids: list[str],
) -> str:
    """Generate a human-readable text report."""
    lines: list[str] = []

    lines.append("=" * 70)
    lines.append("HASIL ANALISIS B0 vs T1 -- EKSPERIMEN BASELINE")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Jumlah rater      : {len(rater_ids)}")
    lines.append(f"Rater             : {', '.join(rater_ids)}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("CATATAN INTERPRETASI")
    lines.append("-" * 70)
    lines.append(
        "Hasil gabungan (n=11) didominasi kelompok SSRF yang homogen "
        "(10 dari 11 temuan). Deskripsi rule Semgrep untuk SSRF identik "
        "untuk semua 10 temuan, dan respons AI juga sangat serupa karena "
        "konteks kode yang terbatas. Hasil gabungan TIDAK boleh "
        "diinterpretasikan sebagai representasi temuan yang beragam -- "
        "gunakan hasil per kelompok (SQLi vs SSRF) untuk interpretasi "
        "yang lebih akurat."
    )
    lines.append("")

    for section_name, section_data in [
        ("GABUNGAN (n=11)", combined),
        ("KELOMPOK SQL INJECTION (n=1)", sqli_group),
        ("KELOMPOK SSRF (n=10)", ssrf_group),
    ]:
        lines.append("-" * 70)
        lines.append(section_name)
        lines.append("-" * 70)

        for dim_label, dim_data in section_data.get("dimensions", {}).items():
            lines.append(f"\n  {dim_label}:")
            lines.append(f"    n = {dim_data['n']}")

            if dim_data.get("analysis_type") == "descriptive_only":
                lines.append(f"    B0 = {dim_data['b0_score']}")
                lines.append(f"    T1 = {dim_data['t1_score']}")
                lines.append(
                    f"    Difference (T1-B0) = {dim_data['difference']}"
                )
                lines.append(f"    Note: {dim_data['note']}")
            elif "wilcoxon" in dim_data:
                w = dim_data["wilcoxon"]
                lines.append(
                    f"    B0 mean={w['b0_mean']:.2f}, "
                    f"median={w['b0_median']:.1f}"
                )
                lines.append(
                    f"    T1 mean={w['t1_mean']:.2f}, "
                    f"median={w['t1_median']:.1f}"
                )
                lines.append(
                    f"    Diff mean={w['diff_mean']:.2f}, "
                    f"median={w['diff_median']:.1f}"
                )
                if w.get("statistic") is not None:
                    lines.append(
                        f"    Wilcoxon W={w['statistic']:.1f}, "
                        f"p={w['p_value']:.4f}"
                    )
                    sig = (
                        "YES" if w.get("significant_at_005") else "NO"
                    )
                    lines.append(
                        f"    Significant at alpha=0.05: {sig}"
                    )
                else:
                    lines.append(f"    {w.get('note', '')}")

        lines.append("")

    lines.append("-" * 70)
    lines.append("INTER-RATER AGREEMENT (Cohen's Kappa)")
    lines.append("-" * 70)
    if "note" in inter_rater and inter_rater.get("n_raters", 0) < 2:
        lines.append(f"  {inter_rater['note']}")
    else:
        for pair_key, dims in inter_rater.get("pairwise", {}).items():
            lines.append(f"\n  {pair_key}:")
            for dim_label, kappa_data in dims.items():
                if "kappa" in kappa_data:
                    lines.append(
                        f"    {dim_label}: "
                        f"kappa={kappa_data['kappa']:.3f} "
                        f"({kappa_data['interpretation']})"
                    )
                else:
                    lines.append(
                        f"    {dim_label}: {kappa_data.get('note', 'N/A')}"
                    )

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze B0 vs T1 ratings after data collection.",
    )
    parser.add_argument(
        "--ratings-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=(
            "Directory containing rating CSV file(s) and mapping JSON. "
            "For multiple raters, name files like "
            "rating_sheet_rater1.csv, rating_sheet_rater2.csv."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for analysis results JSON. Defaults to "
             "ratings-dir/analysis_results.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    ratings_dir = args.ratings_dir

    # --- Load mapping ---
    mapping_data = load_mapping(ratings_dir)
    mappings = mapping_data["mappings"]

    # --- Find and load rating CSVs ---
    csv_files = sorted(ratings_dir.glob("rating_sheet_rater*.csv"))
    if not csv_files:
        csv_files = sorted(ratings_dir.glob("rating_sheet*.csv"))
    if not csv_files:
        print(
            "ERROR: No rating CSV files found in "
            f"{ratings_dir}.\n"
            "Ensure completed rating files are named "
            "'rating_sheet_rater*.csv'.",
            file=sys.stderr,
        )
        sys.exit(1)

    all_packets: list[RatedPacket] = []
    rater_ids: list[str] = []

    for i, csv_path in enumerate(csv_files):
        rater_id = csv_path.stem.replace("rating_sheet_", "")
        if not rater_id or rater_id == "rater":
            rater_id = f"rater_{i + 1}"
        packets = load_ratings(csv_path, mappings, rater_id)
        if not packets:
            print(
                f"Skipped {csv_path.name} (no valid ratings, "
                f"possibly empty template)"
            )
            continue
        rater_ids.append(rater_id)
        all_packets.extend(packets)
        print(
            f"Loaded {len(packets)} rated packets from "
            f"{csv_path.name} (rater: {rater_id})"
        )

    if not all_packets:
        print(
            "ERROR: No valid ratings found. "
            "Ensure score columns are filled (1-7).",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Pair scores ---
    all_pairs = pair_scores(all_packets)
    sqli_pairs = [p for p in all_pairs if p.vuln_type == "SQL Injection"]
    ssrf_pairs = [p for p in all_pairs if p.vuln_type == "SSRF"]

    print(
        f"\nPaired scores: {len(all_pairs)} total, "
        f"{len(sqli_pairs)} SQLi, {len(ssrf_pairs)} SSRF"
    )

    # --- Run analysis ---
    combined = analyze_group(all_pairs, "Gabungan (n=11)")
    sqli_group = analyze_group(sqli_pairs, "SQL Injection (n=1)")
    ssrf_group = analyze_group(ssrf_pairs, "SSRF (n=10)")
    inter_rater = analyze_inter_rater(all_packets, rater_ids)

    # --- Save JSON results ---
    output_path = args.output or (ratings_dir / "analysis_results.json")
    results = {
        "combined": combined,
        "sqli_group": sqli_group,
        "ssrf_group": ssrf_group,
        "inter_rater_agreement": inter_rater,
        "raters": rater_ids,
        "notes": {
            "combined_caveat": (
                "Hasil gabungan (n=11) didominasi kelompok SSRF yang "
                "homogen (10/11 temuan). Deskripsi rule dan respons AI "
                "SSRF sangat serupa antar temuan. Interpretasi harus "
                "mempertimbangkan dominasi ini."
            ),
            "sqli_caveat": (
                "n=1 untuk SQL Injection: tidak cukup untuk uji "
                "statistik. Hanya skor deskriptif yang dilaporkan."
            ),
        },
    }
    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nAnalysis results saved -> {output_path}")

    # --- Generate and save text report ---
    report = generate_report(
        combined, sqli_group, ssrf_group, inter_rater, rater_ids
    )
    report_path = output_path.with_suffix(".txt")
    report_path.write_text(report, encoding="utf-8")
    print(f"Text report saved -> {report_path}")

    # --- Print report to console ---
    print("\n" + report)


if __name__ == "__main__":
    main()
