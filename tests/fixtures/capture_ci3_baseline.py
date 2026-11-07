"""Rekam output CI3 dari kode saat ini ke ci3_baseline.json (acuan uji regresi)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pipeline.ai_engine import PHPAIEngine  # noqa: E402
from pipeline.converter import RectorConverter, PHPVersion  # noqa: E402
from pipeline.scanner import SemgrepScanner  # noqa: E402
from pipeline import analyzer as analyzer_module  # noqa: E402


def capture() -> dict:
    """Return the CI3 artefacts that must stay byte-identical."""
    conv = RectorConverter(rector_exe="rector")
    sets = conv._choose_level_sets({PHPVersion.PHP7}, "8.3")
    from pipeline import converter as cm
    cfg = conv._write_rector_config(Path("C:/fixed/output"), sets + list(cm._QUALITY_SETS))
    rector_php = cfg.read_text(encoding="utf-8")
    cfg.unlink()
    rector_php = re.sub(r"'[^']*fixed/output'", "'FIXED_OUTPUT'", rector_php)

    scanner = SemgrepScanner(semgrep_exe=Path("semgrep"), exclude_dirs=["third_party"])
    cmd = scanner._build_command(Path("TARGET"))
    cmd = [c.replace(str(ROOT), "ROOT") for c in cmd]

    engine = PHPAIEngine()
    prompt = engine._build_prompt("echo $x;\necho $y;\necho $z;\necho $w;", "XSS", "File: a.php", ["A.8.28"])

    noise = getattr(analyzer_module, "_CI3_NOISE_SUBSTRINGS", None)
    if noise is None:
        from pipeline.profiles import CI3
        noise = CI3.noise_substrings
    return {"rector_php": rector_php, "semgrep_cmd": cmd, "prompt": prompt, "noise": list(noise)}


if __name__ == "__main__":
    out = Path(__file__).with_name("ci3_baseline.json")
    out.write_text(json.dumps(capture(), indent=1, ensure_ascii=False), encoding="utf-8")
    print("written", out)
