"""
test_profiles.py -- Uji profil framework.

Bagian CI3 membandingkan output dengan rekaman dari kode sebelum profil ditambahkan,
sehingga perubahan apa pun pada hasil penelitian CI3 akan terdeteksi.  Bagian Laravel
menguji aturan versi, filter noise, dan rule Semgrep pada aplikasi dummy.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from capture_ci3_baseline import capture  # noqa: E402
from pipeline import laravel_version as lv  # noqa: E402
from pipeline import profiles  # noqa: E402
from pipeline.ai_engine import PHPAIEngine  # noqa: E402
from pipeline.composer_analyzer import ComposerAnalyzer  # noqa: E402
from pipeline.converter import RectorConverter  # noqa: E402
from pipeline.laravel_version import FrameworkConfigError, LaravelVersionInfo  # noqa: E402
from pipeline.profiles import CI3, LARAVEL, FrameworkRun, resolve_framework_run  # noqa: E402
from pipeline.scanner import SemgrepScanner, _find_semgrep_exe  # noqa: E402

SAMPLE = ROOT / "tests" / "sample_laravel"
BASELINE = ROOT / "tests" / "fixtures" / "ci3_baseline.json"


def lock_version(major: int, minor: int = 0) -> LaravelVersionInfo:
    """Return a version as if read from composer.lock."""
    return LaravelVersionInfo(major, minor, "composer.lock")


# ---------------------------------------------------------------------------
# CI3 regression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["rector_php", "semgrep_cmd", "prompt", "noise"])
def test_ci3_output_matches_baseline(key: str) -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert capture()[key] == baseline[key]


def test_default_run_uses_ci3_without_framework_paths() -> None:
    run = FrameworkRun()
    assert run.profile is CI3
    assert not run.rector_sets
    assert not run.rector_symbol_paths
    assert not run.phpstan_symbol_paths
    assert not CI3.default_exclude_dirs
    assert CI3.ai_context == ""


def test_empty_framework_context_keeps_engine_prompt_input() -> None:
    assert PHPAIEngine()._framework_context == ""


def test_ci3_warns_when_input_looks_like_laravel() -> None:
    run = resolve_framework_run("ci3", SAMPLE, "8.3")
    assert run.profile is CI3
    assert any("artisan" in w for w in run.warnings)


def test_target_laravel_needs_laravel_profile(tmp_path: Path) -> None:
    with pytest.raises(FrameworkConfigError):
        resolve_framework_run("ci3", tmp_path, "8.3", 10)


# ---------------------------------------------------------------------------
# Laravel version detection
# ---------------------------------------------------------------------------


def test_lock_file_wins_over_manifest() -> None:
    assert lv.detect_laravel_version(SAMPLE) == LaravelVersionInfo(8, 83, "composer.lock")


@pytest.mark.parametrize(
    ("constraint", "expected"),
    [
        ("^8.75", (8, 75)),
        ("^6.20|^7.0", (6, 20)),
        ("7.*", (7, 0)),
        ("~6.0", (6, 0)),
        (">=8.0 <9.0", (8, 0)),
    ],
)
def test_manifest_constraint_uses_lowest_version(
    tmp_path: Path, constraint: str, expected: tuple[int, int]
) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": constraint}}), encoding="utf-8"
    )
    found = lv.detect_laravel_version(tmp_path)
    assert found is not None
    assert (found.major, found.minor, found.source) == (*expected, "composer.json")


@pytest.mark.parametrize("content", [None, "{not json", '{"require": {}}', '{"require": {"laravel/framework": "dev-master"}}'])
def test_no_version_found_returns_none(tmp_path: Path, content: str | None) -> None:
    if content is not None:
        (tmp_path / "composer.json").write_text(content, encoding="utf-8")
    assert lv.detect_laravel_version(tmp_path) is None


# ---------------------------------------------------------------------------
# Upgrade rules
# ---------------------------------------------------------------------------


def test_rector_sets_cover_only_versions_after_current() -> None:
    assert lv.rector_sets_for_upgrade(lock_version(8), 10) == [
        "LaravelSetList::LARAVEL_90",
        "LaravelSetList::LARAVEL_100",
    ]


@pytest.mark.parametrize("target", [None, 8])
def test_rector_sets_empty_without_upgrade(target: int | None) -> None:
    assert lv.rector_sets_for_upgrade(lock_version(8), target) == []


@pytest.mark.parametrize(
    ("major", "target", "php"),
    [
        (5, 10, "8.1"),    # source too old
        (8, 7, "8.0"),     # downgrade
        (8, 99, "8.3"),    # unknown target
        (8, 13, "8.2"),    # Laravel 13 needs PHP 8.3
        (8, 9, "7.4"),     # Laravel 9 needs PHP 8
        (9, None, "7.4"),  # current major already needs PHP 8
    ],
)
def test_impossible_combinations_are_rejected(major: int, target: int | None, php: str) -> None:
    with pytest.raises(FrameworkConfigError):
        lv.validate_target(lock_version(major), target, php)


@pytest.mark.parametrize(
    ("version", "target", "php"),
    [(lock_version(8, 83), 12, "8.2"), (lock_version(6, 20), 13, "8.3"), (lock_version(7, 30), 7, "8.0")],
)
def test_valid_combinations_pass(version: LaravelVersionInfo, target: int, php: str) -> None:
    assert lv.validate_target(version, target, php) == []


def test_warns_when_release_predates_php8_support() -> None:
    warnings = lv.validate_target(lock_version(8, 11), None, "8.0")
    assert any("8.12" in w for w in warnings)


def test_warns_when_old_major_targets_newer_php() -> None:
    warnings = lv.validate_target(lock_version(8, 83), None, "8.3")
    assert any("does not guarantee" in w for w in warnings)


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(FrameworkConfigError):
        profiles.get_profile("symfony")


def test_laravel_profile_needs_laravel_in_composer(tmp_path: Path) -> None:
    with pytest.raises(FrameworkConfigError):
        resolve_framework_run("laravel", tmp_path, "8.3")


# ---------------------------------------------------------------------------
# Source download
# ---------------------------------------------------------------------------


def _fake_composer(monkeypatch: pytest.MonkeyPatch, results: list[tuple[int, str]]) -> list[list[str]]:
    """Replace Composer with queued (exit code, stderr) results; return recorded calls."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        code, stderr = results.pop(0)
        return subprocess.CompletedProcess(cmd, code, stdout="", stderr=stderr)

    monkeypatch.setattr(lv.shutil, "which", lambda _: "composer")
    monkeypatch.setattr(lv.subprocess, "run", fake_run)
    return calls


def test_download_disables_package_code_and_is_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_composer(monkeypatch, [(0, "")])
    first = lv.ensure_laravel_sources(12, cache_root=tmp_path)
    second = lv.ensure_laravel_sources(12, cache_root=tmp_path)
    assert first == second
    assert first.has_advisories is False
    assert len(calls) == 1
    assert {"--no-scripts", "--no-plugins"} <= set(calls[0])
    assert "--no-security-blocking" not in calls[0]


def test_advisory_block_retries_and_is_remembered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake_composer(monkeypatch, [(2, "affected by security\n advisories"), (0, "")])
    assert lv.ensure_laravel_sources(10, cache_root=tmp_path).has_advisories is True
    assert "--no-security-blocking" in calls[1]
    assert lv.ensure_laravel_sources(10, cache_root=tmp_path).has_advisories is True
    assert len(calls) == 2


def test_failed_download_raises_and_is_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_composer(monkeypatch, [(1, "network down")])
    with pytest.raises(FrameworkConfigError, match="network down"):
        lv.ensure_laravel_sources(12, cache_root=tmp_path)
    assert not (tmp_path / "12" / ".complete").exists()


def _sources_fail(_: int) -> lv.LaravelSources:
    raise FrameworkConfigError("offline")


def test_requested_upgrade_stops_without_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profiles, "ensure_laravel_sources", _sources_fail)
    with pytest.raises(FrameworkConfigError, match="offline"):
        resolve_framework_run("laravel", SAMPLE, "8.2", 12)


def test_no_upgrade_only_warns_without_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profiles, "ensure_laravel_sources", _sources_fail)
    run = resolve_framework_run("laravel", SAMPLE, "8.0")
    assert not run.phpstan_symbol_paths
    assert any("offline" in w for w in run.warnings)


def test_advisory_target_warns_and_sets_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources = lv.LaravelSources(tmp_path / "vendor", has_advisories=True)
    monkeypatch.setattr(profiles, "ensure_laravel_sources", lambda _: sources)
    run = resolve_framework_run("laravel", SAMPLE, "8.1", 10)
    assert any("security advisories" in w for w in run.warnings)
    assert run.phpstan_symbol_paths == (tmp_path / "vendor",)
    assert run.rector_symbol_paths[0].parts[-2:] == ("src", "Illuminate")
    assert run.to_dict()["rector_sets"] == ["LaravelSetList::LARAVEL_90", "LaravelSetList::LARAVEL_100"]


# ---------------------------------------------------------------------------
# Laravel noise filter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [
        r"Class App\Models\User extends unknown class Illuminate\Database\Eloquent\Model.",
        r"Instantiated class Illuminate\Support\Fluent not found.",
        r"Parameter $request of method App\A::b() has invalid type Illuminate\Http\Request.",
        r"Call to static method select() on an unknown class Illuminate\Support\Facades\DB.",
        "Function view not found.",
        r"Call to an undefined static method App\Models\User::create().",
        r"Call to an undefined method App\User::where().",
    ],
)
def test_laravel_noise_is_filtered(message: str) -> None:
    assert LARAVEL.is_noise(message)


@pytest.mark.parametrize(
    "message",
    [
        r"Parameter #1 $request of method App\A::b() expects Illuminate\Http\Request, string given.",
        "Undefined variable: $undefinedVariable",
        "Function my_own_helper not found.",
        r"Call to an undefined static method App\Models\User::notAQueryMethod().",
        r"Access to an undefined property App\A::$input.",
        r"Class Google\Client not found.",
    ],
)
def test_real_errors_survive_laravel_filter(message: str) -> None:
    assert not LARAVEL.is_noise(message)


def test_ci3_filter_still_hides_what_laravel_keeps() -> None:
    message = r"Access to an undefined property App\A::$input."
    assert CI3.is_noise(message)
    assert not LARAVEL.is_noise(message)


# ---------------------------------------------------------------------------
# Rector config
# ---------------------------------------------------------------------------


def test_laravel_rector_config_has_imports_paths_and_skip(tmp_path: Path) -> None:
    source = tmp_path / "Illuminate"
    config = RectorConverter(rector_exe="rector")._write_rector_config(
        tmp_path / "out", ["LaravelSetList::LARAVEL_90"], LARAVEL, [source]
    )
    text = config.read_text(encoding="utf-8")
    config.unlink()
    assert "use RectorLaravel\\Set\\LaravelSetList;" in text
    assert f"->withAutoloadPaths([\n        '{source.as_posix()}'," in text
    assert "->withSkip([\n        '*.blade.php'," in text
    assert "SetList::TYPE_DECLARATION" not in LARAVEL.quality_sets


def test_rector_config_is_valid_php(tmp_path: Path) -> None:
    php = shutil.which("php")
    if php is None:
        pytest.skip("php not installed")
    config = RectorConverter(rector_exe="rector")._write_rector_config(
        tmp_path / "out", ["LaravelSetList::LARAVEL_90"], LARAVEL, [tmp_path]
    )
    result = subprocess.run([php, "-l", str(config)], capture_output=True, text=True)
    config.unlink()
    assert result.returncode == 0, result.stdout


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------


def test_composer_override_names_target() -> None:
    action, suggestion, safe = lv.composer_override(lock_version(8), 12, "8.2")
    assert (action, safe) == ("upgrade", False)
    assert "^12.0" in suggestion


def test_composer_analyzer_uses_override() -> None:
    entry = ("upgrade", "custom text", False)
    rec = ComposerAnalyzer(overrides={"laravel/framework": entry})._evaluate("laravel/framework", "^8.0")
    assert rec.suggestion == "custom text"


# ---------------------------------------------------------------------------
# Semgrep rules (end to end)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def laravel_scan(tmp_path_factory: pytest.TempPathFactory):
    """Scan a copy of the sample: Semgrep ignores tests/ paths by default."""
    try:
        exe = _find_semgrep_exe()
    except FileNotFoundError:
        pytest.skip("semgrep not installed")
    target = tmp_path_factory.mktemp("scan") / "app"
    shutil.copytree(SAMPLE, target)
    scanner = SemgrepScanner(semgrep_exe=exe, exclude_dirs=list(LARAVEL.default_exclude_dirs), profile=LARAVEL)
    return scanner.run(target)


def _hits(result, rule: str) -> list:
    return [f for f in result.findings if f.rule_id.endswith(rule)]


def test_blade_raw_output_is_xss_and_escaped_output_is_not(laravel_scan) -> None:
    hits = _hits(laravel_scan, "laravel-blade-raw-output-xss")
    assert [f.line_start for f in hits] == [1]
    assert hits[0].vuln_type == "XSS"


@pytest.mark.parametrize(
    ("rule", "vuln_type"),
    [
        ("laravel-mass-assignment-empty-guarded", "Mass Assignment"),
        ("laravel-mass-assignment-request-all", "Mass Assignment"),
        ("laravel-raw-query-concat-sql-injection", "SQL Injection"),
        ("laravel-env-outside-config", "Other"),
        ("laravel-debug-enabled", "Other"),
    ],
)
def test_rules_fire_with_expected_category(laravel_scan, rule: str, vuln_type: str) -> None:
    hits = _hits(laravel_scan, rule)
    assert hits, f"{rule} did not fire"
    assert {f.vuln_type for f in hits} == {vuln_type}


def test_env_inside_config_is_allowed(laravel_scan) -> None:
    hits = _hits(laravel_scan, "laravel-env-outside-config")
    assert all("config" not in Path(f.file_path).parts for f in hits)
