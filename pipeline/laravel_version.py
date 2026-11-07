"""
laravel_version.py -- Deteksi versi Laravel dan aturan upgrade-nya.

Membaca versi aplikasi dari composer.lock atau composer.json, menghitung set
Rector yang diperlukan, dan menolak kombinasi versi Laravel dan PHP yang mustahil.
Data versi PHP berasal dari constraint laravel/framework di Packagist (2026-11-07).

Juga mengunduh sumber Laravel ke cache lokal sebagai referensi simbol untuk Rector
dan PHPStan.  Unduhan tidak menjalankan kode apa pun dan tidak mengirim kode aplikasi.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_PACKAGE = "laravel/framework"

SOURCES_CACHE: Path = Path(__file__).resolve().parent.parent / ".cache" / "laravel_sources"

MIN_SOURCE_MAJOR = 6
TESTED_SOURCE_MAJORS = (6, 7, 8)
MAX_KNOWN_MAJOR = 13

# Minimum PHP allowed by the composer constraint of each Laravel major.
PHP_FLOOR: dict[int, tuple[int, int]] = {
    6: (7, 2), 7: (7, 2), 8: (7, 3), 9: (8, 0),
    10: (8, 1), 11: (8, 2), 12: (8, 2), 13: (8, 3),
}

# First release of each major whose composer constraint accepts PHP 8.
FIRST_PHP8_RELEASE: dict[int, tuple[int, int]] = {6: (6, 20), 7: (7, 29), 8: (8, 12)}


class FrameworkConfigError(ValueError):
    """Raised when the requested framework settings cannot work."""


@dataclass(frozen=True)
class LaravelVersionInfo:
    """Laravel version of the application being migrated."""

    major: int
    minor: int
    source: Literal["composer.lock", "composer.json"]


def _read_json(path: Path) -> dict | None:
    """Return parsed JSON from *path*, or None if missing or invalid."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _lowest_version(constraint: str) -> tuple[int, int] | None:
    """Return the lowest (major, minor) named in a composer constraint."""
    found = [
        (int(major), int(minor or 0))
        for major, minor in re.findall(r"(?<![\w.])v?(\d+)(?:\.(\d+))?", constraint)
    ]
    return min(found) if found else None


def detect_laravel_version(input_dir: Path) -> LaravelVersionInfo | None:
    """
    Read the application's Laravel version; composer.lock wins over composer.json.

    A composer.json constraint can name several versions, so its lowest one is
    used.  That can only add upgrade rules, never skip a needed one.
    """
    lock = _read_json(input_dir / "composer.lock")
    if lock is not None:
        for package in lock.get("packages", []):
            if package.get("name") == _PACKAGE:
                version = _lowest_version(str(package.get("version", "")))
                if version:
                    return LaravelVersionInfo(*version, source="composer.lock")

    manifest = _read_json(input_dir / "composer.json")
    if manifest is not None:
        version = _lowest_version(str(manifest.get("require", {}).get(_PACKAGE, "")))
        if version:
            return LaravelVersionInfo(*version, source="composer.json")
    return None


def rector_sets_for_upgrade(
    current: LaravelVersionInfo, target_major: int | None
) -> list[str]:
    """Return per-version Rector sets after the current major, up to the target."""
    if target_major is None:
        return []
    return [
        f"LaravelSetList::LARAVEL_{major}0"
        for major in range(current.major + 1, target_major + 1)
    ]


def _php_tuple(version: str) -> tuple[int, int]:
    """Convert ``"8.3"`` to ``(8, 3)``."""
    major, minor = version.split(".")[:2]
    return int(major), int(minor)


def validate_target(
    current: LaravelVersionInfo, target_major: int | None, target_php: str
) -> list[str]:
    """Raise FrameworkConfigError on impossible settings; return non-fatal warnings."""
    if current.major < MIN_SOURCE_MAJOR:
        raise FrameworkConfigError(
            f"Laravel {current.major}.{current.minor} is not supported: "
            f"the source must be Laravel {MIN_SOURCE_MAJOR} or newer."
        )
    if target_major is not None:
        if target_major > MAX_KNOWN_MAJOR:
            raise FrameworkConfigError(
                f"Laravel {target_major} is unknown: "
                f"the newest known major is {MAX_KNOWN_MAJOR}."
            )
        if target_major < current.major:
            raise FrameworkConfigError(
                f"--target-laravel {target_major} is older than the application "
                f"(Laravel {current.major}.{current.minor})."
            )

    effective = target_major if target_major is not None else current.major
    php = _php_tuple(target_php)
    floor = PHP_FLOOR.get(effective)
    if floor is not None and php < floor:
        raise FrameworkConfigError(
            f"Laravel {effective} needs PHP {floor[0]}.{floor[1]} or newer, "
            f"but the target is PHP {target_php}."
        )

    warnings: list[str] = []
    if current.major not in TESTED_SOURCE_MAJORS:
        warnings.append(
            f"Laravel {current.major} as a source is untested: only "
            f"{TESTED_SOURCE_MAJORS[0]}-{TESTED_SOURCE_MAJORS[-1]} were designed for."
        )
    first_php8 = FIRST_PHP8_RELEASE.get(current.major)
    if (
        target_major in (None, current.major)
        and php >= (8, 0)
        and first_php8 is not None
        and current.source == "composer.lock"
        and (current.major, current.minor) < first_php8
    ):
        warnings.append(
            f"Laravel {current.major}.{current.minor} does not accept PHP 8: update to "
            f"{first_php8[0]}.{first_php8[1]} or newer, or set --target-laravel."
        )
    if effective <= 8 and php > (8, 0):
        warnings.append(
            f"Laravel {effective} allows PHP ^8.0 in composer, which does not guarantee "
            f"it runs well on PHP {target_php}. Consider a newer --target-laravel."
        )
    return warnings


@dataclass(frozen=True)
class LaravelSources:
    """Cached Laravel sources, used only to look up symbols."""

    vendor: Path
    has_advisories: bool


def _run_composer(cmd: list[str], project: Path, timeout_sec: int) -> subprocess.CompletedProcess[str]:
    """Run Composer in *project* and capture its output."""
    return subprocess.run(
        cmd, cwd=project, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout_sec,
    )


def ensure_laravel_sources(
    major: int, cache_root: Path = SOURCES_CACHE, timeout_sec: int = 600
) -> LaravelSources:
    """
    Return cached sources of Laravel *major*, downloading them if needed.

    Scripts and plugins are disabled, so the download executes no package code.
    Composer refuses majors with security advisories.  These files are only read
    for symbols, so the download retries with --no-security-blocking and reports
    has_advisories, which main.py shows as a warning about the chosen target.
    Raises FrameworkConfigError when the sources cannot be obtained.
    """
    project = cache_root / str(major)
    marker = project / ".complete"
    if marker.is_file():
        advisories = marker.read_text(encoding="utf-8").strip() == "advisories"
        return LaravelSources(project / "vendor", advisories)

    composer = shutil.which("composer")
    if composer is None:
        raise FrameworkConfigError("Composer not found on PATH: cannot get Laravel sources.")

    cmd = [
        composer, "install", "--no-scripts", "--no-plugins", "--no-autoloader",
        "--ignore-platform-reqs", "--no-interaction", "--no-progress",
    ]
    advisories = False
    try:
        project.mkdir(parents=True, exist_ok=True)
        (project / "composer.json").write_text(
            json.dumps({"require": {_PACKAGE: f"^{major}.0"}}), encoding="utf-8"
        )
        proc = _run_composer(cmd, project, timeout_sec)
        output = " ".join(f"{proc.stdout} {proc.stderr}".split())
        if proc.returncode != 0 and "security advisories" in output:
            advisories = True
            proc = _run_composer([*cmd, "--no-security-blocking"], project, timeout_sec)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FrameworkConfigError(f"Could not get Laravel {major} sources: {exc}") from exc
    if proc.returncode != 0:
        raise FrameworkConfigError(
            f"Could not get Laravel {major} sources: {proc.stderr.strip()[-300:]}"
        )
    marker.write_text("advisories" if advisories else "ok", encoding="utf-8")
    return LaravelSources(project / "vendor", advisories)


def composer_override(
    current: LaravelVersionInfo, target_major: int | None, target_php: str
) -> tuple[str, str, bool]:
    """Return the (action, suggestion, php8_safe) entry for laravel/framework."""
    if target_major is not None and target_major > current.major:
        return (
            "upgrade",
            f"Update laravel/framework to ^{target_major}.0 and follow the official "
            f"upgrade guide for each major version; target PHP {target_php}.",
            False,
        )
    first_php8 = FIRST_PHP8_RELEASE.get(current.major)
    if first_php8 is not None and _php_tuple(target_php) >= (8, 0):
        return (
            "upgrade",
            f"laravel/framework accepts PHP 8 from {first_php8[0]}.{first_php8[1]} "
            f"in the {current.major}.x line; use that release or newer.",
            False,
        )
    return ("safe", f"Laravel {current.major} accepts PHP {target_php}.", True)
