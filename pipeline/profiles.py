"""
profiles.py -- Profil framework untuk pipeline migrasi.

Mengumpulkan semua hal yang berbeda antar framework (filter noise PHPStan,
konfigurasi Semgrep tambahan, set Rector, konteks prompt AI) sebagai data,
sehingga modul lain tidak perlu bercabang berdasarkan nama framework.
Profil ``ci3`` adalah default dan menjaga perilaku pipeline tetap sama.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    from pipeline.laravel_version import (
        FrameworkConfigError,
        LaravelVersionInfo,
        composer_override,
        detect_laravel_version,
        ensure_laravel_sources,
        rector_sets_for_upgrade,
        validate_target,
    )
except ModuleNotFoundError:
    from laravel_version import (  # type: ignore[no-redef]
        FrameworkConfigError,
        LaravelVersionInfo,
        composer_override,
        detect_laravel_version,
        ensure_laravel_sources,
        rector_sets_for_upgrade,
        validate_target,
    )

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# (keywords, vuln_type_label, iso_controls, priority) -- same shape as scanner._VULN_RULES
VulnRule = tuple[tuple[str, ...], str, list[str], int]

# Code quality sets appended after the Rector level chain.
DEFAULT_QUALITY_SETS: tuple[str, ...] = (
    "SetList::CODE_QUALITY",
    "SetList::DEAD_CODE",
    "SetList::EARLY_RETURN",
    "SetList::TYPE_DECLARATION",
)

# ---------------------------------------------------------------------------
# CI3 framework false-positive filter
# ---------------------------------------------------------------------------
# PHPStan cannot see CodeIgniter 3's dynamic architecture: the base classes
# live in system/ (excluded), constants are defined at runtime in index.php,
# and Composer vendor/ is not copied to output/.  All errors matching these
# substrings are CI3 structural noise, not real application bugs.
_CI3_NOISE_SUBSTRINGS: tuple[str, ...] = (
    # CI3 base class hierarchy (system/ excluded from analysis)
    "extends unknown class CI_",
    "extends unknown class MX_",
    # CI3 runtime constants (defined by index.php, invisible to static analysis)
    "Constant ENVIRONMENT not found",
    "Constant FCPATH not found",
    "Constant APPPATH not found",
    "Constant BASEPATH not found",
    "Constant EXT not found",
    # CI3 built-in magic properties accessed via $this->
    "::$load.", "::$db.", "::$input.", "::$output.",
    "::$config.", "::$session.", "::$uri.", "::$router.",
    "::$security.", "::$form_validation.", "::$email.",
    "::$upload.", "::$pagination.", "::$cache.", "::$lang.",
    "::$benchmark.", "::$hooks.",
    # CI3 URL / form / template helpers (loaded by CI3, not in PHPStan scope)
    "Function base_url not found",
    "Function site_url not found",
    "Function redirect not found",
    "Function anchor not found",
    "Function form_open not found",
    "Function form_close not found",
    "Function set_value not found",
    "Function form_error not found",
    "Function validation_errors not found",
    "Function get_instance not found",
    "Function log_message not found",
    "Function show_error not found",
    "Function show_404 not found",
    "Function html_escape not found",
    "Function set_status_header not found",
    "Function current_url not found",
    "Function previous_url not found",
    "Function strip_image_tags not found",
    "Function encode_php_tags not found",
    "Function function_usable not found",
    "Function is_https not found",
    "Function is_cli not found",
    "Function remove_invisible_characters not found",
    # Composer packages absent from output/ (vendor/ not copied by Rector).
    # Matched on the bare namespace so both "unknown class X\..." and
    # "Instantiated class X\... not found" phrasings are caught -- PHPStan
    # uses different verbs depending on how the class is referenced.
    "Dotenv\\",
    "createUnsafeImmutable",
    "createMutable",
    "PhpOffice\\",
    "Firebase\\",
    "Google\\",
    "chriskacerguis\\",
    "Kreait\\",
    "Ngekoding\\",
)

# ---------------------------------------------------------------------------
# Laravel false-positive filter
# ---------------------------------------------------------------------------
# output/ has no vendor/, so PHPStan cannot see framework classes.  Only
# "symbol is missing" messages are filtered.  Messages that merely mention a
# framework type (e.g. "expects Illuminate\Http\Request, string given") are
# real errors and must stay visible.
_LARAVEL_VENDOR_NS = r"(?:Illuminate|Laravel|Symfony|Carbon|Fruitcake|Fideloper|Facade)\\"
_LARAVEL_HELPERS = (
    "abort|abort_if|abort_unless|app|asset|auth|back|bcrypt|cache|collect|config|"
    "cookie|csrf_token|database_path|dd|dispatch|dump|e|env|event|info|logger|"
    "now|old|optional|policy|public_path|redirect|report|request|rescue|resolve|"
    "resource_path|response|retry|route|session|storage_path|tap|throw_if|"
    "throw_unless|today|trans|url|validator|value|view"
)
# Eloquent forwards these to the query builder through __callStatic and __call,
# which PHPStan reports as undefined on model classes.
_ELOQUENT_FORWARDED = (
    "count|create|find|findMany|findOrFail|first|firstOrCreate|firstOrFail|firstOrNew|"
    "firstWhere|get|join|latest|leftJoin|limit|oldest|orderBy|paginate|pluck|select|"
    "simplePaginate|updateOrCreate|where|whereBetween|whereDate|whereHas|whereIn|"
    "whereNotIn|whereNotNull|whereNull|with|withCount"
)
_LARAVEL_NOISE_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^Call to an undefined (?:static )?method App\\\S+::(?:" + _ELOQUENT_FORWARDED + r")\(\)"
    ),
    re.compile(rf"unknown (?:class|trait|interface) {_LARAVEL_VENDOR_NS}"),
    re.compile(rf"\b[Cc]lass {_LARAVEL_VENDOR_NS}\S+ not found"),
    re.compile(rf"has invalid (?:return )?type {_LARAVEL_VENDOR_NS}"),
    re.compile(rf"has unknown class {_LARAVEL_VENDOR_NS}"),
    re.compile(rf"^Function (?:{_LARAVEL_HELPERS}) not found"),
)


# ---------------------------------------------------------------------------
# Profile definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkProfile:
    """Semua hal yang berbeda antar framework; modul lain hanya membaca data ini."""

    name: str
    # analyzer.py
    noise_substrings: tuple[str, ...] = ()
    noise_regexes: tuple[re.Pattern[str], ...] = ()
    # scanner.py
    extra_semgrep_configs: tuple[Path, ...] = ()
    extra_vuln_rules: tuple[VulnRule, ...] = ()
    # converter.py
    rector_imports: tuple[str, ...] = ()
    rector_skip: tuple[str, ...] = ()
    quality_sets: tuple[str, ...] = DEFAULT_QUALITY_SETS
    # main.py: merged with --exclude
    default_exclude_dirs: tuple[str, ...] = ()
    # ai_engine.py: appended to the prompt context; empty = prompt unchanged
    ai_context: str = ""

    def is_noise(self, message: str) -> bool:
        """Return True if a PHPStan message is framework noise for this profile."""
        return any(s in message for s in self.noise_substrings) or any(
            r.search(message) for r in self.noise_regexes
        )


CI3 = FrameworkProfile(name="ci3", noise_substrings=_CI3_NOISE_SUBSTRINGS)

LARAVEL = FrameworkProfile(
    name="laravel",
    noise_regexes=_LARAVEL_NOISE_REGEXES,
    extra_semgrep_configs=(_PROJECT_ROOT / "rules_frameworks" / "laravel",),
    extra_vuln_rules=(
        (("mass-assignment",), "Mass Assignment", ["A.8.28", "A.8.26"], 3),
    ),
    rector_imports=("RectorLaravel\\Set\\LaravelSetList",),
    rector_skip=("*.blade.php",),
    # TYPE_DECLARATION stays off until checked against real applications: added
    # types must match framework parent signatures, and the sample app is too
    # small to show that they do.
    quality_sets=tuple(s for s in DEFAULT_QUALITY_SETS if s != "SetList::TYPE_DECLARATION"),
    default_exclude_dirs=("vendor", "node_modules", "storage"),
    ai_context=(
        "Framework: Laravel. Prefer Eloquent or query builder bindings, "
        "Blade {{ }} escaping, and $fillable over $guarded = []."
    ),
)

_PROFILES: dict[str, FrameworkProfile] = {p.name: p for p in (CI3, LARAVEL)}
FRAMEWORK_CHOICES: tuple[str, ...] = tuple(_PROFILES)


def get_profile(name: str) -> FrameworkProfile:
    """Return the profile called *name*, or raise FrameworkConfigError."""
    try:
        return _PROFILES[name]
    except KeyError:
        raise FrameworkConfigError(f"Unknown framework profile: {name}") from None


# ---------------------------------------------------------------------------
# Per-run resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkRun:
    """A profile plus the values that depend on the application being migrated."""

    profile: FrameworkProfile = CI3
    current_version: LaravelVersionInfo | None = None
    target_major: int | None = None
    rector_sets: tuple[str, ...] = ()
    composer_overrides: dict[str, tuple[str, str, bool]] = field(default_factory=dict)
    # Framework sources for symbol lookup only; empty = tool calls unchanged.
    # Rector gets the framework alone: scanning all of vendor/ made its workers time out.
    rector_symbol_paths: tuple[Path, ...] = ()
    phpstan_symbol_paths: tuple[Path, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Return the fields recorded in pipeline_result_*.json."""
        cur = self.current_version
        return {
            "name": self.profile.name,
            "current_version": f"{cur.major}.{cur.minor}" if cur else None,
            "version_source": cur.source if cur else None,
            "target_major": self.target_major,
            "rector_sets": list(self.rector_sets),
        }


def resolve_framework_run(
    name: str,
    input_dir: Path,
    target_php: str,
    target_laravel: int | None = None,
) -> FrameworkRun:
    """
    Build the FrameworkRun for this pipeline run.

    Raises FrameworkConfigError for impossible combinations, so main.py can stop
    before output/ is cleaned.
    """
    profile = get_profile(name)

    if profile is not LARAVEL:
        if target_laravel is not None:
            raise FrameworkConfigError("--target-laravel needs --framework laravel.")
        warnings: tuple[str, ...] = ()
        if (input_dir / "artisan").is_file():
            warnings = (
                "File 'artisan' found in the input: this looks like a Laravel app, "
                "but the ci3 profile is active. Use --framework laravel if it is.",
            )
        return FrameworkRun(profile=profile, warnings=warnings)

    current = detect_laravel_version(input_dir)
    if current is None:
        raise FrameworkConfigError(
            f"laravel/framework not found in composer.lock or composer.json under {input_dir}."
        )
    warnings = tuple(validate_target(current, target_laravel, target_php))

    # Rector's Laravel rules fail without these classes, so a requested upgrade
    # needs them.  The target major is used because it has every class those rules
    # name; e.g. the Laravel 9 set expects the Factory class added in Laravel 8.
    rector_paths: tuple[Path, ...] = ()
    phpstan_paths: tuple[Path, ...] = ()
    source_major = target_laravel or current.major
    try:
        sources = ensure_laravel_sources(source_major)
        rector_paths = (sources.vendor / "laravel" / "framework" / "src" / "Illuminate",)
        phpstan_paths = (sources.vendor,)
        if sources.has_advisories:
            warnings += (
                f"Composer blocks Laravel {source_major} because of security advisories, "
                "so upgrading the application to it will fail or stay vulnerable. "
                "Check https://packagist.org/security-advisories/ and consider a newer target.",
            )
    except FrameworkConfigError as exc:
        if target_laravel is not None:
            raise
        warnings += (f"{exc} PHPStan will not see Laravel classes.",)

    return FrameworkRun(
        profile=profile,
        current_version=current,
        target_major=target_laravel,
        rector_sets=tuple(rector_sets_for_upgrade(current, target_laravel)),
        composer_overrides={
            "laravel/framework": composer_override(current, target_laravel, target_php)
        },
        rector_symbol_paths=rector_paths,
        phpstan_symbol_paths=phpstan_paths,
        warnings=warnings,
    )
