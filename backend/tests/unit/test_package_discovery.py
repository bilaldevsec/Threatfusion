"""Unit tests for package discovery, zero-PYTHONPATH editable installation, and TF-005 parsing."""

from datetime import UTC, datetime
import os
from pathlib import Path
import subprocess
import sys
import warnings

import pytest
from setuptools import find_packages

from threatfusion.datasets.adapters.base import SourceRowValidationError, parse_required_timestamp

ALL_THREATFUSION_PACKAGES = [
    "threatfusion",
    "threatfusion.alerts",
    "threatfusion.api",
    "threatfusion.config",
    "threatfusion.datasets",
    "threatfusion.datasets.adapters",
    "threatfusion.db",
    "threatfusion.features",
    "threatfusion.models",
    "threatfusion.operations",
    "threatfusion.preprocessing",
    "threatfusion.schemas",
    "threatfusion.utils",
]


def test_setuptools_find_packages_discovers_all_subpackages() -> None:
    """Setuptools discovery locates all subpackages under backend/src."""
    repo_root = Path(__file__).resolve().parents[3]
    backend_src = repo_root / "backend" / "src"
    discovered = find_packages(where=str(backend_src))
    assert sorted(discovered) == sorted(ALL_THREATFUSION_PACKAGES)


def test_setuptools_find_packages_discovers_top_level_src() -> None:
    """Setuptools discovery from repo root locates top-level src package."""
    repo_root = Path(__file__).resolve().parents[3]
    discovered = find_packages(where=str(repo_root), include=["threatfusion*", "src*"])
    assert "src" in discovered


def test_subprocess_import_zero_pythonpath_external_cwd(tmp_path: Path) -> None:
    """Subprocess imports of threatfusion and all subpackages succeed from external cwd without PYTHONPATH."""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    script = "\n".join(
        [
            "import sys",
            "packages = [",
            *[f"    {pkg!r}," for pkg in ALL_THREATFUSION_PACKAGES],
            "    'src',",
            "]",
            "for pkg in packages:",
            "    mod = __import__(pkg)",
            "    assert mod is not None",
            "import src",
            "import threatfusion",
            "assert src.threatfusion is threatfusion",
            "print('ALL_PACKAGES_IMPORTED_SUCCESSFULLY')",
        ]
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert (
        result.returncode == 0
    ), f"Subprocess failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    assert "ALL_PACKAGES_IMPORTED_SUCCESSFULLY" in result.stdout


def test_clean_source_alias_resolution(tmp_path: Path) -> None:
    """src alias resolves directly to threatfusion package namespace without side-effects."""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    script = (
        "import src\n"
        "import threatfusion\n"
        "assert src.threatfusion is threatfusion\n"
        "assert threatfusion.__name__ == 'threatfusion'\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert (
        result.returncode == 0
    ), f"Subprocess failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"


def test_tf_005_iso_timestamp_parsing_without_pandas_warnings() -> None:
    """ISO-8601 timestamps parse cleanly to UTC without emitting UserWarning (TF-005)."""
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")

        dt1 = parse_required_timestamp("2026-03-01T10:00:00Z", "test_source", "timestamp")
        assert dt1 == datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)

        dt2 = parse_required_timestamp("2026-03-01T10:00:00.123456Z", "test_source", "timestamp")
        assert dt2 == datetime(2026, 3, 1, 10, 0, 0, 123456, tzinfo=UTC)

        dt3 = parse_required_timestamp("2026-03-01T12:00:00+02:00", "test_source", "timestamp")
        assert dt3 == datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)

        dt4 = parse_required_timestamp("2026-03-01T10:00:00", "test_source", "timestamp")
        assert dt4 == datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)

        # Confirm zero UserWarnings were captured during ISO timestamp parsing
        user_warnings = [w for w in recorded if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0


def test_tf_005_epoch_and_fallback_parsing() -> None:
    """Numeric epoch seconds and dayfirst fallback parse accurately; invalid values fail closed."""
    # Numeric epoch
    dt_epoch = parse_required_timestamp("1422057600", "unsw_nb15", "stime")
    assert dt_epoch == datetime(2015, 1, 24, 0, 0, 0, tzinfo=UTC)

    # Datetime object pass-through
    raw_dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert parse_required_timestamp(raw_dt, "test", "time") == raw_dt

    # Missing / empty fails closed
    with pytest.raises(SourceRowValidationError):
        parse_required_timestamp("", "test", "time")
    with pytest.raises(SourceRowValidationError):
        parse_required_timestamp(None, "test", "time")
    with pytest.raises(SourceRowValidationError):
        parse_required_timestamp("not-a-timestamp", "test", "time")
