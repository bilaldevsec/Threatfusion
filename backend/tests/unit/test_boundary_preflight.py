"""B6 runtime import isolation. A stand-in directory represents the protected repo."""

from __future__ import annotations

from pathlib import Path

from threatfusion.evaluation.boundary_preflight import (
    CANONICAL_ACTIVE_WORKSPACE,
    check_b6_runtime_import_isolation,
    run_boundary_preflight,
)


def test_b6_fails_when_pythonpath_points_at_protected_stand_in(tmp_path: Path) -> None:
    stand_in = tmp_path / "protected_stand_in"
    stand_in.mkdir()
    active = CANONICAL_ACTIVE_WORKSPACE.resolve()
    module_file = active / "backend" / "src" / "threatfusion" / "__init__.py"
    passed, findings = check_b6_runtime_import_isolation(
        active_rp=active,
        protected_rp=stand_in.resolve(),
        pythonpath=str(stand_in),
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert passed is False
    assert any(item.startswith("B6: PYTHONPATH entry ") for item in findings)

    report = run_boundary_preflight(
        protected=stand_in,
        pythonpath=str(stand_in),
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert report.checks["B6"]["passed"] is False
    assert report.decision_verdict == "NO-GO"
    assert report.passed is False


def test_b6_passes_when_pythonpath_is_unset() -> None:
    active = CANONICAL_ACTIVE_WORKSPACE.resolve()
    module_file = active / "backend" / "src" / "threatfusion" / "__init__.py"
    passed, findings = check_b6_runtime_import_isolation(
        active_rp=active,
        protected_rp=Path("/tmp/threatfusion-b6-absent-stand-in"),
        pythonpath="",
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert passed is True
    assert findings == []

    report = run_boundary_preflight(pythonpath="", module_file=module_file)
    assert report.checks["B6"]["passed"] is True
    assert report.decision_verdict == "GO"
    assert report.passed is True
