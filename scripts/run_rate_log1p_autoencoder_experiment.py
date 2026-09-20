"""Historical rate-log1p runner, closed after its blocked one-attempt disposition.

The retained ``prepare`` and ``run`` implementation documents the executed experiment, but is unsafe
to reuse until the preparation-access and resource-enforcement defects in the frozen protocol are
corrected under new authorization. The CLI rejects both modes. ``render`` remains available to recover
presentation files from an already completed report without fitting or scoring.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path

for variable in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "BLIS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ[variable] = "1"

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "backend/src"
CLOSED_EXECUTION_CODE = "experiment_closed_blocked_no_reuse"


def _landlock(read_paths: list[Path], write_paths: list[Path]) -> dict[str, object]:
    libc = ctypes.CDLL(None, use_errno=True)
    create, add, restrict = 444, 445, 446
    abi = libc.syscall(create, 0, 0, 1)
    if abi < 3:
        raise RuntimeError("landlock_abi_too_old")
    handled = (1 << 15) - 1

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathRule(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    attr = Ruleset(handled)
    ruleset_fd = libc.syscall(create, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    read_access = 1 | 4 | 8
    write_access = handled
    try:
        read_rules = [(path, read_access if path.is_dir() else (1 | 4)) for path in read_paths]
        for path, access in read_rules + [(p, write_access) for p in write_paths]:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(access, fd)
                if libc.syscall(add, ruleset_fd, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule:{path}")
            finally:
                os.close(fd)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl_no_new_privs")
        if libc.syscall(restrict, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset_fd)
    return {"mechanism": "Linux Landlock", "abi": int(abi), "no_new_privileges": True}


def _assert_denied(paths: list[Path]) -> list[dict[str, object]]:
    evidence = []
    for path in paths:
        try:
            with path.open("rb") as handle:
                handle.read(1)
        except PermissionError as exc:
            evidence.append({"path": str(path), "denied": True, "errno": exc.errno})
        else:
            raise RuntimeError(f"prohibited_path_accessible:{path.name}")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "run", "render"))
    parser.add_argument("--prepared-id", default="rate-log1p-january-input-b5e6e5d-v1")
    parser.add_argument("--preprocessing-id", default="rate-log1p-all-train-b5e6e5d-v1")
    parser.add_argument("--run-id", default="rate-log1p-autoencoder-b5e6e5d-v1")
    args = parser.parse_args()
    if args.mode in {"prepare", "run"}:
        print(f"rate-log1p experiment failed code={CLOSED_EXECUTION_CODE}", file=sys.stderr)
        return 1
    prepared = ROOT / "data/processed/unsw_rate_log1p_inputs" / args.prepared_id
    preprocessing = (
        ROOT / "data/processed/unsw_network_rate_log1p_preprocessing" / args.preprocessing_id
    )
    run = ROOT / "artifacts/models/network_rate_log1p_autoencoder" / args.run_id
    baseline = ROOT / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1"
    forest = (
        ROOT
        / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1"
    )
    protocol = ROOT / "docs/network_rate_log1p_autoencoder_protocol.md"
    for path in (prepared.parent, preprocessing.parent, run.parent):
        path.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(SOURCE))
    if args.mode == "prepare":
        from threatfusion.models.network_rate_log1p_experiment import prepare_january_rate_inputs

        result = prepare_january_rate_inputs(
            project_root=ROOT,
            manifest_path=ROOT / "data/manifests/unsw_nb15.yaml",
            assignment_directory=ROOT
            / "data/interim/unsw_development_split/full-assignment-f10992-v1",
            preflight_report_path=ROOT
            / "data/interim/unsw_split_preflight/full-f10992-v1/preflight_report.json",
            baseline_directory=baseline,
            output_directory=prepared,
        )
        print(
            f"admission completed=true train={result['populations']['train']['rows']} validation={result['populations']['validation']['rows']}"
        )
        return 0
    if args.mode == "render":
        from threatfusion.models.network_rate_log1p_experiment import render_report

        markdown, chart = render_report(run / "evaluation_report.json", run)
        print(f"render completed=true report={markdown} chart={chart}")
        return 0
    read_paths = [
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc"),
        Path("/proc"),
        ROOT / ".venv",
        Path(sys.base_prefix),
        SOURCE,
        Path(__file__),
        protocol,
        prepared,
        baseline,
        forest,
    ]
    read_paths.extend([Path("/sys"), Path("/dev")])
    isolation = _landlock(read_paths, [preprocessing.parent, run.parent, Path("/tmp")])
    isolation["denial_probes"] = _assert_denied(
        [
            ROOT / "data/raw/unsw_nb15/official/UNSW-NB15_1.csv",
            ROOT
            / "artifacts/reports/network_classical_evaluation/full-february-classical-2528ee8-v1/X_test.npy",
            ROOT
            / "artifacts/reports/network_classical_evaluation/full-february-classical-2528ee8-v1/y_test.npy",
            ROOT
            / "data/raw/cse_cic_ids2018/official/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        ]
    )
    from threatfusion.models.network_rate_log1p_experiment import run_experiment

    result = run_experiment(
        project_root=ROOT,
        prepared_directory=prepared,
        baseline_directory=baseline,
        forest_directory=forest,
        preprocessing_directory=preprocessing,
        run_directory=run,
        protocol_path=protocol,
        isolation_evidence=isolation,
    )
    print(
        f"experiment completed=true passed={str(result.passed).lower()} artifact_identity={result.artifact_identity} report={result.report_path}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = getattr(exc, "code", "experiment_cli_failure")
        print(f"rate-log1p experiment failed code={code}", file=sys.stderr)
        raise SystemExit(1)
