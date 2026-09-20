"""Bind the completed rate-log1p experiment and rendered outputs without recomputation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "artifacts/models/network_rate_log1p_autoencoder/rate-log1p-autoencoder-b5e6e5d-v1"
PREPROCESSING = (
    ROOT / "data/processed/unsw_network_rate_log1p_preprocessing/rate-log1p-all-train-b5e6e5d-v1"
)
PREPARED = ROOT / "data/processed/unsw_rate_log1p_inputs/rate-log1p-january-input-b5e6e5d-v1"
BASELINE_EXPECTED = {
    "autoencoder_config.json": "51d4d664b5e017c5b039a08dc897d63e81a0b1e140eb1bb16457997ffa0727c2",
    "autoencoder_state.pt": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    "threshold.json": "79bc7f3def3a4ed745fbc85d9cbf36a04f4fb4384de4db065569f81f60c78e3e",
    "artifact_manifest.json": "c142d3352b406a689b6317f48ae513540076b02ffb2e0fdef9cd3e6a83da1866",
    "evaluation_report.json": "0ec77eda4a58e40e1b75087bbc5131f39cad54d553771e174ea303bc506c3bef",
}
MAX_BYTES = 256 * 1024**2


def digest(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def main() -> None:
    report = json.loads((RUN / "evaluation_report.json").read_text(encoding="utf-8"))
    if report.get("completed") is not True or report.get("disposition") != "FAIL_preserve_baseline":
        raise RuntimeError("completed_failed_candidate_report_required")
    source_snapshot = RUN / "completion_finalizer.snapshot.py"
    source_snapshot.write_bytes(Path(__file__).read_bytes())
    bound = {
        "run": {
            path.name: digest(path)
            for path in sorted(RUN.iterdir())
            if path.is_file() and path.name != "completion_manifest.json"
        },
        "preprocessing": {
            path.name: digest(path) for path in sorted(PREPROCESSING.iterdir()) if path.is_file()
        },
        "admitted_inputs": {
            path.name: digest(path) for path in sorted(PREPARED.iterdir()) if path.is_file()
        },
    }
    baseline_dir = ROOT / "artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2"
    baseline = {name: digest(baseline_dir / name) for name in BASELINE_EXPECTED}
    if any(baseline[name]["sha256"] != expected for name, expected in BASELINE_EXPECTED.items()):
        raise RuntimeError("baseline_autoencoder_hash_mismatch")
    total = sum(item["size_bytes"] for group in bound.values() for item in group.values())
    if total > MAX_BYTES:
        raise RuntimeError("candidate_artifact_budget_exceeded")
    admission = json.loads((PREPARED / "admission_report.json").read_text(encoding="utf-8"))
    preparation_test_rows = admission["admission_boundary"]["test_rows_seen_for_alignment_only"]
    review_blockers = [
        {
            "code": "preparation_accessed_february_test_rows",
            "evidence": {"test_rows_seen": preparation_test_rows},
        },
        {
            "code": "preparation_resource_limits_not_hard_enforced",
            "evidence": "preparation recorded runtime and peak RSS only after traversal",
        },
        {
            "code": "artifact_budget_not_verified_before_fitting",
            "evidence": "candidate artifact total was checked only after model fitting",
        },
        {
            "code": "execution_peak_rss_not_hard_enforced",
            "evidence": "peak RSS was checked only after fitting and scoring completed",
        },
        {
            "code": "cli_failure_code_not_strictly_allowlisted",
            "evidence": "generic exceptions may contribute exception-derived text to stderr",
        },
    ]
    payload = {
        "schema_version": "unsw_rate_log1p_completion_manifest_v1",
        "completed": True,
        "reported_scientific_disposition": "FAIL_preserve_baseline",
        "completion_review_disposition": "BLOCKED_preserve_baseline",
        "protocol_valid": False,
        "review_blockers": review_blockers,
        "candidate_metrics_retained_as_protocol_invalid_development_evidence": True,
        "no_training_fitting_calibration_or_scoring": True,
        "bound_files": bound,
        "baseline_autoencoder": baseline,
        "baseline_preserved": True,
        "bound_candidate_bytes_before_this_manifest": total,
        "artifact_budget_bytes": MAX_BYTES,
        "finalizer_source": digest(source_snapshot),
    }
    temporary = RUN / "completion_manifest.json.tmp"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(RUN / "completion_manifest.json")
    print(
        "completion bound=true "
        f"disposition={payload['completion_review_disposition']} bytes={total}"
    )


if __name__ == "__main__":
    main()
