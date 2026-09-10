"""AlertCandidate identity, SQLite idempotency, and registered-UNSW integration tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import csv
import hashlib
import json
import math
import sqlite3
from uuid import uuid4

import numpy as np
import pytest
import yaml

import threatfusion.models.network_inference as inference
from threatfusion.alerts.network_alerts import (
    build_alert_candidate,
    infer_and_persist_registered_attack,
)
from threatfusion.db.alert_repository import (
    MAX_ALERT_LIST_LIMIT,
    AlertCandidateRepository,
    AlertPersistenceError,
)
from threatfusion.models.network_inference import (
    NetworkInferenceResult,
    RegisteredUnswInferenceResult,
)
from threatfusion.preprocessing.network_behavior_v1 import NetworkBehaviorPreprocessor
from threatfusion.schemas.alert_candidate import (
    ALERT_CANDIDATE_SCHEMA_VERSION,
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    AlertCandidateError,
    derive_alert_candidate_id,
    derive_source_event_id,
)

RAW_NAMES = tuple(
    "srcip sport dstip dsport proto state dur sbytes dbytes sttl dttl sloss dloss service "
    "sload dload spkts dpkts swin dwin stcpb dtcpb smeansz dmeansz trans_depth res_bdy_len "
    "sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat is_sm_ips_ports ct_state_ttl "
    "ct_flw_http_mthd is_ftp_login ct_ftp_cmd ct_srv_src ct_srv_dst ct_dst_ltm ct_src_ltm "
    "ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm attack_cat label".split()
)


def _raw_row(*, label: str = "0") -> list[str]:
    values = dict.fromkeys(RAW_NAMES, "0")
    values.update(
        srcip="192.0.2.1",
        dstip="198.51.100.2",
        sport="1234",
        dsport="443",
        proto="tcp",
        dur="0.1",
        sbytes="120",
        dbytes="60",
        spkts="2",
        dpkts="1",
        stime="1421928000",
        ltime="1421928001",
        label=label,
    )
    return [values[name] for name in RAW_NAMES]


def _registered_result(
    *,
    correlation_id: str | None = None,
    score: float = 0.75,
    model_identity: str = "random_forest",
    model_version: str = "network_random_forest_baseline_v1",
    artifact_sha256: str = "a" * 64,
    predicted_class: str = "Attack",
    status: str = "completed",
) -> RegisteredUnswInferenceResult:
    return RegisteredUnswInferenceResult(
        source_event_id=derive_source_event_id(
            source_representation=inference.UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            manifest_sha256="b" * 64,
            source_member_sha256="c" * 64,
            row_number=7,
        ),
        observed_at=datetime(2015, 1, 22, tzinfo=UTC),
        model_artifact_sha256=artifact_sha256,
        inference=NetworkInferenceResult(
            correlation_id=correlation_id or str(uuid4()),
            model_identity=model_identity,
            model_version=model_version,
            contract_identity="network_behavior_v1",
            source_representation_identity=inference.UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            attack_probability=score if status == "completed" else None,
            decision_threshold=0.5,
            predicted_class=predicted_class if status == "completed" else None,
            status=status,
            reason="inference_succeeded" if status == "completed" else "model_prediction_failed",
            processed_at=datetime.now(UTC).isoformat(),
            latency_ms=1.0,
        ),
    )


def _candidate(**updates):
    registered = _registered_result(
        correlation_id=updates.pop("correlation_id", None),
        score=updates.pop("score", 0.75),
        model_identity=updates.pop("model_identity", "random_forest"),
        model_version=updates.pop("model_version", "network_random_forest_baseline_v1"),
        artifact_sha256=updates.pop("artifact_sha256", "a" * 64),
    )
    candidate = build_alert_candidate(
        registered, created_at=updates.pop("created_at", datetime(2026, 9, 10, tzinfo=UTC))
    )
    return replace(candidate, **updates) if updates else candidate


def test_source_and_candidate_ids_are_deterministic_and_domain_bound():
    first = _candidate(correlation_id=str(uuid4()), created_at=datetime(2026, 9, 10, tzinfo=UTC))
    retry = _candidate(correlation_id=str(uuid4()), created_at=datetime(2026, 9, 11, tzinfo=UTC))
    assert first.source_event_id == retry.source_event_id
    assert first.alert_candidate_id == retry.alert_candidate_id

    logistic = _candidate(
        model_identity="logistic_regression",
        model_version="network_logistic_baseline_v1",
        artifact_sha256="d" * 64,
    )
    changed_policy = derive_alert_candidate_id(
        source_event_id=first.source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity=first.model_identity,
        model_version=first.model_version,
        model_artifact_sha256=first.model_artifact_sha256,
        decision_policy_version="different_policy_v2",
    )
    changed_detector = derive_alert_candidate_id(
        source_event_id=first.source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version="v2",
        model_identity=first.model_identity,
        model_version=first.model_version,
        model_artifact_sha256=first.model_artifact_sha256,
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    assert (
        len(
            {
                first.alert_candidate_id,
                logistic.alert_candidate_id,
                changed_policy,
                changed_detector,
            }
        )
        == 4
    )
    assert first.schema_version == ALERT_CANDIDATE_SCHEMA_VERSION


@pytest.mark.parametrize(
    "registered",
    [
        _registered_result(predicted_class="Normal"),
        _registered_result(status="rejected"),
    ],
)
def test_only_successful_attack_inference_can_create_candidate(registered):
    with pytest.raises(AlertCandidateError, match="^inference_not_actionable$"):
        build_alert_candidate(registered)


def test_alert_contract_is_utc_and_privacy_minimized():
    candidate = _candidate()
    assert candidate.observed_at.utcoffset() == candidate.created_at.utcoffset() == timedelta(0)
    assert "uncalibrated_model_score" in candidate.to_dict()
    assert repr(candidate) == "<AlertCandidate>"
    prohibited = {
        "raw_row",
        "feature_values",
        "transformed_features",
        "src_ip",
        "dst_ip",
        "label",
        "attack_category",
        "filename",
        "path",
        "severity",
        "confidence",
        "incident_id",
    }
    assert prohibited.isdisjoint(candidate.to_dict())
    with pytest.raises(AlertCandidateError, match="^alert_candidate_invalid$"):
        replace(candidate, created_at=datetime(2026, 9, 10))


def test_first_insert_retry_conflict_and_retrieval(tmp_path):
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    first = _candidate(correlation_id=str(uuid4()))
    retry = _candidate(correlation_id=str(uuid4()), created_at=datetime(2026, 9, 11, tzinfo=UTC))
    assert repository.insert(first).disposition == "created"
    existing = repository.insert(retry)
    assert existing.disposition == "existing"
    assert existing.candidate == first
    assert repository.get(first.alert_candidate_id) == first
    assert repository.get("alert_candidate_v1:" + "0" * 64) is None

    conflicting = replace(first, uncalibrated_model_score=0.8)
    with pytest.raises(AlertPersistenceError, match="^alert_candidate_identity_conflict$"):
        repository.insert(conflicting)
    assert repository.get(first.alert_candidate_id) == first


def test_one_ulp_score_roundoff_is_idempotent_after_reopen(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    first = _candidate(
        correlation_id=str(uuid4()),
        created_at=datetime(2026, 9, 10, tzinfo=UTC),
        score=0.75,
    )
    retry = _candidate(
        correlation_id=str(uuid4()),
        created_at=datetime(2026, 9, 11, tzinfo=UTC),
        score=math.nextafter(0.75, 1.0),
    )

    assert AlertCandidateRepository(path).insert(first).disposition == "created"
    result = AlertCandidateRepository(path).insert(retry)

    assert result.disposition == "existing"
    assert result.candidate == first
    assert AlertCandidateRepository(path).list() == (first,)


def test_listing_is_bounded_and_deterministic(tmp_path):
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    candidates = []
    for index in range(4):
        registered = _registered_result(artifact_sha256=f"{index + 10:064x}")
        candidate = build_alert_candidate(
            registered,
            created_at=datetime(2026, 9, 10, index // 2, tzinfo=UTC),
        )
        repository.insert(candidate)
        candidates.append(candidate)
    expected = sorted(candidates, key=lambda item: (item.created_at, item.alert_candidate_id))
    assert repository.list(limit=2) == tuple(expected[:2])
    assert repository.list(limit=2, offset=2) == tuple(expected[2:])
    for limit in (0, MAX_ALERT_LIST_LIMIT + 1, True, "1"):
        with pytest.raises(AlertPersistenceError, match="^list_limit_invalid$"):
            repository.list(limit=limit)
    for offset in (-1, 1_000_001, True, "0"):
        with pytest.raises(AlertPersistenceError, match="^list_offset_invalid$"):
            repository.list(offset=offset)


def test_reopen_preserves_rows_and_schema_mismatch_fails(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    candidate = _candidate()
    AlertCandidateRepository(path).insert(candidate)
    assert AlertCandidateRepository(path).get(candidate.alert_candidate_id) == candidate
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 2")
    with pytest.raises(AlertPersistenceError, match="^database_schema_mismatch$"):
        AlertCandidateRepository(path)


def test_weakened_column_constraints_fail_schema_verification(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE repository_metadata (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT INTO repository_metadata VALUES (?, ?)",
            ("schema_identity", "alert_candidate_sqlite_v1"),
        )
        connection.execute(
            "CREATE TABLE alert_candidates ("
            + ", ".join(f"{name} TEXT" for name in _candidate().to_dict())
            + ")"
        )
        connection.execute("PRAGMA user_version = 1")
    with pytest.raises(AlertPersistenceError, match="^database_schema_mismatch$"):
        AlertCandidateRepository(path)


def test_corruption_is_not_replaced_and_errors_are_sanitized(tmp_path):
    path = tmp_path / "secret-database.sqlite3"
    damaged = b"not a sqlite database /private/secret"
    path.write_bytes(damaged)
    with pytest.raises(AlertPersistenceError, match="^database_corrupt$") as error:
        AlertCandidateRepository(path)
    assert path.read_bytes() == damaged
    assert "secret" not in str(error.value)
    assert "/private" not in str(error.value)


def test_failed_insert_rolls_back_and_hides_sqlite_details(tmp_path):
    path = tmp_path / "alerts.sqlite3"
    repository = AlertCandidateRepository(path)
    first = _candidate()
    repository.insert(first)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON alert_candidates "
            "BEGIN SELECT RAISE(ABORT, 'secret SQL detail'); END"
        )
    second = _candidate(artifact_sha256="d" * 64)
    with pytest.raises(AlertPersistenceError, match="^database_write_failed$") as error:
        repository.insert(second)
    assert repository.list() == (first,)
    assert "secret" not in str(error.value)


def test_database_lock_is_bounded_and_sanitized(tmp_path):
    path = tmp_path / "private-lock.sqlite3"
    repository = AlertCandidateRepository(path)
    lock = sqlite3.connect(path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(AlertPersistenceError, match="^database_busy$") as error:
            repository.insert(_candidate())
    finally:
        lock.rollback()
        lock.close()
    assert "private" not in str(error.value)
    assert "sqlite" not in str(error.value).lower()


def test_concurrent_retries_create_exactly_one_row(tmp_path):
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    candidates = [
        _candidate(
            correlation_id=str(uuid4()), created_at=datetime(2026, 9, 10, 0, index, tzinfo=UTC)
        )
        for index in range(8)
    ]
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(repository.insert, candidates))
    assert [result.disposition for result in results].count("created") == 1
    assert [result.disposition for result in results].count("existing") == 7
    assert len(repository.list()) == 1


class _ScoreModel:
    classes_ = np.asarray([0, 1])

    def __init__(self, attack_score=0.75):
        self.attack_score = attack_score
        self.calls = 0

    def predict_proba(self, matrix):
        self.calls += 1
        return np.asarray([[1 - self.attack_score, self.attack_score]])


def _make_registered_boundary(tmp_path, monkeypatch, raw_values=None, raw_rows=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    metadata = b"No.,Name,Type,Description\n" + b"".join(
        f"{index},{name},type,fixture\n".encode() for index, name in enumerate(RAW_NAMES, 1)
    )
    metadata_path = tmp_path / "NUSW-NB15_features.csv"
    metadata_path.write_bytes(metadata)
    raw_path = tmp_path / "UNSW-NB15_1.csv"
    rows = raw_rows if raw_rows is not None else [raw_values or _raw_row()]
    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerows(rows)
    raw_digest = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    manifest = yaml.safe_dump(
        {
            "name": "unsw_nb15",
            "version": "fixture",
            "license_note": "fixture",
            "files": [
                {
                    "path": metadata_path.name,
                    "role": "raw",
                    "rows": 49,
                    "sha256": hashlib.sha256(metadata).hexdigest(),
                },
                {
                    "path": raw_path.name,
                    "role": "raw",
                    "rows": len(rows),
                    "sha256": raw_digest,
                },
            ],
        }
    ).encode()
    manifest_path = tmp_path / "data/manifests/unsw_nb15.yaml"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(manifest)
    monkeypatch.setattr(
        inference, "APPROVED_UNSW_MANIFEST_HASH", hashlib.sha256(manifest).hexdigest()
    )
    model = _ScoreModel()
    monkeypatch.setattr(inference, "_preprocessing_snapshot", lambda path: {})
    monkeypatch.setattr(inference, "_model_snapshot", lambda path, choice: {})
    monkeypatch.setattr(
        inference,
        "_verify_preprocessor",
        lambda snapshot: NetworkBehaviorPreprocessor(1, (0.0,) * 10, (1.0,) * 10, ()),
    )
    monkeypatch.setattr(
        inference,
        "_verify_model",
        lambda snapshot, choice: inference._LoadedModel(
            model,
            choice.value,
            (
                "network_random_forest_baseline_v1"
                if choice is inference.NetworkModelChoice.RANDOM_FOREST
                else "network_logistic_baseline_v1"
            ),
        ),
    )
    return (
        inference.UnswNetworkInferenceBoundary(project_root=tmp_path),
        raw_digest,
        model,
        raw_path,
    )


@pytest.fixture
def registered_boundary(tmp_path, monkeypatch):
    return _make_registered_boundary(tmp_path, monkeypatch)


def test_registered_unsw_attack_persists_idempotently(registered_boundary, tmp_path):
    boundary, member_digest, model, _ = registered_boundary
    repository = AlertCandidateRepository(tmp_path / "state/alerts.sqlite3")
    first = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256=member_digest, row_number=1
    )
    retry = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256=member_digest, row_number=1
    )
    assert first.disposition == "created"
    assert retry.disposition == "existing"
    assert (
        first.persistence.candidate.alert_candidate_id
        == retry.persistence.candidate.alert_candidate_id
    )
    assert len(repository.list()) == 1
    assert model.calls == 2


def test_rejected_unknown_or_normal_registered_input_creates_no_candidate(
    registered_boundary, tmp_path
):
    boundary, member_digest, model, raw_path = registered_boundary
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    unknown = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256="d" * 64, row_number=1
    )
    raw_path.write_bytes(b"corrupt registered member")
    rejected = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256=member_digest, row_number=1
    )
    assert (unknown.disposition, rejected.disposition) == ("not_actionable", "not_actionable")
    assert model.calls == 0
    assert repository.list() == ()


def test_registered_malformed_row_creates_no_candidate(tmp_path, monkeypatch):
    malformed = _raw_row()
    malformed[RAW_NAMES.index("dur")] = "nan"
    boundary, member_digest, model, _ = _make_registered_boundary(
        tmp_path / "registered", monkeypatch, malformed
    )
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    outcome = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256=member_digest, row_number=1
    )
    assert (outcome.disposition, outcome.reason) == (
        "not_actionable",
        "registered_event_rejected",
    )
    assert model.calls == 0
    assert repository.list() == ()


def test_registered_digest_covers_exact_csv_stream_and_logical_record_ordinal(
    tmp_path, monkeypatch
):
    first = _raw_row()
    first[RAW_NAMES.index("attack_cat")] = "quoted\nvalue"
    second = _raw_row()
    second[RAW_NAMES.index("stime")] = "1421929000"
    boundary, member_digest, model, _ = _make_registered_boundary(
        tmp_path / "registered",
        monkeypatch,
        raw_rows=[first, second],
    )
    real_fdopen = inference.os.fdopen

    class NoRewind:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def seek(self, *args, **kwargs):
            pytest.fail("registered bytes were reopened or reread after digesting")

    monkeypatch.setattr(
        inference.os,
        "fdopen",
        lambda descriptor, *args, **kwargs: NoRewind(real_fdopen(descriptor, *args, **kwargs)),
    )

    result = boundary.infer_registered(source_member_sha256=member_digest, row_number=2)

    assert result.observed_at == datetime.fromtimestamp(1421929000, tz=UTC)
    assert model.calls == 1


def test_repository_insert_never_invokes_predictor(registered_boundary, tmp_path, monkeypatch):
    boundary, member_digest, model, _ = registered_boundary
    registered = boundary.infer_registered(source_member_sha256=member_digest, row_number=1)
    candidate = build_alert_candidate(registered)
    before = model.calls

    def forbidden(*args, **kwargs):
        pytest.fail("persistence invoked prediction")

    monkeypatch.setattr(inference, "attack_probabilities", forbidden)
    repository = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    repository.insert(candidate)
    assert model.calls == before


def test_database_stores_only_candidate_columns(registered_boundary, tmp_path):
    boundary, member_digest, _, _ = registered_boundary
    path = tmp_path / "alerts.sqlite3"
    repository = AlertCandidateRepository(path)
    outcome = infer_and_persist_registered_attack(
        boundary, repository, source_member_sha256=member_digest, row_number=1
    )
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(alert_candidates)")}
        stored = json.dumps(connection.execute("SELECT * FROM alert_candidates").fetchone())
    assert columns == set(outcome.persistence.candidate.to_dict())
    for secret in ("192.0.2.1", "198.51.100.2", "UNSW-NB15_1.csv", str(tmp_path), "feature_values"):
        assert secret not in stored
