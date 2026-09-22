"""Focused contract and cleanup tests for the evaluator demonstration."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Event, enumerate as enumerate_threads

import pytest

import scripts.run_fyp_progress_demo as demo
from scripts.run_fyp_progress_demo import (
    V2_ARTIFACT_IDENTITY,
    DemoError,
    _temporary_runtime,
    _validate_report,
    _write_report,
)


def _valid_report() -> dict[str, object]:
    return {
        "status": "completed",
        "random_forest_producer_demo": {
            "status": "completed",
            "tls_version": "TLSv1.3",
            "records": [
                {
                    "known_label": "Normal",
                    "predicted_class": "Normal",
                    "disposition": "not_actionable",
                    "alert_candidate_id": None,
                },
                {
                    "known_label": "Attack",
                    "predicted_class": "Attack",
                    "disposition": "created",
                    "alert_candidate_id": "a" * 64,
                },
            ],
            "alerts_after_first": 1,
            "inference_calls_after_first": 2,
            "alert_insert_calls_after_first": 1,
            "replay": {
                "http_status": 200,
                "wire_bytes_identical": True,
                "cached_response_bytes_identical": True,
                "alerts_after_retry": 1,
                "inference_calls_after_retry": 2,
                "alert_insert_calls_after_retry": 1,
            },
            "authenticated_invalid_request": {
                "http_status": 400,
                "reason": "request_rejected",
                "response_bound": True,
                "alerts_after_rejection": 1,
                "inference_calls_after_rejection": 2,
                "alert_insert_calls_after_rejection": 1,
            },
        },
        "experimental_v2_autoencoder_demo": {
            "status": "completed",
            "artifact_identity": V2_ARTIFACT_IDENTITY,
            "artifact_files_verified": 9,
            "product_registry_approved": False,
            "producer_workflow_integrated": False,
            "fusion_enabled": False,
            "records": [
                {
                    "reconstruction_score": 0.1,
                    "threshold": 0.2,
                    "operator": ">",
                    "anomaly": False,
                },
                {
                    "reconstruction_score": 0.3,
                    "threshold": 0.2,
                    "operator": ">",
                    "anomaly": True,
                },
            ],
        },
    }


def test_demo_evidence_contract_accepts_exact_replay_and_separate_ae() -> None:
    _validate_report(_valid_report())


def test_demo_evidence_contract_rejects_repeated_inference() -> None:
    report = _valid_report()
    report["random_forest_producer_demo"]["replay"]["inference_calls_after_retry"] = 4
    with pytest.raises(DemoError, match="^demo_assertion_failed$"):
        _validate_report(report)


def test_temporary_runtime_cleans_up_after_failure() -> None:
    retained: Path | None = None
    with pytest.raises(RuntimeError, match="stop"):
        with _temporary_runtime() as runtime:
            retained = runtime
            (runtime / "private.key").write_text("temporary", encoding="ascii")
            raise RuntimeError("stop")
    assert retained is not None and not retained.exists()


def test_evidence_write_is_complete_json(tmp_path: Path) -> None:
    report = _valid_report()
    target = _write_report(report, tmp_path)
    assert json.loads(target.read_text(encoding="utf-8")) == report
    assert not tuple(tmp_path.glob(".*.tmp"))


def test_setup_failure_closes_service_and_exits_nonzero(monkeypatch, capsys) -> None:
    class Service:
        alerts = object()
        orchestrator = object()
        closed = 0

        def close(self) -> None:
            self.closed += 1

    service = Service()
    monkeypatch.setattr(demo, "_git_revision", lambda: "a" * 40)
    monkeypatch.setattr(demo, "UnswNetworkInferenceBoundary", lambda **kwargs: object())
    monkeypatch.setattr(demo, "_autoencoder_evidence", lambda boundary: {})
    monkeypatch.setattr(demo, "_create_credentials", lambda runtime: {})
    monkeypatch.setattr(demo, "_create_service", lambda *args: service)

    def fail_instrumentation(*args) -> None:
        raise DemoError("instrumentation_setup_failed")

    monkeypatch.setattr(demo, "_instrument_actual_calls", fail_instrumentation)

    assert demo.main([]) == 1
    assert service.closed == 1
    assert json.loads(capsys.readouterr().out) == {
        "reason": "instrumentation_setup_failed",
        "status": "failed",
    }


def test_client_failure_closes_listener_and_joins_request_thread(monkeypatch) -> None:
    closed = Event()

    class Listener:
        address = ("127.0.0.1", 1)

        def close(self) -> None:
            closed.set()

    class Orchestrator:
        def process_one(self) -> None:
            if not closed.wait(1):
                raise RuntimeError("listener_not_closed")

    service = type("Service", (), {"listener": Listener(), "orchestrator": Orchestrator()})()

    def fail_connect(*args, **kwargs) -> None:
        raise OSError

    monkeypatch.setattr(demo.socket, "create_connection", fail_connect)
    with pytest.raises(DemoError, match="^loopback_tls_exchange_failed$"):
        demo._exchange(service, {}, b"request")
    assert closed.is_set()
    assert not any(thread.name == "threatfusion-fyp-demo-request" for thread in enumerate_threads())
