"""Fail-closed live analyst console: Suricata admission, UNSW scoring, WAL, MITRE retrieval."""

from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from threatfusion.advisory.chromadb_mitre_rag import ChromaDbMitrePlaybookRag
from threatfusion.api.live_analyst_console import (
    PRODUCTION_FUSION_ENABLED,
    LiveAdmissionLedger,
    LiveConsoleError,
    answer_mitre_copilot,
    ingest_suricata_eve,
    ingest_unsw_raw_row,
    serve_live_analyst_console,
)
from threatfusion.datasets.unsw_raw import UNSW_RAW_COLUMN_COUNT

REPO_ROOT = Path(__file__).resolve().parents[3]


def _suricata_record() -> dict[str, object]:
    return {
        "timestamp": "2026-10-15T12:00:00.000000+00:00",
        "event_type": "flow",
        "src_ip": "198.51.100.27",
        "src_port": 44120,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "flow_id": 98765432101234,
        "flow": {
            "pkts_toserver": 15,
            "pkts_toclient": 12,
            "bytes_toserver": 1250,
            "bytes_toclient": 4800,
            "start": "2026-10-15T12:00:00.000000+00:00",
            "end": "2026-10-15T12:00:01.500000+00:00",
        },
        "rf_attack_probability": 0.99,
        "decision": "Attack",
    }


def test_suricata_admission_stores_features_and_withholds_decision(tmp_path: Path) -> None:
    ledger = LiveAdmissionLedger(tmp_path / "live.sqlite3")
    stored = ingest_suricata_eve(ledger, _suricata_record(), repo_root=REPO_ROOT)

    assert PRODUCTION_FUSION_ENABLED is False
    assert stored["replayed"] is False
    assert stored["production_fusion_enabled"] is False
    assert stored["evidence_state"] == "adapted_unscored"
    assert stored["scoring_reason"] == "suricata_flow_is_not_a_registered_unsw_raw_row"
    assert stored["rf_decision"] is None
    assert stored["rf_attack_probability"] is None
    assert stored["rf_model_sha256"] is None
    assert stored["ae_reconstruction_error"] is None
    assert stored["features"]["dst_port"] == 80
    assert stored["features"]["protocol_tcp"] == 1.0
    assert stored["endpoints"]["dst_ip"] == "10.0.0.5"
    assert ledger.journal_mode() == "wal"
    assert stat.S_IMODE(ledger.db_path.stat().st_mode) == 0o600

    replay = ingest_suricata_eve(ledger, _suricata_record(), repo_root=REPO_ROOT)
    assert replay["replayed"] is True
    assert replay["admission_id"] == stored["admission_id"]
    assert ledger.count() == 1


def test_invalid_suricata_and_fusion_request_do_not_persist(tmp_path: Path) -> None:
    ledger = LiveAdmissionLedger(tmp_path / "live.sqlite3")
    with pytest.raises(LiveConsoleError, match="suricata_record_rejected"):
        ingest_suricata_eve(ledger, {"event_type": "alert"}, repo_root=REPO_ROOT)
    with pytest.raises(LiveConsoleError, match="production_fusion_enabled_must_remain_false"):
        ingest_suricata_eve(
            ledger,
            {"record": _suricata_record(), "production_fusion_enabled": True},
            repo_root=REPO_ROOT,
        )
    assert ledger.count() == 0


def test_unsw_raw_row_fail_closed_without_invented_score(tmp_path: Path) -> None:
    ledger = LiveAdmissionLedger(tmp_path / "live.sqlite3")
    with pytest.raises(LiveConsoleError, match="unsw_raw_row_invalid"):
        ingest_unsw_raw_row(ledger, {"raw_values": ["0"]}, repo_root=REPO_ROOT)

    stored = ingest_unsw_raw_row(
        ledger,
        {"raw_values": ["0"] * UNSW_RAW_COLUMN_COUNT, "production_fusion_enabled": False},
        repo_root=REPO_ROOT,
    )
    assert stored["ae_reconstruction_error"] is None
    assert stored["production_fusion_enabled"] is False
    if stored["evidence_state"] == "live_scored":
        assert stored["scoring_state"] == "completed"
        assert stored["rf_decision"] in {"Attack", "Normal"}
        assert stored["rf_model_sha256"] == (
            "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        )
        assert 0.0 <= stored["rf_attack_probability"] <= 1.0
    else:
        assert stored["rf_decision"] is None
        assert stored["rf_attack_probability"] is None
        assert stored["rf_model_sha256"] is None
        assert stored["evidence_state"] in {
            "model_supply_chain_unverified",
            "scoring_rejected",
        }
    assert ledger.count() == 1


def test_mitre_copilot_retrieves_without_changing_the_decision(tmp_path: Path) -> None:
    ledger = LiveAdmissionLedger(tmp_path / "live.sqlite3")
    stored = ingest_suricata_eve(ledger, _suricata_record(), repo_root=REPO_ROOT)
    rag = ChromaDbMitrePlaybookRag(tmp_path / "rag.sqlite3")

    with pytest.raises(LiveConsoleError, match="empty_question"):
        answer_mitre_copilot(question="   ", rag=rag)

    answer = answer_mitre_copilot(
        question="network service discovery active scanning probe",
        rag=rag,
        ledger=ledger,
        admission_id=stored["admission_id"],
    )
    assert answer["detection_authority"] is False
    assert answer["production_fusion_enabled"] is False
    assert answer["evidence_state"] == "retrieved"
    assert any(hit["technique_id"] == "T1046" for hit in answer["hits"])
    reread = ledger.get(stored["admission_id"])
    assert reread is not None
    assert reread["rf_decision"] is None
    assert reread["rf_attack_probability"] is None
    assert reread["evidence_state"] == "adapted_unscored"
    assert reread["mitre_hits"][0]["technique_id"]


def test_loopback_http_queue_and_copilot(tmp_path: Path) -> None:
    server = serve_live_analyst_console(
        host="127.0.0.1",
        port=0,
        ledger_path=tmp_path / "live.sqlite3",
        repo_root=REPO_ROOT,
        rag_db_path=tmp_path / "rag.sqlite3",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
            assert response.status == 200
            assert 'data-queue-source="live"' in page
        body = json.dumps(_suricata_record()).encode("utf-8")
        request = urllib.request.Request(
            base + "/api/v1/ingest/suricata-eve",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            admitted = json.loads(response.read().decode("utf-8"))
        assert admitted["rf_decision"] is None
        with urllib.request.urlopen(base + "/api/v1/live-queue", timeout=2) as response:
            queue = json.loads(response.read().decode("utf-8"))
        assert queue["production_fusion_enabled"] is False
        assert len(queue["admissions"]) == 1
        question = json.dumps(
            {
                "question": "exploit public facing application",
                "admission_id": admitted["admission_id"],
            }
        ).encode("utf-8")
        copilot = urllib.request.Request(
            base + "/api/v1/copilot/mitre",
            data=question,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(copilot, timeout=2) as response:
            answer = json.loads(response.read().decode("utf-8"))
        assert answer["detection_authority"] is False
        assert answer["hits"]
        huge = urllib.request.Request(
            base + "/api/v1/ingest/suricata-eve",
            data=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(1024 * 1024 + 1)},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(huge, timeout=2)
        assert raised.value.code == 413
    finally:
        server.shutdown()
        server.server_close()


def test_console_js_defaults_to_stored_campaigns() -> None:
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    page = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "fetch('/api/v1/live/campaigns')" in script
    assert "let selectedIncidentId = '';" in script
    assert "Campaign store unavailable. Offline sample queue is the fallback." in script
    assert 'data-queue-source="live"' in page
    assert "selectedIncidentId = SAMPLE_INCIDENTS[0].id;" not in script


def test_non_loopback_bind_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LiveConsoleError, match="loopback_bind_required"):
        serve_live_analyst_console(
            host="0.0.0.0",
            port=0,
            ledger_path=tmp_path / "live.sqlite3",
            repo_root=REPO_ROOT,
        )
