"""Victim-namespace drop stays fail-closed until a verified callback names 172.29.0.10."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from threatfusion.api.live_soc_console import (
    RANGE_ATTACKER_CONTAINER,
    RANGE_VICTIM_CONTAINER,
    approve_live_soar,
    contain_range_source,
    persist_scored_flow,
    range_docker_argv,
    rollback_range_source,
    score_canonical_flow,
    store_flow_provenance,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]


def _features() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


class _Runner:
    def __init__(self, *, running: bool = True) -> None:
        self.running = running
        self.blocked = False
        self.calls: list[str] = []

    def __call__(self, action: str) -> dict[str, bool]:
        self.calls.append(action)
        if action == "status":
            return {"running": self.running}
        if action == "drop":
            self.blocked = True
            return {"applied": True}
        if action == "rollback":
            self.blocked = False
            return {"removed": True}
        if action == "probe":
            return {"reachable": not self.blocked}
        raise AssertionError(action)


def _ready(tmp_path: Path, source: str = "172.29.0.10") -> tuple[Path, Path, int]:
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    flow_id = int(stored["flow_id"])
    store_flow_provenance(
        live_db,
        flow_id,
        entity_namespace_id="lab:range-bridge-01",
        src_entity_id=source,
        dst_entity_id="172.29.0.20",
        protocol="tcp",
        service_or_port="80",
        clock_synchronized=True,
    )
    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    assert approved["containment_executed"] is False
    with sqlite3.connect(live_db) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET callback_recorded = 1, callback_signature = ?
            WHERE flow_id = ?
            """,
            ("ab" * 32, flow_id),
        )
    return live_db, soar_db, flow_id


def test_range_commands_stay_inside_the_named_containers() -> None:
    for action in ("status", "drop_check", "drop", "rollback", "probe"):
        argv = range_docker_argv(action)
        assert argv[0] == "docker"
        assert argv[1] in {"inspect", "exec"}
        if "iptables" in argv:
            assert argv[1] == "exec"
            assert argv[2] == RANGE_VICTIM_CONTAINER
        if "curl" in argv:
            assert argv[2] == RANGE_ATTACKER_CONTAINER
            assert "http://172.29.0.20/" in argv


def test_containment_refuses_without_the_exact_callback_and_when_the_range_is_down(
    tmp_path: Path,
) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path, source="10.0.0.4")
    runner = _Runner()
    refused = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert refused["http_status"] == 403
    assert refused["containment_executed"] is False
    assert runner.calls == []

    live_db, soar_db, flow_id = _ready(tmp_path / "callback")
    with sqlite3.connect(live_db) as conn:
        conn.execute("UPDATE live_flows SET callback_recorded = 0, callback_signature = ''")
    refused = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert refused["reason"] == "callback_not_recorded"
    assert refused["http_status"] == 403

    live_db, soar_db, flow_id = _ready(tmp_path / "down")
    stopped = _Runner(running=False)
    down = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=stopped)
    assert down["reason"] == "range_not_running"
    assert down["containment_executed"] is False
    assert "drop" not in stopped.calls


def test_drop_and_rollback_follow_the_victim_probe(tmp_path: Path) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path)
    runner = _Runner()
    dropped = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert dropped["evidence_state"] == "verified"
    assert dropped["containment_executed"] is True
    assert dropped["reason"] == "containment_applied"
    assert runner.calls == ["status", "drop", "probe"]
    restored = rollback_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert restored["containment_executed"] is False
    assert restored["reason"] == "containment_rolled_back"
    assert runner.blocked is False
