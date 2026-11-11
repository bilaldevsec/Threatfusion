"""Victim-namespace drop stays fail-closed until a verified callback names 172.29.0.10."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from threatfusion.api.live_soc_console import (
    AZURE_LOCAL_CONTAINMENT_BADGE,
    RANGE_ATTACKER_CONTAINER,
    RANGE_VICTIM_CONTAINER,
    apply_azure_kernel_isolation,
    approve_live_soar,
    azure_victim_ssh_argv,
    contain_range_source,
    enroll_lab_operator,
    persist_scored_flow,
    probe_local_and_azure_firewall,
    range_docker_argv,
    read_azure_victim_public_ip,
    rollback_range_source,
    score_canonical_flow,
    store_flow_provenance,
    _run_range_action,
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
    policy = tmp_path / "operator-policy"
    policy.parent.mkdir(parents=True, exist_ok=True)
    if not policy.parent.is_symlink():
        os.chmod(policy.parent, 0o700)
    assert enroll_lab_operator(policy, "lab_operator")["identity_verified"] is True
    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=policy,
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


def test_rollback_refuses_before_containment_is_applied(tmp_path: Path) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path)
    runner = _Runner()
    refused = rollback_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert refused["reason"] == "containment_not_applied"
    assert refused["http_status"] == 409
    assert runner.calls == []


def test_scenario_replay_records_containment_without_a_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("threatfusion.api.live_soc_console._range_lab_active", lambda: False)
    live_db, soar_db, flow_id = _ready(tmp_path, source="10.0.0.4")
    with sqlite3.connect(live_db) as conn:
        conn.execute(
            "UPDATE live_flows SET source_label = ? WHERE flow_id = ?",
            ("live_scenario_replay", flow_id),
        )
    dropped = contain_range_source(live_db, soar_db, flow_id=flow_id)
    assert dropped["http_status"] == 200
    assert dropped["evidence_state"] == "simulated"
    assert dropped["containment_executed"] is False
    assert dropped["containment_state"] in {"simulated_applied", "simulated_rolled_back"}
    assert dropped["containment_state"] == "simulated_applied"
    assert dropped["reason"] == "simulated_containment_recorded"
    assert dropped["containment_mode"] == "simulated_scenario_no_host_enforcement"
    assert dropped["target"] == "10.0.0.4"
    assert dropped["simulated_rule"] == "iptables -I INPUT -s 10.0.0.4 -j DROP (simulated)"
    with sqlite3.connect(live_db) as conn:
        state, rule = conn.execute(
            "SELECT containment_state, containment_rule FROM live_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
    assert state == "simulated_applied"
    assert rule == "iptables -I INPUT -s 10.0.0.4 -j DROP (simulated)"
    with sqlite3.connect(soar_db) as conn:
        actions = [
            row[0]
            for row in conn.execute("SELECT action FROM soar_audit_events ORDER BY rowid ASC")
        ]
    assert "simulated_containment_recorded" in actions
    restored = rollback_range_source(live_db, soar_db, flow_id=flow_id)
    assert restored["evidence_state"] == "simulated"
    assert restored["containment_executed"] is False
    assert restored["containment_state"] in {"simulated_applied", "simulated_rolled_back"}
    assert restored["containment_state"] == "simulated_rolled_back"
    assert restored["reason"] == "simulated_rollback_recorded"
    assert restored["simulated_rule"] == "iptables -D INPUT -s 10.0.0.4 -j DROP (simulated)"
    with sqlite3.connect(live_db) as conn:
        state = conn.execute(
            "SELECT containment_state FROM live_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()[0]
    assert state == "simulated_rolled_back"


def test_injected_failing_runner_still_reports_range_down_for_the_lab_source(
    tmp_path: Path,
) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path)
    stopped = _Runner(running=False)
    down = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=stopped)
    assert down["reason"] == "range_not_running"
    assert down["containment_executed"] is False


def test_unknown_containment_target_is_rejected(tmp_path: Path) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path, source="203.0.113.50")
    refused = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=_Runner())
    assert refused["reason"] == "containment_target_rejected"
    assert refused["http_status"] == 403
    assert refused["containment_executed"] is False


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


def test_range_active_scenario_uses_real_iptables_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path, source="10.0.0.4")
    with sqlite3.connect(live_db) as conn:
        conn.execute(
            "UPDATE live_flows SET source_label = ? WHERE flow_id = ?",
            ("live_scenario_replay", flow_id),
        )
    monkeypatch.setattr(
        "threatfusion.api.live_soc_console._range_lab_active",
        lambda: True,
    )
    runner = _Runner()
    dropped = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=runner)
    assert dropped["http_status"] == 200
    assert dropped["evidence_state"] == "verified"
    assert dropped["reason"] == "containment_applied"
    assert dropped["containment_executed"] is True
    assert dropped["target"] == "172.29.0.10"
    assert "drop" in runner.calls
    assert "probe" in runner.calls


def test_azure_victim_address_rejects_missing_and_private_values(tmp_path: Path) -> None:
    assert read_azure_victim_public_ip(tmp_path / "absent.json") == ""
    path = tmp_path / "azure_portal_state.json"
    path.write_text(json.dumps({"victim_public_ip": "10.0.0.5"}), encoding="utf-8")
    assert read_azure_victim_public_ip(path) == ""
    path.write_text(json.dumps({"victim_public_ip": "52.230.32.81"}), encoding="utf-8")
    assert read_azure_victim_public_ip(path) == "52.230.32.81"
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    assert read_azure_victim_public_ip(link) == ""


def test_azure_ssh_commands_match_the_victim_kernel_filter() -> None:
    isolate = azure_victim_ssh_argv("52.230.32.81", "isolate")
    rollback = azure_victim_ssh_argv("52.230.32.81", "rollback")
    assert isolate[:6] == (
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=3",
        "-o",
    )
    assert isolate[-2] == "azureuser@52.230.32.81"
    assert (
        isolate[-1] == "sudo iptables -C INPUT -s 172.29.0.10 -j DROP 2>/dev/null "
        "|| sudo iptables -I INPUT 1 -s 172.29.0.10 -j DROP"
    )
    assert rollback[-1] == "sudo iptables -D INPUT -s 172.29.0.10 -j DROP 2>/dev/null || true"


def test_unreachable_azure_ssh_falls_back_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "azure_portal_state.json"
    path.write_text(json.dumps({"victim_public_ip": "52.230.32.81"}), encoding="utf-8")

    def unreachable(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=8)

    monkeypatch.setattr("subprocess.run", unreachable)
    result = apply_azure_kernel_isolation("isolate", state_path=path)
    assert result["attempted"] is True
    assert result["applied"] is False
    assert result["reason"] == "azure_ssh_unreachable"
    assert result["victim_public_ip"] == "52.230.32.81"


def test_local_drop_still_applies_when_azure_ssh_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "azure_portal_state.json"
    path.write_text(json.dumps({"victim_public_ip": "52.230.32.81"}), encoding="utf-8")
    monkeypatch.setattr(
        "threatfusion.api.live_soc_console.AZURE_PORTAL_STATE_PATH",
        path,
    )
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    seen: list[tuple[str, ...]] = []

    class _Completed:
        def __init__(self, code: int, stdout: str = "") -> None:
            self.returncode = code
            self.stdout = stdout
            self.stderr = ""

    def fake_run(argv: tuple[str, ...], **_kwargs: object) -> _Completed:
        seen.append(tuple(argv))
        if argv[0] == "ssh":
            raise OSError("azure ssh unreachable")
        return _Completed(0, "true")

    monkeypatch.setattr("subprocess.run", fake_run)
    dropped = _run_range_action("drop")
    assert dropped["applied"] is True
    assert dropped["azure_kernel"]["applied"] is False
    assert dropped["azure_kernel"]["reason"] == "azure_ssh_unreachable"
    assert any(item[0] == "ssh" and item[-2] == "azureuser@52.230.32.81" for item in seen)
    restored = _run_range_action("rollback")
    assert restored["removed"] is True
    assert restored["azure_kernel"]["reason"] == "azure_ssh_unreachable"


def test_dual_probe_badge_requires_local_and_azure_drops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "azure_portal_state.json"
    path.write_text(json.dumps({"victim_public_ip": "52.230.32.81"}), encoding="utf-8")

    class _Completed:
        def __init__(self, code: int) -> None:
            self.returncode = code
            self.stdout = ""
            self.stderr = ""

    def fake_run(argv: tuple[str, ...], **_kwargs: object) -> _Completed:
        if argv[0] == "ssh":
            assert argv[-1] == "sudo iptables -C INPUT -s 172.29.0.10 -j DROP"
            return _Completed(0)
        assert argv[0] == "docker"
        return _Completed(0)

    monkeypatch.setattr("subprocess.run", fake_run)
    probe = probe_local_and_azure_firewall(path)
    assert probe["local_drop_active"] is True
    assert probe["azure_drop_active"] is True
    assert probe["local_reachable"] is False
    assert probe["azure_reachable"] is False
    assert probe["badge"] == AZURE_LOCAL_CONTAINMENT_BADGE
    assert probe["status"] == "blocked_azure_and_local"


def test_containment_response_carries_the_azure_and_local_badge(tmp_path: Path) -> None:
    live_db, soar_db, flow_id = _ready(tmp_path)

    class _AzureRunner(_Runner):
        def __call__(self, action: str) -> dict[str, object]:
            result: dict[str, object] = dict(super().__call__(action))
            if action == "drop":
                result["azure_kernel"] = {
                    "attempted": True,
                    "applied": True,
                    "victim_public_ip": "52.230.32.81",
                }
            return result

    dropped = contain_range_source(live_db, soar_db, flow_id=flow_id, runner=_AzureRunner())
    assert dropped["reason"] == "containment_applied"
    assert dropped["firewall_scope"] == "azure_and_local"
    assert dropped["containment_badge"] == AZURE_LOCAL_CONTAINMENT_BADGE
    assert dropped["reachability_probe"]["badge"] == AZURE_LOCAL_CONTAINMENT_BADGE
    assert dropped["production_fusion_enabled"] is False


def test_console_isolate_button_posts_the_azure_local_badge() -> None:
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    server = (REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py").read_text(
        encoding="utf-8"
    )
    assert "/api/soar/isolate" in script
    assert "/api/soar/rollback" in script
    assert AZURE_LOCAL_CONTAINMENT_BADGE in script
    assert '"/api/soar/isolate"' in server
