"""Live console scoring, notes, copilot, drift, and n8n workbench."""

from __future__ import annotations

from pathlib import Path

import sqlite3

from threatfusion.api.live_soc_console import (
    add_analyst_note,
    answer_mitre_copilot,
    approve_live_soar,
    correlate_stored_attacks,
    drift_for_stored_flows,
    list_live_campaigns,
    list_live_flows,
    persist_scored_flow,
    private_ip_guard_response,
    read_n8n_workbench,
    record_triage_action,
    replay_benchmark_attack_burst,
    constitutional_health,
    replay_live_scenarios,
    score_canonical_flow,
    store_flow_provenance,
    export_grounded_handoff,
    record_analyst_verdict,
    record_case_assignment,
)
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _features(**overrides: float) -> dict[str, float]:
    values = {name: 1.0 for name in CANONICAL_14_FEATURES}
    values.update(overrides)
    return values


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


class _WideModel:
    n_features_in_ = 49

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        raise AssertionError("mismatched feature width must not be scored")


def test_score_uses_injected_forest_and_refuses_width_mismatch() -> None:
    scored = score_canonical_flow(
        _features(),
        repo_root=REPO_ROOT,
        model=_Width14Model(),
        supply_verified=True,
    )
    assert scored["decision"] == "Attack"
    assert scored["rf_attack_probability"] == 0.81
    assert scored["evidence_state"] == "verified"
    assert scored["production_fusion_enabled"] is False
    assert scored["ae_changes_alert_decision"] is False
    assert (
        scored["model_sha256"]
        == FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["expected_sha256"]
    )

    mismatched = score_canonical_flow(
        _features(),
        repo_root=REPO_ROOT,
        model=_WideModel(),
        supply_verified=True,
    )
    assert mismatched["decision"] == "withheld"
    assert mismatched["reason"] == "feature_contract_mismatch"
    assert mismatched["rf_attack_probability"] is None


def test_missing_feature_is_withheld_and_notes_round_trip(tmp_path: Path) -> None:
    incomplete = score_canonical_flow({}, repo_root=REPO_ROOT, supply_verified=True)
    assert incomplete["decision"] == "withheld"
    assert incomplete["reason"].startswith("missing_feature:")
    stored = persist_scored_flow(tmp_path / "live.sqlite3", _features(), incomplete)
    rows = list_live_flows(tmp_path / "live.sqlite3")
    assert rows[0]["flow_id"] == stored["flow_id"]
    assert rows[0]["decision"] == "withheld"
    refused = add_analyst_note(
        tmp_path / "live.sqlite3", flow_id=stored["flow_id"], author_id="", note_text="x"
    )
    assert refused["evidence_state"] == "unavailable"
    saved = add_analyst_note(
        tmp_path / "live.sqlite3",
        flow_id=stored["flow_id"],
        author_id="analyst_a",
        note_text="Reviewed the withheld score.",
    )
    assert saved["evidence_state"] == "verified"


def test_copilot_refuses_containment_and_drift_reads_rows(tmp_path: Path) -> None:
    refused = answer_mitre_copilot("please isolate the host", tmp_path / "rag.sqlite3")
    assert refused["execution_authorized"] is False
    assert refused["reason"] == "containment_refused"
    assert refused["hits"] == []
    answered = answer_mitre_copilot("command and control beacon", tmp_path / "rag.sqlite3")
    assert answered["execution_authorized"] is False
    assert answered["hits"]
    assert answered["hits"][0]["technique_id"].startswith("T")

    empty = drift_for_stored_flows(tmp_path / "missing.sqlite3")
    assert empty["evidence_state"] == "unavailable"
    persist_scored_flow(
        tmp_path / "live.sqlite3",
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    drift = drift_for_stored_flows(tmp_path / "live.sqlite3")
    assert drift["evidence_state"] == "verified"
    assert drift["changes_model_weights"] is False


def test_workbench_lists_six_nodes_without_dispatch() -> None:
    report = read_n8n_workbench(
        REPO_ROOT / "docker" / "n8n" / "workflows" / "threatfusion_soar_playbook.json"
    )
    assert report["node_count"] == 6
    assert report["execution_authorized"] is False
    assert report["evidence_state"] == "verified"


def test_campaigns_read_stored_flows_and_incident_rows(tmp_path: Path) -> None:
    empty = list_live_campaigns(
        tmp_path / "missing.sqlite3", incidents_db_path=tmp_path / "missing-incidents.sqlite3"
    )
    assert empty["evidence_state"] == "unavailable"
    assert empty["campaigns"] == []
    assert empty["incidents"] == []
    assert empty["production_fusion_enabled"] is False

    replay = replay_benchmark_attack_burst(
        tmp_path / "live.sqlite3",
        repo_root=REPO_ROOT,
        model=_Width14Model(),
        supply_verified=True,
    )
    assert replay["member_count"] == 5
    assert replay["source_label"] == "recorded_unsw_nb15"
    assert replay["fixture_origin"] == "study_triage_cases"
    assert replay["production_fusion_enabled"] is False
    assert replay["execution_authorized"] is False
    assert replay["ae_changes_alert_decision"] is False
    assert {row["rf_attack_probability"] for row in replay["flows"]} == {0.81}
    assert {row["decision"] for row in replay["flows"]} == {"Attack"}

    incidents_db = tmp_path / "incidents.sqlite3"
    with sqlite3.connect(incidents_db) as conn:
        conn.execute("""
            CREATE TABLE incidents (
                incident_id TEXT,
                window_type TEXT,
                constituent_alert_count INTEGER,
                max_probability_score REAL,
                escalated_decision TEXT,
                earliest_observed_at TEXT,
                provenance_status TEXT
            )
            """)
        conn.execute(
            """
            INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "inc_stored_01",
                "30.0s_burst",
                2,
                0.91,
                "Attack",
                "2026-10-27T00:00:00+00:00",
                "verified_entity_bearing",
            ),
        )

    listed = list_live_campaigns(tmp_path / "live.sqlite3", incidents_db_path=incidents_db)
    assert listed["evidence_state"] == "verified"
    assert listed["flow_count"] == 5
    assert listed["incident_count"] == 1
    assert listed["campaigns"][0]["member_count"] == 5
    assert listed["campaigns"][0]["source_label"] == "recorded_unsw_nb15"
    assert listed["incidents"][0]["incident_id"] == "inc_stored_01"
    assert listed["production_fusion_enabled"] is False


def test_soar_approval_writes_linked_hash_and_does_not_execute(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    refused = approve_live_soar(
        live_db, soar_db, flow_id=stored["flow_id"], actor_id="", reason="because"
    )
    assert refused["evidence_state"] == "unavailable"
    assert refused["execution_authorized"] is False
    assert not soar_db.exists()

    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=stored["flow_id"],
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    assert approved["evidence_state"] == "verified"
    assert approved["operator_state"] == "approved_local"
    assert approved["ledger_state"] == "approved"
    assert approved["execution_authorized"] is False
    assert approved["containment_executed"] is False
    assert approved["production_fusion_enabled"] is False
    assert len(approved["entry_sha256"]) == 64
    assert len(approved["prev_entry_sha256"]) == 64
    assert approved["entry_sha256"] != approved["prev_entry_sha256"]

    again = approve_live_soar(
        live_db,
        soar_db,
        flow_id=stored["flow_id"],
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    assert again["reason"] == "already_approved"
    assert again["entry_sha256"] == approved["entry_sha256"]
    listed = list_live_campaigns(live_db)
    stored_flow = listed["campaigns"][0]["flows"][0]
    assert stored_flow["entry_sha256"] == approved["entry_sha256"]
    assert stored_flow["audit_chain_verified"] == 1


def test_dispatch_records_signed_callback_and_mttr(tmp_path: Path, monkeypatch) -> None:
    import importlib.util
    import threading
    from http.server import ThreadingHTTPServer

    from threatfusion.api.live_soc_console import approve_live_soar, dispatch_approved_callback

    spec = importlib.util.spec_from_file_location(
        "contract_server_under_test",
        REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py",
    )
    assert spec is not None and spec.loader is not None
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)
    MispAndCallbackContractHandler = server_module.MispAndCallbackContractHandler

    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-01")
    MispAndCallbackContractHandler.soar_db_path = str(soar_db)
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    approve_live_soar(
        live_db,
        soar_db,
        flow_id=stored["flow_id"],
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        refused = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=stored["flow_id"],
            contract_base_url="",
            hmac_secret="lab-hmac-secret-01",
        )
        assert refused["evidence_state"] == "unavailable"
        assert refused["containment_executed"] is False
        port = server.server_address[1]
        dispatched = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=stored["flow_id"],
            contract_base_url=f"http://127.0.0.1:{port}",
            hmac_secret="lab-hmac-secret-01",
            outbox_db_path=tmp_path / "thehive.sqlite3",
        )
        assert dispatched["evidence_state"] == "verified"
        assert dispatched["callback_recorded"] is True
        assert dispatched["verify_state"] is True
        assert dispatched["execution_authorized"] is False
        assert dispatched["containment_executed"] is False
        assert dispatched["execution_path"] == "local_contract_fallback"
        assert len(dispatched["signature_sha256"]) == 64
        assert str(dispatched["thehive_case_id"]).startswith("case_")
        assert dispatched["mttr_seconds"] >= 0.0
        again = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=stored["flow_id"],
            contract_base_url=f"http://127.0.0.1:{port}",
            hmac_secret="lab-hmac-secret-01",
        )
        assert again["reason"] == "already_recorded"
        assert again["signature_sha256"] == dispatched["signature_sha256"]
    finally:
        server.shutdown()
        server.server_close()


def test_verified_burst_stitches_and_private_ip_is_refused(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    score = score_canonical_flow(
        _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    first = persist_scored_flow(live_db, _features(), score)
    second = persist_scored_flow(live_db, _features(), score)
    benign = score_canonical_flow(
        _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    benign["decision"] = "Benign"
    benign["rf_attack_probability"] = 0.2
    persist_scored_flow(live_db, _features(), benign)
    for flow_id in (first["flow_id"], second["flow_id"]):
        stored = store_flow_provenance(
            live_db,
            flow_id,
            entity_namespace_id="lab:edge-01",
            src_entity_id="198.51.100.27",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
            clock_synchronized=True,
        )
        assert stored["evidence_state"] == "verified"
    report = correlate_stored_attacks(live_db, tmp_path / "incidents.sqlite3")
    assert report["production_fusion_enabled"] is False
    assert report["burst_window_seconds"] == 30.0
    assert report["campaign_window_seconds"] == 600.0
    assert report["burst_incident_count"] == 1
    assert report["correlated_flow_count"] == 2
    assert report["max_constituent_count"] == 2
    assert report["timeline"]["event_count"] == 2
    assert {event["window_type"] for event in report["timeline"]["events"]} == {"burst_30s"}
    blocked_status, blocked = private_ip_guard_response("10.0.0.4")
    assert blocked_status == 422
    assert blocked["private_ip_guard_triggered"] is True
    open_status, opened = private_ip_guard_response("8.8.8.8")
    assert open_status == 200
    assert opened["private_ip_guard_triggered"] is False


def test_triage_actions_persist_and_handoff_stays_grounded(tmp_path: Path) -> None:
    from threatfusion.advisory.explanation_engine import (
        AdvisoryEvidenceBundle,
        verify_explanation_groundedness,
    )

    live_db = tmp_path / "live.sqlite3"
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    provenance = store_flow_provenance(
        live_db,
        stored["flow_id"],
        entity_namespace_id="lab:edge-01",
        src_entity_id="198.51.100.27",
        dst_entity_id="10.0.0.5",
        protocol="tcp",
        service_or_port="80",
        clock_synchronized=True,
    )
    assert provenance["evidence_state"] == "verified"
    refused = record_triage_action(
        live_db, flow_id=stored["flow_id"], action="contain", actor_id="analyst_a"
    )
    assert refused["evidence_state"] == "unavailable"
    blank_actor = record_triage_action(
        live_db, flow_id=stored["flow_id"], action="acknowledge", actor_id="  "
    )
    assert blank_actor["evidence_state"] == "unavailable"
    expected = (
        ("acknowledge", "acknowledged"),
        ("escalate", "escalated"),
        ("dismiss", "dismissed"),
    )
    for action, state in expected:
        saved = record_triage_action(
            live_db, flow_id=stored["flow_id"], action=action, actor_id="analyst_a"
        )
        assert saved["triage_state"] == state
    listed = list_live_flows(live_db)
    assert listed[0]["triage_state"] == "dismissed"
    with sqlite3.connect(live_db) as conn:
        rows = conn.execute(
            "SELECT action, triage_state, actor_id FROM triage_events ORDER BY event_id"
        ).fetchall()
    assert rows == [
        ("acknowledge", "acknowledged", "analyst_a"),
        ("escalate", "escalated", "analyst_a"),
        ("dismiss", "dismissed", "analyst_a"),
    ]
    exported = export_grounded_handoff(live_db, flow_id=stored["flow_id"])
    assert exported["grounded"] is True
    assert exported["production_fusion_enabled"] is False
    assert exported["report"]["block_3_technique"] == "unavailable"
    assert exported["report"]["block_2_triage_count"] == 3
    assert exported["report"]["block_2_latest_triage_state"] == "dismissed"
    assert exported["report"]["stored_addresses"] == ["198.51.100.27", "10.0.0.5"]
    assert exported["containment_executed"] is False
    transitions = [
        event
        for event in exported["handoff"]["timeline"]["events"]
        if event["kind"] == "analyst_transition"
    ]
    assert [event["to_state"] for event in transitions] == [
        "acknowledged",
        "escalated",
        "dismissed",
    ]
    assert "Technique: unavailable" in exported["markdown"]
    assert "Containment was not executed." in exported["markdown"]
    blocked = export_grounded_handoff(
        live_db,
        flow_id=stored["flow_id"],
        brief="host 203.0.113.99 was isolated",
    )
    assert blocked["evidence_state"] == "unavailable"
    assert blocked["grounded"] is False
    assert blocked["reason"] == "explanation_not_grounded"
    assert "markdown" not in blocked
    assert "203.0.113.99" not in str(blocked)
    cited = export_grounded_handoff(
        live_db,
        flow_id=stored["flow_id"],
        brief="Stored source 198.51.100.27 stays on this flow.",
    )
    assert cited["grounded"] is True
    assert "198.51.100.27" in cited["brief"]
    missing = export_grounded_handoff(live_db, flow_id=999)
    assert missing["grounded"] is False
    assert missing["reason"] == "flow_not_stored"
    bundle = AdvisoryEvidenceBundle(
        candidate_id="live_flow:1",
        record_id="live_flow:1",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=0.81,
        rf_threshold=0.5,
        top_feature_signals={},
    )
    assert verify_explanation_groundedness("host 203.0.113.99 was isolated", bundle) is False


def test_triage_and_handoff_routes_round_trip(tmp_path: Path, monkeypatch) -> None:
    import importlib.util
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    spec = importlib.util.spec_from_file_location(
        "contract_server_triage_under_test",
        REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py",
    )
    assert spec is not None and spec.loader is not None
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)
    handler = server_module.MispAndCallbackContractHandler

    live_db = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]

        def post(path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
            body = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request) as response:
                    return response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        for action, state in (
            ("acknowledge", "acknowledged"),
            ("escalate", "escalated"),
            ("dismiss", "dismissed"),
        ):
            status, body = post(
                "/api/v1/live/triage",
                {"flow_id": stored["flow_id"], "action": action, "actor_id": "analyst_a"},
            )
            assert status == 200
            assert body["triage_state"] == state
            assert body["evidence_state"] == "verified"
        refused_status, refused_body = post(
            "/api/v1/live/triage",
            {"flow_id": stored["flow_id"], "action": "contain", "actor_id": "analyst_a"},
        )
        assert refused_status == 400
        assert refused_body["evidence_state"] == "unavailable"
        assert list_live_flows(live_db)[0]["triage_state"] == "dismissed"
        status, exported = post("/api/v1/live/handoff", {"flow_id": stored["flow_id"]})
        assert status == 200
        assert exported["grounded"] is True
        assert exported["production_fusion_enabled"] is False
        assert exported["containment_executed"] is False
        report = exported["report"]
        assert isinstance(report, dict)
        assert report["block_3_technique"] == "unavailable"
        assert report["block_2_triage_count"] == 3
        assert report["block_2_latest_triage_state"] == "dismissed"
        assert "Technique: unavailable" in str(exported["markdown"])
        blocked_status, blocked = post(
            "/api/v1/live/handoff",
            {"flow_id": stored["flow_id"], "brief": "host 203.0.113.99 was isolated"},
        )
        assert blocked_status == 400
        assert blocked["grounded"] is False
        assert blocked["reason"] == "explanation_not_grounded"
        assert "markdown" not in blocked
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_source_qualification_is_visible_and_tf012_tf002_stay_open() -> None:
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    register = (REPO_ROOT / "docs" / "issue_register.md").read_text(encoding="utf-8")
    assert "UNSW-NB15 and CIC byte layers are not interchangeable." in html
    assert "CIC is not a validated compatible external test." in html
    stripped = html.replace("CIC is not a validated compatible external test.", "")
    assert "validated compatible external test" not in stripped
    for issue_id in ("TF-012", "TF-002", "TF-008", "TF-009", "TF-010", "TF-011"):
        row = next(line for line in register.splitlines() if line.startswith(f"| {issue_id} |"))
        assert row.rstrip().endswith("| open |")


def test_analyst_verdict_assignment_and_glass_box_stay_beside_the_forest(tmp_path: Path) -> None:
    db_path = tmp_path / "live.sqlite3"
    score = score_canonical_flow(
        _features(),
        repo_root=REPO_ROOT,
        model=_Width14Model(),
        supply_verified=True,
    )
    stored = persist_scored_flow(db_path, _features(), score)
    flow_id = int(stored["flow_id"])
    refused = record_analyst_verdict(
        db_path,
        flow_id=flow_id,
        verdict="false_positive",
        rationale="Contact 203.0.113.50 about this row.",
        actor_id="analyst_a",
    )
    assert refused["reason"] == "explanation_not_grounded"
    saved = record_analyst_verdict(
        db_path,
        flow_id=flow_id,
        verdict="false_positive",
        rationale="The stored score stands. No new address is named.",
        actor_id="analyst_a",
    )
    assert saved["evidence_state"] == "verified"
    assert saved["frozen_rf_decision"] == "Attack"
    assert saved["decision_unchanged"] is True
    assigned = record_case_assignment(
        db_path,
        flow_id=flow_id,
        assignee_id="analyst_a",
        review_status="in_review",
    )
    assert assigned["evidence_state"] == "verified"
    queue = list_live_campaigns(db_path)
    flow = queue["campaigns"][0]["flows"][0]
    assert flow["decision"] == "Attack"
    assert flow["analyst_verdict"] == "false_positive"
    assert flow["assignee_id"] == "analyst_a"
    assert flow["review_status"] == "in_review"
    assert queue["flow_count"] == 1
    assert queue["campaign_count"] == 1
    item_ids = [item["id"] for item in flow["glass_box"]["items"]]
    assert item_ids == [
        "flow_contract_valid",
        "rf_scored",
        "correlation_window_checked",
        "misp_rfc1918_guard",
        "soar_hash_chain",
    ]
    scored = next(item for item in flow["glass_box"]["items"] if item["id"] == "rf_scored")
    assert scored["passed"] is True
    assert flow["glass_box"]["frozen_rf_decision"] == "Attack"
    assert flow["glass_box"]["analyst_verdict"] == "false_positive"
    handoff = export_grounded_handoff(db_path, flow_id=flow_id)
    assert handoff["grounded"] is True
    assert "Frozen Random Forest decision: Attack" in handoff["markdown"]
    assert "Analyst verdict: false_positive" in handoff["markdown"]
    assert "Assignee: analyst_a" in handoff["markdown"]
    assert "Review status: in_review" in handoff["markdown"]
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert "Frozen Benchmark Evaluation Baseline" in html
    assert "216,568" in html
    assert 'id="liveHeroFlowCount"' in html
    assert 'id="queueSearch"' in html
    assert 'id="queueDecisionFilter"' in html
    assert 'id="queueVerdictFilter"' in html
    assert 'id="glassBoxChecklist"' in html
    assert "/api/v1/live/verdict" in script
    assert "/api/v1/live/assignment" in script


def test_constitutional_health_reports_digests_and_seven_checks() -> None:
    report = constitutional_health(REPO_ROOT)
    assert report["production_fusion_enabled"] is False
    assert report["containment_executed"] is False
    assert report["tf_008_through_tf_011"] == "open"
    assert report["checks_total"] == 7
    assert report["boundary_verdict"] in {"GO", "NO-GO"}
    assert report["truth_verdict"] in {"GO", "NO-GO"}
    assert len(report["receipt_sha256"]) == 64
    forest = report["model_digests"]["random_forest"]
    assert forest["verified"] is True
    assert forest["sha256"].startswith("bd2853a6")
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="btnConstitutionalHealth"' in html
    assert "/api/v1/live/health" in script


def test_four_scenario_replay_uses_the_frozen_forest(tmp_path: Path) -> None:
    db = tmp_path / "scenarios.sqlite3"
    result = replay_live_scenarios(db, repo_root=REPO_ROOT)
    assert result["evidence_state"] == "verified"
    assert result["production_fusion_enabled"] is False
    assert result["containment_executed"] is False
    assert result["member_count"] == 4
    by_id = {row["scenario_id"]: row for row in result["flows"]}
    assert set(by_id) == {"web_exploit", "ssh_brute", "internal_recon", "benign_false_alarm"}
    for scenario_id in ("web_exploit", "ssh_brute", "internal_recon"):
        assert by_id[scenario_id]["decision"] == "Attack"
        assert by_id[scenario_id]["reason"] == "frozen_random_forest_scored"
    assert by_id["web_exploit"]["scenario_label"] == "T1190"
    assert by_id["ssh_brute"]["scenario_label"] == "T1110"
    assert by_id["internal_recon"]["scenario_label"] == "T1046"
    assert by_id["internal_recon"]["misp_guard_status"] == 422
    assert by_id["internal_recon"]["private_ip_guard_triggered"] is True
    assert by_id["internal_recon"]["external_lookup_performed"] is False
    assert by_id["benign_false_alarm"]["decision"] == "Benign"
    assert by_id["benign_false_alarm"]["scenario_label"] is None
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="btnReplayScenarios"' in html
    assert "/api/v1/live/scenarios" in script


def test_live_console_is_one_screen() -> None:
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="inspectorCaseTitle">No stored campaign selected' in html
    assert 'data-sample-only="true" hidden' in html
    assert "setSampleSurfacesHidden" in script
    assert "syncLiveInspector" in script
    assert "Case #001842: Active C2 Reconnaissance" not in html


def test_triage_controls_are_wired_in_the_page() -> None:
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="btnAcknowledge"' in html
    assert 'id="btnEscalate"' in html
    assert 'id="btnDismiss"' in html
    assert 'id="btnExportHandoff"' in html
    assert 'id="shiftHandoffNote"' in html
    assert 'id="shiftHandoffReport"' in html
    assert "/api/v1/live/triage" in script
    assert "/api/v1/live/handoff" in script
    assert "triageState" in script
    assert "shiftHandoffReport" in script
    assert "production_fusion_enabled = True" not in script


def test_live_product_launcher_starts_one_process() -> None:
    script = (REPO_ROOT / "scripts" / "run_live_product.sh").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert script.startswith("#!/usr/bin/env bash\n")
    assert "run_misp_and_callback_contract_server.py" in script
    assert "--dry-run" in script
    assert "--smoke" in script
    assert "--seed-demo" in script
    assert "THREATFUSION_SOAR_LEDGER_DB_PATH" in script
    assert "already in use" in script
    assert "production_fusion_enabled = True" not in script
    assert (
        "+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"
        in readme
    )
    assert "TF-008, TF-009, TF-010, and TF-011 remain open." in readme


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    import json
    import urllib.error
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return response.status, parsed if isinstance(parsed, dict) else {}
    except urllib.error.HTTPError as exc:
        parsed = json.loads(exc.read().decode("utf-8"))
        return exc.code, parsed if isinstance(parsed, dict) else {}


def test_http_dispatch_records_four_block_case_hmac_and_ledger_mttr(
    tmp_path: Path, monkeypatch
) -> None:
    """Drive the launcher path: no explicit ledger, real verify-state, case, and HMAC."""
    import hashlib
    import hmac
    import json
    import threading
    import time
    import urllib.request
    from http.server import ThreadingHTTPServer

    from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    live_db = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.delenv("THREATFUSION_SOAR_LEDGER_DB_PATH", raising=False)
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-01")
    previous_ledger = MispAndCallbackContractHandler.soar_db_path
    MispAndCallbackContractHandler.soar_db_path = None
    MispAndCallbackContractHandler.seen_verify_idempotency_keys.clear()
    MispAndCallbackContractHandler.seen_callback_idempotency_keys.clear()
    scored = score_canonical_flow(
        _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    stored = persist_scored_flow(live_db, _features(), scored)
    other = persist_scored_flow(live_db, _features(), scored)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        missing_status, missing = _post_json(
            f"{base}/api/v1/live/soar/dispatch", {"flow_id": stored["flow_id"]}
        )
        assert missing_status == 400
        assert missing["reason"] == "flow_not_stored"
        assert missing["containment_executed"] is False
        assert missing["production_fusion_enabled"] is False

        approved_status, approved = _post_json(
            f"{base}/api/v1/live/soar/approve",
            {
                "flow_id": stored["flow_id"],
                "actor_id": "analyst_a",
                "reason": "Analyst recorded local approval. Containment is not executed.",
            },
        )
        assert approved_status == 200
        assert approved["ledger_state"] == "approved"
        assert approved["execution_authorized"] is False

        unapproved_status, unapproved = _post_json(
            f"{base}/api/v1/live/soar/dispatch", {"flow_id": other["flow_id"]}
        )
        assert unapproved_status == 403
        assert unapproved["reason"] == "playbook_not_approved"
        assert unapproved["containment_executed"] is False
        time.sleep(0.05)

        status, dispatched = _post_json(
            f"{base}/api/v1/live/soar/dispatch", {"flow_id": stored["flow_id"]}
        )
        assert status == 200
        assert dispatched["evidence_state"] == "verified"
        assert dispatched["verify_state"] is True
        assert dispatched["callback_recorded"] is True
        assert dispatched["four_block_recorded"] is True
        assert dispatched["execution_authorized"] is False
        assert dispatched["containment_executed"] is False
        assert dispatched["production_fusion_enabled"] is False
        assert dispatched["thehive_status"] == "queued_offline"
        assert str(dispatched["thehive_case_id"]).startswith("case_")
        signature = dispatched["signature_sha256"]
        assert isinstance(signature, str) and len(signature) == 64
        assert signature == signature.lower()

        soar_db = live_db.with_name("threatfusion-live-soar.sqlite3")
        record = SoarPlaybookSqliteRepository(soar_db).get_record(dispatched["playbook_id"])
        assert record is not None
        assert record.state == "approved"
        assert record.t_approval_queued is not None
        assert record.t_callback_verified is not None
        assert record.t_callback_verified >= record.t_approval_queued
        expected_mttr = round(
            max(0.0, float(record.t_callback_verified) - float(record.t_approval_queued)),
            6,
        )
        assert record.t_response == expected_mttr
        assert dispatched["mttr_seconds"] == expected_mttr
        assert expected_mttr > 0.0

        signed_body = json.dumps(
            {
                "candidate_id": dispatched["candidate_id"],
                "case_id": dispatched["thehive_case_id"],
                "playbook_id": dispatched["playbook_id"],
                "t_approval_queued": dispatched["t_approval_queued"],
                "t_callback_verified": dispatched["t_callback_verified"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert hmac.new(b"lab-hmac-secret-01", signed_body, hashlib.sha256).hexdigest() == signature

        with sqlite3.connect(soar_db) as conn:
            scopes = {row[0] for row in conn.execute("SELECT scope FROM contract_idempotency_keys")}
        assert scopes == {"verify", "callback"}

        outbox = live_db.with_name("threatfusion-live-thehive.sqlite3")
        with sqlite3.connect(outbox) as conn:
            description, case_status = conn.execute(
                "SELECT description, status FROM thehive_cases WHERE case_id = ?",
                (dispatched["thehive_case_id"],),
            ).fetchone()
        assert case_status == "queued_offline"
        for label in (
            "Block 1 (Executive Summary):",
            "Block 2 (Attack Timeline):",
            "Block 3 (MITRE Mapping):",
            "Block 4 (Cryptographic SOAR Status):",
        ):
            assert label in description

        with urllib.request.urlopen(f"{base}/api/v1/live/campaigns", timeout=5.0) as response:
            campaigns = json.loads(response.read().decode("utf-8"))
        flows = [
            flow
            for campaign in campaigns["campaigns"]
            for flow in campaign["flows"]
            if flow["flow_id"] == stored["flow_id"]
        ]
        assert len(flows) == 1
        flow = flows[0]
        assert flow["mttr_seconds"] == expected_mttr
        assert flow["callback_signature"] == signature
        assert flow["thehive_case_id"] == dispatched["thehive_case_id"]

        again_status, again = _post_json(
            f"{base}/api/v1/live/soar/dispatch", {"flow_id": stored["flow_id"]}
        )
        assert again_status == 200
        assert again["reason"] == "already_recorded"
        assert again["signature_sha256"] == signature
        assert again["mttr_seconds"] == expected_mttr
    finally:
        MispAndCallbackContractHandler.soar_db_path = previous_ledger
        server.shutdown()
        server.server_close()

    dashboard = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert "signedLocalCallback" in dashboard
    assert "Callback MTTR" in dashboard
    assert "flow.mttr_seconds" in dashboard
    assert "Host containment was not executed." in dashboard
