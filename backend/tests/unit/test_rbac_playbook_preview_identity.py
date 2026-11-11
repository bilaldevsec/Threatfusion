"""Session sign-in, rollback identity preservation, and playbook preview."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from threatfusion.api.live_soc_console import (
    _connect,
    azure_portal_status,
    enroll_lab_operator,
    preview_soar_playbook,
    rbac_login,
    rbac_logout,
    rbac_register,
    rbac_session_status,
    rollback_range_source,
)

_BILAL = "Muhammad Bilal (21K-3551) · Tier-3 Approver | verified mTLS cert (/CN=lab_operator)"
_SUHAIB = "Muhammad Suhaib (22K-4302) · Tier-1 Triage | No SOAR Cert (Triage Only)"
_HASNAIN = "Muhammad Hasnain (22K-4718) · Auditor | Read-Only Compliance Token"
REPO_ROOT = Path(__file__).resolve().parents[3]


def _insert_flow(db_path: Path, **fields: object) -> int:
    with _connect(db_path) as conn:
        columns = [
            "observed_at_utc",
            "features_json",
            "decision",
            "evidence_state",
            "reason",
            "model_sha256",
            "production_fusion_enabled",
            "case_title",
            "src_entity_id",
            "dst_entity_id",
            "flow_protocol",
            "service_or_port",
            "sensor_observation_json",
            "identity_verified",
            "identity_label",
            "operator_id",
            "prev_entry_sha256",
        ]
        values = [
            "2026-11-11T00:00:00+00:00",
            "{}",
            fields.get("decision", "Attack"),
            "verified",
            "stored",
            "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            0,
            fields.get("case_title", "scenario label T1046"),
            fields.get("src_entity_id", "172.29.0.10"),
            fields.get("dst_entity_id", "172.29.0.20"),
            fields.get("flow_protocol", "tcp"),
            str(fields.get("service_or_port", "22")),
            json.dumps(
                {
                    "proto": fields.get("flow_protocol", "tcp"),
                    "src_port": int(fields.get("src_port", 44121)),
                    "dst_port": int(fields.get("dst_port", 22)),
                }
            ),
            int(fields.get("identity_verified", 0)),
            fields.get("identity_label", "unverified_local_label"),
            fields.get("operator_id", "lab_operator"),
            fields.get("prev_entry_sha256", "ab" * 32),
        ]
        conn.execute(
            f"INSERT INTO live_flows ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            values,
        )
        row = conn.execute("SELECT last_insert_rowid()").fetchone()
    return int(row[0])


def _identity(db_path: Path, flow_id: int) -> int:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT identity_verified FROM live_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
    return int(row["identity_verified"] or 0)


def test_seeded_logins_bind_the_header_to_the_signed_in_role(tmp_path: Path, monkeypatch) -> None:
    live = tmp_path / "live.sqlite3"
    monkeypatch.delenv("THREATFUSION_OPERATOR_POLICY_DIR", raising=False)
    refused = rbac_login(live, username="bilal.21k3551@nu.edu.pk", access_code="wrong-code")
    assert refused["http_status"] == 401
    assert refused["authenticated"] is False
    bilal = rbac_login(live, username="bilal.21k3551@nu.edu.pk", access_code="TF-Bilal-3551!")
    assert bilal["authenticated"] is True
    assert bilal["actor_id"] == "lab_operator"
    assert "/CN=lab_operator" not in bilal["header_identity"]
    policy = tmp_path / "operator-policy"
    assert enroll_lab_operator(policy, "lab_operator")["identity_verified"] is True
    monkeypatch.setenv("THREATFUSION_OPERATOR_POLICY_DIR", str(policy))
    enrolled = rbac_login(live, username="bilal.21k3551@nu.edu.pk", access_code="TF-Bilal-3551!")
    assert enrolled["header_identity"] == _BILAL
    assert enrolled["identity_verified"] is True
    assert enrolled["certificate_subject"] == "/CN=lab_operator"
    suhaib = rbac_login(live, username="suhaib.22k4302@nu.edu.pk", access_code="TF-Suhaib-4302!")
    assert suhaib["header_identity"] == _SUHAIB
    assert "/CN=lab_operator" not in suhaib["header_identity"]
    assert suhaib["certificate_subject"] == ""
    assert suhaib["identity_verified"] is False
    hasnain = rbac_login(live, username="hasnain.22k4718@nu.edu.pk", access_code="TF-Hasnain-4718!")
    assert hasnain["header_identity"] == _HASNAIN
    assert "/CN=lab_operator" not in hasnain["header_identity"]
    anonymous = rbac_logout(live, str(hasnain["session_token"]))
    assert anonymous["authenticated"] is False
    assert rbac_session_status(live, str(hasnain["session_token"]))["authenticated"] is False


def test_custom_account_does_not_receive_the_lab_certificate(tmp_path: Path) -> None:
    live = tmp_path / "live.sqlite3"
    created = rbac_register(
        live,
        username="analyst.new@nu.edu.pk",
        access_code="TF-Custom-9000!",
        display_name="New Analyst",
        role="tier1_triage",
    )
    assert created["authenticated"] is True
    assert created["actor_id"] != "lab_operator"
    assert "/CN=lab_operator" not in created["header_identity"]
    assert "No SOAR Cert (Triage Only)" in created["header_identity"]


def test_rollback_keeps_verified_identity_and_suhaib_has_no_lab_cert(
    tmp_path: Path, monkeypatch
) -> None:
    live = tmp_path / "live.sqlite3"
    soar = tmp_path / "soar.sqlite3"
    soar.write_bytes(b"")
    flow_id = _insert_flow(
        live,
        identity_verified=1,
        identity_label="verified_mtls_lab_operator",
        operator_id="lab_operator",
        src_entity_id="10.1.1.1",
    )
    policy = tmp_path / "operator-policy"
    assert enroll_lab_operator(policy, "lab_operator")["identity_verified"] is True
    monkeypatch.setenv("THREATFUSION_OPERATOR_POLICY_DIR", str(policy))
    bilal = rbac_login(live, username="bilal.21k3551@nu.edu.pk", access_code="TF-Bilal-3551!")
    kept = rollback_range_source(
        live,
        soar,
        flow_id=flow_id,
        actor_id="lab_operator",
        session_token=str(bilal["session_token"]),
    )
    assert _identity(live, flow_id) == 1
    assert kept["flow_identity_preserved"] is True
    assert kept["header_identity"] == _BILAL
    assert kept["identity_verified"] is True
    suhaib = rbac_login(live, username="suhaib.22k4302@nu.edu.pk", access_code="TF-Suhaib-4302!")
    switched = rollback_range_source(
        live,
        soar,
        flow_id=flow_id,
        actor_id="tier1_analyst",
        session_token=str(suhaib["session_token"]),
    )
    assert _identity(live, flow_id) == 1
    assert switched["header_identity"] == _SUHAIB
    assert "/CN=lab_operator" not in json.dumps(switched["header_identity"])
    assert switched["certificate_subject"] == ""
    assert switched["identity_verified"] is False


def test_playbook_preview_changes_with_the_technique(tmp_path: Path) -> None:
    live = tmp_path / "live.sqlite3"
    recon = _insert_flow(
        live, case_title="Network Service Discovery scenario label T1046", dst_port=22
    )
    brute = _insert_flow(
        live,
        case_title="SSH Credential Brute-Force scenario label T1110",
        dst_port=22,
        service_or_port="22",
    )
    web = _insert_flow(
        live, case_title="Public-Facing Web Exploit scenario label T1190", dst_port=80
    )
    flood = _insert_flow(live, case_title="High-Rate Network DoS scenario label T1498", dst_port=80)
    benign = _insert_flow(
        live, decision="Benign", case_title="Normal Enterprise HTTP", dst_port=443
    )
    previews = {
        "T1046": preview_soar_playbook(live, flow_id=recon),
        "T1110": preview_soar_playbook(live, flow_id=brute),
        "T1190": preview_soar_playbook(live, flow_id=web),
        "T1498": preview_soar_playbook(live, flow_id=flood),
    }
    filenames = {
        "T1046": "soar_pb_t1046_recon_quarantine.py",
        "T1110": "soar_pb_t1110_ssh_bruteforce.py",
        "T1190": "soar_pb_t1190_web_exploit_waf.py",
        "T1498": "soar_pb_t1498_dos_sinkhole.py",
    }
    for technique, preview in previews.items():
        assert preview["script_filename"] == filenames[technique]
        assert preview["mitre_technique_id"] == technique
        assert preview["firewall_rule_preview"].startswith(
            "iptables -I INPUT 1 -s 172.29.0.10 -p tcp --dport "
        )
        assert "[Step 1: HMAC-SHA256 Approval]" in preview["execution_steps_log"][0]["line"]
        assert (
            "[Step 4: Rollback & Reachability Probe]" in preview["execution_steps_log"][3]["line"]
        )
        ast.parse(preview["rendered_python_code"])
        assert f"FLOW_ID = {preview['flow_id']}" in preview["rendered_python_code"]
        assert technique in preview["rendered_python_code"]
    assert len({item["rendered_python_code"] for item in previews.values()}) == 4
    quiet = preview_soar_playbook(live, flow_id=benign)
    assert quiet["script_filename"] == "soar_pb_benign_noop_guard.py"
    assert quiet["firewall_rule_preview"] == "noop: benign flow, no iptables change"
    ast.parse(quiet["rendered_python_code"])


def test_azure_status_reads_the_portal_state_file(tmp_path: Path) -> None:
    path = tmp_path / "azure_portal_state.json"
    path.write_text(
        json.dumps(
            {
                "tenant_id": "tenant-1",
                "subscription_id": "sub-1",
                "app_id": "app-1",
                "resource_group": "ThreatFusion-RG",
                "victim_vm_ip": "172.29.0.20",
                "attacker_vm_ip": "172.29.0.10",
            }
        ),
        encoding="utf-8",
    )
    status = azure_portal_status(path)
    assert status["connected"] is True
    assert status["tenant_id"] == "tenant-1"
    assert (
        status["terminal_snippet"] == "scripts/deploy_azure_cyber_range.sh --provision-live-azure"
    )
    assert "http://" not in status["terminal_snippet"]
    assert "https://" not in status["terminal_snippet"]


def test_header_has_one_chain_pill_and_one_operator_pill() -> None:
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert html.count('id="headerChainBadge"') == 1
    assert html.count('id="ledgerBadge"') == 0
    assert html.count('id="operatorAuthBadge"') == 1
    assert html.count('id="operatorIdentityBadge"') == 0
    assert 'id="btnOpenIdentityModal"' in html
    assert 'id="identityModal"' in html
    assert 'id="soarPlaybookInspector"' in html
    assert 'id="soarPlaybookInspectorSide"' in html
    assert 'id="azurePortalStatus"' in html
    assert "http://" not in html
    assert "https://" not in html
    assert "Playbook hash chain: verified (HMAC-SHA256)" in script
    assert "/api/rbac/login" in script
    assert "/api/soar/playbook-preview" in script
    assert "/api/azure/status" in script
    assert "/api/soar/rollback" in script
