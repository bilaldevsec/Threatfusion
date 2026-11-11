"""Inspectable lab SOAR responder templates.

Each technique renders a syntax-clean Python script for the analyst console.
The preview does not execute the script and does not change a firewall.
"""

from __future__ import annotations

import ast
from typing import Any

_DEFAULT_DPORT = {
    "T1046": 22,
    "T1110": 22,
    "T1190": 80,
    "T1498": 80,
    "BENIGN": 443,
}
_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "T1046": {
        "playbook_id": "pb-discovery-network-contain-v1",
        "script_filename": "soar_pb_t1046_recon_quarantine.py",
        "mitre_technique_id": "T1046",
        "thehive_severity": 2,
        "target_service": "tcp/scan",
    },
    "T1110": {
        "playbook_id": "pb-ssh-bruteforce-contain-v1",
        "script_filename": "soar_pb_t1110_ssh_bruteforce.py",
        "mitre_technique_id": "T1110",
        "thehive_severity": 3,
        "target_service": "tcp/22",
    },
    "T1190": {
        "playbook_id": "pb-web-exploit-contain-v1",
        "script_filename": "soar_pb_t1190_web_exploit_waf.py",
        "mitre_technique_id": "T1190",
        "thehive_severity": 3,
        "target_service": "tcp/80",
    },
    "T1498": {
        "playbook_id": "pb-network-dos-sinkhole-v1",
        "script_filename": "soar_pb_t1498_dos_sinkhole.py",
        "mitre_technique_id": "T1498",
        "thehive_severity": 4,
        "target_service": "tcp/80",
    },
    "BENIGN": {
        "playbook_id": "pb-benign-noop-guard-v1",
        "script_filename": "soar_pb_benign_noop_guard.py",
        "mitre_technique_id": "BENIGN",
        "thehive_severity": 1,
        "target_service": "tcp/443",
    },
}


def technique_for_flow(*, decision: str, case_title: str, playbook_id: str) -> str:
    """Pick the responder family from the stored label. Benign stays a no-op."""
    if str(decision or "") != "Attack":
        return "BENIGN"
    haystack = f"{case_title} {playbook_id}"
    for technique in ("T1046", "T1110", "T1190", "T1498"):
        if technique in haystack:
            return technique
    lowered = haystack.lower()
    if "brute" in lowered or "ssh" in lowered:
        return "T1110"
    if "exploit" in lowered or "web" in lowered:
        return "T1190"
    if "dos" in lowered or "flood" in lowered:
        return "T1498"
    if "recon" in lowered or "discovery" in lowered or "scan" in lowered:
        return "T1046"
    return "T1498"


def firewall_rule_preview(*, technique: str, src_ip: str, proto: str, dport: int) -> str:
    if technique == "BENIGN":
        return "noop: benign flow, no iptables change"
    return f"iptables -I INPUT 1 -s {src_ip} -p {proto} --dport {dport} -j DROP"


def render_python_playbook(technique: str, fields: dict[str, Any]) -> str:
    """Return a syntax-clean responder populated with this flow's live values."""
    spec = _PLAYBOOKS[technique]
    source = f'''"""ThreatFusion lab SOAR responder {spec["script_filename"]}.

MITRE {spec["mitre_technique_id"]}. Human approval is required before any
firewall change. Rendering this module does not execute it.
"""

FLOW_ID = {fields["flow_id"]!r}
SRC_IP = {fields["src_ip"]!r}
DST_IP = {fields["dst_ip"]!r}
SPORT = {fields["sport"]!r}
DPORT = {fields["dport"]!r}
PROTO = {fields["proto"]!r}
RF_ATTACK_PROBABILITY = {fields["rf_attack_probability"]!r}
AE_MSE = {fields["ae_mse"]!r}
DNN_PREDICTED_CLASS = {fields["dnn_predicted_class"]!r}
HMAC_PREV_SHA256 = {fields["hmac_prev_sha256"]!r}
MITRE_TECHNIQUE_ID = {spec["mitre_technique_id"]!r}
PLAYBOOK_ID = {spec["playbook_id"]!r}
THEHIVE_SEVERITY = {spec["thehive_severity"]!r}
TARGET_SERVICE = {spec["target_service"]!r}
SCRIPT_FILENAME = {spec["script_filename"]!r}


def firewall_rule() -> str:
    if MITRE_TECHNIQUE_ID == "BENIGN":
        return "noop: benign flow, no iptables change"
    return (
        "iptables -I INPUT 1 -s "
        + str(SRC_IP)
        + " -p "
        + str(PROTO)
        + " --dport "
        + str(DPORT)
        + " -j DROP"
    )


def main() -> int:
    print(SCRIPT_FILENAME)
    print(PLAYBOOK_ID)
    print(firewall_rule())
    print(HMAC_PREV_SHA256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    ast.parse(source)
    return source


def execution_steps_log(
    *,
    approved: bool,
    dispatched: bool,
    contained: bool,
    rolled_back: bool,
) -> list[dict[str, str]]:
    """Four-step trace. Later steps stay waiting until the earlier gate is recorded."""

    def _status(done: bool, ready: bool) -> str:
        if done:
            return "complete"
        if ready:
            return "ready"
        return "waiting"

    step1 = _status(approved, True)
    step2 = _status(dispatched, approved)
    step3 = _status(contained, dispatched)
    step4 = _status(rolled_back, contained)
    return [
        {
            "step": "1",
            "status": step1,
            "line": f"[Step 1: HMAC-SHA256 Approval] {step1}",
        },
        {
            "step": "2",
            "status": step2,
            "line": f"[Step 2: n8n Webhook & TheHive Case Creation] {step2}",
        },
        {
            "step": "3",
            "status": step3,
            "line": f"[Step 3: Victim Container iptables Containment] {step3}",
        },
        {
            "step": "4",
            "status": step4,
            "line": f"[Step 4: Rollback & Reachability Probe] {step4}",
        },
    ]


def preview_fields(
    *,
    technique: str,
    flow_id: int,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    proto: str,
    rf_attack_probability: float | None,
    ae_mse: float | None,
    dnn_predicted_class: str,
    hmac_prev_sha256: str,
    approved: bool,
    dispatched: bool,
    contained: bool,
    rolled_back: bool,
) -> dict[str, Any]:
    spec = dict(_PLAYBOOKS[technique])
    safe_proto = proto if proto in {"tcp", "udp", "icmp"} else "tcp"
    safe_dport = dport if dport > 0 else int(_DEFAULT_DPORT[technique])
    fields = {
        "flow_id": int(flow_id),
        "src_ip": src_ip or "0.0.0.0",
        "dst_ip": dst_ip or "0.0.0.0",
        "sport": int(sport) if sport > 0 else 0,
        "dport": int(safe_dport),
        "proto": safe_proto,
        "rf_attack_probability": rf_attack_probability,
        "ae_mse": ae_mse,
        "dnn_predicted_class": dnn_predicted_class or "unavailable",
        "hmac_prev_sha256": hmac_prev_sha256 or "",
    }
    rule = firewall_rule_preview(
        technique=technique,
        src_ip=str(fields["src_ip"]),
        proto=safe_proto,
        dport=int(safe_dport),
    )
    return {
        "playbook_id": spec["playbook_id"],
        "script_filename": spec["script_filename"],
        "mitre_technique_id": spec["mitre_technique_id"],
        "thehive_severity": spec["thehive_severity"],
        "target_service": spec["target_service"],
        "firewall_rule_preview": rule,
        "rendered_python_code": render_python_playbook(technique, fields),
        "execution_steps_log": execution_steps_log(
            approved=approved,
            dispatched=dispatched,
            contained=contained,
            rolled_back=rolled_back,
        ),
        "production_fusion_enabled": False,
    }


__all__ = [
    "execution_steps_log",
    "firewall_rule_preview",
    "preview_fields",
    "render_python_playbook",
    "technique_for_flow",
]
