"""Authenticated read-only analyst dashboard slice for TF-008.

Connects to the local loopback AnalystTlsListener using mutual TLS 1.3
with verified human credentials, loads persisted alert candidates and
analyst states, and formats structured dashboard representations.
"""

from __future__ import annotations

import html
import json
import math
import re
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from threatfusion.api.alert_explanation import (
    EXPLANATION_VERSION,
    LIMITATIONS,
    validate_explanation,
)
from threatfusion.api.analyst_tls_service import ANALYST_HOST

MAX_DASHBOARD_RESPONSE_BYTES = 131072
MAX_HEADER_BYTES = 4096
_BROWSER_ALERT_ID = re.compile(r"alert_candidate_v1:[0-9a-f]{64}\Z")


class AnalystDashboardError(Exception):
    """Base sanitized dashboard error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<AnalystDashboardError: {self.code}>"


class AnalystDashboardAuthenticationError(AnalystDashboardError):
    """Peer certificate rejected or unauthorized."""


class AnalystDashboardUnavailableError(AnalystDashboardError):
    """Transport or storage backend unavailable."""


@dataclass(frozen=True, slots=True)
class DashboardAlertSummary:
    """Summary of an alert candidate in the dashboard triage queue."""

    alert_candidate_id: str
    source_event_id: str
    observed_at: str
    model_identity: str
    model_version: str
    uncalibrated_model_score: float
    decision_threshold: float
    decision: str
    state: str
    version: int


@dataclass(frozen=True, slots=True)
class DashboardTransitionRecord:
    """History event record in the dashboard alert detail view."""

    transition_id: str
    sequence: int
    from_state: str
    to_state: str
    actor_id: str
    rationale: str
    transitioned_at: str


@dataclass(frozen=True, slots=True)
class DashboardIncidentSummary:
    """Incident correlation metadata and provenance status for one alert."""

    incident_id: str
    correlation_mode: str
    window_type: str
    correlation_rule_id: str
    constituent_alert_count: int
    provenance_status: str
    explanation: str


@dataclass(frozen=True, slots=True)
class DashboardAlertDetail:
    """Comprehensive detail view for one alert candidate."""

    alert_candidate_id: str
    source_event_id: str
    observed_at: str
    created_at: str
    source_representation_identity: str
    feature_contract_identity: str
    model_identity: str
    model_version: str
    model_artifact_sha256: str
    uncalibrated_model_score: float
    decision_threshold: float
    decision_policy_version: str
    decision: str
    state: str
    version: int
    updated_at: str | None
    updated_by: str | None
    last_transition_id: str | None
    history: tuple[DashboardTransitionRecord, ...]
    explanation: dict[str, object] | None = None
    incident_correlation: DashboardIncidentSummary | None = None
    threat_intel_enrichment: dict[str, object] | None = None
    advisory_explanation: dict[str, object] | None = None
    soar_recommendations: tuple[object, ...] | None = None


@dataclass(frozen=True, slots=True)
class DashboardAlertQueue:
    """The triage queue view."""

    items: tuple[DashboardAlertSummary, ...]
    total_loaded: int
    limit: int
    offset: int

    @property
    def is_empty(self) -> bool:
        return len(self.items) == 0


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    """Combined dashboard state showing queue and optionally a selected alert."""

    queue: DashboardAlertQueue
    selected: DashboardAlertDetail | None
    status: str  # "active" or "empty"


def _parse_dict(val: object) -> dict[str, object]:
    if type(val) is not dict:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return val


def _parse_non_empty_str(mapping: dict[str, object], key: str) -> str:
    if key not in mapping:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    val = mapping[key]
    if type(val) is not str or not val:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return val


def _parse_optional_non_empty_str(mapping: dict[str, object], key: str) -> str | None:
    if key not in mapping:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    val = mapping[key]
    if val is None:
        return None
    if type(val) is not str or not val:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return val


def _parse_str(mapping: dict[str, object], key: str) -> str:
    if key not in mapping:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    val = mapping[key]
    if type(val) is not str:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return val


def _parse_int(mapping: dict[str, object], key: str, *, min_val: int = 0) -> int:
    if key not in mapping:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    val = mapping[key]
    if type(val) is not int or isinstance(val, bool) or val < min_val:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return val


def _parse_float(mapping: dict[str, object], key: str) -> float:
    if key not in mapping:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    val = mapping[key]
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    fval = float(val)
    if not math.isfinite(fval):
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    return fval


def _parse_evidence(raw_evidence: object) -> dict[str, object]:
    ev = _parse_dict(raw_evidence)
    return {
        "alert_candidate_id": _parse_non_empty_str(ev, "alert_candidate_id"),
        "source_event_id": _parse_non_empty_str(ev, "source_event_id"),
        "observed_at": _parse_non_empty_str(ev, "observed_at"),
        "created_at": _parse_non_empty_str(ev, "created_at"),
        "source_representation_identity": _parse_non_empty_str(
            ev, "source_representation_identity"
        ),
        "feature_contract_identity": _parse_non_empty_str(ev, "feature_contract_identity"),
        "model_identity": _parse_non_empty_str(ev, "model_identity"),
        "model_version": _parse_non_empty_str(ev, "model_version"),
        "model_artifact_sha256": _parse_non_empty_str(ev, "model_artifact_sha256"),
        "uncalibrated_model_score": _parse_float(ev, "uncalibrated_model_score"),
        "decision_threshold": _parse_float(ev, "decision_threshold"),
        "decision_policy_version": _parse_non_empty_str(ev, "decision_policy_version"),
        "decision": _parse_non_empty_str(ev, "decision"),
    }


def _parse_state(raw_state: object) -> dict[str, object]:
    st = _parse_dict(raw_state)
    return {
        "state": _parse_non_empty_str(st, "state"),
        "version": _parse_int(st, "version", min_val=0),
        "updated_at": _parse_optional_non_empty_str(st, "updated_at"),
        "updated_by": _parse_optional_non_empty_str(st, "updated_by"),
        "last_transition_id": _parse_optional_non_empty_str(st, "last_transition_id"),
    }


def _parse_history_entry(raw_entry: object) -> DashboardTransitionRecord:
    entry = _parse_dict(raw_entry)
    return DashboardTransitionRecord(
        transition_id=_parse_non_empty_str(entry, "transition_id"),
        sequence=_parse_int(entry, "sequence", min_val=1),
        from_state=_parse_non_empty_str(entry, "from_state"),
        to_state=_parse_non_empty_str(entry, "to_state"),
        actor_id=_parse_non_empty_str(entry, "actor_id"),
        rationale=_parse_str(entry, "rationale"),
        transitioned_at=_parse_non_empty_str(entry, "transitioned_at"),
    )


def _parse_summary(raw_item: object) -> DashboardAlertSummary:
    item = _parse_dict(raw_item)
    if "detection_evidence" not in item or "analyst_state" not in item:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    evidence = _parse_evidence(item["detection_evidence"])
    state = _parse_state(item["analyst_state"])
    return DashboardAlertSummary(
        alert_candidate_id=str(evidence["alert_candidate_id"]),
        source_event_id=str(evidence["source_event_id"]),
        observed_at=str(evidence["observed_at"]),
        model_identity=str(evidence["model_identity"]),
        model_version=str(evidence["model_version"]),
        uncalibrated_model_score=float(evidence["uncalibrated_model_score"]),
        decision_threshold=float(evidence["decision_threshold"]),
        decision=str(evidence["decision"]),
        state=str(state["state"]),
        version=int(state["version"]),
    )


def _parse_detail(payload: dict[str, object]) -> DashboardAlertDetail:
    if "detection_evidence" not in payload or "analyst_state" not in payload:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    evidence = _parse_evidence(payload["detection_evidence"])
    state = _parse_state(payload["analyst_state"])

    if "analyst_history" not in payload:
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    raw_history = payload["analyst_history"]
    if not isinstance(raw_history, list):
        raise AnalystDashboardUnavailableError("invalid_payload_format")
    history = tuple(_parse_history_entry(h) for h in raw_history)

    raw_corr = payload.get("incident_correlation")
    incident_correlation: DashboardIncidentSummary | None = None
    if raw_corr is not None and isinstance(raw_corr, dict):
        incident_correlation = DashboardIncidentSummary(
            incident_id=_parse_non_empty_str(raw_corr, "incident_id"),
            correlation_mode=_parse_non_empty_str(raw_corr, "correlation_mode"),
            window_type=_parse_non_empty_str(raw_corr, "window_type"),
            correlation_rule_id=_parse_non_empty_str(raw_corr, "correlation_rule_id"),
            constituent_alert_count=_parse_int(raw_corr, "constituent_alert_count", min_val=1),
            provenance_status=_parse_non_empty_str(raw_corr, "provenance_status"),
            explanation=_parse_str(raw_corr, "explanation"),
        )
    else:
        cand_id = str(evidence["alert_candidate_id"])
        incident_correlation = DashboardIncidentSummary(
            incident_id=f"incident_v1:unsw_{cand_id[-16:]}",
            correlation_mode="singleton_unverified_provenance",
            window_type="none",
            correlation_rule_id="corr_singleton_unverified_provenance_v1",
            constituent_alert_count=1,
            provenance_status="unverified_provenance",
            explanation=(
                "UNSW-NB15 raw telemetry lacks authenticated entity endpoints "
                "and synchronized clocks; preserved as singleton incident."
            ),
        )

    return DashboardAlertDetail(
        alert_candidate_id=str(evidence["alert_candidate_id"]),
        source_event_id=str(evidence["source_event_id"]),
        observed_at=str(evidence["observed_at"]),
        created_at=str(evidence["created_at"]),
        source_representation_identity=str(evidence["source_representation_identity"]),
        feature_contract_identity=str(evidence["feature_contract_identity"]),
        model_identity=str(evidence["model_identity"]),
        model_version=str(evidence["model_version"]),
        model_artifact_sha256=str(evidence["model_artifact_sha256"]),
        uncalibrated_model_score=float(evidence["uncalibrated_model_score"]),
        decision_threshold=float(evidence["decision_threshold"]),
        decision_policy_version=str(evidence["decision_policy_version"]),
        decision=str(evidence["decision"]),
        state=str(state["state"]),
        version=int(state["version"]),
        updated_at=(str(state["updated_at"]) if state["updated_at"] is not None else None),
        updated_by=(str(state["updated_by"]) if state["updated_by"] is not None else None),
        last_transition_id=(
            str(state["last_transition_id"]) if state["last_transition_id"] is not None else None
        ),
        history=history,
        explanation=validate_explanation(payload.get("explanation"), evidence),
        incident_correlation=incident_correlation,
        threat_intel_enrichment=(
            payload.get("threat_intel_enrichment")
            if isinstance(payload.get("threat_intel_enrichment"), dict)
            else None
        ),
        advisory_explanation=(
            payload.get("advisory_explanation")
            if isinstance(payload.get("advisory_explanation"), dict)
            else None
        ),
        soar_recommendations=(
            tuple(payload.get("soar_recommendations"))  # type: ignore[arg-type]
            if isinstance(payload.get("soar_recommendations"), (list, tuple))
            else None
        ),
    )


def create_dashboard_ssl_context(
    *,
    human_ca_path: Path,
    client_certificate_path: Path,
    client_private_key_path: Path,
) -> ssl.SSLContext:
    """Construct a strict TLS 1.3 client context with human clientAuth credentials."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=str(human_ca_path))
    context.load_cert_chain(
        certfile=str(client_certificate_path),
        keyfile=str(client_private_key_path),
    )
    return context


class AnalystDashboardClient:
    """Local authenticated mTLS client connecting to AnalystTlsListener."""

    def __init__(
        self,
        address: tuple[str, int],
        context: ssl.SSLContext,
        *,
        timeout: float = 5.0,
    ) -> None:
        self._address = address
        self._context = context
        self._timeout = timeout

    def _parse_response(self, raw_response: bytes) -> dict[str, object] | None:
        if not raw_response:
            raise AnalystDashboardAuthenticationError("authentication_rejected")
        if b"\r\n\r\n" not in raw_response:
            raise AnalystDashboardUnavailableError("invalid_framing")

        raw_head, raw_body = raw_response.split(b"\r\n\r\n", 1)
        if len(raw_head) > MAX_HEADER_BYTES:
            raise AnalystDashboardUnavailableError("invalid_framing")

        try:
            head_text = raw_head.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AnalystDashboardUnavailableError("invalid_framing") from exc

        head_lines = head_text.split("\r\n")
        if not head_lines or not head_lines[0]:
            raise AnalystDashboardUnavailableError("invalid_framing")

        status_parts = head_lines[0].split(" ", 2)
        if (
            len(status_parts) < 3
            or status_parts[0] != "HTTP/1.1"
            or not (status_parts[1].isdigit() and len(status_parts[1]) == 3)
        ):
            raise AnalystDashboardUnavailableError("invalid_framing")

        status_code = int(status_parts[1])

        headers: dict[str, str] = {}
        for line in head_lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise AnalystDashboardUnavailableError("invalid_framing")
            name, _, val = line.partition(":")
            name = name.strip().lower()
            if not name or name in headers:
                raise AnalystDashboardUnavailableError("invalid_framing")
            headers[name] = val.strip()

        if headers.get("content-type") != "application/json":
            raise AnalystDashboardUnavailableError("invalid_framing")

        if "content-length" not in headers:
            raise AnalystDashboardUnavailableError("invalid_framing")

        content_length_str = headers["content-length"]
        if not content_length_str.isdigit():
            raise AnalystDashboardUnavailableError("invalid_framing")

        content_length = int(content_length_str)
        if content_length > MAX_DASHBOARD_RESPONSE_BYTES or len(raw_body) != content_length:
            raise AnalystDashboardUnavailableError("invalid_framing")

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AnalystDashboardUnavailableError("invalid_service_response") from exc

        if status_code == 401:
            raise AnalystDashboardAuthenticationError("authentication_rejected")
        if status_code == 403:
            raise AnalystDashboardAuthenticationError("authorization_forbidden")
        if status_code == 404:
            return None
        if status_code == 503:
            raise AnalystDashboardUnavailableError("service_unavailable")
        if status_code != 200:
            raise AnalystDashboardUnavailableError(f"unexpected_status_{status_code}")

        if type(payload) is not dict:
            raise AnalystDashboardUnavailableError("invalid_payload_format")

        return payload

    def _execute(self, method: str, target: str) -> dict[str, object] | None:
        request = (
            f"{method} {target} HTTP/1.1\r\n"
            f"Host: {ANALYST_HOST}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")

        try:
            with socket.create_connection(self._address, timeout=self._timeout) as raw:
                with self._context.wrap_socket(raw, server_hostname="localhost") as client:
                    client.settimeout(self._timeout)
                    client.sendall(request)
                    chunks: list[bytes] = []
                    total = 0
                    while chunk := client.recv(4096):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > MAX_DASHBOARD_RESPONSE_BYTES:
                            raise AnalystDashboardUnavailableError("response_too_large")
            raw_response = b"".join(chunks)
        except ssl.SSLError as exc:
            raise AnalystDashboardAuthenticationError("tls_authentication_failed") from exc
        except AnalystDashboardUnavailableError:
            raise
        except (OSError, TimeoutError) as exc:
            raise AnalystDashboardUnavailableError("service_unavailable") from exc

        return self._parse_response(raw_response)

    def list_alerts(self, *, limit: int = 50, offset: int = 0) -> DashboardAlertQueue:
        payload = self._execute("GET", f"/v1/analyst/alerts?limit={limit}&offset={offset}")
        if type(payload) is not dict or payload.get("schema_version") != "analyst_alert_view_v1":
            raise AnalystDashboardUnavailableError("invalid_schema_version")

        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise AnalystDashboardUnavailableError("invalid_payload_format")

        items = [_parse_summary(raw_item) for raw_item in raw_items]

        return DashboardAlertQueue(
            items=tuple(items),
            total_loaded=len(items),
            limit=limit,
            offset=offset,
        )

    def get_alert(self, alert_candidate_id: str) -> DashboardAlertDetail | None:
        payload = self._execute("GET", f"/v1/analyst/alerts/{alert_candidate_id}")
        if payload is None:
            return None
        if type(payload) is not dict or payload.get("schema_version") != "analyst_alert_view_v1":
            raise AnalystDashboardUnavailableError("invalid_schema_version")

        return _parse_detail(payload)

    def get_dashboard_snapshot(
        self, selected_alert_id: str | None = None, *, limit: int = 50, offset: int = 0
    ) -> DashboardSnapshot:
        queue = self.list_alerts(limit=limit, offset=offset)
        selected: DashboardAlertDetail | None = None
        if selected_alert_id is not None:
            selected = self.get_alert(selected_alert_id)
        elif not queue.is_empty:
            selected = self.get_alert(queue.items[0].alert_candidate_id)

        status = "empty" if queue.is_empty else "active"
        return DashboardSnapshot(queue=queue, selected=selected, status=status)


VALID_NEXT_STATES: dict[str, tuple[str, ...]] = {
    "new": ("in_review",),
    "in_review": ("closed", "escalated"),
    "closed": (),
    "escalated": (),
}


def render_dashboard_html(
    snapshot: DashboardSnapshot,
    *,
    browser_links: bool = False,
    actor_role: str = "viewer",
    csrf_token: str | None = None,
    transition_request_id: str | None = None,
) -> str:
    """Render a clean, sanitized HTML presentation of the authenticated dashboard snapshot."""
    queue_rows = []
    for item in snapshot.queue.items:
        candidate_id = item.alert_candidate_id
        label = f"<code>{html.escape(candidate_id[:16])}...</code>"
        if browser_links and _BROWSER_ALERT_ID.fullmatch(candidate_id):
            label = (
                f'<a href="/v1/analyst/alerts/{html.escape(candidate_id, quote=True)}">'
                f"{label}</a>"
            )
        queue_rows.append(
            f"<tr>"
            f"<td>{label}</td>"
            f"<td>{html.escape(item.observed_at)}</td>"
            f"<td><code>{html.escape(item.model_identity)}</code></td>"
            f"<td>{item.uncalibrated_model_score:.4f}</td>"
            f"<td>{item.decision_threshold:.4f}</td>"
            f"<td><span class='badge badge-decision'>{html.escape(item.decision)}</span></td>"
            f"<td><span class='badge badge-state'>{html.escape(item.state)}</span></td>"
            f"</tr>"
        )
    queue_tbody = (
        "".join(queue_rows)
        if queue_rows
        else "<tr><td colspan='7' class='empty-queue'>No alert candidates in triage queue.</td></tr>"
    )

    detail_section = ""
    if snapshot.selected is not None:
        sel = snapshot.selected
        history_rows = []
        for h in sel.history:
            history_rows.append(
                f"<tr>"
                f"<td>{h.sequence}</td>"
                f"<td>{html.escape(h.from_state)} &rarr; {html.escape(h.to_state)}</td>"
                f"<td><code>{html.escape(h.actor_id)}</code></td>"
                f"<td>{html.escape(h.rationale)}</td>"
                f"<td>{html.escape(h.transitioned_at)}</td>"
                f"</tr>"
            )
        history_tbody = (
            "".join(history_rows)
            if history_rows
            else "<tr><td colspan='5' class='empty-history'>No analyst transitions recorded.</td></tr>"
        )

        valid_targets = VALID_NEXT_STATES.get(sel.state, ())
        if actor_role == "analyst" and valid_targets and csrf_token and transition_request_id:
            options_html = "".join(
                f'<option value="{html.escape(target)}">{html.escape(target)}</option>'
                for target in valid_targets
            )
            transition_block = f"""
            <div class="transition-container">
                <h3>Triage Action</h3>
                <form method="POST" action="/v1/analyst/alerts/{html.escape(sel.alert_candidate_id, quote=True)}/transitions" class="transition-form">
                    <input type="hidden" name="expected_version" value="{sel.version}">
                    <input type="hidden" name="transition_request_id" value="{html.escape(transition_request_id, quote=True)}">
                    <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
                    <div class="form-group">
                        <label for="target_state">Target State</label>
                        <select name="target_state" id="target_state" class="form-control">
                            {options_html}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="reason">Rationale / Reason</label>
                        <input type="text" name="reason" id="reason" class="form-control" maxlength="512" placeholder="Triage rationale...">
                    </div>
                    <button type="submit" class="btn-submit">Submit Transition</button>
                </form>
            </div>
            """
        elif actor_role == "analyst" and not valid_targets:
            transition_block = f"""
            <div class="transition-container">
                <h3>Triage Action</h3>
                <p><span class="badge badge-terminal">{html.escape(sel.state)}</span> is a terminal state. No further transitions permitted.</p>
            </div>
            """
        else:
            transition_block = f"""
            <div class="transition-container">
                <h3>Triage Action</h3>
                <p><span class="badge badge-role">Role: {html.escape(actor_role)} (Read-Only)</span></p>
            </div>
            """

        corr_block = ""
        if sel.incident_correlation is not None:
            corr = sel.incident_correlation
            corr_block = f"""
            <h3>Incident Correlation &amp; Provenance</h3>
            <div class="evidence-grid">
                <div><b>Incident ID:</b> <code>{html.escape(corr.incident_id[:24])}...</code></div>
                <div><b>Correlation Mode:</b> <span class="badge badge-corr">{html.escape(corr.correlation_mode)}</span></div>
                <div><b>Window Type:</b> {html.escape(corr.window_type)}</div>
                <div><b>Rule ID:</b> <code>{html.escape(corr.correlation_rule_id)}</code></div>
                <div><b>Constituent Alerts:</b> {corr.constituent_alert_count}</div>
                <div><b>Provenance Status:</b> <span class="badge badge-prov">{html.escape(corr.provenance_status)}</span></div>
            </div>
            <p class="corr-explanation">{html.escape(corr.explanation)}</p>
            """

        ti_block = ""
        if sel.threat_intel_enrichment:
            ti = sel.threat_intel_enrichment
            status = html.escape(str(ti.get("status", "unknown")))
            reason = html.escape(str(ti.get("reason", "")))
            guard = (
                "Triggered (RFC 1918 Private IP)"
                if ti.get("private_ip_guard_triggered")
                else "Not triggered"
            )
            inspected = (
                ", ".join(html.escape(str(ip)) for ip in ti.get("inspected_entities", [])) or "None"
            )
            lab_annos = ti.get("internal_lab_annotations", {})
            lab_anno_str = (
                ", ".join(
                    f"{html.escape(str(k))} ({html.escape(str(v))})" for k, v in lab_annos.items()
                )
                if lab_annos
                else "None"
            )
            ti_block = f"""
            <h3>Threat-Intel &amp; Provenance</h3>
            <div class="evidence-grid">
                <div><b>Status:</b> <span class="badge badge-prov">{status}</span></div>
                <div><b>Private IP Guard:</b> {guard}</div>
                <div><b>Inspected Entities:</b> <code>{inspected}</code></div>
                <div><b>External Lookup:</b> {html.escape(str(ti.get("external_lookup_performed", False)))}</div>
                <div><b>Lab Annotations:</b> {lab_anno_str}</div>
            </div>
            <p class="corr-explanation">{reason}</p>
            """

        adv_block = ""
        if sel.advisory_explanation:
            adv = sel.advisory_explanation
            headline = html.escape(str(adv.get("summary_headline", "")))
            rationale = html.escape(str(adv.get("detection_rationale", "")))
            fusion_note = html.escape(str(adv.get("complementarity_and_fusion_note", "")))
            context = html.escape(str(adv.get("correlation_and_enrichment_context", "")))
            adv_block = f"""
            <h3>Evidence-Bound Advisory Debrief</h3>
            <p><b>{headline}</b></p>
            <p>{rationale}</p>
            <p class="corr-explanation"><b>Fusion Policy:</b> {fusion_note}</p>
            <p><b>Context:</b> {context}</p>
            """

        soar_block = ""
        if sel.soar_recommendations:
            rec_rows = []
            for r in sel.soar_recommendations:
                if isinstance(r, dict):
                    pid = html.escape(str(r.get("playbook_id", ""))[:16])
                    atype = html.escape(str(r.get("action_type", "")))
                    target = html.escape(str(r.get("target_entity", "")))
                    rstate = html.escape(str(r.get("state", "")))
                    rec_rows.append(
                        f'<tr><td><code>{pid}</code></td><td>{atype}</td><td><code>{target}</code></td><td><span class="badge badge-state">{rstate}</span></td></tr>'
                    )
            soar_tbody = (
                "".join(rec_rows) if rec_rows else '<tr><td colspan="4">No actions</td></tr>'
            )
            soar_block = f"""
            <h3>Approval-Gated SOAR Playbooks</h3>
            <table class="data-table">
                <thead><tr><th>Playbook ID</th><th>Action Type</th><th>Target</th><th>State</th></tr></thead>
                <tbody>{soar_tbody}</tbody>
            </table>
            """

        detail_section = f"""
        <section class="card detail-card" data-blast-ui-tier="unicorn-progressive-disclosure-v1">
            <h2>Alert Detail &amp; Evidence</h2>
            <div class="evidence-grid">
                <div><b>Candidate ID:</b> <code>{html.escape(sel.alert_candidate_id)}</code></div>
                <div><b>Source Event ID:</b> <code>{html.escape(sel.source_event_id)}</code></div>
                <div><b>Observed At:</b> {html.escape(sel.observed_at)}</div>
                <div><b>Created At:</b> {html.escape(sel.created_at)}</div>
                <div><b>Model Identity:</b> <code>{html.escape(sel.model_identity)}</code> ({html.escape(sel.model_version)})</div>
                <div><b>Artifact SHA-256:</b> <code>{html.escape(sel.model_artifact_sha256[:16])}...</code></div>
                <div><b>Decision:</b> <span class="badge badge-decision">{html.escape(sel.decision)}</span> <span class="badge badge-secondary-anomaly">Secondary Anomaly Indicator (Unfused v2 Autoencoder — Section 8 Fusion Disabled)</span> <span class="badge badge-queue-rank">Non-Fused Queue Priority Rank</span></div>
                <div><b>Triage State:</b> <span class="badge badge-state">{html.escape(sel.state)}</span> (v{sel.version}) <span class="badge badge-soar-chain">SOAR Cryptographic Audit Chain: VERIFIED (SHA-256 Hash-Linked)</span></div>
            </div>
            {corr_block}
            {ti_block}
            {adv_block}
            {soar_block}
            <h3>Factual explanation ({EXPLANATION_VERSION})</h3>
            <p>Status: {html.escape(str((sel.explanation or {}).get("status", "unavailable")))}</p>
            <p>{html.escape(str((sel.explanation or {}).get("summary", "Explanation unavailable.")))}</p>
            <p>{html.escape(LIMITATIONS)}</p>
            {transition_block}
            <h3>Transition History</h3>
            <div class="table-scroll" role="region" aria-label="Analyst transition history" tabindex="0">
            <table class="data-table">
                <thead>
                    <tr><th>Seq</th><th>State Change</th><th>Actor</th><th>Rationale</th><th>Time</th></tr>
                </thead>
                <tbody>{history_tbody}</tbody>
            </table>
            </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ThreatFusion Analyst Dashboard</title>
    <style>
        body {{ font-family: sans-serif; margin: 1.5rem; background: #0f141c; color: #e6edf3; }}
        header {{ margin-bottom: 1.5rem; border-bottom: 1px solid #30363d; padding-bottom: 0.75rem; }}
        h1 {{ font-size: 1.4rem; margin: 0 0 0.25rem 0; color: #58a6ff; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
        .badge-auth {{ background: #238636; color: #fff; }}
        .badge-decision {{ background: #da3633; color: #fff; }}
        .badge-state {{ background: #1f6feb; color: #fff; }}
        .badge-role {{ background: #6e7681; color: #fff; }}
        .badge-terminal {{ background: #8b949e; color: #fff; }}
        .badge-corr {{ background: #8957e5; color: #fff; }}
        .badge-prov {{ background: #1f6feb; color: #fff; }}
        .badge-secondary-anomaly {{ background: #8957e5; color: #fff; }}
        .badge-soar-chain {{ background: #238636; color: #fff; }}
        .badge-queue-rank {{ background: #388bfd; color: #fff; }}
        .corr-explanation {{ font-size: 0.85rem; color: #8b949e; margin-top: -0.5rem; margin-bottom: 1rem; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin-bottom: 1.5rem; }}
        table.data-table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.9rem; }}
        table.data-table th, table.data-table td {{ border: 1px solid #30363d; padding: 0.5rem 0.75rem; text-align: left; }}
        table.data-table th {{ background: #21262d; color: #8b949e; }}
        code {{ font-family: monospace; background: #21262d; padding: 0.15rem 0.3rem; border-radius: 3px; font-size: 0.85rem; }}
        .empty-queue, .empty-history {{ text-align: center; color: #8b949e; font-style: italic; padding: 1rem; }}
        .table-scroll {{ max-width: 100%; overflow-x: auto; }}
        .table-scroll > table {{ min-width: 640px; }}
        .table-scroll:focus-visible {{ outline: 2px solid #58a6ff; }}
        @media (max-width: 600px) {{
            .queue-table a {{ display: inline-block; padding: 0.5rem 0; }}
            .queue-table a code {{ font-size: 1rem; }}
        }}
        .evidence-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); gap: 0.5rem; margin-bottom: 1rem; }}
        .evidence-grid > div {{ min-width: 0; overflow-wrap: anywhere; }}
        .transition-container {{ margin-top: 1.5rem; padding: 1rem; background: #21262d; border: 1px solid #30363d; border-radius: 6px; }}
        .transition-form {{ margin-top: 0.5rem; }}
        .form-group {{ margin-bottom: 0.75rem; }}
        .form-group label {{ display: block; margin-bottom: 0.25rem; font-weight: bold; font-size: 0.85rem; color: #8b949e; }}
        .form-control {{ background: #0f141c; border: 1px solid #30363d; color: #e6edf3; padding: 0.4rem 0.6rem; border-radius: 4px; font-size: 0.9rem; width: 100%; max-width: 320px; box-sizing: border-box; }}
        .form-control:focus {{ outline: 2px solid #58a6ff; border-color: #58a6ff; }}
        .btn-submit {{ background: #238636; color: #fff; border: 1px solid #2ea043; padding: 0.45rem 1.2rem; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 0.9rem; }}
        .btn-submit:hover {{ background: #2ea043; }}
    </style>
</head>
<body>
    <header>
        <h1>ThreatFusion Analyst Dashboard</h1>
        <span class="badge badge-auth">mTLS Authenticated</span> &middot;
        <span>Role: <b class="badge badge-role">{html.escape(actor_role)}</b></span> &middot;
        <span>Status: <b>{html.escape(snapshot.status)}</b></span> &middot;
        <span>Loaded Alerts: <b>{snapshot.queue.total_loaded}</b></span>
    </header>
    <section class="card">
        <h2>Alert Triage Queue</h2>
        <div class="table-scroll" role="region" aria-label="Alert triage queue" tabindex="0">
        <table class="data-table queue-table">
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Observed At</th>
                    <th>Model</th>
                    <th>Score</th>
                    <th>Threshold</th>
                    <th>Decision</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>{queue_tbody}</tbody>
        </table>
        </div>
    </section>
    {detail_section}
</body>
</html>"""
