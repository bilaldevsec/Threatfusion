"""Neutral 4-Block Investigation Case Anatomy schema and builder.

Shared by Stage 5 explanations and Stage 6 SOAR / TheHive case creation
without introducing any dependency from SOAR modules onto advisory modules
(preserving Gate G9 import isolation).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any

RECALL_GAIN_BADGE: str = (
    "+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"
)
MITRE_TECHNIQUE_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CANONICAL_INDEXED_TECHNIQUES: frozenset[str] = frozenset(
    {
        "T1021",
        "T1041",
        "T1046",
        "T1048",
        "T1059",
        "T1071.001",
        "T1110",
        "T1133",
        "T1190",
        "T1210",
        "T1498",
        "T1499",
        "T1552",
        "T1557",
        "T1595",
    }
)


@dataclass(frozen=True, slots=True)
class SoarCaseEvidenceInput:
    """Neutral duck-typed evidence bundle for SOAR / TheHive 4-block case anatomy."""

    candidate_id: str
    record_id: str
    rf_model_version: str
    rf_attack_probability: float
    rf_threshold: float
    top_feature_signals: Mapping[str, float]
    ae_v2_reconstruction_error: float | None = None
    ae_v2_threshold: float = 0.1181361214680695
    incident_id: str | None = None
    correlation_status: str = "uncorrelatable_missing_entity"
    enrichment_result: Any | None = None
    observed_at: str | None = None
    chroma_rag_hits: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutiveSummaryBlock:
    """Block 1: Executive Summary with primary decision authority and RFC1918 guard."""

    risk_level: str
    rf_probability: float
    autoencoder_anomaly_rank: int
    recall_gain_badge: str
    affected_network_assets: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "rf_probability": self.rf_probability,
            "autoencoder_anomaly_rank": self.autoencoder_anomaly_rank,
            "recall_gain_badge": self.recall_gain_badge,
            "affected_network_assets": list(self.affected_network_assets),
        }


@dataclass(frozen=True, slots=True)
class AttackTimelineBlock:
    """Block 2: Attack Timeline with burst/campaign windowing and volume deltas."""

    window_type: str  # "30.0s_burst" | "600.0s_campaign"
    correlated_flow_count: int
    chronological_flow_progression: tuple[dict[str, Any], ...]
    byte_volume_delta: int
    packet_volume_delta: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_type": self.window_type,
            "correlated_flow_count": self.correlated_flow_count,
            "chronological_flow_progression": list(self.chronological_flow_progression),
            "byte_volume_delta": self.byte_volume_delta,
            "packet_volume_delta": self.packet_volume_delta,
        }


@dataclass(frozen=True, slots=True)
class MitreMappingBlock:
    """Block 3: MITRE ATT&CK Mapping grounded in stored/RAG evidence."""

    technique_id: str
    tactic_name: str
    cosine_similarity: float
    defensive_rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "tactic_name": self.tactic_name,
            "cosine_similarity": self.cosine_similarity,
            "defensive_rationale": self.defensive_rationale,
        }


@dataclass(frozen=True, slots=True)
class CryptographicSoarStatusBlock:
    """Block 4: Cryptographic SOAR Status with immutable SHA-256 hash chain and HMAC."""

    playbook_id: str
    playbook_state: str  # "pending_approval" | "approved" | "executed_simulated"
    prev_entry_sha256: str
    entry_sha256: str
    audit_chain_valid: bool
    hmac_signature_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "playbook_state": self.playbook_state,
            "prev_entry_sha256": self.prev_entry_sha256,
            "entry_sha256": self.entry_sha256,
            "audit_chain_valid": self.audit_chain_valid,
            "hmac_signature_verified": self.hmac_signature_verified,
        }


@dataclass(frozen=True, slots=True)
class FourBlockInvestigationAnatomy:
    """Standardized 4-Block Investigation Case Anatomy for TheHive, Advisory & Dashboard."""

    block_1_executive_summary: ExecutiveSummaryBlock
    block_2_attack_timeline: AttackTimelineBlock
    block_3_mitre_mapping: MitreMappingBlock
    block_4_cryptographic_soar_status: CryptographicSoarStatusBlock

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_1_executive_summary": self.block_1_executive_summary.to_dict(),
            "block_2_attack_timeline": self.block_2_attack_timeline.to_dict(),
            "block_3_mitre_mapping": self.block_3_mitre_mapping.to_dict(),
            "block_4_cryptographic_soar_status": self.block_4_cryptographic_soar_status.to_dict(),
        }


def _collect_known_ips(bundle: Any, provenance: Any | None) -> set[str]:
    known_ips: set[str] = set()
    enrichment = getattr(bundle, "enrichment_result", None)
    inspected = getattr(enrichment, "inspected_entities", None) if enrichment else None
    if inspected:
        known_ips.update(str(ip) for ip in inspected)
    if provenance is not None:
        src = getattr(provenance, "src_ip", None) or getattr(provenance, "src_entity_id", None)
        dst = getattr(provenance, "dst_ip", None) or getattr(provenance, "dst_entity_id", None)
        for cand in (src, dst):
            if cand and isinstance(cand, str):
                clean_cand = cand.split(":")[-1]
                if _IP_REGEX.match(clean_cand):
                    known_ips.add(clean_cand)
    return known_ips


def _candidate_explanation_grounded(
    candidate_explanation: Any,
    bundle: Any,
    known_ips: set[str],
) -> bool:
    if candidate_explanation is None:
        return True
    if isinstance(candidate_explanation, str):
        found_ips = set(_IP_REGEX.findall(candidate_explanation))
        return not any(ip not in known_ips for ip in found_ips)
    if isinstance(candidate_explanation, Mapping):
        text_vals = " ".join(
            str(v)
            for v in candidate_explanation.values()
            if isinstance(v, (str, list, tuple, dict))
        )
        found_ips = set(_IP_REGEX.findall(text_vals))
        return not any(ip not in known_ips for ip in found_ips)
    # Duck-typed structured explanation object (e.g., EvidenceBoundExplanation)
    if getattr(candidate_explanation, "advisory_only_non_authoritative", None) is not True:
        return False
    if getattr(candidate_explanation, "groundedness_verified", None) is False:
        return False
    get_allowed = getattr(bundle, "get_allowed_evidence_keys", None)
    cited = getattr(candidate_explanation, "cited_evidence_keys", None)
    if callable(get_allowed) and cited is not None:
        allowed_keys = set(get_allowed())
        if not set(cited).issubset(allowed_keys):
            return False
    text_parts = [
        str(getattr(candidate_explanation, attr, "") or "")
        for attr in (
            "summary_headline",
            "detection_rationale",
            "complementarity_and_fusion_note",
            "correlation_and_enrichment_context",
        )
    ]
    checks = getattr(candidate_explanation, "recommended_analyst_checks", ()) or ()
    text_parts.extend(str(item) for item in checks)
    found_ips = set(_IP_REGEX.findall(" ".join(text_parts)))
    return not any(ip not in known_ips for ip in found_ips)


def build_soar_four_block_investigation_anatomy(
    bundle: Any,
    *,
    candidate_explanation: Any | None = None,
    provenance: Any | None = None,
    candidate_affected_assets: Sequence[str] | None = None,
    window_type: str = "30.0s_burst",
    correlated_flow_count: int = 1,
    chronological_flow_progression: Sequence[dict[str, Any]] | None = None,
    byte_volume_delta: int = 0,
    packet_volume_delta: int = 0,
    technique_id: str | None = None,
    tactic_name: str | None = None,
    cosine_similarity: float | None = None,
    defensive_rationale: str | None = None,
    soar_record: Any | None = None,
    soar_repo: Any | None = None,
    playbook_id: str | None = None,
    playbook_state: str = "pending_approval",
    prev_entry_sha256: str | None = None,
    entry_sha256: str | None = None,
    audit_chain_valid: bool = True,
    hmac_signature_verified: bool = True,
) -> FourBlockInvestigationAnatomy:
    """Construct a fail-closed 4-Block Investigation Anatomy from duck-typed SOAR evidence."""
    known_ips = _collect_known_ips(bundle, provenance)
    explanation_grounded = _candidate_explanation_grounded(candidate_explanation, bundle, known_ips)

    final_assets: list[str]
    if candidate_affected_assets is not None and explanation_grounded:
        candidate_ips = [ip.strip() for ip in candidate_affected_assets if ip.strip()]
        if candidate_ips and all(ip in known_ips for ip in candidate_ips):
            final_assets = candidate_ips
        else:
            final_assets = sorted(known_ips)
    else:
        final_assets = sorted(known_ips)

    prob = float(getattr(bundle, "rf_attack_probability", 0.0))
    if prob >= 0.90:
        risk_level = "CRITICAL"
    elif prob >= 0.70:
        risk_level = "HIGH"
    elif prob >= 0.50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    ae_err = getattr(bundle, "ae_v2_reconstruction_error", None)
    ae_thresh = float(getattr(bundle, "ae_v2_threshold", 0.1181361214680695))
    ae_rank = 1 if (ae_err is not None and ae_err > ae_thresh) else 2

    block_1 = ExecutiveSummaryBlock(
        risk_level=risk_level,
        rf_probability=prob,
        autoencoder_anomaly_rank=ae_rank,
        recall_gain_badge=RECALL_GAIN_BADGE,
        affected_network_assets=tuple(final_assets),
    )

    win_str = str(window_type).lower()
    norm_window = "600.0s_campaign" if "600" in win_str or "campaign" in win_str else "30.0s_burst"
    observed_at = getattr(bundle, "observed_at", None) or ""
    flows_tuple = (
        tuple(chronological_flow_progression)
        if chronological_flow_progression is not None
        else (
            {
                "timestamp_utc": observed_at,
                "src_ip": final_assets[0] if final_assets else "",
                "dst_ip": final_assets[1] if len(final_assets) > 1 else "",
                "protocol": (
                    provenance.protocol.upper()
                    if provenance is not None and getattr(provenance, "protocol", None)
                    else "UNKNOWN"
                ),
                "bytes": int(byte_volume_delta),
                "packets": int(packet_volume_delta),
            },
        )
    )
    block_2 = AttackTimelineBlock(
        window_type=norm_window,
        correlated_flow_count=max(1, int(correlated_flow_count)),
        chronological_flow_progression=flows_tuple,
        byte_volume_delta=int(byte_volume_delta),
        packet_volume_delta=int(packet_volume_delta),
    )

    chosen_tid: str | None = None
    chosen_tactic = "Unavailable"
    chosen_score = 0.0
    chosen_rationale = "No grounded MITRE ATT&CK mapping available from stored evidence."

    rag_hits = getattr(bundle, "chroma_rag_hits", None) or ()
    rag_hit = rag_hits[0] if rag_hits else None
    if rag_hit:
        tid_hit = getattr(rag_hit, "technique_id", None) or (
            rag_hit.get("technique_id") if isinstance(rag_hit, Mapping) else None
        )
        tname_hit = getattr(rag_hit, "technique_name", "") or (
            rag_hit.get("technique_name", "") if isinstance(rag_hit, Mapping) else ""
        )
        tactic_hit = getattr(rag_hit, "tactic", "") or (
            rag_hit.get("tactic", "") if isinstance(rag_hit, Mapping) else ""
        )
        score_raw = getattr(rag_hit, "cosine_similarity", None)
        if score_raw is None and isinstance(rag_hit, Mapping):
            score_raw = rag_hit.get("cosine_similarity")
        score_hit = float(score_raw) if score_raw is not None else 0.0
        desc_hit = getattr(rag_hit, "description", "") or (
            rag_hit.get("description", "") if isinstance(rag_hit, Mapping) else ""
        )
        if tid_hit and MITRE_TECHNIQUE_REGEX.match(str(tid_hit)):
            chosen_tid = str(tid_hit)
            chosen_tactic = tactic_hit or "Unavailable"
            chosen_score = score_hit
            chosen_rationale = desc_hit or (
                f"ChromaDB 64-dim semantic RAG hit: {tname_hit}"
                if tname_hit
                else "ChromaDB semantic RAG hit."
            )

    if technique_id is not None and explanation_grounded:
        clean_tid = str(technique_id).strip()
        if MITRE_TECHNIQUE_REGEX.match(clean_tid) and clean_tid in CANONICAL_INDEXED_TECHNIQUES:
            chosen_tid = clean_tid
            if tactic_name:
                chosen_tactic = str(tactic_name)
            if cosine_similarity is not None:
                chosen_score = float(cosine_similarity)
            if defensive_rationale:
                chosen_rationale = str(defensive_rationale)

    if chosen_tid is None:
        chosen_tid = "unavailable"
        chosen_tactic = "Unavailable"
        chosen_score = 0.0
        chosen_rationale = "No grounded MITRE ATT&CK mapping available from stored evidence."

    block_3 = MitreMappingBlock(
        technique_id=chosen_tid,
        tactic_name=chosen_tactic,
        cosine_similarity=round(chosen_score, 4),
        defensive_rationale=chosen_rationale,
    )

    effective_pbid = playbook_id or "unavailable"
    effective_state = (
        playbook_state
        if playbook_state in ("pending_approval", "approved", "executed_simulated")
        else "pending_approval"
    )
    chain_valid = bool(audit_chain_valid)

    if soar_record is not None:
        effective_pbid = getattr(soar_record, "playbook_id", effective_pbid)
        st = getattr(soar_record, "state", effective_state)
        if st in ("pending_approval", "approved", "executed_simulated"):
            effective_state = st

    if soar_repo is not None and hasattr(soar_repo, "verify_audit_chain_integrity"):
        ok, _ = soar_repo.verify_audit_chain_integrity()
        chain_valid = bool(ok)

    block_4 = CryptographicSoarStatusBlock(
        playbook_id=effective_pbid,
        playbook_state=effective_state,
        prev_entry_sha256=prev_entry_sha256 or "",
        entry_sha256=entry_sha256 or "",
        audit_chain_valid=chain_valid,
        hmac_signature_verified=bool(hmac_signature_verified),
    )

    return FourBlockInvestigationAnatomy(
        block_1_executive_summary=block_1,
        block_2_attack_timeline=block_2,
        block_3_mitre_mapping=block_3,
        block_4_cryptographic_soar_status=block_4,
    )


__all__ = [
    "AttackTimelineBlock",
    "CANONICAL_INDEXED_TECHNIQUES",
    "CryptographicSoarStatusBlock",
    "ExecutiveSummaryBlock",
    "FourBlockInvestigationAnatomy",
    "MITRE_TECHNIQUE_REGEX",
    "MitreMappingBlock",
    "RECALL_GAIN_BADGE",
    "SoarCaseEvidenceInput",
    "build_soar_four_block_investigation_anatomy",
]
