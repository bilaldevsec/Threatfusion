"""Sourced Threat-Intelligence Enrichment with strict RFC 1918 Private-IP Guard.

Enforces Section 13.C of ThreatFusion:
- Rule 1 (Provenance Gate): Unverified provenance contracts skip enrichment.
- Rule 2 (Private IP Guard): Private/loopback/link-local/reserved addresses
  (e.g., Slide 14 Attacker 10.0.0.4 and Victim 10.0.0.5) trigger internal
  lab annotations and are NEVER sent to external public threat-intel feeds.
- Rule 3 (Sourced Feed Lookup & Outage Isolation): Evaluates public IPs against
  feed snapshots with staleness and outage isolation so threat-intel failures
  never block Random Forest alert creation or triage.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract


@dataclass(frozen=True, slots=True)
class ThreatIntelIndicatorMatch:
    """A matched indicator of compromise from an authenticated feed source."""

    indicator: str
    indicator_type: str  # "ipv4", "ipv6", "domain", "sha256"
    feed_source: str
    threat_category: str
    confidence: float  # 0.0 to 1.0
    first_seen_utc: str
    last_seen_utc: str
    reference_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "feed_source": self.feed_source,
            "threat_category": self.threat_category,
            "confidence": self.confidence,
            "first_seen_utc": self.first_seen_utc,
            "last_seen_utc": self.last_seen_utc,
            "reference_id": self.reference_id,
        }


@dataclass(frozen=True, slots=True)
class ThreatIntelEnrichmentResult:
    """Structured enrichment outcome with provenance and privacy status."""

    status: str  # "matched_verified_ioc", "clean_no_ioc_match", "internal_lab_entity_annotated", "skipped_unverified_provenance", "degraded_enrichment_unavailable", "degraded_enrichment_stale"
    provenance_verified: bool
    external_lookup_performed: bool
    private_ip_guard_triggered: bool
    inspected_entities: tuple[str, ...]
    internal_lab_annotations: Mapping[str, str]
    matches: tuple[ThreatIntelIndicatorMatch, ...]
    feed_snapshot_id: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "provenance_verified": self.provenance_verified,
            "external_lookup_performed": self.external_lookup_performed,
            "private_ip_guard_triggered": self.private_ip_guard_triggered,
            "inspected_entities": list(self.inspected_entities),
            "internal_lab_annotations": dict(self.internal_lab_annotations),
            "matches": [m.to_dict() for m in self.matches],
            "feed_snapshot_id": self.feed_snapshot_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ThreatIntelFeedSnapshot:
    """Immutable snapshot of threat intelligence indicators with validity bounds."""

    snapshot_id: str
    generated_at_utc: datetime
    max_staleness_seconds: float
    indicators: Mapping[str, ThreatIntelIndicatorMatch] = field(default_factory=dict)


class SourcedThreatIntelEnricher:
    """Enrichment engine enforcing provenance gating, RFC 1918 suppression, and outage isolation."""

    DEFAULT_INTERNAL_LAB_REGISTRY: dict[str, str] = {
        "10.0.0.4": "azure_lab_attacker_vm_slide14",
        "10.0.0.5": "azure_lab_victim_suricata_vm_slide14",
    }

    def __init__(
        self,
        feed_snapshot: ThreatIntelFeedSnapshot | None = None,
        feed_provider: Any = None,
        internal_lab_registry: Mapping[str, str] | None = None,
    ) -> None:
        self.feed_snapshot = feed_snapshot
        self.feed_provider = feed_provider
        self.internal_lab_registry = (
            dict(internal_lab_registry)
            if internal_lab_registry is not None
            else dict(self.DEFAULT_INTERNAL_LAB_REGISTRY)
        )

    def enrich_entity_contract(
        self,
        contract: EntityProvenanceContract | None,
        *,
        current_time: datetime | None = None,
    ) -> ThreatIntelEnrichmentResult:
        """Enrich an entity contract adhering to strict safety rules.

        Rule 1: If contract is None or not contract.is_verified(), return skipped_unverified_provenance.
        Rule 2: Parse IPs. If private/loopback/link-local/reserved, trigger private_ip_guard_triggered
                and annotate internal lab role without public feed query.
        Rule 3: If public IPs, query feed snapshot/provider with outage and staleness isolation.
        """
        now = current_time or datetime.now(UTC)

        # Rule 1: Provenance Gate
        if contract is None or not contract.is_verified():
            return ThreatIntelEnrichmentResult(
                status="skipped_unverified_provenance",
                provenance_verified=False,
                external_lookup_performed=False,
                private_ip_guard_triggered=False,
                inspected_entities=(),
                internal_lab_annotations={},
                matches=(),
                feed_snapshot_id=None,
                reason="Provenance contract is missing or not verified; intelligence lookup skipped.",
            )

        # Extract entities to inspect
        raw_ips: list[str] = []
        src_ip = getattr(contract, "src_ip", getattr(contract, "src_entity_id", None))
        dst_ip = getattr(contract, "dst_ip", getattr(contract, "dst_entity_id", None))
        if src_ip:
            raw_ips.append(str(src_ip))
        if dst_ip and dst_ip != src_ip:
            raw_ips.append(str(dst_ip))

        private_guard_triggered = False
        internal_annotations: dict[str, str] = {}
        public_ips_to_query: list[str] = []

        # Rule 2: Private / Loopback / Link-Local IP Guard
        for ip_str in raw_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                # Non-IP entity or malformed IP string
                continue

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
            ):
                private_guard_triggered = True
                role = self.internal_lab_registry.get(ip_str, "internal_private_entity")
                internal_annotations[ip_str] = role
            else:
                public_ips_to_query.append(ip_str)

        # If all entities are private / internal lab entities:
        if raw_ips and not public_ips_to_query:
            return ThreatIntelEnrichmentResult(
                status="internal_lab_entity_annotated",
                provenance_verified=True,
                external_lookup_performed=False,
                private_ip_guard_triggered=True,
                inspected_entities=tuple(raw_ips),
                internal_lab_annotations=internal_annotations,
                matches=(),
                feed_snapshot_id=self.feed_snapshot.snapshot_id if self.feed_snapshot else None,
                reason="Internal lab / private IP entities annotated; external lookups suppressed per RFC 1918 guard.",
            )

        # Rule 3: Public IP Sourced Feed Lookup with Outage / Staleness Isolation
        # Check provider or snapshot availability
        if self.feed_provider is not None:
            try:
                provider_matches = self.feed_provider.query_indicators(public_ips_to_query)
                matches_list = [
                    m for m in provider_matches if isinstance(m, ThreatIntelIndicatorMatch)
                ]
                status = "matched_verified_ioc" if matches_list else "clean_no_ioc_match"
                return ThreatIntelEnrichmentResult(
                    status=status,
                    provenance_verified=True,
                    external_lookup_performed=True,
                    private_ip_guard_triggered=private_guard_triggered,
                    inspected_entities=tuple(raw_ips),
                    internal_lab_annotations=internal_annotations,
                    matches=tuple(matches_list),
                    feed_snapshot_id=getattr(self.feed_provider, "snapshot_id", None),
                    reason="Provider lookup completed successfully.",
                )
            except Exception as exc:
                return ThreatIntelEnrichmentResult(
                    status="degraded_enrichment_unavailable",
                    provenance_verified=True,
                    external_lookup_performed=True,
                    private_ip_guard_triggered=private_guard_triggered,
                    inspected_entities=tuple(raw_ips),
                    internal_lab_annotations=internal_annotations,
                    matches=(),
                    feed_snapshot_id=None,
                    reason=f"Feed provider exception: {exc}",
                )

        if self.feed_snapshot is None:
            return ThreatIntelEnrichmentResult(
                status="degraded_enrichment_unavailable",
                provenance_verified=True,
                external_lookup_performed=False,
                private_ip_guard_triggered=private_guard_triggered,
                inspected_entities=tuple(raw_ips),
                internal_lab_annotations=internal_annotations,
                matches=(),
                feed_snapshot_id=None,
                reason="No threat intelligence feed snapshot configured.",
            )

        # Staleness check
        gen_time = self.feed_snapshot.generated_at_utc
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=UTC)
        age_seconds = (now - gen_time).total_seconds()
        if age_seconds > self.feed_snapshot.max_staleness_seconds:
            return ThreatIntelEnrichmentResult(
                status="degraded_enrichment_stale",
                provenance_verified=True,
                external_lookup_performed=True,
                private_ip_guard_triggered=private_guard_triggered,
                inspected_entities=tuple(raw_ips),
                internal_lab_annotations=internal_annotations,
                matches=(),
                feed_snapshot_id=self.feed_snapshot.snapshot_id,
                reason=f"Feed snapshot age {age_seconds:.1f}s exceeds maximum staleness {self.feed_snapshot.max_staleness_seconds:.1f}s.",
            )

        # Query snapshot indicators
        found_matches: list[ThreatIntelIndicatorMatch] = []
        for pub_ip in public_ips_to_query:
            if pub_ip in self.feed_snapshot.indicators:
                found_matches.append(self.feed_snapshot.indicators[pub_ip])

        status = "matched_verified_ioc" if found_matches else "clean_no_ioc_match"
        reason = (
            f"Matched {len(found_matches)} indicators in verified feed snapshot."
            if found_matches
            else "No known indicators matched in verified feed snapshot."
        )

        return ThreatIntelEnrichmentResult(
            status=status,
            provenance_verified=True,
            external_lookup_performed=True,
            private_ip_guard_triggered=private_guard_triggered,
            inspected_entities=tuple(raw_ips),
            internal_lab_annotations=internal_annotations,
            matches=tuple(found_matches),
            feed_snapshot_id=self.feed_snapshot.snapshot_id,
            reason=reason,
        )
