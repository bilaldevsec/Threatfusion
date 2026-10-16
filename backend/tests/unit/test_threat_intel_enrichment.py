"""Unit tests for SourcedThreatIntelEnricher and RFC 1918 Private-IP Guard."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.enrichment.threat_intel import (
    SourcedThreatIntelEnricher,
    ThreatIntelFeedSnapshot,
    ThreatIntelIndicatorMatch,
)


class TestThreatIntelEnrichment:
    """Test provenance gating, RFC 1918 suppression, and outage isolation."""

    def test_unverified_provenance_skips_enrichment(self) -> None:
        """Unverified contract returns skipped_unverified_provenance with 0 external lookups."""
        enricher = SourcedThreatIntelEnricher()

        # Contract None
        res_none = enricher.enrich_entity_contract(None)
        assert res_none.status == "skipped_unverified_provenance"
        assert res_none.provenance_verified is False
        assert res_none.external_lookup_performed is False
        assert res_none.private_ip_guard_triggered is False

        # Contract unverified (missing namespace, clock not synced)
        unverified_contract = EntityProvenanceContract(
            entity_namespace_id=None,
            clock_synchronized=False,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
        )
        res_unverified = enricher.enrich_entity_contract(unverified_contract)
        assert res_unverified.status == "skipped_unverified_provenance"
        assert res_unverified.provenance_verified is False
        assert res_unverified.external_lookup_performed is False

    def test_slide14_private_ips_trigger_private_guard(self) -> None:
        """Slide 14 private IPs (10.0.0.4, 10.0.0.5) trigger private IP guard without external query."""
        enricher = SourcedThreatIntelEnricher()

        verified_contract = EntityProvenanceContract(
            entity_namespace_id="azure_lab:suricata_live_v1",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        assert verified_contract.is_verified() is True

        res = enricher.enrich_entity_contract(verified_contract)

        assert res.status == "internal_lab_entity_annotated"
        assert res.provenance_verified is True
        assert res.external_lookup_performed is False
        assert res.private_ip_guard_triggered is True
        assert res.internal_lab_annotations["10.0.0.4"] == "azure_lab_attacker_vm_slide14"
        assert res.internal_lab_annotations["10.0.0.5"] == "azure_lab_victim_suricata_vm_slide14"
        assert len(res.matches) == 0

    def test_verified_public_ips_matched_ioc(self) -> None:
        """Verified public IP matches indicator in feed snapshot."""
        now = datetime.now(UTC)
        match_ioc = ThreatIntelIndicatorMatch(
            indicator="185.220.101.5",
            indicator_type="ipv4",
            feed_source="misp_core_feed",
            threat_category="c2_infrastructure",
            confidence=0.95,
            first_seen_utc=(now - timedelta(days=2)).isoformat(),
            last_seen_utc=now.isoformat(),
            reference_id="IOC-2026-9045",
        )
        snapshot = ThreatIntelFeedSnapshot(
            snapshot_id="snapshot_20260921_v1",
            generated_at_utc=now,
            max_staleness_seconds=3600.0,
            indicators={"185.220.101.5": match_ioc},
        )
        enricher = SourcedThreatIntelEnricher(feed_snapshot=snapshot)

        verified_contract = EntityProvenanceContract(
            entity_namespace_id="external_sensor_net",
            clock_synchronized=True,
            src_entity_id="185.220.101.5",
            dst_entity_id="192.168.1.50",
            protocol="tcp",
            service_or_port="443",
        )

        res = enricher.enrich_entity_contract(verified_contract, current_time=now)

        assert res.status == "matched_verified_ioc"
        assert res.provenance_verified is True
        assert res.external_lookup_performed is True
        assert res.private_ip_guard_triggered is True  # 192.168.1.50 is private
        assert len(res.matches) == 1
        assert res.matches[0].indicator == "185.220.101.5"
        assert res.matches[0].threat_category == "c2_infrastructure"

    def test_verified_public_ips_clean_no_match(self) -> None:
        """Verified public IP not present in feed snapshot returns clean_no_ioc_match."""
        now = datetime.now(UTC)
        snapshot = ThreatIntelFeedSnapshot(
            snapshot_id="snapshot_clean_v1",
            generated_at_utc=now,
            max_staleness_seconds=3600.0,
            indicators={},
        )
        enricher = SourcedThreatIntelEnricher(feed_snapshot=snapshot)

        verified_contract = EntityProvenanceContract(
            entity_namespace_id="external_sensor_net",
            clock_synchronized=True,
            src_entity_id="185.220.101.5",
            dst_entity_id="193.142.59.20",
            protocol="tcp",
            service_or_port="80",
        )

        res = enricher.enrich_entity_contract(verified_contract, current_time=now)

        assert res.status == "clean_no_ioc_match"
        assert res.provenance_verified is True
        assert res.external_lookup_performed is True
        assert res.private_ip_guard_triggered is False
        assert len(res.matches) == 0

    def test_stale_feed_snapshot_returns_degraded_stale(self) -> None:
        """Feed snapshot older than max_staleness_seconds returns degraded_enrichment_stale."""
        now = datetime.now(UTC)
        old_time = now - timedelta(seconds=7200)
        snapshot = ThreatIntelFeedSnapshot(
            snapshot_id="snapshot_old_v1",
            generated_at_utc=old_time,
            max_staleness_seconds=3600.0,
            indicators={},
        )
        enricher = SourcedThreatIntelEnricher(feed_snapshot=snapshot)

        verified_contract = EntityProvenanceContract(
            entity_namespace_id="external_net",
            clock_synchronized=True,
            src_entity_id="185.220.101.5",
            dst_entity_id="193.142.59.20",
            protocol="tcp",
            service_or_port="80",
        )

        res = enricher.enrich_entity_contract(verified_contract, current_time=now)

        assert res.status == "degraded_enrichment_stale"
        assert res.provenance_verified is True
        assert res.external_lookup_performed is True

    def test_provider_exception_returns_degraded_unavailable(self) -> None:
        """Provider exception/timeout returns degraded_enrichment_unavailable without raising."""

        class FailingProvider:
            def query_indicators(self, ips: list[str]) -> list[Any]:
                raise TimeoutError("Threat-intel service connection timed out")

        enricher = SourcedThreatIntelEnricher(feed_provider=FailingProvider())

        verified_contract = EntityProvenanceContract(
            entity_namespace_id="external_net",
            clock_synchronized=True,
            src_entity_id="185.220.101.5",
            dst_entity_id="193.142.59.20",
            protocol="tcp",
            service_or_port="80",
        )

        res = enricher.enrich_entity_contract(verified_contract)

        assert res.status == "degraded_enrichment_unavailable"
        assert res.provenance_verified is True
        assert res.external_lookup_performed is True
        assert "timed out" in res.reason
