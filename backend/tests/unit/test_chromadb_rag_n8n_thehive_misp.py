"""Unit tests for Milestone #32 SOC Stack Integration.

Covers:
1. ChromaDB Semantic Vector RAG over MITRE ATT&CK & Playbooks (chromadb_mitre_rag.py).
2. Deterministic MISP Threat Intelligence Client & RFC 1918 Guard (n8n_thehive_misp_stack.py).
3. TheHive Case Management Client with SOAR Gate Enforcements.
4. n8n Deterministic Webhook Playbook Client with HMAC-SHA256 Signatures.
5. Docker Compose & n8n Workflow JSON Artifact Verification.
6. End-to-End SOC Demo & Analyst Dashboard Integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from threatfusion.advisory.chromadb_mitre_rag import (
    CANONICAL_MITRE_AND_PLAYBOOK_CORPUS,
    ChromaDbMitrePlaybookRag,
    ChromaRagQueryResult,
    DeterministicMitreEmbeddingFunction,
    MitrePlaybookRagDocument,
)
from threatfusion.advisory.explanation_engine import AdvisoryEvidenceBundle
from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.api.analyst_dashboard import (
    DashboardAlertDetail,
    DashboardAlertQueue,
    DashboardSnapshot,
    load_frontend_unicorn_bundle,
    render_dashboard_html,
)
import http.server
import sqlite3
import threading
import urllib.error
import urllib.request

from scripts.run_misp_and_callback_contract_server import (
    MispAndCallbackContractHandler,
    is_rfc1918_or_loopback_ip as contract_is_rfc1918,
    verify_hmac_signature,
)
from threatfusion.operations.full_soc_demo import run_full_soc_demo
from threatfusion.soar.n8n_thehive_misp_stack import (
    MispDeterministicClient,
    N8nDeterministicPlaybookClient,
    TheHiveDeterministicClient,
    is_rfc1918_or_loopback_ip,
)
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)

TEST_SOAR_HMAC_SECRET = "threatfusion_soc_test_secret_key_v1"

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestChromaDbMitreRag:
    """Tests for ChromaDB Semantic Vector RAG over MITRE ATT&CK & Playbooks."""

    def test_mitre_corpus_and_document_structure(self) -> None:
        """Verify canonical corpus has 10 enterprise techniques and valid structure."""
        assert len(CANONICAL_MITRE_AND_PLAYBOOK_CORPUS) == 10
        expected_techniques = {
            "T1046",
            "T1190",
            "T1498",
            "T1071.001",
            "T1595",
            "T1110",
            "T1041",
            "T1021",
            "T1059",
            "T1133",
        }
        actual_techniques = {doc.technique_id for doc in CANONICAL_MITRE_AND_PLAYBOOK_CORPUS}
        assert actual_techniques == expected_techniques

        for doc in CANONICAL_MITRE_AND_PLAYBOOK_CORPUS:
            assert isinstance(doc, MitrePlaybookRagDocument)
            assert doc.doc_id.startswith("mitre_doc_")
            assert len(doc.technique_name) > 0
            assert len(doc.tactic) > 0
            assert len(doc.description) > 20
            assert doc.playbook_id.startswith("pb-")
            assert len(doc.deterministic_playbook_steps) >= 3
            assert doc.mitre_version == "15.1"

            d = doc.to_dict()
            assert d["technique_id"] == doc.technique_id
            assert d["playbook_id"] == doc.playbook_id
            assert isinstance(d["deterministic_playbook_steps"], list)

    def test_deterministic_mitre_embedding_function(self) -> None:
        """Verify embedding function computes 64-dim L2-normalized dense vectors deterministically."""
        embed_fn = DeterministicMitreEmbeddingFunction()

        vec1 = embed_fn.embed_text("Exploit Public-Facing Application HTTP port 80 vulnerability")
        vec2 = embed_fn.embed_text("Exploit Public-Facing Application HTTP port 80 vulnerability")
        vec_diff = embed_fn.embed_text("Denial of Service volumetric SYN flood attack")

        assert len(vec1) == 64
        assert len(vec2) == 64
        assert len(vec_diff) == 64

        # Deterministic identical output
        assert vec1 == vec2
        assert vec1 != vec_diff

        # L2-normalization: magnitude must equal 1.0 +/- 1e-4
        norm1 = sum(x * x for x in vec1) ** 0.5
        norm_diff = sum(x * x for x in vec_diff) ** 0.5
        assert pytest.approx(norm1, abs=1e-4) == 1.0
        assert pytest.approx(norm_diff, abs=1e-4) == 1.0

    def test_chromadb_rag_store_initialization_and_mode_0600(self, tmp_path: Path) -> None:
        """Verify SQLite vector store creates collections, seeds corpus, and sets mode 0600."""
        db_file = tmp_path / "chromadb_vectors.sqlite3"
        rag = ChromaDbMitrePlaybookRag(db_file)

        assert db_file.exists()
        file_stat = db_file.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode & stat.S_IRUSR
        assert file_mode & stat.S_IWUSR

        # Verify collection count
        with rag._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM chroma_embeddings")
            count = cur.fetchone()["cnt"]
            assert count == 10

    def test_chromadb_rag_semantic_queries(self, tmp_path: Path) -> None:
        """Verify semantic vector queries return ranked hits by cosine similarity."""
        db_file = tmp_path / "chromadb_vectors.sqlite3"
        rag = ChromaDbMitrePlaybookRag(db_file)

        # Query 1: Network Service Scanning probe
        scan_hits = rag.query_semantic_rag(
            "network service discovery active scanning probe sweep reconnaissance", top_k=3
        )
        assert len(scan_hits) == 3
        top_scan = scan_hits[0]
        assert isinstance(top_scan, ChromaRagQueryResult)
        assert top_scan.rank == 1
        assert top_scan.technique_id in ("T1046", "T1595")
        assert top_scan.cosine_similarity > 0.0
        assert top_scan.distance >= 0.0
        # Results must be sorted ascending by distance
        assert scan_hits[0].distance <= scan_hits[1].distance <= scan_hits[2].distance

        # Query 2: Exfiltration over C2
        exfil_hits = rag.query_semantic_rag(
            "exfiltration over command and control covert channel data theft", top_k=2
        )
        assert len(exfil_hits) == 2
        assert exfil_hits[0].technique_id == "T1041"

    def test_chromadb_rag_query_for_evidence_bundle(self, tmp_path: Path) -> None:
        """Verify query_semantic_rag_for_bundle extracts signals from AdvisoryEvidenceBundle."""
        db_file = tmp_path / "chromadb_vectors.sqlite3"
        rag = ChromaDbMitrePlaybookRag(db_file)

        bundle = AdvisoryEvidenceBundle(
            candidate_id="cand_test_bundle",
            record_id="rec_test_01",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.88,
            rf_threshold=0.50,
            top_feature_signals={
                "dst_port": 80,
                "fwd_packets": 25,
                "bwd_packets": 1,
                "bytes_per_second": 12000.0,
            },
            incident_id="inc_test_01",
            correlation_status="corr_burst_5tuple_30s_v1",
        )

        hits = rag.query_semantic_rag_for_bundle(bundle, top_k=3)
        assert len(hits) == 3
        technique_ids = [h.technique_id for h in hits]
        # Should match web exploit or active scan
        assert any(t in ("T1190", "T1046", "T1595") for t in technique_ids)


class TestMispDeterministicClient:
    """Tests for MISP deterministic indicator lookup and RFC 1918 Private IP Guard."""

    def test_is_rfc1918_or_loopback_ip(self) -> None:
        """Verify RFC 1918, loopback, and link-local address detector."""
        # Private / loopback IPv4
        assert is_rfc1918_or_loopback_ip("10.0.0.4") is True
        assert is_rfc1918_or_loopback_ip("10.0.0.5") is True
        assert is_rfc1918_or_loopback_ip("192.168.1.100") is True
        assert is_rfc1918_or_loopback_ip("172.16.5.20") is True
        assert is_rfc1918_or_loopback_ip("127.0.0.1") is True
        assert is_rfc1918_or_loopback_ip("169.254.10.10") is True

        # Private / loopback IPv6
        assert is_rfc1918_or_loopback_ip("::1") is True
        assert is_rfc1918_or_loopback_ip("fc00::1") is True
        assert is_rfc1918_or_loopback_ip("fe80::1") is True

        # Public IPv4 / invalid strings
        assert is_rfc1918_or_loopback_ip("8.8.8.8") is False
        assert is_rfc1918_or_loopback_ip("1.1.1.1") is False
        assert is_rfc1918_or_loopback_ip("93.184.216.34") is False
        assert is_rfc1918_or_loopback_ip("142.250.190.46") is False
        assert is_rfc1918_or_loopback_ip("not_an_ip") is False
        assert is_rfc1918_or_loopback_ip("") is False

    def test_misp_client_rfc1918_guard(self, tmp_path: Path) -> None:
        """Verify private IP addresses are suppressed from external lookup."""
        outbox_db = tmp_path / "misp_outbox.sqlite3"
        client = MispDeterministicClient(outbox_db_path=outbox_db)

        res = client.query_indicator("10.0.0.4", indicator_type="ip-dst")
        assert res.private_ip_guard_triggered is True
        assert res.query_mode == "rfc1918_guard_suppressed"
        assert res.matched is False
        assert "rfc1918_private_ip_suppressed" in res.tags

    def test_misp_client_known_hash_fallback(self, tmp_path: Path) -> None:
        """Verify known malware hashes match the canonical verified snapshot."""
        outbox_db = tmp_path / "misp_outbox.sqlite3"
        client = MispDeterministicClient(outbox_db_path=outbox_db)

        # EICAR MD5
        res_eicar = client.query_indicator("44d88612fea8a8f36de82e1278abb02f", indicator_type="md5")
        assert res_eicar.matched is True
        assert res_eicar.threat_level == "high"
        assert "malware:eicar" in res_eicar.tags
        assert res_eicar.query_mode in ("verified_snapshot_fallback", "rest_api")

        # Mirai SHA256
        res_mirai = client.query_indicator(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            indicator_type="sha256",
        )
        assert res_mirai.matched is True
        assert "malware:mirai" in res_mirai.tags

    def test_misp_client_unknown_indicator(self, tmp_path: Path) -> None:
        """Verify unknown public indicator returns clean non-match."""
        outbox_db = tmp_path / "misp_outbox.sqlite3"
        client = MispDeterministicClient(outbox_db_path=outbox_db)

        res = client.query_indicator("99.88.77.66", indicator_type="ip-dst")
        assert res.matched is False
        assert res.threat_level == "undefined"
        assert len(res.tags) == 0

    def test_misp_outbox_persistence_and_mode_0600(self, tmp_path: Path) -> None:
        """Verify queries are logged into the SQLite outbox with mode 0600."""
        outbox_db = tmp_path / "misp_outbox.sqlite3"
        client = MispDeterministicClient(outbox_db_path=outbox_db)

        client.query_indicator("10.0.0.5", indicator_type="ip-dst")
        client.query_indicator("44d88612fea8a8f36de82e1278abb02f", indicator_type="md5")

        assert outbox_db.exists()
        file_stat = outbox_db.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode & stat.S_IRUSR
        assert file_mode & stat.S_IWUSR


class TestTheHiveDeterministicClient:
    """Tests for TheHive Case Management Client with SOAR Gates."""

    def test_thehive_client_enforces_mandatory_soar_approval(self, tmp_path: Path) -> None:
        """Verify unapproved SOAR records raise SoarStateTransitionError."""
        soar_db = tmp_path / "soar.sqlite3"
        repo = SoarPlaybookSqliteRepository(soar_db)
        engine = ApprovalGatedSoarEngine(repo)

        contract = EntityProvenanceContract(
            entity_namespace_id="test",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = engine.recommend_actions_for_alert("cand_hive_unapproved", contract)
        unapproved = recs[0]

        client = TheHiveDeterministicClient(outbox_db_path=tmp_path / "hive_outbox.sqlite3")
        with pytest.raises(SoarStateTransitionError) as exc_info:
            client.create_case_from_soar(
                soar_record=unapproved,
                soar_repo=repo,
                rf_confidence_pct=85.0,
            )
        assert "must be approved or executed_simulated" in str(exc_info.value)

    def test_thehive_client_enforces_audit_hash_chain_integrity(self, tmp_path: Path) -> None:
        """Verify tampered cryptographic audit chain raises SoarStateTransitionError."""
        soar_db = tmp_path / "soar.sqlite3"
        repo = SoarPlaybookSqliteRepository(soar_db)
        engine = ApprovalGatedSoarEngine(repo)

        contract = EntityProvenanceContract(
            entity_namespace_id="test",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = engine.recommend_actions_for_alert("cand_hive_tamper", contract)
        approved = engine.decide_recommendation(
            playbook_id=recs[0].playbook_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="Approved",
            expected_version=1,
        )

        # Tamper with audit trail directly
        with repo._get_connection() as conn:
            conn.execute(
                "UPDATE soar_audit_events SET reason = 'TAMPERED REASON' WHERE playbook_id = ?",
                (approved.playbook_id,),
            )

        client = TheHiveDeterministicClient(outbox_db_path=tmp_path / "hive_outbox.sqlite3")
        with pytest.raises(SoarStateTransitionError) as exc_info:
            client.create_case_from_soar(
                soar_record=approved,
                soar_repo=repo,
                rf_confidence_pct=85.0,
            )
        assert "cryptographic SOAR audit hash chain integrity failed" in str(exc_info.value)

    def test_thehive_client_create_case_success(self, tmp_path: Path) -> None:
        """Verify approved SOAR record successfully creates TheHiveCaseRecord and outbox entry."""
        soar_db = tmp_path / "soar.sqlite3"
        repo = SoarPlaybookSqliteRepository(soar_db)
        engine = ApprovalGatedSoarEngine(repo)

        contract = EntityProvenanceContract(
            entity_namespace_id="test",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = engine.recommend_actions_for_alert("cand_hive_valid", contract)
        approved = engine.decide_recommendation(
            playbook_id=recs[0].playbook_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="Approved valid containment",
            expected_version=1,
        )

        outbox_db = tmp_path / "hive_outbox.sqlite3"
        client = TheHiveDeterministicClient(outbox_db_path=outbox_db)

        case = client.create_case_from_soar(
            soar_record=approved,
            soar_repo=repo,
            rf_confidence_pct=91.5,
            queue_priority_rank=1,
            incident_id="inc_hive_01",
            mitre_tags=["T1046", "T1190"],
            misp_tags=["malware:eicar"],
        )

        assert case.case_id.startswith("case_cand_hive_valid")
        assert case.status in ("created_live", "queued_offline")
        assert case.severity == 3  # >= 80% confidence
        assert "mitre:T1046" in case.tags
        assert "misp:malware:eicar" in case.tags
        assert len(case.observables) == 2


class TestN8nDeterministicPlaybookClient:
    """Tests for n8n Webhook Playbook Client with HMAC-SHA256 and SOAR Gates."""

    def test_n8n_client_enforces_mandatory_soar_approval(self, tmp_path: Path) -> None:
        """Verify unapproved SOAR records raise SoarStateTransitionError."""
        soar_db = tmp_path / "soar.sqlite3"
        repo = SoarPlaybookSqliteRepository(soar_db)
        engine = ApprovalGatedSoarEngine(repo)

        contract = EntityProvenanceContract(
            entity_namespace_id="test",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = engine.recommend_actions_for_alert("cand_n8n_unapproved", contract)
        unapproved = recs[0]

        client = N8nDeterministicPlaybookClient(
            secret_key=TEST_SOAR_HMAC_SECRET, outbox_db_path=tmp_path / "n8n_outbox.sqlite3"
        )
        with pytest.raises(SoarStateTransitionError) as exc_info:
            client.trigger_soar_playbook(
                soar_record=unapproved,
                soar_repo=repo,
                rf_confidence_pct=88.0,
            )
        assert "must be approved or executed_simulated" in str(exc_info.value)

    def test_n8n_client_trigger_playbook_success(self, tmp_path: Path) -> None:
        """Verify approved SOAR record generates HMAC-SHA256 signed execution receipt."""
        soar_db = tmp_path / "soar.sqlite3"
        repo = SoarPlaybookSqliteRepository(soar_db)
        engine = ApprovalGatedSoarEngine(repo)

        contract = EntityProvenanceContract(
            entity_namespace_id="test",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = engine.recommend_actions_for_alert("cand_n8n_valid", contract)
        approved = engine.decide_recommendation(
            playbook_id=recs[0].playbook_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="Approved valid playbook",
            expected_version=1,
        )

        outbox_db = tmp_path / "n8n_outbox.sqlite3"
        client = N8nDeterministicPlaybookClient(
            secret_key=TEST_SOAR_HMAC_SECRET, outbox_db_path=outbox_db
        )

        receipt = client.trigger_soar_playbook(
            soar_record=approved,
            soar_repo=repo,
            rf_confidence_pct=88.5,
            queue_priority_rank=1,
            incident_id="inc_n8n_01",
            thehive_case_id="case_12345",
            mitre_technique_id="T1046",
        )

        assert receipt.execution_id.startswith("exec_")
        assert receipt.status in ("dispatched_live", "queued_durable_outbox")
        assert len(receipt.signature_sha256) == 64
        assert receipt.idempotency_key == f"idem_{approved.playbook_id}_2"
        assert receipt.payload["mitre_technique_id"] == "T1046"
        assert receipt.payload["audit_chain_verified"] is True

    def test_n8n_client_rejects_empty_or_short_hmac_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify N8nDeterministicPlaybookClient raises ValueError on missing/empty/short secret."""
        monkeypatch.delenv("THREATFUSION_SOAR_HMAC_SECRET", raising=False)

        # Empty secret
        with pytest.raises(ValueError, match="at least 16 characters"):
            N8nDeterministicPlaybookClient(secret_key="")

        # Whitespace only
        with pytest.raises(ValueError, match="at least 16 characters"):
            N8nDeterministicPlaybookClient(secret_key="    ")

        # Too short (< 16 characters)
        with pytest.raises(ValueError, match="at least 16 characters"):
            N8nDeterministicPlaybookClient(secret_key="short_secret_12")

        # Missing entirely without env var
        with pytest.raises(ValueError, match="at least 16 characters"):
            N8nDeterministicPlaybookClient()

        # Valid via env var
        monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "valid_secret_via_env_16chars")
        client_env = N8nDeterministicPlaybookClient()
        assert client_env.secret_key == "valid_secret_via_env_16chars"

    def test_n8n_client_propagates_sqlite_error_on_outbox_failure(self, tmp_path: Path) -> None:
        """Verify N8nDeterministicPlaybookClient propagates sqlite3.Error on corrupted outbox DB."""
        bad_db = tmp_path / "corrupted_outbox.sqlite3"
        bad_db.write_bytes(b"not a valid sqlite database header padding" * 20)

        with pytest.raises(sqlite3.Error):
            N8nDeterministicPlaybookClient(
                secret_key=TEST_SOAR_HMAC_SECRET,
                outbox_db_path=bad_db,
            )


class TestDockerStackAndN8nWorkflow:
    """Tests for Docker Compose SOC Stack and n8n Workflow JSON Artifacts."""

    def test_n8n_workflow_json_structure(self) -> None:
        """Verify threatfusion_soar_playbook.json contains Code verification node and DNS hostnames."""
        wf_path = REPO_ROOT / "docker" / "n8n" / "workflows" / "threatfusion_soar_playbook.json"
        assert wf_path.is_file(), f"Workflow file not found: {wf_path}"

        raw_text = wf_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
        assert data["name"] == "ThreatFusion Autonomous SOAR Incident Response Playbook"
        assert "nodes" in data
        assert len(data["nodes"]) == 6

        node_names = [n["name"] for n in data["nodes"]]
        assert any("Webhook Trigger" in name for name in node_names)
        assert "Verify HMAC-SHA256 & Idempotency Envelope" in node_names
        assert any("Verify Approval" in name for name in node_names)
        assert any("Query MISP" in name for name in node_names)
        assert any("TheHive" in name for name in node_names)
        assert any("Notify" in name or "Callback" in name for name in node_names)

        # Invariant (a): Code node checks headers and uses container DNS hostnames
        code_node = next(
            n for n in data["nodes"] if n["name"] == "Verify HMAC-SHA256 & Idempotency Envelope"
        )
        assert code_node["type"] == "n8n-nodes-base.code"
        js_code = code_node["parameters"]["jsCode"]
        assert "x-threatfusion-signature-256" in js_code
        assert "x-idempotency-key" in js_code
        assert "THREATFUSION_SOAR_HMAC_SECRET" in js_code
        assert "http://threatfusion-callback:8443/api/v1/soar/verify-state" in js_code

        # Invariant (a): Zero 127.0.0.1 inside container nodes, all mapped to service DNS
        assert "127.0.0.1" not in raw_text
        assert "http://misp-connector:8080/attributes/restSearch" in raw_text
        assert "http://thehive:9000/api/v1/case" in raw_text
        assert "http://threatfusion-callback:8443/api/v1/soar/callback" in raw_text

    def test_docker_compose_soc_stack_file(self) -> None:
        """Verify docker-compose.soc-stack.yml defines pinned versions, fail-closed secrets, and callback."""
        compose_path = REPO_ROOT / "docker" / "docker-compose.soc-stack.yml"
        assert compose_path.is_file(), f"Docker compose file not found: {compose_path}"

        content = compose_path.read_text(encoding="utf-8")
        # Invariant (b): zero :latest tags
        assert ":latest" not in content

        # Invariant (b): pinned exact versions
        assert "n8nio/n8n:1.68.0" in content
        assert "strangebee/thehive:5.2.10" in content
        assert "chromadb/chroma:0.5.20" in content
        assert "python:3.11.10-slim" in content

        # Invariant (b): N8N_BASIC_AUTH_ACTIVE=true and fail-closed secrets
        assert "N8N_BASIC_AUTH_ACTIVE=true" in content
        assert "${THREATFUSION_N8N_USER:?required}" in content
        assert "${THREATFUSION_N8N_PASSWORD:?required}" in content
        assert "${THREATFUSION_THEHIVE_SECRET:?required}" in content
        assert "${THREATFUSION_SOAR_HMAC_SECRET:?required}" in content
        assert "${THREATFUSION_MISP_API_KEY:?required}" in content

        # Invariant (b): defines threatfusion-callback service and binds to 127.0.0.1
        assert "threatfusion-callback:" in content
        assert "127.0.0.1:8443:8443" in content
        assert "127.0.0.1:8080:8080" in content
        assert "127.0.0.1:9000:9000" in content
        assert "127.0.0.1:5678:5678" in content
        assert "127.0.0.1:8000:8000" in content


class TestMispAndCallbackContractServer:
    """Tests for scripts/run_misp_and_callback_contract_server.py request handler logic."""

    def test_contract_server_request_handler_logic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verify contract server serves restSearch with RFC1918 guard, verify-state, and callback."""
        test_misp_key = "threatfusion_soc_test_misp_key_2026_secure"
        monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", TEST_SOAR_HMAC_SECRET)
        monkeypatch.setenv("THREATFUSION_MISP_API_KEY", test_misp_key)

        db_path = tmp_path / "test_soar_ledger.sqlite3"
        soar_repo = SoarPlaybookSqliteRepository(db_path)
        soar_engine = ApprovalGatedSoarEngine(soar_repo)

        # Configure handler class attributes and clear caches
        MispAndCallbackContractHandler.soar_db_path = str(db_path)
        MispAndCallbackContractHandler.misp_api_key = test_misp_key
        MispAndCallbackContractHandler.seen_verify_idempotency_keys.clear()
        MispAndCallbackContractHandler.seen_callback_idempotency_keys.clear()

        server = http.server.HTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        base_url = f"http://127.0.0.1:{port}"

        # Helper function unit checks
        assert contract_is_rfc1918("10.0.0.4") is True
        assert contract_is_rfc1918("8.8.8.8") is False
        assert verify_hmac_signature(b'{"test": 1}', "bad_sig", TEST_SOAR_HMAC_SECRET) is False

        try:
            # 1. GET /healthz
            req_health = urllib.request.Request(f"{base_url}/healthz")
            with urllib.request.urlopen(req_health, timeout=2.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "ok"

            # 2. POST /attributes/restSearch without Authorization -> 401
            req_no_auth = urllib.request.Request(
                f"{base_url}/attributes/restSearch",
                data=json.dumps({"value": "8.8.8.8"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_no_auth, timeout=2.0)
            assert exc_info.value.code == 401

            # 2b. POST /attributes/restSearch with wrong Authorization -> 401
            req_wrong_auth = urllib.request.Request(
                f"{base_url}/attributes/restSearch",
                data=json.dumps({"value": "8.8.8.8"}).encode("utf-8"),
                headers={
                    "Authorization": "wrong_misp_key_value",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_wrong_auth, timeout=2.0)
            assert exc_info.value.code == 401

            # 3. POST /attributes/restSearch with RFC1918 Private IP -> 422
            req_private_ip = urllib.request.Request(
                f"{base_url}/attributes/restSearch",
                data=json.dumps({"value": "10.0.0.4", "type": "ip-dst"}).encode("utf-8"),
                headers={"Authorization": test_misp_key, "Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_private_ip, timeout=2.0)
            assert exc_info.value.code == 422

            # 4. POST /attributes/restSearch with valid malware hash -> 200 with MISP Attributes
            req_misp_hash = urllib.request.Request(
                f"{base_url}/attributes/restSearch",
                data=json.dumps(
                    {"value": "44d88612fea8a8f36de82e1278abb02f", "type": "md5"}
                ).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {test_misp_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req_misp_hash, timeout=2.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                attrs = data.get("response", {}).get("Attribute", [])
                assert len(attrs) == 1
                assert attrs[0]["event_id"] == "misp_evt_eicar_01"

            # 5. Seed a real SOAR playbook in the SQLite ledger
            contract_prov = EntityProvenanceContract(
                entity_namespace_id="test_m32",
                clock_synchronized=True,
                src_entity_id="10.0.0.4",
                dst_entity_id="10.0.0.5",
                protocol="tcp",
                service_or_port="80",
            )
            recs = soar_engine.recommend_actions_for_alert("cand_srv_test", contract_prov)
            test_pb_id = recs[0].playbook_id
            assert recs[0].state == "pending_approval"

            import hashlib as hashlib_mod
            import hmac as hmac_mod

            # 5a. Signed verify-state for fabricated playbook_id -> 403 Forbidden!
            fab_payload = {
                "candidate_id": "cand_srv_test",
                "playbook_id": "pb-fabricated-999",
                "soar_state": "approved",
                "audit_chain_verified": True,
            }
            fab_bytes = json.dumps(fab_payload, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            fab_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), fab_bytes, hashlib_mod.sha256
            ).hexdigest()
            req_fab = urllib.request.Request(
                f"{base_url}/api/v1/soar/verify-state",
                data=fab_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": fab_sig,
                    "X-Idempotency-Key": "idem_pb-fabricated-999_1",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_fab, timeout=2.0)
            assert exc_info.value.code == 403

            # 5b. Signed verify-state for real playbook still in pending_approval -> 403 Forbidden!
            pending_payload = {
                "candidate_id": "cand_srv_test",
                "playbook_id": test_pb_id,
                "soar_state": "approved",
                "audit_chain_verified": True,
            }
            pending_bytes = json.dumps(
                pending_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            pending_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), pending_bytes, hashlib_mod.sha256
            ).hexdigest()
            req_pending = urllib.request.Request(
                f"{base_url}/api/v1/soar/verify-state",
                data=pending_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": pending_sig,
                    "X-Idempotency-Key": f"idem_{test_pb_id}_1",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_pending, timeout=2.0)
            assert exc_info.value.code == 403

            # 5c. Approve the playbook in SQLite ledger
            approved_rec = soar_engine.decide_recommendation(
                test_pb_id,
                actor_id="analyst-bilal",
                decision="approve",
                reason="Legitimate probe containment",
                expected_version=1,
            )
            assert approved_rec.state == "approved"
            assert approved_rec.version == 2

            approved_payload = {
                "candidate_id": "cand_srv_test",
                "playbook_id": test_pb_id,
                "soar_state": "approved",
                "audit_chain_verified": True,
            }
            approved_bytes = json.dumps(
                approved_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            approved_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), approved_bytes, hashlib_mod.sha256
            ).hexdigest()

            # 5d. Bad signature on approved playbook -> 403 Forbidden!
            req_bad_sig = urllib.request.Request(
                f"{base_url}/api/v1/soar/verify-state",
                data=approved_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": "0" * 64,
                    "X-Idempotency-Key": f"idem_{test_pb_id}_2",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_bad_sig, timeout=2.0)
            assert exc_info.value.code == 403

            # 5e. Valid signature and approved ledger record -> 200 OK!
            req_good_sig = urllib.request.Request(
                f"{base_url}/api/v1/soar/verify-state",
                data=approved_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": approved_sig,
                    "X-Idempotency-Key": f"idem_{test_pb_id}_2",
                },
                method="POST",
            )
            with urllib.request.urlopen(req_good_sig, timeout=2.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["state_verified"] is True
                assert data["verified"] is True
                assert data["idempotency_key"] == f"idem_{test_pb_id}_2"

            # 5f. Replay same idempotency key -> 409 Conflict!
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_good_sig, timeout=2.0)
            assert exc_info.value.code == 409

            # 6. POST /api/v1/soar/callback
            cb_payload = {
                "execution_id": "exec_01",
                "playbook_id": test_pb_id,
                "candidate_id": "cand_srv_test",
                "n8n_status": "completed",
            }
            cb_bytes = json.dumps(cb_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            cb_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), cb_bytes, hashlib_mod.sha256
            ).hexdigest()

            # 6a. Unsigned callback -> 403 Forbidden!
            req_unsigned_cb = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=cb_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_unsigned_cb, timeout=2.0)
            assert exc_info.value.code == 403

            # 6b. Callback with bad signature -> 403 Forbidden!
            req_bad_cb_sig = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=cb_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": "f" * 64,
                    "X-Idempotency-Key": f"idem_{test_pb_id}_2_cb",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_bad_cb_sig, timeout=2.0)
            assert exc_info.value.code == 403

            # 6c. Valid signed callback -> 200 OK!
            req_good_cb = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=cb_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": cb_sig,
                    "X-Idempotency-Key": f"idem_{test_pb_id}_2_cb",
                },
                method="POST",
            )
            with urllib.request.urlopen(req_good_cb, timeout=2.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["callback_recorded"] is True

            # 6d. Replay callback idempotency key -> 409 Conflict!
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_good_cb, timeout=2.0)
            assert exc_info.value.code == 409

        finally:
            server.shutdown()
            server.server_close()

    def test_callback_fails_closed_when_soar_db_path_is_none_or_playbook_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verify POST /api/v1/soar/callback unconditionally fails closed on None db_path or missing/empty playbook_id."""
        monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", TEST_SOAR_HMAC_SECRET)

        db_path = tmp_path / "test_callback_gate_ledger.sqlite3"
        soar_repo = SoarPlaybookSqliteRepository(db_path)
        soar_engine = ApprovalGatedSoarEngine(soar_repo)

        # Seed an approved record in the test ledger
        contract_prov = EntityProvenanceContract(
            entity_namespace_id="test_m32",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = soar_engine.recommend_actions_for_alert("cand_cb_test", contract_prov)
        valid_pb_id = recs[0].playbook_id
        soar_engine.decide_recommendation(
            valid_pb_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="Approved valid containment",
            expected_version=1,
        )

        orig_db_path = MispAndCallbackContractHandler.soar_db_path
        MispAndCallbackContractHandler.soar_db_path = str(db_path)
        MispAndCallbackContractHandler.seen_callback_idempotency_keys.clear()

        server = http.server.HTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        base_url = f"http://127.0.0.1:{port}"

        import hashlib as hashlib_mod
        import hmac as hmac_mod

        try:
            # (a) Set soar_db_path = None, send valid HMAC-signed callback with fabricated playbook_id -> 403 Forbidden
            MispAndCallbackContractHandler.soar_db_path = None

            fab_payload = {
                "playbook_id": "fabricated",
                "candidate_id": "fake",
                "n8n_status": "completed",
            }
            fab_bytes = json.dumps(fab_payload, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            fab_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), fab_bytes, hashlib_mod.sha256
            ).hexdigest()

            req_fab = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=fab_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": fab_sig,
                    "X-Idempotency-Key": "idem_cb_probe_none_db_01",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_fab, timeout=2.0)
            assert exc_info.value.code == 403
            err_data = json.loads(exc_info.value.read().decode("utf-8"))
            assert err_data.get("callback_recorded") is False

            # (b) Restore soar_db_path to configured db_path, send valid HMAC-signed callback with empty playbook_id -> 403 Forbidden
            MispAndCallbackContractHandler.soar_db_path = str(db_path)

            empty_pb_payload = {
                "playbook_id": "",
                "candidate_id": "cand_cb_test",
                "n8n_status": "completed",
            }
            empty_pb_bytes = json.dumps(
                empty_pb_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            empty_pb_sig = hmac_mod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), empty_pb_bytes, hashlib_mod.sha256
            ).hexdigest()

            req_empty_pb = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=empty_pb_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": empty_pb_sig,
                    "X-Idempotency-Key": "idem_cb_probe_empty_pb_02",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req_empty_pb, timeout=2.0)
            assert exc_info.value.code == 403
            err_data_empty = json.loads(exc_info.value.read().decode("utf-8"))
            assert err_data_empty.get("callback_recorded") is False

        finally:
            MispAndCallbackContractHandler.soar_db_path = orig_db_path
            server.shutdown()
            server.server_close()


class TestEndToEndSocDemoAndDashboardIntegration:
    """Tests for Turnkey SOC Demo and Analyst Dashboard Integration."""

    def test_full_soc_demo_incorporates_chromadb_misp_thehive_n8n(self, tmp_path: Path) -> None:
        """Verify run_full_soc_demo incorporates all Milestone #32 components."""
        report = run_full_soc_demo(tmp_path)

        track_b = report["track_b_azure_live_spine"]
        assert "chromadb_mitre_rag_hits" in track_b
        assert len(track_b["chromadb_mitre_rag_hits"]) == 3
        assert "misp_hash_and_ioc_lookup" in track_b
        assert (
            track_b["misp_hash_and_ioc_lookup"]["dest_ip_query"]["private_ip_guard_triggered"]
            is True
        )
        assert track_b["misp_hash_and_ioc_lookup"]["sample_malware_hash_query"]["matched"] is True

        assert "thehive_case_record" in track_b
        assert track_b["thehive_case_record"]["case_id"].startswith("case_")

        assert "n8n_playbook_receipt" in track_b
        assert track_b["n8n_playbook_receipt"]["execution_id"].startswith("exec_")
        assert len(track_b["n8n_playbook_receipt"]["signature_sha256"]) == 64

        # Verify Markdown report file
        md_file = tmp_path / "full_soc_demo_report.md"
        assert md_file.exists()
        md_text = md_file.read_text(encoding="utf-8")
        assert "### Milestone #32 ChromaDB Semantic Vector RAG" in md_text
        assert "### Milestone #32 MISP Threat Intelligence & IOC Lookups" in md_text
        assert "### Milestone #32 TheHive v4/v5 Incident Case Record" in md_text
        assert "### Milestone #32 Deterministic n8n SOAR Webhook Execution Receipt" in md_text

    def test_analyst_dashboard_renders_m32_badges(self) -> None:
        """Verify render_dashboard_html renders evidence-bound M32 badges conditionally."""
        # Case A: Alert with NO attached SOAR/RAG evidence -> renders data-evidence-state="unavailable"
        detail_unattached = DashboardAlertDetail(
            alert_candidate_id="alert_cand_m32_test_01",
            source_event_id="src_event_m32_01",
            observed_at="2026-10-18T10:00:00Z",
            created_at="2026-10-18T10:00:01Z",
            source_representation_identity="azure.victim_vm.suricata.eve_flow.v1",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.9125,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="new",
            version=0,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
            soar_recommendations=None,
            advisory_explanation=None,
        )
        queue = DashboardAlertQueue(items=(), total_loaded=0, limit=10, offset=0)
        snapshot = DashboardSnapshot(queue=queue, selected=detail_unattached, status="active")

        html_unattached = render_dashboard_html(snapshot)

        # Invariant (e): renders data-evidence-state="unavailable" and pending/not-attached labels
        assert 'data-evidence-state="unavailable"' in html_unattached
        assert (
            "SOAR Cryptographic Audit Chain: Not Attached / No SOAR Playbook Recorded"
            in html_unattached
        )
        assert (
            "ChromaDB Semantic RAG: Not Attached / Pending Advisory Evaluation" in html_unattached
        )
        assert (
            "n8n Deterministic Playbook &amp; TheHive Case Status: Pending Analyst Approval / Not Dispatched"
            in html_unattached
        )

        # Invariant (e): strictly separate model badges, no combined confidence badge
        assert "badge-rf-confidence" in html_unattached
        assert "Primary Authority: Frozen Random Forest Confidence (91.25%)" in html_unattached
        assert "badge-secondary-anomaly" in html_unattached
        assert (
            "Secondary Non-Fused Queue Priority Signal: v2 Autoencoder — Section 8 Fusion Disabled"
            in html_unattached
        )
        assert "Prioritized Alert Confidence Score" not in html_unattached

        # Case B: Alert with LOOSE / UNVERIFIED dicts (no valid hashes, no valid RAG hits, no receipts)
        detail_loose = DashboardAlertDetail(
            alert_candidate_id="alert_cand_m32_test_loose",
            source_event_id="src_event_m32_loose",
            observed_at="2026-10-18T10:00:00Z",
            created_at="2026-10-18T10:00:01Z",
            source_representation_identity="azure.victim_vm.suricata.eve_flow.v1",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.8850,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="in_review",
            version=1,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
            soar_recommendations=(
                {
                    "playbook_id": "pb-isolate-01",
                    "action_type": "quarantine_host",
                    "target_entity": "10.0.0.5",
                    "state": "approved",
                    # Missing entry_hash / audit_hash
                },
            ),
            advisory_explanation={
                "summary_headline": "Loose advisory dict without valid hits",
                "detection_rationale": "High burst rate",
                "cited_evidence_keys": ["candidate_id"],
                "mitre_rag_hits": [],  # Empty hits
            },
            soar_audit_chain_verified=False,
            soar_audit_chain_head_sha256=None,
            thehive_case_record=None,
            n8n_playbook_receipt=None,
        )
        snapshot_loose = DashboardSnapshot(queue=queue, selected=detail_loose, status="active")
        html_loose = render_dashboard_html(snapshot_loose)

        # Loose dicts must FAIL CLOSED to unavailable
        assert 'data-evidence-state="unavailable"' in html_loose
        assert (
            "SOAR Cryptographic Audit Chain: Not Attached / No SOAR Playbook Recorded" in html_loose
        )
        assert "ChromaDB Semantic RAG: Not Attached / Pending Advisory Evaluation" in html_loose
        assert (
            "n8n Deterministic Playbook &amp; TheHive Case Status: Pending Analyst Approval / Not Dispatched"
            in html_loose
        )

        # Case C: Alert WITH fully verified SOAR chain, RAG hits, TheHive case, and n8n receipt
        detail_verified = DashboardAlertDetail(
            alert_candidate_id="alert_cand_m32_test_02",
            source_event_id="src_event_m32_02",
            observed_at="2026-10-18T10:00:00Z",
            created_at="2026-10-18T10:00:01Z",
            source_representation_identity="azure.victim_vm.suricata.eve_flow.v1",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.8850,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="in_review",
            version=1,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
            soar_recommendations=(
                {
                    "playbook_id": "pb-isolate-01",
                    "action_type": "quarantine_host",
                    "target_entity": "10.0.0.5",
                    "state": "approved",
                    "entry_hash": "a" * 64,
                },
            ),
            advisory_explanation={
                "summary_headline": "Active scanner reconnaissance detected",
                "detection_rationale": "High burst rate on port 80",
                "cited_evidence_keys": ["candidate_id"],
                "mitre_rag_hits": [
                    {
                        "technique_id": "T1046",
                        "playbook_id": "pb-isolate-01",
                        "cosine_similarity": 0.88,
                    }
                ],
            },
            soar_audit_chain_verified=True,
            soar_audit_chain_head_sha256="a" * 64,
            thehive_case_record={"case_id": "case_12345"},
            n8n_playbook_receipt={"execution_id": "exec_12345", "signature_sha256": "b" * 64},
        )
        snapshot_verified = DashboardSnapshot(
            queue=queue, selected=detail_verified, status="active"
        )
        html_verified = render_dashboard_html(snapshot_verified)

        assert "SOAR Cryptographic Audit Chain: VERIFIED (SHA-256 Hash-Linked)" in html_verified
        assert "ChromaDB Semantic RAG: MITRE ATT&amp;CK &amp; Playbook Assistant" in html_verified
        assert (
            "n8n Deterministic Playbook &amp; TheHive Case Status: Dispatched / Live Case Created"
            in html_verified
        )
        assert 'data-evidence-state="verified"' in html_verified
        assert 'data-evidence-state="active"' in html_verified


class TestFrontendUnicornAssetBundle:
    """Tests for Milestone #35 SOC Unicorn Frontend Asset Bundle & Interactive Walkthrough."""

    def test_frontend_assets_exist_and_load_cleanly(self) -> None:
        """Verify frontend/index.html, css/soc_unicorn.css, js/soc_dashboard.js, and README.md exist and load."""
        frontend_dir = REPO_ROOT / "frontend"
        assert frontend_dir.is_dir()

        index_file = frontend_dir / "index.html"
        css_file = frontend_dir / "css" / "soc_unicorn.css"
        js_file = frontend_dir / "js" / "soc_dashboard.js"
        readme_file = frontend_dir / "README.md"

        for f in (index_file, css_file, js_file, readme_file):
            assert f.is_file(), f"Missing required frontend asset: {f}"
            assert f.stat().st_size > 200, f"Frontend asset too small or empty: {f}"

        # Verify load_frontend_unicorn_bundle returns all assets
        bundle = load_frontend_unicorn_bundle(REPO_ROOT)
        assert isinstance(bundle, dict)
        assert "index_html" in bundle and len(bundle["index_html"]) > 500
        assert "css" in bundle and len(bundle["css"]) > 500
        assert "js" in bundle and len(bundle["js"]) > 500

    def test_frontend_assets_zero_placeholders_and_air_gapped(self) -> None:
        """Verify frontend assets contain zero ****** placeholders, zero unrendered templates, and zero CDN links."""
        bundle = load_frontend_unicorn_bundle(REPO_ROOT)

        for name, text in bundle.items():
            assert "******" not in text, f"Asset '{name}' contains forbidden '******' placeholder"
            assert "__TODO__" not in text, f"Asset '{name}' contains unfinished '__TODO__' marker"

        # Zero external CDN dependencies in HTML and CSS
        index_text = bundle["index_html"]
        assert "cdn." not in index_text
        assert "http://" not in index_text
        assert "https://" not in index_text
        assert "googleapis.com" not in index_text
        assert "cloudflare.com" not in index_text

        css_text = bundle["css"]
        assert "@import url(http" not in css_text
        assert "http://" not in css_text
        assert "https://" not in css_text

    def test_frontend_badge_separation_and_exact_canonical_recall_comparison(self) -> None:
        """Verify .badge-rf-confidence and .badge-secondary-anomaly separation and canonical recall string."""
        bundle = load_frontend_unicorn_bundle(REPO_ROOT)
        css_text = bundle["css"]
        html_text = bundle["index_html"]
        js_text = bundle["js"]

        # 1. CSS defines distinct badge classes
        assert ".badge-rf-confidence" in css_text
        assert ".badge-secondary-anomaly" in css_text
        assert '[data-evidence-state="verified"]' in css_text
        assert '[data-evidence-state="pending"]' in css_text
        assert '[data-evidence-state="unavailable"]' in css_text

        # 2. HTML enforces 3-tier progressive disclosure contract
        assert 'data-blast-ui-tier="unicorn-progressive-disclosure-v1"' in html_text
        assert "badge-rf-confidence" in html_text
        assert "badge-secondary-anomaly" in html_text

        # 3. Exact canonical recall comparison string
        canonical_recall_str = (
            "+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"
        )
        assert canonical_recall_str in html_text
        assert canonical_recall_str in js_text

    def test_frontend_deterministic_receipt_verification_in_js(self) -> None:
        """Verify client-side js/soc_dashboard.js implements deterministic receipt verifiers and 6-stage walkthrough."""
        bundle = load_frontend_unicorn_bundle(REPO_ROOT)
        js_text = bundle["js"]

        # Digest and MITRE regex verifiers
        assert "SHA256_HEX_REGEX" in js_text
        assert "MITRE_TECHNIQUE_REGEX" in js_text
        assert "verifySoarChain" in js_text
        assert "verifyChromaRagHits" in js_text
        assert "verifyHiveAndN8nReceipt" in js_text

        # Enforces data-evidence-state="unavailable" when receipts fail
        assert "'unavailable'" in js_text
        assert "'verified'" in js_text

        # 6-stage walkthrough scenario definitions
        assert "Stage 1: Suricata Flow Telemetry & 14-Feature Ingestion" in js_text
        assert "Stage 2: Frozen Random Forest Fast-Path Inference" in js_text
        assert "Stage 3: Dual-Window Incident Correlation & Workload Shield" in js_text
        assert "Stage 4: ChromaDB 64-Dim MITRE Vector RAG & MISP Private-IP Guard" in js_text
        assert "Stage 5: Evidence-Bound Advisory Debrief & Anti-Hallucination Guard" in js_text
        assert "Stage 6: Approval-Gated SOAR Ledger & Case Dispatch" in js_text


class TestMilestone36ArchitecturalElevation:
    """Automated verification tests for Mega-Milestone #36 Architectural Elevation."""

    def test_mtti_mttr_intervals_and_operational_velocity_contract(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verify deterministic calculation of MTTI and MTTR intervals, DB persistence, and contract server endpoint."""
        from threatfusion.alerts.correlation_engine import IncidentRecord, IncidentSqliteRepository
        from threatfusion.correlation.incident_correlation import (
            MTTI_MANUAL_BASELINE_SECONDS,
            MTTR_MANUAL_BASELINE_SECONDS,
            build_operational_velocity_report,
            compute_mtti,
            compute_mttr,
            record_mtti_telemetry,
        )

        # 1. Mathematical calculation of MTTI without clock drift
        t_ingest = 1729350000.000000
        t_rag = 1729350001.250555
        mtti = compute_mtti(t_ingest, t_rag)
        assert mtti == 1.250555
        assert compute_mtti(t_ingest, t_ingest - 10.0) == 0.0  # Safe non-negative

        # 2. Mathematical calculation of MTTR without clock drift
        t_queued = 1729350100.000000
        t_verified = 1729350104.500123
        mttr = compute_mttr(t_queued, t_verified)
        assert mttr == 4.500123
        assert compute_mttr(t_queued, t_queued - 5.0) == 0.0  # Safe non-negative

        from datetime import UTC, datetime

        # 3. SQLite Persistence in IncidentSqliteRepository
        inc_db = tmp_path / "test_incidents.sqlite3"
        inc_repo = IncidentSqliteRepository(inc_db)
        inc_rec = IncidentRecord(
            schema_version="incident_record_v1",
            incident_id="inc_m36_test_01",
            correlation_mode="burst_correlated",
            window_type="30.0s_burst",
            correlation_rule_id="corr_burst_5tuple_30s_v1",
            entity_namespace_id="test_m36",
            constituent_alert_ids=("cand_01", "cand_02"),
            constituent_alert_count=2,
            max_probability_score=0.945,
            escalated_decision="Attack",
            earliest_observed_at=datetime.fromtimestamp(t_ingest, tz=UTC).isoformat(),
            latest_observed_at=datetime.fromtimestamp(t_rag, tz=UTC).isoformat(),
            provenance_status="verified_entity_bearing",
            created_at=datetime.now(UTC).isoformat(),
            t_flow_ingest=t_ingest,
            t_rag_grounded=t_rag,
            t_investigation=mtti,
        )
        inc_repo.insert(inc_rec)
        timings = inc_repo.list_incident_timings()
        assert len(timings) == 1
        assert timings[0]["incident_id"] == "inc_m36_test_01"
        assert timings[0]["t_investigation"] == 1.250555
        recorded_inv = record_mtti_telemetry(inc_repo, "inc_m36_test_01", t_ingest, t_rag)
        assert recorded_inv == 1.250555

        # 4. SQLite Persistence in SoarPlaybookSqliteRepository
        soar_db = tmp_path / "test_soar.sqlite3"
        soar_repo = SoarPlaybookSqliteRepository(soar_db)
        soar_engine = ApprovalGatedSoarEngine(soar_repo)
        prov = EntityProvenanceContract(
            entity_namespace_id="test_m36",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        recs = soar_engine.recommend_actions_for_alert("cand_01", prov)
        pb_id = recs[0].playbook_id
        soar_engine.decide_recommendation(
            pb_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="containment",
            expected_version=1,
        )
        t_resp = soar_repo.record_callback_verification(
            playbook_id=pb_id,
            t_callback_verified=t_verified,
            t_approval_queued=t_queued,
        )
        assert t_resp == 4.500123
        resp_timings = soar_repo.list_response_timings()
        assert len(resp_timings) == 1
        assert resp_timings[0]["t_response"] == 4.500123

        # 5. Build OperationalVelocityReport
        report = build_operational_velocity_report(
            incident_timings=timings,
            response_timings=resp_timings,
        )
        assert report.schema_version == "operational_velocity_v1"
        assert report.mtti_seconds_mean == 1.250555
        assert report.mtti_manual_baseline_seconds == MTTI_MANUAL_BASELINE_SECONDS
        assert report.mtti_speedup_ratio > 800.0
        assert report.mttr_seconds_mean == 4.500123
        assert report.mttr_manual_baseline_seconds == MTTR_MANUAL_BASELINE_SECONDS
        assert report.mttr_speedup_ratio > 500.0
        assert len(report.per_incident_timings) == 1
        assert "noise_reduction_funnel" in report.to_dict()

        # 6. Contract Server Endpoint Verification
        monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", TEST_SOAR_HMAC_SECRET)
        monkeypatch.setenv("THREATFUSION_SOAR_LEDGER_DB_PATH", str(soar_db))
        monkeypatch.setenv("THREATFUSION_INCIDENTS_DB_PATH", str(inc_db))

        MispAndCallbackContractHandler.soar_db_path = str(soar_db)
        MispAndCallbackContractHandler.seen_verify_idempotency_keys.clear()
        MispAndCallbackContractHandler.seen_callback_idempotency_keys.clear()

        server = http.server.HTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{port}"

        try:
            # 6a. GET / serves frontend index.html
            req_index = urllib.request.Request(f"{base_url}/")
            with urllib.request.urlopen(req_index, timeout=2.0) as resp:
                assert resp.status == 200
                assert "text/html" in resp.headers.get("Content-Type", "")
                html_body = resp.read().decode("utf-8")
                assert "ThreatFusion SOC Console" in html_body
                assert "velocityRibbon" in html_body

            # 6b. GET /css/soc_unicorn.css serves CSS
            req_css = urllib.request.Request(f"{base_url}/css/soc_unicorn.css")
            with urllib.request.urlopen(req_css, timeout=2.0) as resp:
                assert resp.status == 200
                assert "text/css" in resp.headers.get("Content-Type", "")

            # 6c. GET /js/soc_dashboard.js serves JS
            req_js = urllib.request.Request(f"{base_url}/js/soc_dashboard.js")
            with urllib.request.urlopen(req_js, timeout=2.0) as resp:
                assert resp.status == 200
                assert "application/javascript" in resp.headers.get("Content-Type", "")

            # 6d. GET /api/v1/metrics/operational-velocity returns deterministic JSON
            req_vel = urllib.request.Request(f"{base_url}/api/v1/metrics/operational-velocity")
            with urllib.request.urlopen(req_vel, timeout=2.0) as resp:
                assert resp.status == 200
                vel_data = json.loads(resp.read().decode("utf-8"))
                assert vel_data["schema_version"] == "operational_velocity_v1"
                assert vel_data["mtti_seconds_mean"] == 1.250555
                assert vel_data["mttr_seconds_mean"] == 4.500123
                assert vel_data["mtti_speedup_ratio"] > 800.0
                assert vel_data["mttr_speedup_ratio"] > 500.0
                assert "noise_reduction_funnel" in vel_data

            # 6e. POST /api/v1/soar/callback computes t_response in receipt
            import hashlib as hlib
            import hmac as hmod

            cb_payload = {
                "playbook_id": pb_id,
                "candidate_id": "cand_01",
                "t_approval_queued": t_queued,
                "t_callback_verified": t_verified + 1.0,
            }
            cb_bytes = json.dumps(cb_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            cb_sig = hmod.new(
                TEST_SOAR_HMAC_SECRET.encode("utf-8"), cb_bytes, hlib.sha256
            ).hexdigest()
            req_cb = urllib.request.Request(
                f"{base_url}/api/v1/soar/callback",
                data=cb_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Signature-256": cb_sig,
                    "X-Idempotency-Key": f"idem_{pb_id}_cb_m36",
                },
                method="POST",
            )
            with urllib.request.urlopen(req_cb, timeout=2.0) as resp:
                assert resp.status == 200
                cb_data = json.loads(resp.read().decode("utf-8"))
                assert cb_data["callback_recorded"] is True
                assert cb_data["t_response"] == 5.500123
        finally:
            server.shutdown()
            server.server_close()

    def test_alert_noise_reduction_funnel_and_compression_ratio(self) -> None:
        """Verify 4-Tier Alert Noise Compression Funnel counter math and compression ratio."""
        from threatfusion.api.analyst_dashboard import compute_alert_noise_reduction_funnel

        # 1. Benchmark population (January 2026: 216,568 flows -> 4,358 -> 24 -> 8)
        funnel = compute_alert_noise_reduction_funnel(
            tier1_raw_flows_ingested=216568,
            tier2_triage_queue_candidates=4358,
            tier3_correlated_incidents=24,
            tier4_actionable_soar_playbooks=8,
        )
        assert funnel.tier1_raw_flows_ingested == 216568
        assert funnel.tier2_triage_queue_candidates == 4358
        assert funnel.tier3_correlated_incidents == 24
        assert funnel.tier4_actionable_soar_playbooks == 8
        # Formula: round((1.0 - (24 / 216568)) * 100.0, 4) == 99.9889
        expected_ratio = round((1.0 - (24.0 / 216568.0)) * 100.0, 4)
        assert funnel.noise_compression_ratio_pct == expected_ratio
        assert funnel.noise_compression_ratio_pct == 99.9889

        # 2. Multi-flow burst condition (e.g. 5,000 flows -> 250 -> 10 -> 4)
        burst_funnel = compute_alert_noise_reduction_funnel(
            tier1_raw_flows_ingested=5000,
            tier2_triage_queue_candidates=250,
            tier3_correlated_incidents=10,
            tier4_actionable_soar_playbooks=4,
        )
        expected_burst_ratio = round((1.0 - (10.0 / 5000.0)) * 100.0, 4)
        assert burst_funnel.noise_compression_ratio_pct == expected_burst_ratio
        assert burst_funnel.noise_compression_ratio_pct == 99.8000

        # 3. Edge-case zero flows handled safely (clamped to max(1, tier1))
        zero_funnel = compute_alert_noise_reduction_funnel(
            tier1_raw_flows_ingested=0,
            tier2_triage_queue_candidates=0,
            tier3_correlated_incidents=0,
            tier4_actionable_soar_playbooks=0,
        )
        assert zero_funnel.tier1_raw_flows_ingested == 0
        assert zero_funnel.noise_compression_ratio_pct == 100.0

        # 4. Negative values raise ValueError
        with pytest.raises(ValueError, match="cannot be negative"):
            compute_alert_noise_reduction_funnel(tier1_raw_flows_ingested=-1)

    def test_four_block_investigation_anatomy_groundedness_and_fail_closed_fallback(
        self, tmp_path: Path
    ) -> None:
        """Verify 4-Block Investigation Anatomy fail-closed groundedness, entity provenance, and dashboard rendering."""
        from threatfusion.advisory.explanation_engine import (
            AdvisoryEvidenceBundle,
            build_four_block_investigation_anatomy,
        )
        from threatfusion.api.analyst_dashboard import (
            DashboardAlertDetail,
            DashboardAlertQueue,
            DashboardSnapshot,
            render_dashboard_html,
        )
        from threatfusion.soar.n8n_thehive_misp_stack import TheHiveDeterministicClient
        from threatfusion.soar.playbook_ledger import (
            ApprovalGatedSoarEngine,
            SoarPlaybookSqliteRepository,
        )

        bundle = AdvisoryEvidenceBundle(
            candidate_id="cand_m36_anatomy",
            record_id="rec_m36_01",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.9450,
            rf_threshold=0.50,
            top_feature_signals={"sbytes": 2450.0, "rate": 180.5},
            observed_at="2026-10-20T12:00:00Z",
        )
        prov = EntityProvenanceContract(
            entity_namespace_id="test_m36",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )

        # 1. Case A: Valid Grounded Anatomy Generation
        anatomy = build_four_block_investigation_anatomy(
            bundle,
            provenance=prov,
            candidate_explanation="Frozen Random Forest identified high volumetric rate attack targeting host 10.0.0.5.",
            candidate_affected_assets=["10.0.0.4", "10.0.0.5"],
            window_type="30.0s_burst",
            correlated_flow_count=5,
            technique_id="T1071.001",
            tactic_name="Command and Control",
            cosine_similarity=0.942,
            playbook_id="pb-isolate-01",
            playbook_state="approved",
            audit_chain_valid=True,
            hmac_signature_verified=True,
        )

        # Block 1 Executive Summary assertions
        assert anatomy.block_1_executive_summary.risk_level == "CRITICAL"
        assert anatomy.block_1_executive_summary.rf_probability == 0.9450
        assert (
            anatomy.block_1_executive_summary.recall_gain_badge
            == "+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"
        )
        assert anatomy.block_1_executive_summary.affected_network_assets == ("10.0.0.4", "10.0.0.5")

        # Block 2 Attack Timeline assertions
        assert anatomy.block_2_attack_timeline.window_type == "30.0s_burst"
        assert anatomy.block_2_attack_timeline.correlated_flow_count == 5

        # Block 3 MITRE Mapping assertions
        assert anatomy.block_3_mitre_mapping.technique_id == "T1071.001"
        assert anatomy.block_3_mitre_mapping.tactic_name == "Command and Control"
        assert anatomy.block_3_mitre_mapping.cosine_similarity == 0.942

        # Block 4 SOAR Status assertions
        assert anatomy.block_4_cryptographic_soar_status.playbook_id == "pb-isolate-01"
        assert anatomy.block_4_cryptographic_soar_status.playbook_state == "approved"
        assert anatomy.block_4_cryptographic_soar_status.audit_chain_valid is True
        assert anatomy.block_4_cryptographic_soar_status.hmac_signature_verified is True

        # 2. Case B: Fail-Closed Behavior on Hallucinated Entities and MITRE IDs
        hallucinated_anatomy = build_four_block_investigation_anatomy(
            bundle,
            provenance=prov,
            candidate_explanation="Malicious probe from ungrounded external IP 198.51.100.99 with technique T9999.",
            candidate_affected_assets=["198.51.100.99"],  # Hallucinated IP
            technique_id="T9999",  # Hallucinated technique ID
        )

        # Hallucinated IP rejected -> falls back closed to grounded allowed IPs
        assert (
            "198.51.100.99"
            not in hallucinated_anatomy.block_1_executive_summary.affected_network_assets
        )
        assert set(hallucinated_anatomy.block_1_executive_summary.affected_network_assets) == {
            "10.0.0.4",
            "10.0.0.5",
        }

        # Hallucinated MITRE ID rejected -> falls back closed to canonical indexed technique
        assert hallucinated_anatomy.block_3_mitre_mapping.technique_id != "T9999"
        assert hallucinated_anatomy.block_3_mitre_mapping.technique_id == "T1071.001"

        # 3. Case C: TheHive Case Integration attaches 4-block anatomy
        soar_db = tmp_path / "test_soar_hive.sqlite3"
        soar_repo = SoarPlaybookSqliteRepository(soar_db)
        soar_engine = ApprovalGatedSoarEngine(soar_repo)
        recs = soar_engine.recommend_actions_for_alert("cand_m36_hive", prov)
        pb_id = recs[0].playbook_id
        soar_engine.decide_recommendation(
            pb_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="containment",
            expected_version=1,
        )
        approved_rec = soar_repo.get_record(pb_id)

        hive_client = TheHiveDeterministicClient(
            thehive_url="http://thehive.internal:9000",
            api_key="test_hive_key",
            outbox_db_path=tmp_path / "hive_outbox.sqlite3",
        )
        case_rec = hive_client.create_case_from_soar(
            soar_record=approved_rec,
            soar_repo=soar_repo,
            rf_confidence_pct=94.5,
        )
        assert case_rec.case_id.startswith("case_")
        assert "4-Block Investigation Anatomy" in case_rec.description
        assert "Block 1 (Executive Summary):" in case_rec.description
        assert "Block 2 (Attack Timeline):" in case_rec.description
        assert "Block 3 (MITRE Mapping):" in case_rec.description
        assert "Block 4 (Cryptographic SOAR Status):" in case_rec.description

        # 4. Case D: Dashboard HTML rendering contains data-anatomy-block="1", "2", "3", "4"
        detail = DashboardAlertDetail(
            alert_candidate_id="cand_m36_html",
            source_event_id="src_01",
            observed_at="2026-10-20T12:00:00Z",
            created_at="2026-10-20T12:00:01Z",
            source_representation_identity="azure.suricata",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.9250,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="in_review",
            version=1,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
        )
        queue = DashboardAlertQueue(items=(), total_loaded=0, limit=10, offset=0)
        snap = DashboardSnapshot(queue=queue, selected=detail, status="active")
        rendered_html = render_dashboard_html(snap)
        assert 'data-anatomy-block="1"' in rendered_html
        assert 'data-anatomy-block="2"' in rendered_html
        assert 'data-anatomy-block="3"' in rendered_html
        assert 'data-anatomy-block="4"' in rendered_html
        assert (
            "+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"
            in rendered_html
        )

    def test_operational_velocity_decomposition_and_toil_savings(self) -> None:
        """Verify Dropzone/Prophet-style Operational Velocity Decomposition (TTD + TTA + TTI = Conclusion)."""
        from threatfusion.correlation import (
            DEFAULT_TTA_MEAN_MS,
            DEFAULT_TTD_MEAN_MS,
            DEFAULT_VELOCITY_FORMULA,
            MANUAL_L1_TRIAGE_BASELINE_SECONDS,
            build_operational_velocity_report,
        )

        # 1. Default report calculation
        rep = build_operational_velocity_report()
        assert rep.ttd_mean_ms == DEFAULT_TTD_MEAN_MS
        assert rep.tta_mean_ms == DEFAULT_TTA_MEAN_MS
        assert rep.tti_mean_seconds == 1.25
        assert rep.total_time_to_conclusion_seconds == 1.281
        assert rep.velocity_formula == DEFAULT_VELOCITY_FORMULA
        assert rep.manual_l1_triage_baseline_seconds == MANUAL_L1_TRIAGE_BASELINE_SECONDS
        assert rep.analyst_toil_saved_seconds == 898.719
        assert rep.analyst_toil_saved_pct == 99.8577

        # 2. Check serialized dictionary structure
        d = rep.to_dict()
        assert "velocity_decomposition" in d
        decomp = d["velocity_decomposition"]
        assert decomp["ttd_mean_ms"] == 18.4
        assert decomp["tta_mean_ms"] == 12.6
        assert decomp["tti_mean_seconds"] == 1.25
        assert decomp["total_time_to_conclusion_seconds"] == 1.281
        assert decomp["velocity_formula"] == DEFAULT_VELOCITY_FORMULA
        assert decomp["manual_l1_triage_baseline_seconds"] == 900.0
        assert decomp["analyst_toil_saved_seconds"] == 898.719
        assert decomp["analyst_toil_saved_pct"] == 99.8577

        # 3. Custom telemetry overrides
        custom_inc = [{"incident_id": "inc_1", "t_investigation": 0.850}]
        custom_rep = build_operational_velocity_report(
            incident_timings=custom_inc,
            ttd_mean_ms=10.0,
            tta_mean_ms=5.0,
            manual_l1_triage_baseline_seconds=900.0,
        )
        assert custom_rep.ttd_mean_ms == 10.0
        assert custom_rep.tta_mean_ms == 5.0
        assert custom_rep.tti_mean_seconds == 0.850
        # total = (10/1000) + (5/1000) + 0.850 = 0.010 + 0.005 + 0.850 = 0.865
        assert custom_rep.total_time_to_conclusion_seconds == 0.865
        assert custom_rep.analyst_toil_saved_seconds == 899.135
        expected_pct = round((1.0 - (0.865 / 900.0)) * 100.0, 4)
        assert custom_rep.analyst_toil_saved_pct == expected_pct

    def test_verify_frontend_asset_bundle_enterprise_palette_and_dom_markers(
        self, tmp_path: Path
    ) -> None:
        """Verify static asset bundle audit confirms Enterprise Dark-Slate tokens and DOM hooks."""
        import re
        from threatfusion.api.analyst_dashboard import verify_frontend_asset_bundle

        # 1. Active repository bundle audit
        result = verify_frontend_asset_bundle()
        assert result["verified"] is True
        assert result["assets"] == ["css", "index_html", "js"]
        assert len(result["sha256"]) == 3
        for k in ("css", "index_html", "js"):
            assert re.fullmatch(r"^[0-9a-f]{64}$", result["sha256"][k])

        backend_code = Path("backend/src/threatfusion/api/analyst_dashboard.py").read_text(encoding="utf-8")
        assert "data-copy-hash" in backend_code

        # 2. Defective bundle missing required markers raises ValueError
        bad_dir = tmp_path / "bad_frontend_repo"
        bad_fe = bad_dir / "frontend"
        bad_fe.mkdir(parents=True)
        (bad_fe / "index.html").write_text("<html><body>Empty</body></html>", encoding="utf-8")
        (bad_fe / "css").mkdir()
        (bad_fe / "css" / "soc_unicorn.css").write_text("body { color: white; }", encoding="utf-8")
        (bad_fe / "js").mkdir()
        (bad_fe / "js" / "soc_dashboard.js").write_text("console.log('hi');", encoding="utf-8")

        with pytest.raises(ValueError, match="Required frontend asset marker missing"):
            verify_frontend_asset_bundle(bad_dir)

    def test_five_tab_investigation_inspector_and_cryptographic_fail_closed(self) -> None:
        """Verify 5-Tab Investigation Inspector generation and cryptographic fail-closed validation."""
        from threatfusion.api.analyst_dashboard import (
            TriageQueueCardView,
            build_five_tab_investigation_inspector,
        )

        valid_receipt = {
            "execution_id": "exec_n8n_test_01",
            "signature_sha256": "44d88612fea8a8f36de82e1278abb02f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
        }
        valid_chain = (
            {
                "entry_hash": "GENESIS_BLOCK_00000000000000000000000000000000000000000000000000000000",
                "prev_hash": "GENESIS_BLOCK_00000000000000000000000000000000000000000000000000000000",
            },
            {
                "entry_hash": "44d88612fea8a8f36de82e1278abb02f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
                "prev_hash": "GENESIS_BLOCK_00000000000000000000000000000000000000000000000000000000",
            },
        )

        # 1. Valid verified card
        card_valid = TriageQueueCardView(
            campaign_id="camp_m37_valid",
            alert_candidate_id="cand_m37_01",
            source_ip="10.0.0.4",
            dest_ip="10.0.0.5",
            technique_id="T1071.001",
            soar_receipt=valid_receipt,
            audit_chain=valid_chain,
            explanation="Deterministic Frozen Random Forest detected Web Protocols on host 10.0.0.5.",
        )
        inspector = build_five_tab_investigation_inspector(card_valid)
        assert inspector["evidence_state"] == "verified"
        assert inspector["tab_1_executive_summary"]["evidence_state"] == "verified"
        assert inspector["tab_1_executive_summary"]["asset_exposure"] == "RFC1918 Internal"
        assert inspector["tab_3_mitre_and_playbook"]["evidence_state"] == "verified"
        assert inspector["tab_3_mitre_and_playbook"]["technique_id"] == "T1071.001"
        assert inspector["tab_4_evidence_locker"]["frozen_rf_precision"] == "95.266%"
        assert inspector["tab_5_soar_audit_changelog"]["evidence_state"] == "verified"
        assert inspector["tab_5_soar_audit_changelog"]["copy_hash_attr"] == "data-copy-hash"
        assert "data-copy-hash" in inspector["tab_5_soar_audit_changelog"]["html"]

        # 2. Forged SOAR receipt fails closed
        card_forged_receipt = TriageQueueCardView(
            campaign_id="camp_m37_forged",
            alert_candidate_id="cand_m37_02",
            source_ip="10.0.0.4",
            dest_ip="10.0.0.5",
            soar_receipt={"execution_id": "exec_fake", "signature_sha256": "not-a-valid-sha256-hash"},
            audit_chain=valid_chain,
        )
        insp_forged = build_five_tab_investigation_inspector(card_forged_receipt)
        assert insp_forged["tab_5_soar_audit_changelog"]["evidence_state"] == "unavailable"
        assert insp_forged["evidence_state"] == "unavailable"

        # 3. Ungrounded / Hallucinated explanation fails closed
        card_hallucinated = TriageQueueCardView(
            campaign_id="camp_m37_hallucinated",
            alert_candidate_id="cand_m37_03",
            source_ip="10.0.0.4",
            dest_ip="10.0.0.5",
            soar_receipt=valid_receipt,
            audit_chain=valid_chain,
            explanation="Attack originating from ungrounded external IP 198.51.100.99 with unauthorized backdoor.",
        )
        insp_hallucinated = build_five_tab_investigation_inspector(card_hallucinated)
        assert insp_hallucinated["tab_1_executive_summary"]["evidence_state"] == "unavailable"
        assert insp_hallucinated["evidence_state"] == "unavailable"

    def test_analyst_dashboard_html_renders_investor_grade_ui_ux_layers(self) -> None:
        """Verify render_dashboard_html renders Enterprise Dark-Slate tokens, Layer 1, 2, and 3 markers."""
        from threatfusion.api.analyst_dashboard import (
            DashboardAlertDetail,
            DashboardAlertQueue,
            DashboardSnapshot,
            render_dashboard_html,
        )

        detail = DashboardAlertDetail(
            alert_candidate_id="cand_m37_render_01",
            source_event_id="src_event_01",
            observed_at="2026-10-20T12:00:00Z",
            created_at="2026-10-20T12:00:01Z",
            source_representation_identity="azure.suricata",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.9527,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="in_review",
            version=1,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
        )
        queue = DashboardAlertQueue(items=(), total_loaded=0, limit=10, offset=0)
        snap = DashboardSnapshot(queue=queue, selected=detail, status="active")

        html = render_dashboard_html(snap)

        # Enterprise Dark-Slate design tokens
        assert "#090D16" in html
        assert "#111827" in html

        # Layer 1 Hero Strip hooks
        assert 'data-layer="hero-investor-hook"' in html
        assert "99%+ Alert Noise Eliminated" in html
        assert "TTD (Time to Detect, ms) + TTA (Time to Acknowledge, ms) + TTI (Time to Investigate, s) = Total Time to Conclusion" in html
        assert "900.0s" in html
        assert "mTLS 1.3 Active" in html
        assert "Model Weights Frozen &amp; Verified" in html
        assert "SOAR Audit Ledger: Intact" in html

        # Layer 2 Architecture Ribbon hooks
        assert 'data-layer="architecture-ribbon"' in html
        assert 'data-pipeline-stage="1"' in html
        assert 'data-pipeline-stage="2"' in html
        assert 'data-pipeline-stage="3"' in html
        assert 'data-pipeline-stage="4"' in html
        assert 'data-pipeline-stage="5"' in html
        assert 'data-pipeline-stage="6"' in html

        # Layer 3 Split Workspace & 5-Tab Inspector hooks
        assert 'data-layer="split-investigation-workspace"' in html
        assert 'data-inspector-tab="1"' in html
        assert 'data-inspector-tab="2"' in html
        assert 'data-inspector-tab="3"' in html
        assert 'data-inspector-tab="4"' in html
        assert 'data-inspector-tab="5"' in html
        assert 'data-anatomy-block="1"' in html
        assert 'data-anatomy-block="2"' in html
        assert 'data-anatomy-block="3"' in html
        assert 'data-anatomy-block="4"' in html

        # Click-to-copy hash parity and attributes
        assert "data-copy-hash" in html
        assert 'title="Click to copy SHA-256 digest"' in html
        assert "navigator.clipboard.writeText" in html
        assert "data-copy-hash" in Path("backend/src/threatfusion/api/analyst_dashboard.py").read_text(encoding="utf-8")
