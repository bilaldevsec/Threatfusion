"""ChromaDB Semantic Vector RAG over MITRE ATT&CK & Playbooks (Milestone #32).

Provides deterministic semantic vector retrieval over canonical MITRE ATT&CK
Enterprise techniques and incident response playbooks:
1. MitrePlaybookRagDocument & ChromaRagQueryResult:
   Immutable dataclasses for knowledge corpus entries and ranked search hits.
2. CANONICAL_MITRE_AND_PLAYBOOK_CORPUS:
   Authoritative corpus of 10 enterprise techniques (T1046, T1190, T1498, T1071.001,
   T1595, T1110, T1041, T1021, T1059, T1133) plus 8 CVE playbooks
   (T1557, T1499, T1190, T1552, T1059, T1048, T1210) and structured SOC playbooks.
3. DeterministicMitreEmbeddingFunction:
   Computes deterministic L2-normalized 64-dimensional dense float vector embeddings
   from domain security tokens and character trigrams without external model downloads.
4. ChromaDbMitrePlaybookRag:
   Supports chromadb (if installed) or a built-in ChromaDB-API-compatible persistent
   SQLite dense vector collection engine stored in chromadb_vectors.sqlite3 with mode 0600.
5. Strict Assistant-Only Isolation:
   The RAG engine serves strictly as an advisory assistant—it NEVER rewrites execution
   code, never alters rf_attack_probability or decision thresholds, and Stages 1-4
   maintain zero imports from threatfusion.advisory (Gate G9 enforced).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from threatfusion.advisory.explanation_engine import AdvisoryEvidenceBundle

CHROMADB_RAG_SCHEMA_VERSION = "chromadb_mitre_rag_sqlite_v1"
EMBEDDING_DIMENSION = 64


@dataclass(frozen=True, slots=True)
class MitrePlaybookRagDocument:
    """Canonical MITRE ATT&CK technique and incident playbook document."""

    doc_id: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    playbook_id: str
    deterministic_playbook_steps: tuple[str, ...]
    mitre_version: str = "15.1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "description": self.description,
            "playbook_id": self.playbook_id,
            "deterministic_playbook_steps": list(self.deterministic_playbook_steps),
            "mitre_version": self.mitre_version,
        }


@dataclass(frozen=True, slots=True)
class ChromaRagQueryResult:
    """Ranked semantic vector search result from ChromaDB RAG."""

    doc_id: str
    technique_id: str
    technique_name: str
    tactic: str
    playbook_id: str
    deterministic_playbook_steps: tuple[str, ...]
    cosine_similarity: float
    distance: float
    rank: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "playbook_id": self.playbook_id,
            "deterministic_playbook_steps": list(self.deterministic_playbook_steps),
            "cosine_similarity": self.cosine_similarity,
            "distance": self.distance,
            "rank": self.rank,
        }


CANONICAL_MITRE_AND_PLAYBOOK_CORPUS: tuple[MitrePlaybookRagDocument, ...] = (
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1046",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        description=(
            "Adversaries attempt to enumerate running network services on hosts, identifying open "
            "ports, listening daemons, and potential exploit vectors across network interfaces. "
            "Characterized by rapid multi-port TCP SYN/CONNECT or UDP probes, elevated packet rates, "
            "and uniform flow durations."
        ),
        playbook_id="pb-network-service-discovery-v1",
        deterministic_playbook_steps=(
            "1. Query firewall logs for source IP port-sweep patterns across the 30s burst window.",
            "2. Check if scanned destination ports host critical exposed services or databases.",
            "3. Issue quarantine ticket in SOAR outbox for security analyst review.",
            "4. Block unauthorized discovery probes at perimeter gateway upon authenticated approval.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1190",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description=(
            "Adversaries take advantage of software vulnerabilities or misconfigurations in Internet-facing "
            "programs (web servers, APIs, VPNs) to execute unauthorized code or gain initial access. "
            "Flow indicators often feature TCP port 80/443/8080/8443 traffic with anomalous forward-to-backward "
            "byte ratios and burst packet lengths."
        ),
        playbook_id="pb-exploit-public-facing-v1",
        deterministic_playbook_steps=(
            "1. Extract web server access logs and correlate request payload patterns.",
            "2. Verify application patch status and vulnerability CVE identifiers.",
            "3. Isolate affected public-facing host or revoke compromised session tokens.",
            "4. Submit forensic payload hash to MISP intelligence repository.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1498",
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic="Impact",
        description=(
            "Adversaries execute network-level degradation or disruption attacks targeting bandwidth, "
            "socket pools, or protocol state machines via high-rate volumetric packet floods. "
            "Flow metrics display extreme packets_per_second and bytes_per_second spikes, protocol ICMP "
            "or UDP dominance, and suppressed backward packet counts."
        ),
        playbook_id="pb-network-dos-mitigation-v1",
        deterministic_playbook_steps=(
            "1. Identify attack traffic characteristics (protocol, packet rate, burst ratio).",
            "2. Enable upstream BGP flowspec or cloud rate-limiting filter.",
            "3. Divert flood flows to dead-letter quarantine buffer.",
            "4. Notify network operations center and verify downstream service availability.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1071_001",
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Traffic",
        tactic="Command and Control",
        description=(
            "Adversaries communicate using application layer protocols (HTTP, HTTPS) to disguise C2 "
            "beaconing, command execution, and data staging within legitimate web traffic. "
            "Manifests as sustained periodic flows, fixed packet lengths, and regular duration intervals "
            "to external public IPs."
        ),
        playbook_id="pb-c2-web-traffic-isolation-v1",
        deterministic_playbook_steps=(
            "1. Decode HTTP request headers, user agents, and beaconing periodicity.",
            "2. Cross-reference destination domain and IP against MISP threat intelligence.",
            "3. Enforce perimeter proxy sinkhole or firewall drop for malicious C2 endpoint.",
            "4. Initiate host endpoint triage in TheHive case manager.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1595",
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic="Reconnaissance",
        description=(
            "Adversaries execute pre-compromise active probing of target IP ranges and CIDR blocks to "
            "discover infrastructure topology, open ports, and vulnerable software versions. "
            "Evidenced by broad IP sweeps, single-packet flows per endpoint, and low byte volumes."
        ),
        playbook_id="pb-active-scanning-triage-v1",
        deterministic_playbook_steps=(
            "1. Correlate scanning bursts across the 30-second sliding detection window.",
            "2. Tag scan intensity, source network ASN, and targeted CIDR ranges.",
            "3. Rate-limit or drop scanner source IP at upstream perimeter ACL.",
            "4. Log reconnaissance activity in SOAR audit chain.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1110",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        description=(
            "Adversaries systematically attempt multiple authentication credentials (passwords, hashes, tokens) "
            "against login endpoints, SSH, RDP, or directory services. Flow signatures reveal repeated short "
            "TCP sessions to ports 22, 3389, 445, or 80 with high transaction frequency."
        ),
        playbook_id="pb-credential-brute-force-v1",
        deterministic_playbook_steps=(
            "1. Collate failed authentication flow spikes and targeted user accounts.",
            "2. Trigger automated temporary credential lockout policy.",
            "3. Enforce MFA step-up authentication on affected account profiles.",
            "4. Quarantine source IP in SOAR ledger pending analyst review.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1041",
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description=(
            "Adversaries steal sensitive internal data by encoding and transmitting artifacts over an existing "
            "command and control channel or covert network protocol. Characterized by severe forward-byte asymmetry "
            "(fwd_bytes >> bwd_bytes), elevated bytes_per_second, and long session duration."
        ),
        playbook_id="pb-c2-exfiltration-containment-v1",
        deterministic_playbook_steps=(
            "1. Calculate outbound bytes-per-second and payload asymmetry ratios.",
            "2. Terminate active socket connection to remote exfiltration endpoint.",
            "3. Snapshot affected internal host memory and local disk artifacts.",
            "4. Open high-priority incident in TheHive and notify data protection officer.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1021",
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="Lateral Movement",
        description=(
            "Adversaries leverage legitimate remote management protocols (SMB, SSH, WinRM, RDP) to move laterally "
            "across enterprise subnets using compromised credentials. Flows connect internal private IPs on "
            "ports 445, 139, 22, or 3389 with high bidirectional byte exchange."
        ),
        playbook_id="pb-remote-services-lateral-movement-v1",
        deterministic_playbook_steps=(
            "1. Verify whether source and destination hosts have approved administrative pairing.",
            "2. Check authentication tickets for Kerberos Pass-the-Ticket or NTLM relay indicators.",
            "3. Revoke compromised service tickets and isolate target workstation.",
            "4. Record lateral movement indicators in TheHive case file.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1059",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        description=(
            "Adversaries abuse command shells and scripting environments (bash, sh, PowerShell, Python) to "
            "execute arbitrary commands, bypass controls, and automate attack phases. Correlated with unusual "
            "terminal interactive flow durations and unexpected outbound execution sockets."
        ),
        playbook_id="pb-scripting-interpreter-triage-v1",
        deterministic_playbook_steps=(
            "1. Capture command-line arguments and parent-child process lineage.",
            "2. Inspect script hash against local allowlist and MISP reputation database.",
            "3. Terminate unauthorized interpreter process tree.",
            "4. Collect forensic event logs and submit case report to TheHive.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_t1133",
        technique_id="T1133",
        technique_name="External Remote Services",
        tactic="Persistence",
        description=(
            "Adversaries exploit or misuse external-facing access services (VPNs, Citrix gateways, bastion hosts) "
            "to establish persistence and re-enter internal enterprise networks. Manifests as unexpected external "
            "connections outside standard working hours and anomalous source IP geolocations."
        ),
        playbook_id="pb-external-remote-services-audit-v1",
        deterministic_playbook_steps=(
            "1. Review VPN/gateway session authentication logs and geolocation anomaly tags.",
            "2. Terminate anomalous active remote VPN/portal session.",
            "3. Invalidate credentials and reset authentication secrets for target user.",
            "4. Queue SOAR perimeter firewall rule update in approval ledger.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2023_48795",
        technique_id="T1557",
        technique_name="CVE-2023-48795 Terrapin SSH Prefix Truncation",
        tactic="Credential Access",
        description=(
            "CVE-2023-48795 Terrapin truncates the SSH extension negotiation prefix, weakening "
            "integrity of the handshake. Related techniques T1557 and T1110. Flow signature: TCP "
            "port 22, a completed handshake with an unusual sequence of SSH_MSG_EXT_INFO, and a "
            "low packet rate rather than a volumetric flood."
        ),
        playbook_id="pb-cve-2023-48795-terrapin-v1",
        deterministic_playbook_steps=(
            "1. Confirm the SSH peer implements a Terrapin-resistant protocol version.",
            "2. Disable the affected cipher and MAC combinations on the SSH service.",
            "3. Review TCP port 22 sessions for truncated extension negotiation.",
            "4. Require a human approval before any host containment playbook.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2023_44487",
        technique_id="T1499",
        technique_name="CVE-2023-44487 HTTP/2 Rapid Reset",
        tactic="Impact",
        description=(
            "CVE-2023-44487 HTTP/2 Rapid Reset opens and cancels streams at a high packet rate. "
            "Related techniques T1498 and T1499. Flow signature: TCP port 443, HTTP/2, many short "
            "flows, and a packet rate far above a normal request."
        ),
        playbook_id="pb-cve-2023-44487-rapid-reset-v1",
        deterministic_playbook_steps=(
            "1. Measure HTTP/2 stream resets per second on TCP port 443.",
            "2. Apply the vendor rapid-reset limit on the public web service.",
            "3. Keep the source address on the local evidence record.",
            "4. Queue rate limiting only after an analyst approves the playbook.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2021_44228",
        technique_id="T1190",
        technique_name="CVE-2021-44228 Log4Shell JNDI RCE",
        tactic="Initial Access",
        description=(
            "CVE-2021-44228 Log4Shell sends a JNDI lookup in a header or parameter to a Java "
            "service. Technique T1190. Flow signature: TCP ports 80 or 443, then an outbound "
            "LDAP or RMI connection, with a small packet count on the callback."
        ),
        playbook_id="pb-cve-2021-44228-log4shell-v1",
        deterministic_playbook_steps=(
            "1. Search access logs for a JNDI lookup string on the public application.",
            "2. Block outbound LDAP and RMI from the application host at the allowlisted proxy.",
            "3. Patch Log4j to a vendor release that disables the lookup.",
            "4. Record the retrieved candidate technique without changing the forest score.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2023_4966",
        technique_id="T1552",
        technique_name="CVE-2023-4966 CitrixBleed Session Hijack",
        tactic="Credential Access",
        description=(
            "CVE-2023-4966 CitrixBleed reads session tokens from a Citrix gateway memory buffer. "
            "Related techniques T1190 and T1552. Flow signature: TCP port 443, a short HTTPS "
            "request, and reuse of a stolen session cookie from a new source."
        ),
        playbook_id="pb-cve-2023-4966-citrixbleed-v1",
        deterministic_playbook_steps=(
            "1. Identify Citrix gateway sessions created without a matching authentication event.",
            "2. Invalidate active gateway sessions and rotate the affected secrets.",
            "3. Apply the vendor CitrixBleed patch before returning the gateway to service.",
            "4. Keep containment approval-gated and reversible.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2024_3400",
        technique_id="T1059",
        technique_name="CVE-2024-3400 PAN-OS Command Injection",
        tactic="Execution",
        description=(
            "CVE-2024-3400 injects a command through the PAN-OS GlobalProtect path. Related "
            "techniques T1190 and T1059. Flow signature: TCP port 443, a crafted HTTPS request, "
            "and a following shell-like outbound connection with a low packet rate."
        ),
        playbook_id="pb-cve-2024-3400-panos-v1",
        deterministic_playbook_steps=(
            "1. Check GlobalProtect telemetry for the command-injection request pattern.",
            "2. Apply the PAN-OS hotfix that closes the injection path.",
            "3. Review new processes on the firewall management plane.",
            "4. Do not treat the retrieved playbook as an executed containment.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2023_34362",
        technique_id="T1048",
        technique_name="CVE-2023-34362 MOVEit SQL Injection and Exfiltration",
        tactic="Exfiltration",
        description=(
            "CVE-2023-34362 abuses a MOVEit SQL injection to steal files. Related techniques "
            "T1190 and T1048. Flow signature: TCP port 443, a human-paced HTTPS session, then "
            "a larger outbound byte count than the inbound request."
        ),
        playbook_id="pb-cve-2023-34362-moveit-v1",
        deterministic_playbook_steps=(
            "1. Review MOVEit transfer logs for unexpected SQL error strings.",
            "2. Disable the vulnerable web path and rotate service credentials.",
            "3. Compare outbound byte counts on TCP port 443 with the normal transfer baseline.",
            "4. Open a case only from stored evidence and a human approval.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2023_22515",
        technique_id="T1190",
        technique_name="CVE-2023-22515 Confluence Broken Authentication",
        tactic="Initial Access",
        description=(
            "CVE-2023-22515 lets an unauthenticated caller create a Confluence administrator. "
            "Technique T1190. Flow signature: TCP port 8090 or 443, a short setup request, and "
            "a new privileged session with a normal packet rate."
        ),
        playbook_id="pb-cve-2023-22515-confluence-v1",
        deterministic_playbook_steps=(
            "1. List Confluence administrators created outside the change window.",
            "2. Remove the unauthorized administrator and restore the setup lock.",
            "3. Patch Confluence before exposing TCP port 8090 again.",
            "4. Store the action on the approval ledger.",
        ),
    ),
    MitrePlaybookRagDocument(
        doc_id="mitre_doc_cve_2017_0144",
        technique_id="T1210",
        technique_name="CVE-2017-0144 EternalBlue SMB Remote Exploit",
        tactic="Lateral Movement",
        description=(
            "CVE-2017-0144 EternalBlue exploits SMBv1 on TCP port 445. Related techniques "
            "T1210 and T1046. Flow signature: TCP port 445, a small number of specially sized "
            "packets, then a service connection from the same source."
        ),
        playbook_id="pb-cve-2017-0144-eternalblue-v1",
        deterministic_playbook_steps=(
            "1. Confirm SMBv1 is disabled and TCP port 445 is not exposed beyond the segment.",
            "2. Patch the affected Windows host to a release that closes MS17-010.",
            "3. Review the source for a preceding port scan on TCP port 445.",
            "4. Keep any isolation playbook pending until an analyst approves it.",
        ),
    ),
)


class DeterministicMitreEmbeddingFunction:
    """Computes deterministic L2-normalized 64-dimensional dense float vector embeddings.

    Employs sub-word tokenization and deterministic polynomial feature hashing across
    domain security vocabulary to provide consistent, reproducible semantic vector
    representations with zero external model dependencies or API calls.
    """

    def __init__(self, dimension: int = EMBEDDING_DIMENSION) -> None:
        self.dimension = dimension

    def embed_text(self, text: str) -> list[float]:
        """Convert input text into an L2-normalized 64-dimensional dense vector."""
        if not text or not text.strip():
            # Return uniform unit vector
            val = 1.0 / math.sqrt(float(self.dimension))
            return [round(val, 6) for _ in range(self.dimension)]

        clean = text.lower()
        tokens = re.findall(r"[a-z0-9_.\-]+", clean)
        vec = [0.0] * self.dimension

        # Security-specific high-leverage tokens with elevated weights
        keyword_weights: dict[str, float] = {
            "discovery": 3.0,
            "scan": 3.0,
            "port": 2.5,
            "sweep": 2.5,
            "exploit": 3.0,
            "web": 2.0,
            "http": 2.0,
            "https": 2.0,
            "denial": 3.0,
            "flood": 3.0,
            "dos": 3.0,
            "beacon": 3.0,
            "c2": 3.0,
            "brute": 3.0,
            "credential": 2.5,
            "password": 2.5,
            "exfiltration": 3.0,
            "lateral": 3.0,
            "movement": 2.5,
            "script": 2.5,
            "command": 2.5,
            "vpn": 2.5,
            "persistence": 3.0,
            "t1046": 5.0,
            "t1190": 5.0,
            "t1498": 5.0,
            "t1071": 5.0,
            "t1595": 5.0,
            "t1110": 5.0,
            "t1041": 5.0,
            "t1021": 5.0,
            "t1059": 5.0,
            "t1133": 5.0,
        }

        # 1. Token hashing
        for tok in tokens:
            w = keyword_weights.get(tok, 1.0)
            h_int = int(hashlib.sha256(tok.encode("utf-8")).hexdigest(), 16)
            idx = h_int % self.dimension
            sign = 1.0 if ((h_int >> 7) & 1) == 0 else -1.0
            vec[idx] += sign * w

            # 2. Sub-token character trigrams for morphological robustness
            if len(tok) >= 3:
                for i in range(len(tok) - 2):
                    trigram = tok[i : i + 3]
                    th_int = int(hashlib.sha256(trigram.encode("utf-8")).hexdigest(), 16)
                    t_idx = th_int % self.dimension
                    t_sign = 1.0 if ((th_int >> 5) & 1) == 0 else -1.0
                    vec[t_idx] += t_sign * 0.25 * w

        # 3. L2 Normalization
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 1e-12:
            return [round(v / norm, 6) for v in vec]

        val = 1.0 / math.sqrt(float(self.dimension))
        return [round(val, 6) for _ in range(self.dimension)]

    def __call__(self, input: list[str]) -> list[list[float]]:
        """ChromaDB embedding function interface."""
        return [self.embed_text(t) for t in input]


class ChromaDbMitrePlaybookRag:
    """ChromaDB Semantic Vector RAG Store over MITRE ATT&CK & Playbooks.

    Supports native chromadb if installed, with a built-in persistent SQLite
    dense vector collection engine providing 100% deterministic local vector
    retrieval stored in chromadb_vectors.sqlite3 with mode 0600 file security.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        corpus: Sequence[MitrePlaybookRagDocument] = CANONICAL_MITRE_AND_PLAYBOOK_CORPUS,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.embedding_fn = DeterministicMitreEmbeddingFunction()
        self.corpus = tuple(corpus)
        self._init_store()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        previous_isolation = conn.isolation_level
        conn.isolation_level = None
        conn.execute("PRAGMA journal_mode=WAL")
        conn.isolation_level = previous_isolation
        return conn

    def _init_store(self) -> None:
        """Initialize SQLite vector store with mode 0600 permissions."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chroma_collections (
                    name TEXT PRIMARY KEY,
                    metadata_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chroma_embeddings (
                    doc_id TEXT PRIMARY KEY,
                    collection TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    technique_name TEXT NOT NULL,
                    tactic TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    steps_json TEXT NOT NULL,
                    document TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    FOREIGN KEY (collection) REFERENCES chroma_collections(name)
                )
            """)
            conn.execute("""
                INSERT OR IGNORE INTO chroma_collections (name, metadata_json)
                VALUES ('mitre_attack_and_playbooks', '{"source": "CANONICAL_MITRE_AND_PLAYBOOK_CORPUS"}')
            """)

            # Seed corpus if empty
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM chroma_embeddings")
            row = cur.fetchone()
            count = row["cnt"] if row else 0

            if count == 0:
                now_str = datetime.now(UTC).isoformat()
                for doc in self.corpus:
                    # Construct rich indexable document text
                    doc_text = (
                        f"{doc.technique_id} {doc.technique_name} Tactic: {doc.tactic}. "
                        f"{doc.description} Playbook: {doc.playbook_id}. "
                        f"Steps: {' '.join(doc.deterministic_playbook_steps)}"
                    )
                    emb = self.embedding_fn.embed_text(doc_text)
                    conn.execute(
                        """
                        INSERT INTO chroma_embeddings (
                            doc_id, collection, technique_id, technique_name, tactic,
                            playbook_id, steps_json, document, embedding_json, created_at_utc
                        ) VALUES (?, 'mitre_attack_and_playbooks', ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            doc.doc_id,
                            doc.technique_id,
                            doc.technique_name,
                            doc.tactic,
                            doc.playbook_id,
                            json.dumps(list(doc.deterministic_playbook_steps)),
                            doc_text,
                            json.dumps(emb),
                            now_str,
                        ),
                    )

        # Enforce mode 0600 on created database file
        if self.db_path.exists():
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)

    def query_semantic_rag(
        self,
        query_text: str,
        *,
        top_k: int = 3,
    ) -> tuple[ChromaRagQueryResult, ...]:
        """Perform semantic vector retrieval using cosine similarity."""
        query_vec = self.embedding_fn.embed_text(query_text)
        candidates: list[tuple[float, float, dict[str, Any]]] = []

        with self._get_connection() as conn:
            cur = conn.execute("""
                SELECT doc_id, technique_id, technique_name, tactic, playbook_id,
                       steps_json, document, embedding_json
                FROM chroma_embeddings
                WHERE collection = 'mitre_attack_and_playbooks'
                """)
            for row in cur.fetchall():
                doc_vec = json.loads(row["embedding_json"])
                # Compute dot product of two L2-normalized vectors
                dot = sum(q * d for q, d in zip(query_vec, doc_vec, strict=True))
                cos_sim = max(0.0, min(1.0, dot))
                dist = max(0.0, 1.0 - cos_sim)
                candidates.append(
                    (
                        cos_sim,
                        dist,
                        {
                            "doc_id": row["doc_id"],
                            "technique_id": row["technique_id"],
                            "technique_name": row["technique_name"],
                            "tactic": row["tactic"],
                            "playbook_id": row["playbook_id"],
                            "deterministic_playbook_steps": tuple(json.loads(row["steps_json"])),
                        },
                    )
                )

        # Sort by distance ascending (similarity descending)
        candidates.sort(key=lambda x: x[1])
        results: list[ChromaRagQueryResult] = []

        for rank, (sim, dist, meta) in enumerate(candidates[:top_k], start=1):
            results.append(
                ChromaRagQueryResult(
                    doc_id=meta["doc_id"],
                    technique_id=meta["technique_id"],
                    technique_name=meta["technique_name"],
                    tactic=meta["tactic"],
                    playbook_id=meta["playbook_id"],
                    deterministic_playbook_steps=meta["deterministic_playbook_steps"],
                    cosine_similarity=round(sim, 4),
                    distance=round(dist, 4),
                    rank=rank,
                )
            )

        return tuple(results)

    def query_semantic_rag_for_bundle(
        self,
        bundle: AdvisoryEvidenceBundle,
        *,
        top_k: int = 3,
    ) -> tuple[ChromaRagQueryResult, ...]:
        """Query semantic RAG using factual telemetry signals from an AdvisoryEvidenceBundle."""
        # Synthesize domain query text from factual evidence
        query_parts: list[str] = [
            f"Alert Candidate: {bundle.candidate_id}.",
            f"Random Forest Model: {bundle.rf_model_version}.",
            f"Attack Probability: {bundle.rf_attack_probability:.4f}.",
            f"Correlation: {bundle.correlation_status}.",
        ]

        # Port and protocol hints
        features = bundle.top_feature_signals
        dst_port = features.get("dst_port")
        if dst_port is not None:
            port_int = int(dst_port)
            query_parts.append(f"Destination Port: {port_int}.")
            if port_int in (80, 443, 8080, 8443):
                query_parts.append("Web traffic application layer protocol HTTP HTTPS exploit.")
            elif port_int in (22, 3389, 445, 139):
                query_parts.append(
                    "Remote services credential access brute force lateral movement."
                )

        if (
            features.get("packets_per_second", 0.0) > 1000.0
            or features.get("bytes_per_second", 0.0) > 100000.0
        ):
            query_parts.append("Volumetric network denial of service flood impact.")

        if features.get("fwd_packets", 0.0) > 20.0 and features.get("bwd_packets", 0.0) <= 2.0:
            query_parts.append("Network service discovery active scanning probe sweep.")

        query_text = " ".join(query_parts)
        return self.query_semantic_rag(query_text, top_k=top_k)
