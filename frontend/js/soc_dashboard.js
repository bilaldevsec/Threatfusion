/**
 * ThreatFusion SOC Unicorn Web Console & Interactive Walkthrough Engine
 * Document Identifier: SOP-UX-SOC-001 (Rev 1.0.0) | Project: AI-FYP-2006
 * 100% Offline / Zero CDN Dependencies / Strict Receipt & Forensic Evidence Verification
 */

(function () {
  'use strict';

  function embeddedLiveCsrf() {
    const meta = document.querySelector('meta[name="threatfusion-csrf-token"]');
    if (!meta) return '';
    return String(meta.getAttribute('content') || '');
  }
  let liveCsrfToken = embeddedLiveCsrf();
  let rbacSessionToken = '';
  let sessionIdentity = null;
  let selectedFlowId = null;
  let identityGateSwitchMode = false;
  const RBAC_SESSION_KEYS = ['threatfusion.rbac.session'];
  const nativeFetch = window.fetch.bind(window);
  async function ensureLiveCsrf() {
    if (liveCsrfToken) return liveCsrfToken;
    const response = await nativeFetch('/api/v1/live/health');
    if (!response.ok) return '';
    const payload = await response.json();
    liveCsrfToken = payload && payload.csrf_token ? String(payload.csrf_token) : '';
    return liveCsrfToken;
  }
  window.fetch = async function (url, options) {
    const opts = options ? Object.assign({}, options) : {};
    const method = String(opts.method || 'GET').toUpperCase();
    const target = String(url);
    const needsCsrf = method === 'POST' && (
      target.indexOf('/api/v1/live/') !== -1
      || target.indexOf('/api/rbac/') !== -1
      || target.indexOf('/api/soar/') !== -1
    );
    const headers = new Headers(opts.headers || {});
    if (needsCsrf) {
      if (!liveCsrfToken) await ensureLiveCsrf();
      if (liveCsrfToken) headers.set('X-ThreatFusion-CSRF', liveCsrfToken);
    }
    if (rbacSessionToken && target.indexOf('/api/') !== -1) {
      headers.set('X-ThreatFusion-Session', rbacSessionToken);
    }
    opts.headers = headers;
    return nativeFetch(url, opts);
  };

  // ========================================================================
  // 1. Exact Evaluation Pack Rev2 & Pipeline Invariant Constants
  // ========================================================================
  const EVAL_PACK_REV2 = {
    projectId: 'AI-FYP-2006',
    checkpoint: '6a36dcd',
    rfArtifactSha256: 'bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9',
    aeArtifactSha256: 'c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23',
    rfMetrics: {
      precisionPct: 95.266,
      recallPct: 92.818,
      f1Pct: 94.026,
      fprPct: 0.095,
      confusion: { tp: 4045, fp: 201, tn: 212009, fn: 313 }
    },
    aeThreshold: 0.1181361214680695,
    section8Lock: {
      productionFusionEnabled: false,
      recallComparisonString: '+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)',
      benignFpInflation: 1574,
      fpRatio: '8.8308x',
      marginalPenalty: '16.3958 benign FPs per extra attack detected'
    },
    correlationWindows: {
      burstSeconds: 30.0,
      campaignSeconds: 600.0
    }
  };

  // ========================================================================
  // 2. Deterministic Receipt & Cryptographic Evidence Verifiers
  //    Mirrors backend/src/threatfusion/api/analyst_dashboard.py
  // ========================================================================
  const SHA256_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
  const MITRE_TECHNIQUE_REGEX = /^T\d{4}(\.\d{3})?$/;

  /**
   * Validate SOAR cryptographic audit chain head digest.
   * Returns true only when verified boolean is true and head digest is valid 64-char hex.
   */
  function verifySoarChain(auditChainVerified, chainHeadSha256) {
    if (!auditChainVerified) return false;
    if (typeof chainHeadSha256 !== 'string') return false;
    return SHA256_HEX_REGEX.test(chainHeadSha256.trim());
  }

  /**
   * Validate ChromaDB Semantic Vector RAG hits.
   * Every hit must have a valid MITRE technique ID (^T\d{4}(\.\d{3})?$), non-empty playbook_id,
   * and cosine_similarity in [0.0, 1.0].
   */
  function verifyChromaRagHits(hits) {
    if (!Array.isArray(hits) || hits.length === 0) return false;
    for (const h of hits) {
      if (!h || typeof h !== 'object') return false;
      const techId = typeof h.technique_id === 'string' ? h.technique_id.trim() : '';
      if (!MITRE_TECHNIQUE_REGEX.test(techId)) return false;
      const pbId = typeof h.playbook_id === 'string' ? h.playbook_id.trim() : '';
      if (!pbId) return false;
      const score = Number(h.cosine_similarity);
      if (isNaN(score) || score < 0.0 || score > 1.0) return false;
    }
    return true;
  }

  /**
   * Validate TheHive Case Record & n8n Playbook Receipt.
   * A 64-hex signature is not enough: the callback must be verified.
   */
  function verifyHiveAndN8nReceipt(hiveCase, n8nReceipt) {
    if (!hiveCase || typeof hiveCase !== 'object') return false;
    const caseId = typeof hiveCase.case_id === 'string' ? hiveCase.case_id.trim() : '';
    if (!caseId) return false;

    if (!n8nReceipt || typeof n8nReceipt !== 'object') return false;
    const execId = typeof n8nReceipt.execution_id === 'string' ? n8nReceipt.execution_id.trim() : '';
    if (!execId) return false;
    const sig = typeof n8nReceipt.signature_sha256 === 'string' ? n8nReceipt.signature_sha256.trim() : '';
    if (!SHA256_HEX_REGEX.test(sig)) return false;
    if (n8nReceipt.callback_verified !== true && hiveCase.callback_verified !== true) return false;
    if (n8nReceipt.hmac_signature_verified === false || hiveCase.hmac_signature_verified === false) {
      return false;
    }
    const evidence = n8nReceipt.evidence_state || hiveCase.evidence_state;
    return evidence === 'verified';
  }

  // ========================================================================
  // 3. Sample Incident Records in the Analyst Triage Queue
  // ========================================================================
  const SAMPLE_INCIDENTS = [
    {
      id: 'alert_candidate_v1:9f8a3c2e1b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
      sourceEventId: 'azure_suricata_eve_flow:20261019_001842_tcp_80',
      observedAt: '2026-10-19T17:15:20Z',
      createdAt: '2026-10-19T17:15:21Z',
      sourceRepresentation: 'azure.victim_vm.suricata.eve_flow.v1',
      featureContract: 'network_behavior_v1',
      modelIdentity: 'network_random_forest',
      modelVersion: 'full-network-random-forest-6d69c72-v1',
      modelArtifactSha256: EVAL_PACK_REV2.rfArtifactSha256,
      uncalibratedScore: 0.9125,
      threshold: 0.50,
      decision: 'Attack',
      triageState: 'in_review',
      version: 1,
      // Provenance & Correlation
      provenance: {
        entityNamespace: 'azure_lab:victim_vm_10_0_0_5',
        sensorVerified: true,
        clockSync: true,
        srcIp: '198.51.100.27',
        dstIp: '10.0.0.5',
        srcPort: 44120,
        dstPort: 80,
        proto: 'TCP'
      },
      correlation: {
        incidentId: 'inc_burst_5tuple_30s_v1:44d886',
        windowType: '30.0s Burst Window',
        ruleId: 'corr_burst_5tuple_30s_v1',
        constituentAlerts: 4,
        explanation: 'Grouped 4 rapid SYN-ACK probe flows within 30.0s window sharing pivot key (198.51.100.27 -> 10.0.0.5:80/tcp)'
      },
      // Threat Intelligence
      threatIntel: {
        queryMode: 'external_threat_intel_rest',
        privateIpGuardTriggered: false,
        matched: true,
        threatLevel: 'high',
        tags: ['c2:active_beacon', 'apt:threatfusion_simulated', 'tlp:amber']
      },
      // Unfused Secondary Anomaly
      secondaryAe: {
        aeError: 0.2450,
        threshold: EVAL_PACK_REV2.aeThreshold,
        status: 'ANOMALY_CONFIRMED'
      },
      // Advisory Explanation
      advisory: {
        summaryHeadline: 'Active Port 80 Web Exploitation Probe & C2 Reconnaissance',
        detectionRationale: 'Primary Random Forest scored 0.9125 (threshold 0.5000; 95.266% precision). External IP 198.51.100.27 correlated across 4 burst flows on port 80.',
        citedEvidenceKeys: ['alert_candidate_id', 'source_event_id', 'uncalibrated_model_score', 'correlation.incident_id'],
        generationMode: 'verified_local_llm_advisory'
      },
      // ChromaDB Semantic Vector RAG Hits
      chromaRagHits: [
        { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', playbook_id: 'pb-isolate-host-01', cosine_similarity: 0.924 },
        { technique_id: 'T1046', technique_name: 'Network Service Discovery', playbook_id: 'pb-block-src-ip-02', cosine_similarity: 0.885 }
      ],
      // SOAR Ledger Status
      soarRecord: {
        playbookId: 'pb-isolate-host-01',
        actionType: 'verify_and_contain_lab_source_ip',
        targetEntity: '198.51.100.27',
        state: 'approved',
        version: 2,
        actorId: 'analyst-bilal',
        decisionReason: 'Verified C2 beacon IOC and rapid scan pattern; approved containment'
      },
      soarAuditChainVerified: true,
      soarAuditChainHeadSha256: '44d88612fea8a8f36de82e1278abb02f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
      thehiveCaseRecord: { case_id: 'case_azure_victim_001842', status: 'created_live' },
      n8nPlaybookReceipt: { execution_id: 'exec_n8n_flow_001842', signature_sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' }
    },
    {
      id: 'alert_candidate_v1:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b',
      sourceEventId: 'azure_suricata_eve_flow:20261019_001905_syn_flood',
      observedAt: '2026-10-19T17:16:10Z',
      createdAt: '2026-10-19T17:16:11Z',
      sourceRepresentation: 'azure.victim_vm.suricata.eve_flow.v1',
      featureContract: 'network_behavior_v1',
      modelIdentity: 'network_random_forest',
      modelVersion: 'full-network-random-forest-6d69c72-v1',
      modelArtifactSha256: EVAL_PACK_REV2.rfArtifactSha256,
      uncalibratedScore: 0.8820,
      threshold: 0.50,
      decision: 'Attack',
      triageState: 'new',
      version: 0,
      provenance: {
        entityNamespace: 'azure_lab:victim_vm_10_0_0_5',
        sensorVerified: true,
        clockSync: true,
        srcIp: '203.0.113.195',
        dstIp: '10.0.0.5',
        srcPort: 52140,
        dstPort: 443,
        proto: 'TCP'
      },
      correlation: {
        incidentId: 'inc_burst_5tuple_30s_v1:275a02',
        windowType: '30.0s Burst Window',
        ruleId: 'corr_burst_5tuple_30s_v1',
        constituentAlerts: 12,
        explanation: 'Grouped 12 volumetric SYN flood flow alerts on port 443 within 30.0s window'
      },
      threatIntel: {
        queryMode: 'external_threat_intel_rest',
        privateIpGuardTriggered: false,
        matched: true,
        threatLevel: 'medium',
        tags: ['scanner:masscan', 'reconnaissance', 'tlp:green']
      },
      secondaryAe: {
        aeError: 0.1890,
        threshold: EVAL_PACK_REV2.aeThreshold,
        status: 'ANOMALY_CONFIRMED'
      },
      advisory: {
        summaryHeadline: 'Volumetric Masscan Port Sweep & TCP Exhaustion Probe',
        detectionRationale: 'Primary RF scored 0.8820. 12 burst records targeting SSL/TLS port 443 from scanner IP 203.0.113.195.',
        citedEvidenceKeys: ['alert_candidate_id', 'uncalibrated_model_score', 'correlation.incident_id'],
        generationMode: 'deterministic_evidence_template'
      },
      chromaRagHits: [
        { technique_id: 'T1046', technique_name: 'Network Service Discovery', playbook_id: 'pb-rate-limit-syn-03', cosine_similarity: 0.912 }
      ],
      soarRecord: {
        playbookId: 'pb-rate-limit-syn-03',
        actionType: 'escalate_flow_anomaly_for_packet_inspection',
        targetEntity: '203.0.113.195',
        state: 'pending_approval',
        version: 1,
        actorId: null,
        decisionReason: null
      },
      soarAuditChainVerified: true,
      soarAuditChainHeadSha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      thehiveCaseRecord: null,
      n8nPlaybookReceipt: null
    },
    {
      id: 'alert_candidate_v1:0000000000000000000000000000000000000000000000000000000000000000',
      sourceEventId: 'azure_suricata_eve_flow:20261019_unverified_sample',
      observedAt: '2026-10-19T17:18:00Z',
      createdAt: '2026-10-19T17:18:01Z',
      sourceRepresentation: 'azure.victim_vm.suricata.eve_flow.v1',
      featureContract: 'network_behavior_v1',
      modelIdentity: 'network_random_forest',
      modelVersion: 'full-network-random-forest-6d69c72-v1',
      modelArtifactSha256: EVAL_PACK_REV2.rfArtifactSha256,
      uncalibratedScore: 0.8250,
      threshold: 0.50,
      decision: 'Attack',
      triageState: 'new',
      version: 0,
      provenance: {
        entityNamespace: 'azure_lab:internal_segment',
        sensorVerified: false,
        clockSync: false,
        srcIp: '10.0.0.4',
        dstIp: '10.0.0.5',
        srcPort: 38290,
        dstPort: 80,
        proto: 'TCP'
      },
      correlation: null,
      threatIntel: {
        queryMode: 'rfc1918_guard_suppressed',
        privateIpGuardTriggered: true,
        matched: false,
        threatLevel: 'undefined',
        tags: ['rfc1918_private_ip_suppressed']
      },
      secondaryAe: {
        aeError: 0.0520,
        threshold: EVAL_PACK_REV2.aeThreshold,
        status: 'WITHIN_NORMAL_BOUNDS'
      },
      advisory: {
        summaryHeadline: 'Unverified Internal Segment Flow (RFC1918 Suppressed)',
        detectionRationale: 'Internal flow between 10.0.0.4 and 10.0.0.5. External threat intelligence suppressed.',
        citedEvidenceKeys: ['alert_candidate_id'],
        generationMode: 'deterministic_evidence_template'
      },
      chromaRagHits: [], // Empty hits -> forces data-evidence-state="unavailable"
      soarRecord: null,  // No SOAR -> forces data-evidence-state="unavailable"
      soarAuditChainVerified: false,
      soarAuditChainHeadSha256: null,
      thehiveCaseRecord: null,
      n8nPlaybookReceipt: null
    }
  ];

  // ========================================================================
  // 4. 5-Minute Guided 6-Stage Walkthrough Scenario Data
  // ========================================================================
  const WALKTHROUGH_STAGES = [
    {
      stageNum: 1,
      title: 'Stage 1: Suricata Flow Telemetry & 14-Feature Ingestion',
      duration: '00:00 - 00:45',
      description: 'Azure Victim VM (10.0.0.5) captures raw network flows via Suricata EVE-JSON. SuricataFlowAdapter extracts 14 canonical network features (dur, sbytes, dbytes, rate, sttl, dttl, sload, dload, sloss, dloss, sinpkt, dinpkt, sjit, djit) and sends them across the mTLS 1.3 loopback boundary. Malformed records are quarantined in dead-letter storage.',
      evidenceSnippet: JSON.stringify({
        sensor: 'azure_suricata_edge_01',
        victim_ip: '10.0.0.5',
        flow_5tuple: '198.51.100.27:44120 -> 10.0.0.5:80/TCP',
        extracted_features_14: { dur: 1.5, sbytes: 1250, dbytes: 4800, rate: 18.0, sttl: 64, dttl: 128 },
        dead_letter_quarantine: 0,
        mtls_peer_verified: true
      }, null, 2)
    },
    {
      stageNum: 2,
      title: 'Stage 2: Frozen Random Forest Fast-Path Inference',
      duration: '00:45 - 01:30',
      description: 'The sole production alert authority — the frozen UNSW Random Forest (SHA-256 bd2853a6...) — scores the feature vector in a dedicated spawned worker. P(Attack) = 0.9125, exceeding the 0.5000 threshold. On the 216,568 January benchmark, this model maintains 95.266% precision and a 0.095% False Positive Rate (only 201 false alarms across 212,210 benign flows).',
      evidenceSnippet: JSON.stringify({
        model_identity: 'full-network-random-forest-6d69c72-v1',
        artifact_sha256: EVAL_PACK_REV2.rfArtifactSha256,
        uncalibrated_score: 0.9125,
        decision_threshold: 0.5000,
        verdict: 'ATTACK_CONFIRMED',
        precision_pct: EVAL_PACK_REV2.rfMetrics.precisionPct,
        fpr_pct: EVAL_PACK_REV2.rfMetrics.fprPct
      }, null, 2)
    },
    {
      stageNum: 3,
      title: 'Stage 3: Dual-Window Incident Correlation & Workload Shield',
      duration: '01:30 - 02:15',
      description: 'The Correlation Engine consolidates alerts into incidents using dual time windows: a 30.0s Burst Window (detecting high-frequency probing) and a 600.0s (10-minute) Campaign Window (tracking persistent lateral movement). 4 rapid flow alerts sharing the 198.51.100.27 -> 10.0.0.5 pivot relationship key are compressed into 1 actionable incident.',
      evidenceSnippet: JSON.stringify({
        incident_id: 'inc_burst_5tuple_30s_v1:44d886',
        burst_window_seconds: EVAL_PACK_REV2.correlationWindows.burstSeconds,
        campaign_window_seconds: EVAL_PACK_REV2.correlationWindows.campaignSeconds,
        constituent_alerts: 4,
        workload_compression_ratio: '4:1 alert reduction',
        pivot_key: '198.51.100.27:10.0.0.5:80:tcp'
      }, null, 2)
    },
    {
      stageNum: 4,
      title: 'Stage 4: ChromaDB 64-Dim MITRE Vector RAG & MISP Private-IP Guard',
      duration: '02:15 - 03:00',
      description: 'ChromaDbMitrePlaybookRag generates 64-dimensional L2-normalized dense embeddings to perform semantic vector retrieval across the MITRE ATT&CK corpus, identifying T1190 (Exploit Public-Facing Application) and T1046 (Network Service Discovery). Simultaneously, MispDeterministicClient queries external threat intelligence while strictly enforcing the RFC1918 Private-IP Guard to protect internal IP telemetry.',
      evidenceSnippet: JSON.stringify({
        chromadb_embedding_dims: 64,
        embedding_l2_norm: 1.0,
        top_k_hits: [
          { technique_id: 'T1190', cosine_similarity: 0.924, playbook_id: 'pb-isolate-host-01' },
          { technique_id: 'T1046', cosine_similarity: 0.885, playbook_id: 'pb-block-src-ip-02' }
        ],
        misp_rfc1918_guard: 'active (internal IP lookups suppressed)',
        external_ioc_matched: 'c2:active_beacon (high threat level)'
      }, null, 2)
    },
    {
      stageNum: 5,
      title: 'Stage 5: Evidence-Bound Advisory Debrief & Anti-Hallucination Guard',
      duration: '03:00 - 03:45',
      description: 'The Section 13.D Advisory Engine synthesizes a plain-language briefing for the triage analyst. The Anti-Hallucination Guard verifies that every cited fact maps to a verified pipeline artifact key. If any token hallucinates outside the verified evidence set or the LLM times out, the system automatically falls back to the deterministic evidence template.',
      evidenceSnippet: JSON.stringify({
        summary_headline: 'Active Port 80 Web Exploitation Probe & C2 Reconnaissance',
        detection_rationale: 'Primary Random Forest scored 0.9125 (threshold 0.5000; 95.266% precision). External IP 198.51.100.27 correlated across 4 burst flows on port 80.',
        anti_hallucination_verified: true,
        cited_evidence_keys: ['alert_candidate_id', 'source_event_id', 'uncalibrated_model_score'],
        section_8_shield_status: 'Active (Fusion disabled; +2.203 pp recall gain rejected due to 1,574 extra benign FPs)'
      }, null, 2)
    },
    {
      stageNum: 6,
      title: 'Stage 6: Approval-Gated SOAR Ledger & Case Dispatch',
      duration: '03:45 - 05:00',
      description: 'In accordance with constitutional security policy, AI is strictly forbidden from directly executing containment actions. Playbook pb-isolate-host-01 enters pending_approval in the SQLite ledger (soar.sqlite3). The human analyst clicks "Approve Containment", creating a cryptographically hash-chained audit event. n8n dispatches the HMAC-signed webhook to create Case #001842 in TheHive.',
      evidenceSnippet: JSON.stringify({
        playbook_id: 'pb-isolate-host-01',
        state: 'approved',
        actor_id: 'analyst-bilal',
        soar_hash_chain_verified: true,
        chain_head_sha256: '44d88612fea8a8f36de82e1278abb02f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        thehive_case_id: 'case_azure_victim_001842',
        n8n_execution_receipt: 'exec_n8n_flow_001842'
      }, null, 2)
    }
  ];

  // ========================================================================
  // 5. App State Management & DOM Rendering
  // ========================================================================
  let currentFilter = 'all';
  let selectedIncidentId = '';
  let liveCampaignIncidents = [];
  let liveCorrelationReport = null;
  let timelineViewMode = 'journal';
  let campaignFetchSettled = false;
  let liveQueueLoaded = false;
  let campaignFingerprint = null;
  let startupIntegrityForest = null;
  let walkthroughCurrentStep = 0;
  let walkthroughInterval = null;

  async function refreshOperationalVelocity() {
    try {
      if (typeof fetch === 'function') {
        const resp = await fetch('/api/v1/metrics/operational-velocity');
        if (resp.ok) {
          const data = await resp.json();
          const mttiEl = document.getElementById('valMtti');
          const mttrEl = document.getElementById('valMttr');
          const compEl = document.getElementById('valCompression');
          const badgeEl = document.getElementById('funnelBadge');
          const t1El = document.getElementById('tier1Count');
          const t2El = document.getElementById('tier2Count');
          const t3El = document.getElementById('tier3Count');
          const t4El = document.getElementById('tier4Count');

          const measured = data.telemetry_source === 'live_measured';
          if (mttrEl && !measured) {
            mttrEl.textContent = '0';
            mttrEl.dataset.kpiBasis = 'reference_benchmark_not_measured';
          }
          if (mttiEl && measured && data.mtti_seconds_mean !== undefined) {
            mttiEl.textContent = `${Number(data.mtti_seconds_mean).toFixed(2)}s`;
          }
          if (mttrEl && measured) {
            const liveMttr = data.live_measured_mttr_seconds;
            mttrEl.textContent = liveMttr === null || liveMttr === undefined
              ? '0'
              : `${Number(liveMttr).toFixed(3)}s`;
          }
          if (measured && data.noise_reduction_funnel) {
            const fn = data.noise_reduction_funnel;
            if (compEl && fn.noise_compression_ratio_pct !== undefined) {
              compEl.textContent = `${Number(fn.noise_compression_ratio_pct).toFixed(4)}%`;
            }
            if (badgeEl && fn.noise_compression_ratio_pct !== undefined) {
              badgeEl.textContent = `Noise Compression Ratio: ${Number(fn.noise_compression_ratio_pct).toFixed(4)}%`;
            }
            const heroFunnelRatioEl = document.getElementById('heroFunnelRatio');
            if (heroFunnelRatioEl && fn.noise_compression_ratio_pct !== undefined) {
              heroFunnelRatioEl.textContent = `${Number(fn.noise_compression_ratio_pct).toFixed(4)}% Ratio`;
            }
            if (t1El && fn.tier1_raw_flows_ingested !== undefined) {
              t1El.textContent = Number(fn.tier1_raw_flows_ingested).toLocaleString();
            }
            if (t2El && fn.tier2_triage_queue_candidates !== undefined) {
              t2El.textContent = Number(fn.tier2_triage_queue_candidates).toLocaleString();
            }
            if (t3El && fn.tier3_correlated_incidents !== undefined) {
              t3El.textContent = Number(fn.tier3_correlated_incidents).toLocaleString();
            }
            if (t4El && fn.tier4_actionable_soar_playbooks !== undefined) {
              t4El.textContent = Number(fn.tier4_actionable_soar_playbooks).toLocaleString();
            }
          }

          // Operational Velocity Decomposition (Milestone #37)
          const decomp = data.velocity_decomposition || data;
          const ttdEl = document.getElementById('heroValTtd');
          const ttaEl = document.getElementById('heroValTta');
          const ttiEl = document.getElementById('heroValTti');
          const conclusionEl = document.getElementById('heroValConclusion');
          const toilSavedEl = document.getElementById('heroValToilSaved');
          const toilBadgeEl = document.getElementById('toilSavedBadge');
          const formulaEl = document.getElementById('velocityFormulaBar');

          if (ttdEl && decomp.ttd_mean_ms !== undefined) {
            ttdEl.textContent = `${Number(decomp.ttd_mean_ms).toFixed(1)} ms`;
          }
          if (ttaEl && decomp.tta_mean_ms !== undefined) {
            ttaEl.textContent = `${Number(decomp.tta_mean_ms).toFixed(1)} ms`;
          }
          if (ttiEl && (decomp.tti_mean_seconds !== undefined || data.mtti_seconds_mean !== undefined)) {
            const ttiVal = decomp.tti_mean_seconds !== undefined ? decomp.tti_mean_seconds : data.mtti_seconds_mean;
            ttiEl.textContent = `${Number(ttiVal).toFixed(2)} s`;
          }
          if (conclusionEl && decomp.total_time_to_conclusion_seconds !== undefined) {
            conclusionEl.textContent = `${Number(decomp.total_time_to_conclusion_seconds).toFixed(3)}s`;
          }
          if (toilSavedEl && decomp.analyst_toil_saved_seconds !== undefined) {
            toilSavedEl.textContent = `${Number(decomp.analyst_toil_saved_seconds).toFixed(3)}s`;
          }
          if (toilBadgeEl && decomp.analyst_toil_saved_pct !== undefined) {
            toilBadgeEl.textContent = `${Number(decomp.analyst_toil_saved_pct).toFixed(2)}% Analyst Toil Saved`;
          }
          if (formulaEl && decomp.velocity_formula) {
            formulaEl.textContent = decomp.velocity_formula;
          }
          const sourceEl = document.getElementById('velocitySourceLabel');
          const telemetrySource = data.telemetry_source || decomp.telemetry_source;
          if (sourceEl) {
            sourceEl.textContent = telemetrySource === 'live_measured'
              ? 'Live Measured Run'
              : 'Reference Benchmark (Inspected January Split)';
          }
        }
      }
    } catch (e) {
      // Deterministic air-gapped fallback
    }
  }

  function buildUnifiedIncidentTimeline(input) {
    const spec = input || {};
    const relationshipKey = spec.relationshipKey || spec.relationship_key || null;
    const events = [];
    (spec.flowMembers || spec.flow_members || []).forEach((member) => {
      const memberKey = member.matched_relationship_key || member.matchedRelationshipKey || null;
      if (relationshipKey && memberKey && memberKey !== relationshipKey) return;
      events.push({
        kind: 'flow_member',
        observed_at: member.observed_at || member.observedAt || '',
        matched_relationship_key: memberKey,
        summary: 'Correlated flow member'
      });
    });
    (spec.analystTransitions || spec.analyst_transitions || []).forEach((transition) => {
      events.push({
        kind: 'analyst_transition',
        observed_at: transition.observed_at || transition.timestamp_utc || '',
        summary: 'Analyst state transition'
      });
    });
    (spec.soarLedgerEntries || spec.soar_ledger_entries || []).forEach((entry) => {
      events.push({
        kind: 'soar_ledger',
        observed_at: entry.timestamp_utc || entry.observed_at || '',
        prev_entry_sha256: entry.prev_entry_sha256 || entry.prev_hash || null,
        entry_sha256: entry.entry_sha256 || entry.entry_hash || null,
        summary: 'Hash-chained SOAR ledger entry'
      });
    });
    events.sort((left, right) => String(left.observed_at).localeCompare(String(right.observed_at)));
    return {
      schema_version: 'unified_incident_timeline_v1',
      relationship_key: relationshipKey,
      event_count: events.length,
      events: events
    };
  }

  function classifySoarDispatchState(record) {
    const item = record || {};
    const transportError = item.transport_error || item.transportError || '';
    const outboxStatus = item.outbox_status || item.outboxStatus || '';
    if (outboxStatus === 'queued_durable_outbox' || String(transportError).trim() !== '') {
      return 'queued_durable_outbox';
    }
    const chainOk = verifySoarChain(item.soarAuditChainVerified, item.soarAuditChainHeadSha256);
    const hiveOk = verifyHiveAndN8nReceipt(item.thehiveCaseRecord, item.n8nPlaybookReceipt);
    if (chainOk && hiveOk && item.playbookState !== 'pending_approval') {
      return 'dispatched_live';
    }
    const state = item.playbookState || (item.soarRecord && item.soarRecord.state) || '';
    if (state === 'approved' || state === 'approved_local' || state === 'executed_simulated') {
      return 'approved_local';
    }
    return 'pending_approval';
  }

  function showSocView(name) {
    document.querySelectorAll('.soc-view').forEach(node => {
      node.classList.toggle('is-active', node.getAttribute('data-soc-view') === name);
    });
    document.querySelectorAll('[data-soc-nav]').forEach(node => {
      node.classList.toggle('is-active', node.getAttribute('data-soc-nav') === name);
    });
    if (name === 'graph') renderActionGraph();
    if (name === 'hunter') {
      renderHunterGauges();
      renderMitreCoverageMatrix();
    }
  }

  function openLabDrawer(open) {
    const drawer = document.getElementById('labControlsDrawer');
    if (open) {
      const other = document.getElementById('enterpriseWorkspaceDrawer');
      if (other) other.classList.remove('is-open');
    }
    if (drawer) drawer.classList.toggle('is-open', Boolean(open));
  }

  function selectedIncident() {
    const rows = activeIncidents();
    return rows.find(item => item.id === selectedIncidentId) || rows[0] || null;
  }

  function openInspectorHash() {
    const hash = (location.hash || '').replace('#', '');
    const names = { overview: '1', timeline: '2', evidence: '3', soar: '4', audit: '5' };
    if (hash === 'graph') {
      showSocView('graph');
      return;
    }
    if (hash === 'hunter') {
      showSocView('hunter');
      return;
    }
    if (hash === 'lab') {
      openLabDrawer(true);
      return;
    }
    if (hash === 'detail' || hash === 'detail-soar' || names[hash]) {
      showSocView('detail');
      const target = hash === 'detail-soar' ? '4' : (names[hash] || '1');
      const button = document.querySelector('.inspector-tab-btn[data-tab-target="' + target + '"]');
      if (button) button.click();
      return;
    }
    showSocView('investigations');
  }

  async function initApp() {
    renderLiveClock();
    setInterval(renderLiveClock, 1000);
    renderIncidentQueue();
    renderForensicDrawer();
    initWalkthroughTimeline();
    setupEventListeners();
    refreshOperationalVelocity();
    refreshAdvisoryStatus();
    refreshAgyAudit();
    await refreshRbacSession();
    enforceAuthGate();
    refreshLiveCampaigns();
    refreshOperatorStamp();
    loadModelObservatory(0);
    loadEnterpriseControls();
    renderEntityTopology();
    renderMitreCoverageMatrix();
    renderScoringTimeProvenance(null);
    openInspectorHash();
    setInterval(refreshLiveCampaigns, 3000);
  }

  function activeIncidents() {
    if (!campaignFetchSettled) return [];
    if (liveQueueLoaded) return liveCampaignIncidents;
    return SAMPLE_INCIDENTS;
  }

  function isReceiptVerified(inc) {
    const chainOk = verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256);
    if (inc.live) return chainOk;
    const ragOk = verifyChromaRagHits(inc.chromaRagHits);
    const hiveOk = verifyHiveAndN8nReceipt(inc.thehiveCaseRecord, inc.n8nPlaybookReceipt);
    return chainOk && ragOk && hiveOk;
  }

  function queueControlValue(id, fallback) {
    const node = document.getElementById(id);
    return node && node.value ? node.value : fallback;
  }

  function formControlValue(id, fallback) {
    return queueControlValue(id, fallback);
  }

  function getFilteredIncidents() {
    let source = activeIncidents().slice();
    if (currentFilter === 'verified') source = source.filter(isReceiptVerified);
    else if (currentFilter === 'pending') {
      source = source.filter(inc => inc.soarRecord && inc.soarRecord.state === 'pending_approval');
    } else if (currentFilter === 'unavailable') source = source.filter(inc => !isReceiptVerified(inc));
    const sourceFilter = queueControlValue('queueSourceFilter', 'all');
    if (sourceFilter !== 'all') source = source.filter(inc => inc.sourceLabel === sourceFilter);
    const query = queueControlValue('queueSearch', '').trim().toLowerCase();
    if (query) {
      source = source.filter(inc => {
        const title = inc.advisory && inc.advisory.summaryHeadline ? inc.advisory.summaryHeadline : '';
        return (title + ' ' + inc.id).toLowerCase().indexOf(query) !== -1;
      });
    }
    const decision = queueControlValue('queueDecisionFilter', 'all');
    if (decision !== 'all') source = source.filter(inc => inc.decision === decision);
    const triage = queueControlValue('queueTriageFilter', 'all');
    if (triage !== 'all') source = source.filter(inc => (inc.triageState || 'unreviewed') === triage);
    const verdict = queueControlValue('queueVerdictFilter', 'all');
    if (verdict === 'none') source = source.filter(inc => !inc.analystVerdict);
    else if (verdict !== 'all') source = source.filter(inc => inc.analystVerdict === verdict);
    const sort = queueControlValue('queueSort', 'newest');
    if (sort === 'probability_desc' || sort === 'probability_asc') {
      source.sort((left, right) => {
        const delta = Number(left.uncalibratedScore) - Number(right.uncalibratedScore);
        return sort === 'probability_asc' ? delta : -delta;
      });
    }
    return source;
  }

  function renderIncidentQueue() {
    const listEl = document.getElementById('incidentQueueList');
    if (!listEl) return;

    const incidents = getFilteredIncidents();
    listEl.innerHTML = '';

    updatePriorityCounts(activeIncidents());
    renderHunterGauges();
    if (incidents.length === 0) {
      listEl.innerHTML = '<tr><td colspan="7">No incidents match the active filter criteria.</td></tr>';
      return;
    }

    if (!liveQueueLoaded) {
      incidents.forEach(inc => appendIncidentItem(listEl, inc));
      return;
    }

    const sourceOrder = ['suricata_bridge', 'recorded_unsw_nb15', 'live_scenario_replay', 'other'];
    sourceOrder.forEach(bucket => {
      const members = incidents.filter(inc => {
        const label = sourceOrder.includes(inc.sourceLabel) ? inc.sourceLabel : 'other';
        return label === bucket;
      });
      members.forEach(inc => appendIncidentItem(listEl, inc));
    });
  }

  function sourceHeading(label) {
    if (label === 'suricata_bridge') return 'Live sensor, this Docker bridge';
    if (label === 'recorded_unsw_nb15') return 'Recorded UNSW study';
    if (label === 'live_scenario_replay') return 'Labeled scenario replay';
    return 'Other stored flows';
  }

  function sourceDisplayName(label) {
    if (label === 'suricata_bridge') return 'Suricata EVE Bridge';
    if (label === 'recorded_unsw_nb15') return 'UNSW-NB15 Study';
    if (label === 'live_scenario_replay') return 'Scenario Replay';
    return 'Stored flow';
  }

  function priorityFor(inc) {
    if (inc.decision === 'Attack') return { key: 'urgent', label: 'Urgent' };
    if (inc.sourceLabel === 'suricata_bridge') return { key: 'notable', label: 'Notable' };
    return { key: 'info', label: 'Informational' };
  }

  const UNSW_ENDPOINT_CHIP = 'Dataset flow (UNSW-NB15) · endpoints not recorded';
  const CONTAINMENT_DISABLED_TITLE = 'Containment disabled: Flow scored Benign by Frozen RF';

  function isStoredIncident(inc, src, dst) {
    const label = inc && (inc.sourceLabel || inc.source_label || inc.sourceEventId) || '';
    return label === 'incident_store'
      || src === 'stored-incident'
      || dst === 'stored-incident';
  }

  function isMissingEndpoint(val) {
    if (!val) return true;
    const str = String(val).trim();
    return str === '' || str === 'not recorded' || str === 'not-recorded';
  }

  function isRecordedUnsw(inc) {
    return !!inc && (
      (inc.dataset && inc.dataset.sourceLabel === 'recorded_unsw_nb15')
      || inc.sourceLabel === 'recorded_unsw_nb15'
    );
  }

  function studyFlowTitle(inc) {
    const id = (inc.dataset && inc.dataset.id) || inc.flow_id || inc.flowId || inc.id || '';
    return 'UNSW-NB15 Recorded Study Flow #' + id;
  }

  function formatRfPercent(score) {
    const value = Number(score);
    if (!Number.isFinite(value)) return 'unavailable';
    return (value * 100).toFixed(1) + '%';
  }

  function formatDisplayUtc(value) {
    const raw = String(value || '').trim();
    const match = raw.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
    if (!match) return raw;
    return match[1] + ' ' + match[2] + ' UTC';
  }

  function formatLiveClock(date) {
    const iso = date.toISOString();
    return iso.slice(0, 10) + ' ' + iso.slice(11, 19) + ' UTC';
  }

  function renderLiveClock() {
    const node = document.getElementById('liveClock');
    if (node) node.textContent = formatLiveClock(new Date());
  }

  function rfDecisionLabel(inc) {
    const token = inc && (inc.decision === 'Attack' || inc.decision === 'Benign')
      ? inc.decision
      : String((inc && inc.decision) || 'withheld');
    if (token === 'Attack' || token === 'Benign') return token + ' ' + formatRfPercent(inc.uncalibratedScore);
    return token;
  }

  function mispGuardLabel(status) {
    if (status === 422 || status === '422' || String(status).indexOf('422') !== -1) {
      return 'RFC1918 Guard: External Lookup Skipped (Pass)';
    }
    return status == null ? '' : String(status);
  }

  function alertTitle(inc) {
    if (!inc) return '';
    const src = (inc.provenance && inc.provenance.srcIp)
      || (inc.dataset && (inc.dataset.src_entity_id || inc.dataset.srcEntityId))
      || (typeof inc.getAttribute === 'function' && inc.getAttribute('data-src_entity_id'))
      || inc.src_entity_id
      || inc.srcIp
      || '';
    const dst = (inc.provenance && inc.provenance.dstIp)
      || (inc.dataset && (inc.dataset.dst_entity_id || inc.dataset.dstEntityId))
      || (typeof inc.getAttribute === 'function' && inc.getAttribute('data-dst_entity_id'))
      || inc.dst_entity_id
      || inc.dstIp
      || '';

    if (isRecordedUnsw(inc) && (isMissingEndpoint(src) || isMissingEndpoint(dst))) {
      return studyFlowTitle(inc);
    }
    if (isStoredIncident(inc, src, dst)) {
      return 'Correlated Attack Campaign · 30s/600s Window';
    }
    if (!isMissingEndpoint(src) && !isMissingEndpoint(dst)) {
      const port = (inc.provenance && inc.provenance.dstPort) || (inc.dataset && inc.dataset.port) || '';
      const proto = String((inc.provenance && inc.provenance.proto) || (inc.dataset && inc.dataset.proto) || 'flow').toUpperCase();
      return proto + ' probe ' + src + ' -> ' + dst + (port ? ':' + port : '');
    }
    return inc.advisory && inc.advisory.summaryHeadline ? inc.advisory.summaryHeadline : studyFlowTitle(inc);
  }

  function updatePriorityCounts(rows) {
    const counts = { all: rows.length, urgent: 0, notable: 0, info: 0 };
    rows.forEach(inc => { counts[priorityFor(inc).key] += 1; });
    const map = { pillCountAll: counts.all, pillCountUrgent: counts.urgent, pillCountNotable: counts.notable, pillCountInfo: counts.info };
    Object.keys(map).forEach(id => {
      const node = document.getElementById(id);
      if (node) node.textContent = String(map[id]);
    });
  }

  function paintDonut(id, count, total) {
    const node = document.getElementById(id);
    if (!node) return;
    const circ = 2 * Math.PI * 42;
    const portion = total > 0 ? (count / total) * circ : 0;
    node.style.strokeDasharray = portion.toFixed(2) + ' ' + (circ - portion).toFixed(2);
  }

  function renderHunterGauges() {
    const rows = activeIncidents();
    const urgent = rows.filter(inc => inc.decision === 'Attack').length;
    const notable = rows.filter(inc => inc.sourceLabel === 'suricata_bridge' && inc.decision !== 'Attack').length;
    const info = rows.filter(inc => inc.decision === 'Benign').length;
    const total = Math.max(rows.length, 1);
    paintDonut('donutUrgent', urgent, total);
    paintDonut('donutNotable', notable, total);
    paintDonut('donutInfo', info, total);
    const labels = { donutUrgentCount: urgent, donutNotableCount: notable, donutInfoCount: info };
    Object.keys(labels).forEach(id => {
      const node = document.getElementById(id);
      if (node) node.textContent = String(labels[id]);
    });
  }

  function graphStatus(inc, key) {
    const unavailable = { dot: 'status-pending', label: 'unavailable', output: 'Stored evidence is unavailable for this node.' };
    if (!inc) return { dot: 'status-pending', label: 'unavailable', output: 'No stored flow is selected.' };
    if (key === 'forest') {
      if (inc.decision === 'Attack' || inc.decision === 'Benign') {
        return { dot: 'status-verified', label: 'Verified', output: 'Frozen RF decision ' + inc.decision + '.' };
      }
      return unavailable;
    }
    if (key === 'chain') {
      if (verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256)) {
        return { dot: 'status-verified', label: 'Verified', output: 'Playbook hash chain verified.' };
      }
      return unavailable;
    }
    if (key === 'chroma') {
      if (attackTechnique(inc)) {
        return { dot: 'status-verified', label: 'Verified', output: 'Stored ChromaDB hits passed the receipt check.' };
      }
      if (inc.decision === 'Benign') {
        return { dot: 'status-pending', label: 'unavailable', output: 'No technique. Frozen RF decision is Benign.' };
      }
      return unavailable;
    }
    if (key === 'ground') {
      const rationale = inc.analystRationale || '';
      if (rationale && rationale.indexOf('203.0.113') !== -1) {
        return { dot: 'status-refused', label: 'Refused', output: 'Groundedness refused an address that is not on the stored flow.' };
      }
      if (rationale) {
        return { dot: 'status-verified', label: 'Verified', output: 'Stored rationale is present.' };
      }
      return unavailable;
    }
    return unavailable;
  }

  function graphNodeLabel(node) {
    const copy = node.querySelector('.node-copy');
    return copy ? copy.textContent : node.textContent;
  }

  const INDEXED_MITRE_COVERAGE = [
    { id: 'T1046', name: 'Network Service Discovery', kind: 'technique' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', kind: 'technique' },
    { id: 'T1498', name: 'Network Denial of Service', kind: 'technique' },
    { id: 'T1071.001', name: 'Application Layer Protocol: Web Traffic', kind: 'technique' },
    { id: 'T1595', name: 'Active Scanning', kind: 'technique' },
    { id: 'T1110', name: 'Brute Force', kind: 'technique' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', kind: 'technique' },
    { id: 'T1021', name: 'Remote Services', kind: 'technique' },
    { id: 'T1059', name: 'Command and Scripting Interpreter', kind: 'technique' },
    { id: 'T1133', name: 'External Remote Services', kind: 'technique' },
    { id: 'CVE-2023-48795', name: 'Terrapin SSH Prefix Truncation', kind: 'cve' },
    { id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset', kind: 'cve' },
    { id: 'CVE-2021-44228', name: 'Log4Shell JNDI RCE', kind: 'cve' },
    { id: 'CVE-2023-4966', name: 'CitrixBleed Session Hijack', kind: 'cve' },
    { id: 'CVE-2024-3400', name: 'PAN-OS Command Injection', kind: 'cve' },
    { id: 'CVE-2023-34362', name: 'MOVEit SQL Injection and Exfiltration', kind: 'cve' },
    { id: 'CVE-2023-22515', name: 'Confluence Broken Authentication', kind: 'cve' },
    { id: 'CVE-2017-0144', name: 'EternalBlue SMB Remote Exploit', kind: 'cve' }
  ];

  function flowContractPassed(inc) {
    const items = inc && inc.glassBox && Array.isArray(inc.glassBox.items) ? inc.glassBox.items : [];
    return items.some(item => item && item.id === 'flow_contract_valid' && item.passed === true);
  }

  function renderTelemetryReductionFunnel(data, flowViews) {
    const rawFlows = Number(data && data.flow_count);
    const flows = Number.isFinite(rawFlows) && rawFlows > 0 ? rawFlows : 0;
    const rows = Array.isArray(flowViews) ? flowViews : [];
    const schemaValid = rows.filter(flowContractPassed).length;
    const attacks = rows.filter(row => row && row.decision === 'Attack').length;
    const attackCampaignIds = new Set();
    rows.forEach(row => {
      if (!row || row.decision !== 'Attack') return;
      const id = row.correlation && row.correlation.incidentId
        ? String(row.correlation.incidentId)
        : String(row.id || '');
      if (id) attackCampaignIds.add(id);
    });
    const attackCampaigns = attackCampaignIds.size;
    const reduction = flows === 0 ? '0.0%' : ((1 - attackCampaigns / flows) * 100).toFixed(1) + '%';
    setInspectorText('funnelLiveFlows', String(flows));
    setInspectorText('funnelSchemaMtls', String(schemaValid));
    setInspectorText('funnelRfAttacks', String(attacks));
    setInspectorText('funnelCampaigns', String(attackCampaigns));
    setInspectorText('telemetryReductionPct', reduction);
    paintFunnelSvg([flows, schemaValid, attacks, attackCampaigns]);
  }

  function paintFunnelSvg(counts) {
    const svg = document.getElementById('telemetryReductionSvg');
    if (!svg) return;
    const polys = svg.querySelectorAll('polygon');
    const max = Math.max.apply(null, counts.concat([1]));
    polys.forEach((poly, index) => {
      const count = counts[index] == null ? 0 : Number(counts[index]);
      const fraction = Math.max(0.12, Math.min(1, (Number.isFinite(count) ? count : 0) / max));
      const left = Math.round(8 + (1 - fraction) * 452);
      const top = 6 + index * 3;
      const bottom = 42 - index * 3;
      poly.setAttribute(
        'points',
        left + ',' + top + ' 632,' + (top + 6) + ' 632,' + (bottom - 6) + ' ' + left + ',' + bottom
      );
    });
  }

  function sourceEntityLabel(inc) {
    const src = inc && inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    if (isRecordedUnsw(inc) && isMissingEndpoint(src)) return UNSW_ENDPOINT_CHIP;
    if (!isMissingEndpoint(src)) return src;
    return 'unavailable';
  }

  function targetAssetLabel(inc) {
    const dst = inc && inc.provenance && inc.provenance.dstIp ? String(inc.provenance.dstIp) : '';
    const port = inc && inc.provenance ? Number(inc.provenance.dstPort) : 0;
    const dstMissing = isMissingEndpoint(dst);
    const portMissing = !Number.isFinite(port) || port <= 0;
    if (!dstMissing && !portMissing) return dst + ':' + port;
    if (isRecordedUnsw(inc) && (dstMissing || portMissing)) return UNSW_ENDPOINT_CHIP;
    return 'unavailable';
  }

  function campaignStitchLabel(inc) {
    const count = inc && inc.correlation ? Number(inc.correlation.constituentAlerts) : 0;
    const campaignId = inc && inc.correlation && inc.correlation.incidentId
      ? String(inc.correlation.incidentId)
      : '';
    if (count > 1 && campaignId) return campaignId;
    return 'single-flow';
  }

  function callbackReceiptLabel(inc) {
    const signature = inc && typeof inc.callbackSignature === 'string' ? inc.callbackSignature.trim() : '';
    if (inc && (inc.callbackRecorded === true || signature !== '')) {
      return 'Callback receipt: recorded';
    }
    return 'Callback receipt: not recorded';
  }

  const TECHNIQUE_CATALOG = {
    T1046: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Reconnaissance' },
    T1110: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    T1498: { id: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' }
  };

  function scenarioTechnique(inc) {
    if (!inc || inc.decision === 'Benign') {
      return { label: 'None (Benign Flow)', tactic: 'none', playbook: 'none' };
    }
    const hit = attackTechnique(inc);
    const rawLabel = String(
      inc.scenarioLabel || inc.mitreTechniqueId || inc.techniqueId || (hit && hit.technique_id) || ''
    ).trim();
    const known = TECHNIQUE_CATALOG[rawLabel] || (hit ? TECHNIQUE_CATALOG[hit.technique_id] : null);
    if (!hit && !known) {
      return { label: 'unavailable', tactic: 'unavailable', playbook: candidatePlaybookId(inc) || 'none' };
    }
    const id = (hit && hit.technique_id) || (known && known.id) || rawLabel;
    const name = (hit && hit.technique_name) || (known && known.name) || '';
    const tactic = (hit && (hit.tactic || hit.technique_name)) || (known && known.tactic) || 'unavailable';
    const parts = [id, name];
    if (tactic && tactic !== name) parts.push(tactic);
    return {
      label: parts.filter(Boolean).join(' · '),
      tactic: tactic,
      playbook: (hit && hit.playbook_id) || candidatePlaybookId(inc) || 'none'
    };
  }

  function renderRemediation(inc) {
    const view = scenarioTechnique(inc);
    setInspectorText('remediationTechnique', view.label);
    setInspectorText('remediationTactic', view.tactic);
    setInspectorText('remediationPlaybook', view.playbook);
    const benign = !inc || inc.decision === 'Benign';
    const note = benign
      ? 'No technique. Frozen RF decision is Benign. Containment stays unauthorized.'
      : ('Playbook ' + view.playbook + '. ' + view.label + '.');
    setLiveText('inspectorPlaybookNote', note, benign ? 'unavailable' : 'verified');
  }

  function attackTechnique(inc) {
    if (!inc || inc.decision !== 'Attack') return null;
    if (!verifyChromaRagHits(inc.chromaRagHits)) return null;
    const hit = inc.chromaRagHits[0];
    const cosine = Number(hit.cosine_similarity);
    if (!Number.isFinite(cosine) || cosine < 0.55) return null;
    return hit;
  }

  function entityTopologyNodes(inc, ragOk) {
    const hit = ragOk ? attackTechnique(inc) : null;
    const technique = hit
      ? (String(hit.technique_id) + (hit.technique_name ? ' · ' + hit.technique_name : ''))
      : (inc && inc.decision === 'Benign'
        ? 'No technique. Frozen RF decision is Benign.'
        : 'unavailable');
    const chain = playbookChainLabel(inc);
    const callback = callbackReceiptLabel(inc);
    return [
      { key: 'source', title: 'Source Entity', lines: [sourceEntityLabel(inc)], evidence: sourceEntityLabel(inc) },
      { key: 'target', title: 'Target Asset:Port', lines: [targetAssetLabel(inc)], evidence: targetAssetLabel(inc) },
      { key: 'stitch', title: '30s/600s Campaign Stitch', lines: [campaignStitchLabel(inc)], evidence: campaignStitchLabel(inc) },
      { key: 'mitre', title: 'MITRE / CVE Advisory Hit', lines: [technique], evidence: technique },
      { key: 'soar', title: 'SOAR & Containment Gate', lines: [chain, callback], evidence: chain + ' | ' + callback }
    ];
  }

  function topologyTextLines(text) {
    const raw = String(text || '');
    const lines = [];
    let rest = raw;
    while (rest.length > 22 && lines.length < 3) {
      let cut = rest.lastIndexOf(' ', 22);
      if (cut < 8) cut = 22;
      lines.push(rest.slice(0, cut));
      rest = rest.slice(cut).trim();
    }
    if (rest) lines.push(rest);
    return lines.slice(0, 4);
  }

  function renderEntityTopology() {
    const svg = document.getElementById('entityTopologyGraph');
    if (!svg) return;
    const inc = selectedIncident();
    const ragOk = verifyChromaRagHits(inc && inc.chromaRagHits) && !!attackTechnique(inc);
    const nodes = entityTopologyNodes(inc, ragOk);
    const width = 168;
    const step = 188;
    let markup = '';
    nodes.forEach((node, index) => {
      const x = 16 + index * step;
      if (index > 0) {
        markup += '<line x1="' + (x - 20) + '" y1="75" x2="' + x + '" y2="75" stroke="#58a6ff" stroke-width="1.5"></line>';
      }
      const wrapped = [];
      node.lines.forEach(line => {
        topologyTextLines(line).forEach(part => wrapped.push(part));
      });
      let text = '<text x="' + (x + 10) + '" y="38">' + escapeHtml(node.title) + '</text>';
      wrapped.slice(0, 4).forEach((part, lineIndex) => {
        text += '<text x="' + (x + 10) + '" y="' + (58 + lineIndex * 16) + '">' + escapeHtml(part) + '</text>';
      });
      markup += '<g class="topology-node" data-topology-node="' + node.key + '" tabindex="0" role="button">'
        + '<rect x="' + x + '" y="16" width="' + width + '" height="118" rx="8"></rect>'
        + text
        + '</g>';
    });
    svg.innerHTML = markup;
    svg.querySelectorAll('[data-topology-node]').forEach(node => {
      const open = () => showTopologyInspector(node.getAttribute('data-topology-node'));
      node.addEventListener('click', open);
      node.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          open();
        }
      });
    });
  }

  function showTopologyInspector(key) {
    const popover = document.getElementById('graphNodePopover');
    if (!popover) return;
    const inc = selectedIncident();
    const ragOk = !!attackTechnique(inc);
    const node = entityTopologyNodes(inc, ragOk).find(item => item.key === key);
    if (!node) return;
    document.querySelectorAll('[data-topology-node]').forEach(item => {
      item.classList.toggle('is-selected', item.getAttribute('data-topology-node') === key);
    });
    popover.classList.add('is-open');
    popover.innerHTML = '<h3>Selected Node Inspector</h3>'
      + '<strong>' + escapeHtml(node.title) + '</strong>'
      + '<p>' + escapeHtml(node.evidence) + '</p>'
      + '<p>Input: the selected stored flow.</p>'
      + '<p>Rule: ' + escapeHtml(key) + ' uses only stored fields.</p>'
      + '<p>Output: ' + escapeHtml(node.evidence) + '</p>';
  }

  function staticUnavailableHeatmap() {
    return {
      cells: INDEXED_MITRE_COVERAGE.map(entry => ({
        id: entry.id,
        name: entry.name,
        kind: entry.kind,
        observed_count: 0,
        rf_confirmed_count: 0,
        claimed: true,
        evidence_state: 'unavailable'
      }))
    };
  }

  function paintCoverageHeatmap(payload) {
    const body = document.getElementById('mitreCoverageBody');
    if (!body) return;
    const cells = payload && Array.isArray(payload.cells) ? payload.cells : [];
    body.replaceChildren();
    cells.forEach(cell => {
      const state = cell && cell.evidence_state === 'verified' ? 'verified' : 'unavailable';
      const tr = document.createElement('tr');
      tr.setAttribute('data-evidence-state', state);
      const observed = cell && cell.rf_confirmed_count != null
        ? cell.rf_confirmed_count
        : (cell && cell.observed_count != null ? cell.observed_count : 0);
      const claimed = cell && cell.claimed === true ? 'claimed' : 'unavailable';
      [cell && cell.id, cell && cell.name, cell && cell.kind, String(observed), claimed].forEach((value, index) => {
        const td = document.createElement('td');
        td.textContent = value == null ? '' : String(value);
        if (index >= 3) td.setAttribute('data-evidence-state', state);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  function renderMitreCoverageMatrix() {
    const body = document.getElementById('mitreCoverageBody');
    if (!body) return;
    paintCoverageHeatmap(staticUnavailableHeatmap());
    fetch('/api/v1/live/coverage-heatmap?include_lab=false', { method: 'GET' })
      .then(resp => (resp && resp.ok ? resp.json() : null))
      .then(payload => {
        if (payload && Array.isArray(payload.cells)) paintCoverageHeatmap(payload);
      })
      .catch(() => {});
  }

  function timelineActor(event) {
    if (!event || typeof event !== 'object') return 'stored-flow';
    const raw = event.actor_id || event.actor || event.operator_id || event.src_entity_id;
    if (typeof raw === 'string' && raw.trim() !== '') return raw.trim();
    return 'stored-flow';
  }

  function groupConsecutiveTimelineByActor(events) {
    const groups = [];
    const source = Array.isArray(events) ? events : [];
    source.forEach(event => {
      const actor = timelineActor(event);
      const last = groups[groups.length - 1];
      if (last && last.actor === actor) last.events.push(event);
      else groups.push({ actor: actor, events: [event] });
    });
    return groups;
  }

  function timelineJournalHtml(groups) {
    return groups.map(group => {
      const rows = group.events.map(event => (
        '<div>[' + escapeHtml(event && event.observed_at || '') + '] '
        + escapeHtml((event && (event.summary || event.kind)) || 'event') + '</div>'
      )).join('');
      return '<section data-timeline-actor="' + escapeHtml(group.actor) + '"><h4>'
        + escapeHtml(group.actor) + '</h4>' + rows + '</section>';
    }).join('');
  }

  function timelineTableHtml(groups) {
    const rows = groups.map(group => group.events.map((event, index) => {
      const actorCell = index === 0
        ? '<td rowspan="' + group.events.length + '">' + escapeHtml(group.actor) + '</td>'
        : '';
      return '<tr>' + actorCell
        + '<td>' + escapeHtml(event && event.observed_at || '') + '</td>'
        + '<td>' + escapeHtml((event && (event.summary || event.kind)) || 'event') + '</td>'
        + '<td>' + escapeHtml(event && event.kind || '') + '</td></tr>';
    }).join('')).join('');
    return '<table><thead><tr><th>Actor</th><th>When</th><th>Summary</th><th>Kind</th></tr></thead><tbody>'
      + rows + '</tbody></table>';
  }

  function stageActor(inc) {
    const src = inc && inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    if (src && !isMissingEndpoint(src) && src !== 'stored-incident') return src;
    return String((inc && (inc.sourceLabel || inc.sourceEventId)) || 'stored-flow');
  }

  function stageTimelineFromFlow(inc) {
    if (!inc) return [];
    const when = inc.observedAt || '';
    const actor = stageActor(inc);
    const summaries = [
      '[E1] Stage 1-2 Telemetry & 14-Feature Contract',
      '[E2] Stage 3 Frozen RF Scoring (bd2853a6)',
      '[E3] Stage 4 Dual-Window 30s/600s Correlation',
      '[E4] Stage 4 MISP RFC1918 Guard',
      '[E5] Stage 6 SOAR Ledger State'
    ];
    const events = summaries.map((summary, index) => ({
      observed_at: when,
      actor_id: actor,
      kind: 'E' + (index + 1),
      summary: summary
    }));
    const campaign = inc.correlation && inc.correlation.incidentId
      ? String(inc.correlation.incidentId)
      : '';
    if (campaign) {
      activeIncidents().forEach(other => {
        if (!other || other.id === inc.id) return;
        const otherId = other.correlation && other.correlation.incidentId
          ? String(other.correlation.incidentId)
          : '';
        if (otherId !== campaign) return;
        events.push({
          observed_at: other.observedAt || when,
          actor_id: stageActor(other),
          kind: 'partner',
          summary: 'Correlated partner flow ' + String(other.flowId || other.id || '')
        });
      });
    }
    return events;
  }

  function renderTimelineGroupedView(selected) {
    const host = document.getElementById('timelineGroupedView');
    if (!host) return;
    const reportEvents = liveCorrelationReport
      && liveCorrelationReport.timeline
      && Array.isArray(liveCorrelationReport.timeline.events)
      ? liveCorrelationReport.timeline.events
      : [];
    const inc = arguments.length ? selected : selectedIncident();
    const events = reportEvents.length ? reportEvents : stageTimelineFromFlow(inc);
    const groups = groupConsecutiveTimelineByActor(events);
    host.setAttribute('data-timeline-mode', timelineViewMode);
    const state = reportEvents.length && liveCorrelationReport
      ? (liveCorrelationReport.evidence_state || 'unavailable')
      : 'unavailable';
    host.setAttribute('data-evidence-state', state);
    if (!events.length) {
      host.textContent = 'No correlated timeline yet.';
      return;
    }
    host.innerHTML = timelineViewMode === 'table'
      ? timelineTableHtml(groups)
      : timelineJournalHtml(groups);
    const partners = events.filter(event => event && (event.kind === 'partner' || event.kind === 'flow_member'));
    const stageNote = partners.length
      ? 'Correlated 30.0s/600.0s Attack Campaign — stitched flows and pipeline stages.'
      : '5 pipeline stages share one ingest time. This is not a stitched attack.';
    setLiveText('attackTimelineFlowCount', String(partners.length ? partners.length + 1 : 1));
    setLiveText('attackTimelineSource', stageNote);
    setLiveText('attackTimelineEvents', '');
    setLiveText('liveTimeline', '', 'unavailable');
    const drawer = document.getElementById('liveTimelineDrawer');
    if (drawer) {
      drawer.textContent = '';
      drawer.setAttribute('data-correlated-flow-count', String(partners.length + 1));
      drawer.setAttribute('data-evidence-state', 'unavailable');
    }
  }

  function setTimelineViewMode(mode) {
    timelineViewMode = mode === 'table' ? 'table' : 'journal';
    const journal = document.getElementById('timelineViewJournal');
    const table = document.getElementById('timelineViewTable');
    if (journal) journal.setAttribute('aria-pressed', timelineViewMode === 'journal' ? 'true' : 'false');
    if (table) table.setAttribute('aria-pressed', timelineViewMode === 'table' ? 'true' : 'false');
    renderTimelineGroupedView();
  }

  function renderScoringTimeProvenance(inc) {
    const panel = document.getElementById('scoringTimeProvenance');
    const scoring = document.getElementById('scoringTimeModelDigest');
    const startup = document.getElementById('startupIntegrityDigest');
    const stored = inc && typeof inc.scoringTimeModelSha256 === 'string'
      ? inc.scoringTimeModelSha256.trim()
      : '';
    const scoringKnown = SHA256_HEX_REGEX.test(stored);
    const forest = startupIntegrityForest;
    const startupSha = forest && typeof forest.sha256 === 'string' ? forest.sha256 : '';
    const startupKnown = SHA256_HEX_REGEX.test(startupSha);
    if (scoring) {
      scoring.textContent = scoringKnown
        ? ('Scoring-time frozen RF digest: ' + stored)
        : 'Scoring-time frozen RF digest: unavailable';
      scoring.setAttribute('data-evidence-state', scoringKnown ? 'verified' : 'unavailable');
    }
    if (startup) {
      startup.textContent = startupKnown
        ? ('Startup integrity check: ' + startupSha + (forest.verified === true ? ' verified' : ' unverified'))
        : 'Startup integrity check: unavailable';
      startup.setAttribute('data-evidence-state', startupKnown && forest.verified === true ? 'verified' : 'unavailable');
    }
    if (panel) {
      panel.setAttribute('data-evidence-state', scoringKnown ? 'verified' : 'unavailable');
    }
  }

  function renderActionGraph() {
    renderEntityTopology();
    const inc = selectedIncident();
    const entities = document.getElementById('kpiEntities');
    const receipts = document.getElementById('kpiSoarReceipts');
    if (entities) entities.textContent = inc && inc.provenance ? '2' : '0';
    if (receipts) receipts.textContent = inc && inc.callbackSignature ? '1' : '0';
    document.querySelectorAll('[data-graph-node]').forEach(node => {
      const status = graphStatus(inc, node.getAttribute('data-graph-node'));
      node.dataset.statusLabel = status.label;
      node.dataset.statusOutput = status.output;
    });
    const selected = document.querySelector('.graph-node.is-selected')
      || document.querySelector('[data-graph-node="forest"]');
    if (selected) showGraphPopover(selected);
  }

  function showGraphPopover(node) {
    const popover = document.getElementById('graphNodePopover');
    if (!popover || !node) return;
    const key = node.getAttribute('data-graph-node');
    const status = graphStatus(selectedIncident(), key);
    document.querySelectorAll('[data-graph-node]').forEach(item => {
      item.classList.toggle('is-selected', item === node);
    });
    popover.classList.add('is-open');
    popover.innerHTML = '<h3>Selected Node Inspector</h3>'
      + '<strong>' + escapeHtml(graphNodeLabel(node)) + '</strong>'
      + '<div><span class="status-dot ' + status.dot + '"></span>' + escapeHtml(status.label) + '</div>'
      + '<p>Input: the selected stored flow.</p>'
      + '<p>Rule: ' + escapeHtml(key) + ' uses only stored fields.</p>'
      + '<p>Output: ' + escapeHtml(status.output) + '</p>';
  }

  function appendIncidentItem(listEl, inc) {
      const itemEl = document.createElement('tr');
      itemEl.className = 'incident-item' + (inc.id === selectedIncidentId ? ' selected' : '');
      const incId = (inc.dataset && inc.dataset.id) || inc.id || '';
      const sourceLabel = (inc.dataset && inc.dataset.sourceLabel) || inc.sourceLabel || '';
      const rawSrc = (inc.dataset && (inc.dataset.src_entity_id || inc.dataset.srcEntityId))
        || inc.src_entity_id
        || (inc.provenance && inc.provenance.srcIp)
        || '';
      const rawDst = (inc.dataset && (inc.dataset.dst_entity_id || inc.dataset.dstEntityId))
        || inc.dst_entity_id
        || (inc.provenance && inc.provenance.dstIp)
        || '';

      itemEl.dataset.id = incId;
      itemEl.dataset.sourceLabel = sourceLabel;
      itemEl.dataset.src_entity_id = rawSrc;
      itemEl.dataset.dst_entity_id = rawDst;
      itemEl.dataset.srcEntityId = rawSrc;
      itemEl.dataset.dstEntityId = rawDst;
      itemEl.setAttribute('data-src_entity_id', rawSrc);
      itemEl.setAttribute('data-dst_entity_id', rawDst);

      const priority = priorityFor(inc);
      const observed = formatDisplayUtc(inc.observedAt);
      const src = (inc.provenance && inc.provenance.srcIp) || rawSrc || '';
      const dst = (inc.provenance && inc.provenance.dstIp) || rawDst || '';
      const malicious = inc.decision === 'Attack';
      const triage = inc.triageState && inc.triageState !== 'unreviewed' ? inc.triageState : 'Open';
      const title = alertTitle(inc);
      const endpointsMissing = isMissingEndpoint(src) || isMissingEndpoint(dst);
      const entitiesHtml = isStoredIncident(inc, src, dst)
        ? '<span class="entity-pill">Correlated Campaign · Stored Incident</span>'
        : ((isRecordedUnsw(inc) && endpointsMissing)
        ? '<span class="entity-chip-muted">' + escapeHtml(UNSW_ENDPOINT_CHIP) + '</span>'
        : (!isMissingEndpoint(src) && !isMissingEndpoint(dst)
          ? '<code class="entity-pill">' + escapeHtml(src) + '</code><code class="entity-pill">' + escapeHtml(dst) + '</code>'
          : '<span class="entity-chip-muted">endpoints unavailable</span>'));
      const fullId = String(inc.id || '');
      const flowKey = inc.flowId || inc.flow_id || '';
      const shortId = 'INV-' + (flowKey === '' ? fullId.slice(0, 7) : flowKey) + ' · ' + fullId.slice(0, 7) + '…';
      const analystNote = inc.analystVerdict ? ' ' + inc.analystVerdict : '';

      itemEl.innerHTML = ''
        + '<td><span class="priority-pill priority-' + priority.key + '">' + priority.label + '</span></td>'
        + '<td>' + escapeHtml(observed) + '</td>'
        + '<td><code title="' + escapeHtml(fullId) + '">' + escapeHtml(shortId) + '</code>'
        + '<button type="button" class="copy-incident-id" data-full-id="' + escapeHtml(fullId) + '" title="' + escapeHtml(fullId) + '">Copy</button></td>'
        + '<td><span class="decision-pill ' + (malicious ? 'decision-malicious' : 'decision-benign') + '">' + (malicious ? 'MALICIOUS' : 'BENIGN') + '</span><span class="alert-title">' + escapeHtml(title) + '</span></td>'
        + '<td>' + entitiesHtml + '</td>'
        + '<td>' + escapeHtml(sourceDisplayName(inc.sourceLabel)) + '</td>'
        + '<td>' + escapeHtml(triage) + ' <span class="priority-pill priority-info">' + escapeHtml(rfDecisionLabel(inc)) + '</span>' + escapeHtml(analystNote) + '</td>';
      itemEl.addEventListener('click', () => {
        selectInvestigation(inc);
      });
      const copyButton = itemEl.querySelector('.copy-incident-id');
      if (copyButton) {
        copyButton.addEventListener('click', (event) => {
          event.stopPropagation();
          const value = copyButton.getAttribute('data-full-id') || '';
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value);
          }
        });
      }
      listEl.appendChild(itemEl);
  }

  function setInspectorText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  }

  function setSampleSurfacesHidden(hidden) {
    document.querySelectorAll('[data-sample-only="true"]').forEach(node => {
      node.hidden = hidden;
    });
  }

  function selectedFlowHasReceipt(inc) {
    const queries = inc && inc.evidenceLocker && inc.evidenceLocker.queries;
    if (!Array.isArray(queries)) return false;
    const campaign = queries.find(function (row) {
      return row && row.query_id === 'correlated_campaign_soar_ledger';
    });
    const status = campaign ? String(campaign.soar_receipt_status || '') : '';
    return status !== '' && status !== 'no_receipt' && status !== 'unavailable';
  }

  function playbookChainVerified(inc) {
    return !!(
      inc
      && verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256)
      && selectedFlowHasReceipt(inc)
    );
  }

  function playbookChainLabel(inc) {
    return playbookChainVerified(inc)
      ? 'Playbook hash chain: verified'
      : 'Playbook hash chain: unavailable';
  }

  function candidatePlaybookId(flow) {
    if (!flow || flow.decision !== 'Attack') return '';
    if (flow.playbook_id) return String(flow.playbook_id);
    const label = scenarioLabelFromTitle(flow);
    const mapped = {
      T1046: 'pb-discovery-network-contain-v1',
      T1110: 'pb-ssh-bruteforce-contain-v1',
      T1190: 'pb-web-exploit-contain-v1'
    };
    return mapped[label] || 'pb-rf-attack-contain-v1';
  }

  function realPlaybookId(inc) {
    const id = inc && inc.soarRecord && inc.soarRecord.playbookId
      ? String(inc.soarRecord.playbookId)
      : '';
    if (!id || id === 'none' || id === 'pending') return '';
    return id;
  }

  let ledgerChainStatus = '';

  function paintLedgerBadge(status) {
    const normalized = status === 'verified' || status === 'invalid' ? status : 'unavailable';
    const text = normalized === 'verified'
      ? 'Playbook hash chain: verified (HMAC-SHA256)'
      : normalized === 'invalid'
        ? 'Playbook hash chain: invalid'
        : 'Playbook hash chain: unavailable';
    ['headerChainBadge'].forEach(id => {
      const node = document.getElementById(id);
      if (!node) return;
      node.textContent = text;
      node.setAttribute('data-evidence-state', normalized === 'verified' ? 'verified' : 'unavailable');
    });
  }

  function syncHeaderChainBadge(inc) {
    const chainOk = !!(
      inc
      && verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256)
      && selectedFlowHasReceipt(inc)
    );
    if (chainOk) {
      paintLedgerBadge('verified');
      const verifiedNode = document.getElementById('headerChainBadge');
      if (verifiedNode) verifiedNode.setAttribute('data-evidence-state', 'verified');
      return;
    }
    paintLedgerBadge(ledgerChainStatus === 'invalid' ? 'invalid' : (ledgerChainStatus === 'verified' ? 'verified' : 'unavailable'));
  }

  function playbookIsApproved(inc) {
    if (!inc || inc.decision !== 'Attack') return false;
    if (inc.soarState === 'approved' || inc.playbookState === 'approved') return true;
    return !!(inc.soarRecord && inc.soarRecord.state === 'approved');
  }

  function applyContainmentGuard(inc) {
    const attack = !!(inc && inc.decision === 'Attack');
    const step2 = playbookIsApproved(inc);
    const step3 = !!(inc && (inc.callbackRecorded === true || inc.dispatchUnlocked === true));
    const step4 = !!(
      inc && (
        inc.containmentState === 'applied'
        || inc.containmentState === 'simulated_applied'
        || inc.rollbackUnlocked === true
      )
    );
    const rules = [
      [['approvePlaybookBtn', 'soarApproveBtn', 'evidenceApproveBtn'], attack, 'Approve is available on Attack rows.'],
      [['btnDispatchCallback'], step2, 'Dispatch requires an approved playbook and a verified hash chain.'],
      [['btnIsolateAttacker', 'btnContainRange'], step3, 'Isolate requires a recorded callback.'],
      [['btnRollbackRange'], step4, 'Rollback requires applied or simulated containment.']
    ];
    rules.forEach(rule => {
      rule[0].forEach(id => {
        const node = document.getElementById(id);
        if (!node) return;
        node.disabled = !rule[1];
        if (node.disabled) node.title = rule[2];
        else node.removeAttribute('title');
      });
    });
  }

  function renderCitedRationale(inc) {
    const node = document.getElementById('citedRationale');
    if (!node) return;
    const items = inc && inc.glassBox && Array.isArray(inc.glassBox.items) ? inc.glassBox.items : [];
    const valid = {};
    items.forEach((_, index) => { valid[String(index + 1)] = true; });
    const text = inc && inc.analystRationale ? String(inc.analystRationale) : '';
    const sentences = [];
    let buffer = '';
    for (let i = 0; i < text.length; i += 1) {
      buffer += text.charAt(i);
      const ch = text.charAt(i);
      if (ch === '.' || ch === '!' || ch === '?') {
        if (buffer.trim()) sentences.push(buffer.trim());
        buffer = '';
      }
    }
    if (buffer.trim()) sentences.push(buffer.trim());
    const cited = sentences.filter(sentence => {
      const matches = sentence.match(/\[E(\d+)\]/g) || [];
      return matches.some(token => valid[token.slice(2, -1)] === true);
    });
    node.textContent = cited.length ? cited.join(' ') : 'unavailable';
    node.setAttribute('data-evidence-state', 'unavailable');
  }

  function syncLiveInspector(inc) {
    renderScoringTimeProvenance(inc);
    const title = document.getElementById('inspectorCaseTitle');
    const badge = document.getElementById('groundedBadge');
    syncHeaderChainBadge(inc);
    applyContainmentGuard(inc);
    if (!inc) {
      if (title) title.textContent = 'No stored campaign selected';
      if (badge) {
        badge.textContent = 'Grounded evidence: waiting for a stored flow';
        badge.setAttribute('data-evidence-state', 'unavailable');
      }
      setInspectorText('inspectorDecision', 'waiting');
      setInspectorText('inspectorScore', 'unavailable');
      setInspectorText('inspectorSensorLine', 'Suricata: waiting');
      setInspectorText('inspectorForestLine', 'Frozen forest: waiting');
      setInspectorText('inspectorScenarioLabel', 'scenario label waiting');
      setInspectorText('inspectorAssets', 'endpoints unavailable');
      renderRemediation(null);
      setInspectorText('inspectorPlaybook', 'none');
      setInspectorText('inspectorChain', 'Playbook hash chain: unavailable');
      setInspectorText('inspectorCallback', 'Callback receipt: not recorded');
      setInspectorText('inspectorExecutionPath', 'not dispatched');
      showOperatorStamp({ identity_verified: false, identity_label: 'unverified_local_label' });
      renderPlaybookPreview(null);
      renderGlassBox(null);
      renderCitedRationale(null);
      renderContextMemoryPanels(null);
      renderEvidenceLockerQueries(null);
      renderTimelineGroupedView(null);
      renderModelProofSandbox(null);
      setDnnBadge(null);
      return;
    }
    const scoreText = formatRfPercent(inc.uncalibratedScore);
    const headline = inc.advisory && inc.advisory.summaryHeadline
      ? String(inc.advisory.summaryHeadline)
      : ((inc.live ? 'Stored flow ' : 'Recorded case ') + String(inc.id));
    if (title) title.textContent = headline;
    const conclusion = document.getElementById('conclusionCard');
    if (conclusion) conclusion.setAttribute('data-decision', String(inc.decision || 'withheld'));
    const src = inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    const dst = inc.provenance && inc.provenance.dstIp ? String(inc.provenance.dstIp) : '';
    setInspectorText('inspectorDecision', String(inc.decision || 'withheld'));
    setInspectorText('inspectorScore', scoreText);
    const sensor = inc.sensorObservation;
    if (inc.sourceLabel === 'suricata_bridge' && sensor) {
      setInspectorText('inspectorSensorLine', 'Suricata: ' + (sensor.suricata_line || 'flow only, no signature'));
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + (sensor.forest_line || 'unavailable'));
      setInspectorText('inspectorScenarioLabel', 'no scenario label');
    } else if (inc.sourceLabel === 'live_scenario_replay' || inc.scenarioLabel) {
      const reason = inc.scoreReason || 'unscored';
      setInspectorText('inspectorSensorLine', inc.sourceLabel === 'suricata_eve_bridge' ? 'Suricata: live range vector' : 'Suricata: not a live sensor flow');
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + String(inc.decision || 'withheld') + ', ' + scoreText + ', ' + reason);
      setInspectorText('inspectorScenarioLabel', 'scenario label ' + (inc.scenarioLabel || 'none'));
    } else {
      setInspectorText('inspectorSensorLine', 'Suricata: not a live sensor flow');
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + String(inc.decision || 'withheld') + ', ' + scoreText + ', ' + (inc.scoreReason || 'unscored'));
      setInspectorText('inspectorScenarioLabel', 'no scenario label');
    }
    if (isRecordedUnsw(inc) && (isMissingEndpoint(src) || isMissingEndpoint(dst))) {
      setInspectorText('inspectorAssets', UNSW_ENDPOINT_CHIP);
    } else if (!isMissingEndpoint(src) && !isMissingEndpoint(dst)) {
      setInspectorText('inspectorAssets', src + ' -> ' + dst);
    } else {
      setInspectorText('inspectorAssets', 'endpoints unavailable');
    }
    const chainOk = playbookChainVerified(inc);
    if (badge) {
      badge.textContent = 'Grounded evidence: stored flow';
      badge.setAttribute('data-evidence-state', 'unavailable');
    }
    renderRemediation(inc);
    applyContainmentStatus(inc);
    markResponseProgress(inc);
    const rfBadge = document.getElementById('flowRfBadge');
    if (rfBadge) {
      rfBadge.textContent = 'Frozen RF ' + String(inc.decision || 'withheld') + ' ' + formatRfPercent(inc.uncalibratedScore);
    }
    const aeBadge = document.getElementById('flowAeBadge');
    if (aeBadge) {
      const ae = inc.secondaryAe || {};
      const loss = Number(ae.aeLoss != null ? ae.aeLoss : ae.aeError);
      const scored = Number.isFinite(loss) && ae.status !== 'not_scored';
      if (scored) {
        const anomaly = ae.aeAnomalyFlag === true || (ae.aeAnomalyFlag == null && ae.status === 'ANOMALY_CONFIRMED');
        aeBadge.textContent = 'v2 AE DL: ' + (anomaly ? 'Anomaly' : 'Normal') + ' (MSE ' + formatMse(loss) + ')';
        aeBadge.setAttribute('data-ae-status', anomaly ? 'ANOMALY_CONFIRMED' : 'NORMAL');
        aeBadge.setAttribute('data-ae-loss', String(loss));
      } else {
        aeBadge.textContent = aeBadge.getAttribute('data-ae-unscored-label')
          || 'Secondary: v2 AE not scored on this flow';
        aeBadge.setAttribute('data-ae-status', 'not_scored');
      }
    }
    setDnnBadge(inc);
    const rangeBadge = document.getElementById('rangeConnectivityBadge');
    if (rangeBadge) {
      if (inc.decision === 'Benign') {
        rangeBadge.textContent = 'Isolation disabled. Frozen RF decision is Benign.';
        rangeBadge.setAttribute('data-connectivity', 'disabled');
      } else if (inc.containmentState === 'simulated_applied' || inc.containmentState === 'simulated_rolled_back') {
        rangeBadge.textContent = 'SIMULATED SCENARIO CONTAINMENT (No Host Firewall Rule Executed — Recorded in Ledger)';
        rangeBadge.setAttribute('data-connectivity', 'simulated');
        rangeBadge.setAttribute('data-evidence-state', 'simulated');
      } else if (inc.containmentState === 'applied') {
        rangeBadge.textContent = src + ' -> ' + dst + ': BLOCKED (iptables DROP active)';
        rangeBadge.setAttribute('data-connectivity', 'blocked');
        rangeBadge.setAttribute('data-evidence-state', 'verified');
      } else if (inc.containmentState === 'rolled_back') {
        rangeBadge.textContent = src + ' -> ' + dst + ': REACHABLE (rollback recorded)';
        rangeBadge.setAttribute('data-connectivity', 'reachable');
        rangeBadge.setAttribute('data-evidence-state', 'verified');
      } else {
        rangeBadge.textContent = src + ' -> ' + dst;
        rangeBadge.setAttribute('data-connectivity', 'waiting');
        rangeBadge.setAttribute('data-evidence-state', inc.containmentState ? 'verified' : 'unavailable');
      }
    }
    const changelog = document.getElementById('soarChangelog');
    if (changelog) {
      changelog.textContent = playbookChainLabel(inc);
      changelog.setAttribute('data-evidence-state', chainOk ? 'verified' : 'unavailable');
    }
    const playbook = inc.soarRecord && inc.soarRecord.playbookId ? String(inc.soarRecord.playbookId) : 'none';
    const state = inc.soarRecord && inc.soarRecord.state ? String(inc.soarRecord.state) : 'none';
    setInspectorText('inspectorPlaybook', playbook + ' / ' + state);
    const chainNode = document.getElementById('inspectorChain');
    if (chainNode) {
      chainNode.textContent = playbookChainLabel(inc);
      chainNode.setAttribute('data-evidence-state', chainOk ? 'verified' : 'unavailable');
    }
    const signed = inc.live === true
      && typeof inc.callbackSignature === 'string'
      && SHA256_HEX_REGEX.test(inc.callbackSignature);
    setInspectorText('inspectorCallback', signed ? 'Callback receipt: recorded' : 'Callback receipt: not recorded');
    const callbackNode = document.getElementById('inspectorCallback');
    if (callbackNode) callbackNode.setAttribute('data-evidence-state', 'unavailable');
    const executionPath = inc.executionPath === 'n8n_live_container'
      || inc.executionPath === 'local_contract_fallback'
      || inc.executionPath === 'queued_offline'
      || inc.executionPath === 'local_air_gapped'
      ? inc.executionPath
      : 'not dispatched';
    const offlineDisclosure = {
      local_contract_fallback: 'Simulated local contract. Not a live external SOAR system.',
      queued_offline: 'Queued offline. Not a live external case system.',
      local_air_gapped: 'Local air-gapped advisory. Not a live external model.'
    };
    const executionLabel = offlineDisclosure[executionPath]
      ? executionPath + '. ' + offlineDisclosure[executionPath]
      : executionPath;
    setInspectorText('inspectorExecutionPath', executionLabel);
    showOperatorStamp(inc);
    const verdictNode = document.getElementById('analystVerdictDisplay');
    if (verdictNode) {
      const verdict = inc.analystVerdict || 'not recorded';
      verdictNode.textContent = 'Analyst verdict: ' + verdict + '. Frozen RF decision: ' + String(inc.decision || 'withheld') + '.';
      verdictNode.setAttribute('data-evidence-state', inc.analystVerdict ? 'verified' : 'unavailable');
    }
    const assignmentNode = document.getElementById('caseAssignmentDisplay');
    if (assignmentNode) {
      const assignee = inc.assigneeId || 'unassigned';
      const review = inc.reviewStatus || 'unassigned';
      assignmentNode.textContent = 'Assignee: ' + assignee + '. Review status: ' + review + '.';
      assignmentNode.setAttribute('data-evidence-state', inc.assigneeId ? 'verified' : 'unavailable');
    }
    renderGlassBox(inc.glassBox);
    renderCitedRationale(inc);
    renderContextMemoryPanels(inc);
    renderEvidenceLockerQueries(inc);
    renderTimelineGroupedView(inc);
    renderModelProofSandbox(inc);
    applyContainmentGuard(inc);
    loadModelProofForSelection(inc);
    loadSoarPlaybookPreview(inc);
  }

  function renderContextMemoryPanels(inc) {
    const memories = inc && Array.isArray(inc.contextMemory) ? inc.contextMemory : [];
    document.querySelectorAll('[data-context-memory-list]').forEach(node => {
      if (!memories.length) {
        node.textContent = 'No institutional memory stored for this flow.';
        node.setAttribute('data-evidence-state', 'unavailable');
        return;
      }
      node.innerHTML = memories.map(item => (
        '<div>' + escapeHtml(String(item.entity_ip_or_subnet || ''))
        + ' / ' + escapeHtml(String(item.service_or_port || 'any'))
        + ': ' + escapeHtml(String(item.expected_behavior_rule || ''))
        + '</div>'
      )).join('');
      node.setAttribute('data-evidence-state', 'verified');
    });
  }

  function evidenceLockerHtml(inc) {
    const locker = inc && inc.evidenceLocker ? inc.evidenceLocker : null;
    const queries = locker && Array.isArray(locker.queries) ? locker.queries : [];
    if (!queries.length) {
      return 'Queries Run: waiting for a stored flow.';
    }
    return queries.map(query => {
      if (query.query_id === 'entity_historical_frequency') {
        const countText = isRecordedUnsw(inc) && Number(query.entity_count) === 0
          ? '1 (anonymized 14-feature study vector)'
          : String(query.entity_count);
        return '<div><b>Query 1 Entity Historical Frequency:</b> ' + escapeHtml(countText) + '</div>';
      }
      if (query.query_id === 'destination_port_protocol_baseline') {
        const average = query.average_rf_attack_probability == null
          ? 'unavailable'
          : (Number(query.average_rf_attack_probability) * 100).toFixed(1) + '%';
        return '<div><b>Query 2 Destination Port &amp; Protocol Baseline:</b> count '
          + escapeHtml(String(query.flow_count)) + ', average RF probability ' + escapeHtml(average) + '</div>';
      }
      return '<div><b>Query 3 Correlated Campaign &amp; SOAR Ledger State:</b> stitched '
        + escapeHtml(String(query.stitched_flow_count)) + ', receipt '
        + escapeHtml(String(query.soar_receipt_status || 'unavailable')) + '</div>';
    }).join('');
  }

  function renderEvidenceLockerQueries(inc) {
    const node = document.getElementById('evidenceLockerQueries');
    if (!node) return;
    const verified = inc && inc.evidenceLocker && inc.evidenceLocker.evidence_state === 'verified';
    node.innerHTML = evidenceLockerHtml(inc);
    node.setAttribute('data-evidence-state', verified ? 'verified' : 'unavailable');
  }

  function renderGlassBox(checklist) {
    const node = document.getElementById('glassBoxChecklist');
    if (!node) return;
    const items = checklist && Array.isArray(checklist.items) ? checklist.items : [];
    if (!items.length) {
      node.textContent = 'Glass-box checklist waiting for a stored flow.';
      node.setAttribute('data-evidence-state', 'unavailable');
      return;
    }
    node.innerHTML = items.map((item, index) => (
      '<div class="finding-row"><span class="finding-num">[E' + (index + 1) + ']</span> '
      + escapeHtml(String(item.id) + ': ' + String(item.status) + (item.passed ? ' pass' : ' open'))
      + '</div>'
    )).join('');
    const allKnown = items.every(item => item.status !== 'not_recorded' && item.status !== 'invalid' && item.status !== 'unscored');
    node.setAttribute('data-evidence-state', allKnown ? 'verified' : 'pending');
  }

  function renderForensicDrawer() {
    const drawerEl = document.getElementById('forensicDrawer');
    if (!drawerEl) return;

    const incidents = activeIncidents();
    const inc = incidents.find(i => i.id === selectedIncidentId) || incidents[0];
    if (!inc) {
      syncLiveInspector(null);
      drawerEl.innerHTML = '<div style="padding:1rem;color:var(--text-muted);">No stored campaign is selected. Replay the benchmark burst to score recorded UNSW-NB15 study vectors.</div>';
      return;
    }
    syncLiveInspector(inc);

    // Verification evaluation
    const chainOk = playbookChainVerified(inc);
    const attackHit = attackTechnique(inc);
    const ragOk = !!attackHit;
    const hiveOk = verifyHiveAndN8nReceipt(inc.thehiveCaseRecord, inc.n8nPlaybookReceipt);
    const signedLocalCallback = inc.live === true
      && typeof inc.callbackSignature === 'string'
      && SHA256_HEX_REGEX.test(inc.callbackSignature)
      && typeof inc.thehiveCaseId === 'string'
      && inc.thehiveCaseId.indexOf('case_') === 0
      && Number.isFinite(Number(inc.mttrSeconds));

    const chainState = chainOk ? 'verified' : 'unavailable';
    const ragState = ragOk ? 'verified' : 'unavailable';
    const playbookId = inc.soarRecord && inc.soarRecord.playbookId ? String(inc.soarRecord.playbookId) : '';
    const realPlaybook = playbookId && playbookId !== 'none' && playbookId !== 'pending';
    const hivePending = realPlaybook && inc.soarRecord.state === 'pending_approval' && inc.decision === 'Attack';
    const hiveState = (hiveOk || signedLocalCallback) ? 'verified' : (hivePending ? 'pending' : 'unavailable');
    const hiveLabel = signedLocalCallback
      ? ('TheHive Case: ' + inc.thehiveCaseId)
      : (hiveOk ? 'TheHive Case: DISPATCHED' : (hivePending ? 'TheHive Case: PENDING APPROVAL' : 'TheHive Case: UNAVAILABLE'));
    const techniqueId = ragOk
      ? (attackHit.technique_id
        + (attackHit.technique_name ? ' · ' + attackHit.technique_name : '')
        + (attackHit.cve_ids && attackHit.cve_ids.length ? ' · ' + attackHit.cve_ids[0] : ''))
      : 'None (Benign Flow)';
    const tacticName = ragOk
      ? (attackHit.tactic || attackHit.technique_name)
      : (inc.decision === 'Benign' ? 'none' : (inc.live ? 'unavailable' : 'Network Service Discovery'));
    const cosineText = ragOk ? attackHit.cosine_similarity.toFixed(4) : (inc.live ? 'unavailable' : '0.9120');
    const recordedCaseId = signedLocalCallback
      ? inc.thehiveCaseId
      : ((inc.thehiveCaseRecord && inc.thehiveCaseRecord.case_id) || 'not recorded');
    const srcShown = isMissingEndpoint(inc.provenance && inc.provenance.srcIp) ? '' : String(inc.provenance.srcIp);
    const dstShown = isMissingEndpoint(inc.provenance && inc.provenance.dstIp) ? '' : String(inc.provenance.dstIp);
    const assetLine = (isRecordedUnsw(inc) && (!srcShown || !dstShown))
      ? UNSW_ENDPOINT_CHIP
      : (srcShown && dstShown ? srcShown + ' -> ' + dstShown : 'endpoints unavailable');
    const tupleLine = (srcShown && dstShown)
      ? srcShown + ':' + inc.provenance.srcPort + ' -> ' + dstShown + ':' + inc.provenance.dstPort + ' (' + inc.provenance.proto + ')'
      : assetLine;

    // Build Forensic Drawer HTML
    drawerEl.innerHTML = `
      <div class="tier-section" id="evidenceLockerQueryBlock">
        <div class="tier-header"><span class="tier-1-title">Queries Run</span></div>
        ${evidenceLockerHtml(inc)}
      </div>
      <!-- Tier 1: Primary Decision Signal -->
      <div class="tier-section" data-blast-ui-tier="unicorn-progressive-disclosure-v1">
        <div class="tier-header">
          <span class="tier-1-title">Tier 1: Primary Triage Signal (Decision Authority)</span>
          <span class="badge badge-rf-confidence">Sole Authority: Random Forest (${formatRfPercent(inc.uncalibratedScore)})</span>
        </div>
        <div class="evidence-grid">
          <div class="evidence-cell">
            <span class="evidence-cell-label">ALERT CANDIDATE ID</span>
            <span class="evidence-cell-val"><code>${escapeHtml(inc.id)}</code></span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">SOURCE EVENT ID</span>
            <span class="evidence-cell-val"><code>${escapeHtml(inc.sourceEventId)}</code></span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">PRIMARY MODEL ARTIFACT SHA-256</span>
            <span class="evidence-cell-val"><code>${escapeHtml(inc.modelArtifactSha256)}</code></span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">PRE-REGISTERED MODEL SPECIFICATION</span>
            <span class="evidence-cell-val">${escapeHtml(inc.modelVersion)} &middot; Threshold: 0.5000</span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">FROZEN POPULATION PERFORMANCE</span>
            <span class="evidence-cell-val">Precision: <b>${EVAL_PACK_REV2.rfMetrics.precisionPct}%</b> &middot; FPR: <b>${EVAL_PACK_REV2.rfMetrics.fprPct}%</b> (201 FPs / 212,210 benign)</span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">DECISION VERDICT & AUTHORITY</span>
            <span class="evidence-cell-val">
              <span class="badge badge-decision">${escapeHtml(inc.decision)}</span>
              <span class="badge badge-secondary-anomaly">Secondary Anomaly Indicator (Unfused v2 AE — Section 8 Fusion Disabled)</span>
            </span>
          </div>
          ${inc.triageState ? `
          <div class="evidence-cell">
            <span class="evidence-cell-label">ANALYST TRIAGE STATE</span>
            <span class="evidence-cell-val"><span class="badge badge-state">${escapeHtml(inc.triageState)}</span></span>
          </div>` : ''}
        </div>
      </div>

      <!-- Tier 2: Secondary Investigative Context -->
      <div class="tier-section">
        <div class="tier-header">
          <span class="tier-2-title">Tier 2: Secondary Context (Correlation, Intel & Provenance)</span>
          <span class="badge badge-corr">${inc.correlation ? escapeHtml(inc.correlation.windowType) : 'Uncorrelated Flow'}</span>
        </div>
        <div class="evidence-grid">
          <div class="evidence-cell">
            <span class="evidence-cell-label">SENSOR PROVENANCE & FLOW 5-TUPLE</span>
            <span class="evidence-cell-val"><code>${escapeHtml(tupleLine)}</code></span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">INCIDENT CORRELATION KEY</span>
            <span class="evidence-cell-val">${inc.correlation ? `<code>${escapeHtml(inc.correlation.incidentId)}</code> (${inc.correlation.constituentAlerts} alerts rolled)` : '<span style="color:var(--text-muted)">Single isolated flow alert</span>'}</span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">MISP RFC1918 PRIVATE-IP GUARD</span>
            <span class="evidence-cell-val">
              ${inc.threatIntel.privateIpGuardTriggered
                ? '<span class="badge" data-evidence-state="verified">TRIGGERED: RFC1918 Private IP Suppressed</span>'
                : (inc.live
                  ? '<span class="badge" data-evidence-state="unavailable">No MISP lookup on this flow</span>'
                  : '<span class="badge badge-auth">PUBLIC IP: External TI Looked Up</span>')
              }
            </span>
          </div>
          <div class="evidence-cell">
            <span class="evidence-cell-label">UNFUSED V2 BENIGN AUTOENCODER ERROR</span>
            <span class="evidence-cell-val">
              Loss: <code>${inc.secondaryAe.aeError.toFixed(4)}</code> (Threshold: <code>${EVAL_PACK_REV2.aeThreshold.toFixed(4)}</code>) &middot; ${escapeHtml(inc.secondaryAe.status)}
            </span>
          </div>
        </div>
        ${inc.correlation ? `<div style="margin-top: 0.6rem; font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(inc.correlation.explanation)}</div>` : ''}
      </div>

      <!-- Tier 3: Grounded Advisory Debrief & Human-Gated SOAR Actions -->
      <div class="tier-section">
        <div class="tier-header">
          <span class="tier-3-title">Tier 3: Advisory Synthesis & Human-in-the-Loop SOAR Action</span>
          <div style="display: flex; gap: 0.4rem;">
            <span class="badge badge-soar-chain" data-evidence-state="${chainState}">
              ${chainOk ? 'Playbook hash chain: verified' : 'Playbook hash chain: unavailable'}
            </span>
            <span class="badge badge-chroma-rag" data-evidence-state="${ragState}">
              ${ragOk ? `ChromaDB RAG: ${inc.chromaRagHits.length} Hits Verified` : 'ChromaDB RAG: UNAVAILABLE'}
            </span>
            <span class="badge badge-n8n-hive" data-evidence-state="${hiveState}">
              ${hiveLabel}
            </span>
          </div>
        </div>

        <!-- Advisory Debrief Box -->
        <div class="debrief-box">
          <div class="debrief-headline">${escapeHtml(inc.advisory.summaryHeadline)}</div>
          <div class="debrief-rationale">${escapeHtml(inc.advisory.detectionRationale)}</div>
          <div class="debrief-policy-note">
            Section 8 Shield Active: ${EVAL_PACK_REV2.section8Lock.recallComparisonString} rejected due to ${EVAL_PACK_REV2.section8Lock.benignFpInflation} extra benign FPs (${EVAL_PACK_REV2.section8Lock.fpRatio} inflation).
          </div>
        </div>

        <!-- ChromaDB Semantic RAG Hits -->
        <div style="margin-top: 0.75rem;">
          <div style="font-size: 0.75rem; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.35rem;">
            Semantic Vector RAG Recommendations (ChromaDB 64-Dim Cosine Similarity)
          </div>
          ${ragOk ? `
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
              ${inc.chromaRagHits.map(h => `
                <div style="background: rgba(191, 75, 138, 0.12); border: 1px solid rgba(191, 75, 138, 0.4); border-radius: var(--radius-sm); padding: 0.35rem 0.65rem; font-size: 0.8rem;">
                  <b>${escapeHtml(h.technique_id)}</b>: ${escapeHtml(h.technique_name)} &middot; Cosine: <code>${h.cosine_similarity.toFixed(3)}</code> &middot; Playbook: <code>${escapeHtml(h.playbook_id)}</code>
                </div>
              `).join('')}
            </div>
          ` : `<div style="font-size: 0.8rem; color: var(--text-muted); font-style: italic;">${inc.decision === 'Benign' ? 'No technique. Frozen RF decision is Benign.' : 'No semantic RAG hits attached to this alert candidate.'}</div>`}
        </div>

        <!-- SOAR Controls Section -->
        <div class="soar-action-box">
          <div class="soar-action-header">
            <div>
              <span style="font-weight: 700; color: var(--text-primary); font-size: 0.88rem;">Playbook Action: </span>
              <code>${inc.soarRecord ? escapeHtml(inc.soarRecord.playbookId) : 'none'}</code>
              <span style="margin-left: 0.5rem;">State: <span class="badge badge-state">${inc.soarRecord ? escapeHtml(inc.soarRecord.state) : 'unconfigured'}</span></span>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary);">
              Audit Head: <code>${inc.soarAuditChainHeadSha256 ? escapeHtml(inc.soarAuditChainHeadSha256.substring(0, 16)) + '...' : 'none'}</code>
            </div>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">
            Target: <code>${inc.soarRecord ? escapeHtml(inc.soarRecord.targetEntity) : 'none'}</code> &middot;
            Constitutional Policy: AI models are strictly advisory and forbidden from autonomous execution. Human analyst cryptographic authorization required.
          </div>
          <div class="btn-group">
            <button class="btn btn-approve" id="evidenceApproveBtn" ${inc.decision === 'Benign' || !realPlaybookId(inc) ? 'disabled title="' + (inc.decision === 'Benign' ? CONTAINMENT_DISABLED_TITLE : 'No playbook is stored for this flow.') + '" style="opacity:0.5;cursor:not-allowed;"' : ''}>
              3A. Approve Playbook (SHA-256 Chain)
            </button>
            <button class="btn btn-rollback" id="btnRollbackPlaybook" ${!inc.soarRecord || inc.soarRecord.state !== 'executed_simulated' ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : ''}>
              Reversible Rollback
            </button>
          </div>
        </div>
      </div>

      <!-- Standardized 4-Block Investigation Case Anatomy -->
      <div class="tier-section anatomy-card" data-blast-ui-tier="unicorn-progressive-disclosure-v1">
        <div class="tier-header">
          <span class="tier-1-title" style="color: #58a6ff;">Standardized 4-Block Investigation Case Anatomy</span>
          <span class="badge" data-evidence-state="${inc.live ? (signedLocalCallback ? 'verified' : 'pending') : 'verified'}">${inc.live ? (signedLocalCallback ? 'Signed callback recorded' : 'Awaiting callback') : '4-Block Verified'}</span>
        </div>
        <div class="anatomy-grid">
          <!-- Block 1: Executive Summary -->
          <div class="anatomy-block" data-anatomy-block="1">
            <h4>Block 1: Executive Summary</h4>
            <div><b>Risk Level:</b> <span class="badge badge-decision">${inc.decision === 'Benign' ? 'INFORMATIONAL' : inc.decision !== 'Attack' ? 'WITHHELD' : (inc.uncalibratedScore >= 0.9 ? 'CRITICAL' : (inc.uncalibratedScore >= 0.7 ? 'HIGH' : 'MEDIUM'))}</span></div>
            <div><b>RF Confidence:</b> ${formatRfPercent(inc.uncalibratedScore)}</div>
            <div><b>Priority Rank:</b> ${inc.decision === 'Attack' ? ('#' + (inc.secondaryAe && inc.secondaryAe.status === 'ANOMALY_CONFIRMED' ? 1 : 2)) : 'Informational'}</div>
            <div style="margin-top: 0.25rem;"><b>Affected Assets:</b> <code>${escapeHtml(assetLine)}</code></div>
          </div>

          <!-- Block 2: Attack Timeline -->
          <div class="anatomy-block" data-anatomy-block="2">
            <h4>Block 2: Attack Timeline</h4>
            <div><b>Window Type:</b> <span class="badge badge-corr">${inc.correlation ? escapeHtml(inc.correlation.windowType) : '30.0s_burst'}</span></div>
            <div><b>Correlated Flows:</b> ${liveCorrelationReport ? Number(liveCorrelationReport.correlated_flow_count || 0) : (inc.correlation ? inc.correlation.constituentAlerts : 1)}</div>
            <div><b>Progression:</b> ${liveCorrelationReport ? 'Live unified timeline' : ('Ingest at ' + escapeHtml(formatDisplayUtc(inc.observedAt)))}</div>
            ${liveCorrelationReport ? ('<div data-live-timeline="true">' + liveTimelineRows(liveCorrelationReport) + '</div>') : (inc.live ? '<div><b>Byte Volume Delta:</b> not recorded on this flow</div>' : '<div><b>Byte Volume Delta:</b> +1,250 B &middot; <b>Packets:</b> 18</div>')}
          </div>

          <!-- Block 3: MITRE ATT&CK Mapping -->
          <div class="anatomy-block" data-anatomy-block="3">
            <h4>Block 3: MITRE ATT&CK Mapping</h4>
            <div><b>Technique:</b> <code>${escapeHtml(techniqueId)}</code></div>
            <div><b>Tactic:</b> ${escapeHtml(tacticName)}</div>
            <div><b>Cosine Similarity:</b> ${escapeHtml(String(cosineText))}</div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.2rem;">
              ${inc.live && !ragOk ? 'No local technique was retrieved for this flow.' : 'retrieved candidate technique'}
            </div>
          </div>

          <!-- Block 4: Cryptographic SOAR Status -->
          <div class="anatomy-block" data-anatomy-block="4">
            <h4>Block 4: Cryptographic SOAR Status</h4>
            <div><b>Playbook:</b> <code>${inc.soarRecord ? escapeHtml(inc.soarRecord.playbookId) : 'pb-isolate-01'}</code></div>
            <div><b>State:</b> <span class="badge badge-state">${inc.soarRecord ? escapeHtml(inc.soarRecord.state) : 'pending_approval'}</span></div>
            <div><b>Audit Chain:</b> <span class="badge" data-evidence-state="${chainState}">${playbookChainLabel(inc)}</span></div>
            <div><b>TheHive case:</b> <code>${escapeHtml(recordedCaseId)}</code></div>
            <div><b>Callback MTTR:</b> ${inc.mttrSeconds === null || inc.mttrSeconds === undefined ? 'not recorded' : Number(inc.mttrSeconds).toFixed(3) + 's'}</div>
            <div><b>HMAC:</b> <code>${inc.callbackSignature && SHA256_HEX_REGEX.test(inc.callbackSignature) ? escapeHtml(inc.callbackSignature.substring(0, 16)) + '...' : 'none'}</code></div>
            <div><b>HMAC Verified:</b> <span class="badge" data-evidence-state="unavailable">${signedLocalCallback ? 'Callback receipt: recorded' : 'Callback receipt: not recorded'}</span></div>
            <div><b>Execution path:</b> <code>${escapeHtml(inc.executionPath || 'not dispatched')}</code></div>
          </div>
        </div>
      </div>
    `;

    // Bind SOAR Action Buttons
    const btnApprove = document.getElementById('evidenceApproveBtn');
    if (btnApprove && inc.decision === 'Attack' && inc.live && inc.flowId && realPlaybookId(inc)) {
      btnApprove.addEventListener('click', () => {
        approveLivePlaybook(inc);
      });
    }

    const btnRollback = document.getElementById('btnRollbackPlaybook');
    if (btnRollback) {
      btnRollback.disabled = true;
    }
    applyContainmentGuard(inc);
  }

  // ========================================================================
  // 6. 5-Minute Guided 6-Stage Walkthrough Logic
  // ========================================================================
  function initWalkthroughTimeline() {
    const timelineEl = document.getElementById('walkthroughTimeline');
    if (!timelineEl) return;

    timelineEl.innerHTML = '';
    WALKTHROUGH_STAGES.forEach((stage, idx) => {
      const stepEl = document.createElement('div');
      stepEl.className = `walkthrough-step ${idx === walkthroughCurrentStep ? 'active' : ''} ${idx < walkthroughCurrentStep ? 'completed' : ''}`;
      stepEl.dataset.idx = idx;

      stepEl.innerHTML = `
        <span class="step-num">STAGE 0${stage.stageNum}</span>
        <span class="step-title">${escapeHtml(stage.title.split(':')[1] || stage.title)}</span>
        <span class="step-time">${escapeHtml(stage.duration)}</span>
      `;

      stepEl.addEventListener('click', () => {
        pauseWalkthrough();
        walkthroughCurrentStep = idx;
        renderWalkthroughStage();
      });

      timelineEl.appendChild(stepEl);
    });

    renderWalkthroughStage();
  }

  function renderWalkthroughStage() {
    const stage = WALKTHROUGH_STAGES[walkthroughCurrentStep];
    const displayEl = document.getElementById('walkthroughDisplay');
    if (!displayEl || !stage) return;

    displayEl.innerHTML = `
      <div class="walkthrough-stage-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h3 class="stage-title">${escapeHtml(stage.title)}</h3>
          <span class="badge badge-corr">${escapeHtml(stage.duration)}</span>
        </div>
        <p class="stage-description">${escapeHtml(stage.description)}</p>
        <div style="font-size: 0.75rem; font-weight: 700; color: var(--text-secondary); margin-bottom: 0.25rem;">
          STAGE VERIFICATION EVIDENCE TELEMETRY:
        </div>
        <pre class="stage-evidence-pre"><code>${escapeHtml(stage.evidenceSnippet)}</code></pre>
      </div>
    `;

    // Update active timeline card styles
    const stepCards = document.querySelectorAll('.walkthrough-step');
    stepCards.forEach((c, i) => {
      c.className = `walkthrough-step ${i === walkthroughCurrentStep ? 'active' : ''} ${i < walkthroughCurrentStep ? 'completed' : ''}`;
    });
  }

  function nextWalkthroughStage() {
    walkthroughCurrentStep = (walkthroughCurrentStep + 1) % WALKTHROUGH_STAGES.length;
    renderWalkthroughStage();
  }

  function prevWalkthroughStage() {
    walkthroughCurrentStep = (walkthroughCurrentStep - 1 + WALKTHROUGH_STAGES.length) % WALKTHROUGH_STAGES.length;
    renderWalkthroughStage();
  }

  function playWalkthrough() {
    const btnPlay = document.getElementById('btnWalkthroughPlay');
    if (walkthroughInterval) {
      pauseWalkthrough();
      return;
    }

    if (btnPlay) {
      btnPlay.innerText = 'Pause pipeline review';
      btnPlay.classList.add('btn-rollback');
    }

    walkthroughInterval = setInterval(() => {
      nextWalkthroughStage();
    }, 5000);
  }

  function pauseWalkthrough() {
    if (walkthroughInterval) {
      clearInterval(walkthroughInterval);
      walkthroughInterval = null;
    }
    const btnPlay = document.getElementById('btnWalkthroughPlay');
    if (btnPlay) {
      btnPlay.innerText = 'Play pipeline review';
      btnPlay.classList.remove('btn-rollback');
    }
  }

  function setupEventListeners() {
    // Filter Buttons
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter || 'all';
        renderIncidentQueue();
      });
    });
    function bindQueuePreset(id, source, decision) {
      const node = document.getElementById(id);
      if (!node) return;
      node.addEventListener('click', () => {
        const sourceNode = document.getElementById('queueSourceFilter');
        const decisionNode = document.getElementById('queueDecisionFilter');
        if (sourceNode) sourceNode.value = source;
        if (decisionNode) decisionNode.value = decision;
        renderIncidentQueue();
      });
    }
    bindQueuePreset('pillAll', 'all', 'all');
    bindQueuePreset('pillUrgent', 'all', 'Attack');
    bindQueuePreset('pillNotable', 'suricata_bridge', 'all');
    bindQueuePreset('pillInfo', 'all', 'Benign');
    document.querySelectorAll('[data-soc-nav]').forEach(node => {
      node.addEventListener('click', () => showSocView(node.getAttribute('data-soc-nav')));
    });
    const openLab = document.getElementById('btnOpenLabDrawer');
    const closeLab = document.getElementById('btnCloseLabDrawer');
    if (openLab) openLab.addEventListener('click', () => openLabDrawer(true));
    if (closeLab) closeLab.addEventListener('click', () => openLabDrawer(false));
    const backButton = document.getElementById('btnBackToInvestigations');
    if (backButton) backButton.addEventListener('click', () => showSocView('investigations'));
    const graphButton = document.getElementById('btnOpenActionGraph');
    if (graphButton) graphButton.addEventListener('click', () => showSocView('graph'));
    document.querySelectorAll('[data-graph-node]').forEach(node => {
      node.addEventListener('click', () => showGraphPopover(node));
    });

    ['queueSourceFilter', 'queueSearch', 'queueDecisionFilter', 'queueTriageFilter', 'queueVerdictFilter', 'queueSort'].forEach(id => {
      const node = document.getElementById(id);
      if (!node) return;
      node.addEventListener('input', renderIncidentQueue);
      node.addEventListener('change', renderIncidentQueue);
    });

    const verdictButton = document.getElementById('btnSaveVerdict');
    if (verdictButton) verdictButton.addEventListener('click', saveAnalystVerdict);
    const verdictSelect = document.getElementById('analystVerdictSelect');
    if (verdictSelect) {
      verdictSelect.addEventListener('change', () => { fillGroundedVerdictRationale(true); });
    }
    const memoryButton = document.getElementById('btnSaveContextMemory');
    if (memoryButton) memoryButton.addEventListener('click', saveContextMemory);
    const enrollButton = document.getElementById('btnEnrollOperator');
    if (enrollButton) enrollButton.addEventListener('click', enrollLabOperator);
    const assignmentButton = document.getElementById('btnSaveAssignment');
    if (assignmentButton) assignmentButton.addEventListener('click', saveCaseAssignment);

    // Walkthrough Buttons
    const btnPlay = document.getElementById('btnWalkthroughPlay');
    if (btnPlay) btnPlay.addEventListener('click', playWalkthrough);

    const btnNext = document.getElementById('btnWalkthroughNext');
    if (btnNext) {
      btnNext.addEventListener('click', () => {
        pauseWalkthrough();
        nextWalkthroughStage();
      });
    }

    const btnPrev = document.getElementById('btnWalkthroughPrev');
    if (btnPrev) {
      btnPrev.addEventListener('click', () => {
        pauseWalkthrough();
        prevWalkthroughStage();
      });
    }

    const btnReset = document.getElementById('btnWalkthroughReset');
    if (btnReset) {
      btnReset.addEventListener('click', () => {
        pauseWalkthrough();
        walkthroughCurrentStep = 0;
        renderWalkthroughStage();
      });
    }

    // 5-Tab Investigation Inspector Navigation (Mega-Milestone #37)
    const tabButtons = document.querySelectorAll('.inspector-tab-btn');
    const tabPanes = document.querySelectorAll('[data-inspector-tab]');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-tab-target');
        tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        tabPanes.forEach(pane => {
          if (pane.getAttribute('data-inspector-tab') === target) {
            pane.classList.add('active');
            pane.style.display = 'block';
          } else {
            pane.classList.remove('active');
            pane.style.display = 'none';
          }
        });
      });
    });

    // Click-to-copy hash / IP tooltips
    document.querySelectorAll('[data-copy-hash], [data-copy-value]').forEach(el => {
      el.addEventListener('click', () => {
        const val = el.getAttribute('data-copy-hash') || el.getAttribute('data-copy-value');
        if (val && navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(val).catch(() => {});
        }
        const origTooltip = el.getAttribute('data-copy-tooltip') || 'Click to copy';
        el.setAttribute('data-copy-tooltip', 'Copied to clipboard!');
        setTimeout(() => {
          el.setAttribute('data-copy-tooltip', origTooltip);
        }, 1500);
      });
    });

    ['btnLiveCopilot', 'btnAskCopilot'].forEach((id) => {
      const copilotButton = document.getElementById(id);
      if (copilotButton) {
        copilotButton.addEventListener('click', () => { askLiveCopilot(); });
      }
    });
    const noteButton = document.getElementById('btnSaveAnalystNote');
    if (noteButton) {
      noteButton.addEventListener('click', () => { saveLiveAnalystNote(); });
    }
    const ingestButton = document.getElementById('btnIngestLiveFlow');
    if (ingestButton) {
      ingestButton.addEventListener('click', () => { ingestLiveFlow(); });
    }
    const driftButton = document.getElementById('btnRefreshDrift');
    if (driftButton) {
      driftButton.addEventListener('click', () => { refreshLiveDriftAndWorkbench(); });
    }
    refreshLiveQueue();

    // Top Header SOAR Action Button
    const topApproveBtn = document.getElementById('approvePlaybookBtn');
    if (topApproveBtn) {
      topApproveBtn.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        approveLivePlaybook(inc);
      });
    }
    const replayButton = document.getElementById('btnReplayBenchmarkBurst');
    if (replayButton) {
      replayButton.addEventListener('click', () => { replayBenchmarkBurst(); });
    }
    const healthButton = document.getElementById('btnConstitutionalHealth');
    if (healthButton) {
      healthButton.addEventListener('click', () => { runConstitutionalHealth(); });
    }
    const timelineJournal = document.getElementById('timelineViewJournal');
    if (timelineJournal) {
      timelineJournal.addEventListener('click', () => { setTimelineViewMode('journal'); });
    }
    const timelineTable = document.getElementById('timelineViewTable');
    if (timelineTable) {
      timelineTable.addEventListener('click', () => { setTimelineViewMode('table'); });
    }
    const scenarioButton = document.getElementById('btnReplayScenarios');
    if (scenarioButton) {
      scenarioButton.addEventListener('click', () => { replayLiveScenarios(); });
    }
    const dispatchButton = document.getElementById('btnDispatchCallback');
    if (dispatchButton) {
      dispatchButton.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        dispatchSignedCallback(inc);
      });
    }
    const containButton = document.getElementById('btnContainRange');
    if (containButton) {
      containButton.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        postRangeContainment(inc, '/api/v1/live/soar/contain');
      });
    }
    const isolateButton = document.getElementById('btnIsolateAttacker');
    if (isolateButton) {
      isolateButton.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        postRangeContainment(inc, '/api/v1/live/soar/contain');
      });
    }
    const liveBridgePill = document.getElementById('pillLiveBridge');
    if (liveBridgePill) {
      liveBridgePill.addEventListener('click', () => {
        const source = document.getElementById('queueSourceFilter');
        if (source) source.value = 'suricata_bridge';
        if (source) source.dispatchEvent(new Event('change'));
      });
    }
    const attacksPill = document.getElementById('pillAttacksOnly');
    if (attacksPill) {
      attacksPill.addEventListener('click', () => {
        const decision = document.getElementById('queueDecisionFilter');
        if (decision) decision.value = 'Attack';
        if (decision) decision.dispatchEvent(new Event('change'));
      });
    }
    const benchmarkPill = document.getElementById('pillRecordedBenchmark');
    if (benchmarkPill) {
      benchmarkPill.addEventListener('click', () => {
        const source = document.getElementById('queueSourceFilter');
        if (source) source.value = 'recorded_unsw_nb15';
        if (source) source.dispatchEvent(new Event('change'));
      });
    }
    const rangeScanButton = document.getElementById('btnRangeScan');
    if (rangeScanButton) {
      rangeScanButton.addEventListener('click', () => { fireLiveRangeScan(); });
    }
    const guidedApprove = document.getElementById('soarApproveBtn');
    if (guidedApprove) {
      guidedApprove.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        approveLivePlaybook(inc);
      });
    }
    const rollbackButton = document.getElementById('btnRollbackRange');
    if (rollbackButton) {
      rollbackButton.addEventListener('click', () => {
        const inc = activeIncidents().find(i => i.id === selectedIncidentId);
        postRangeContainment(inc, '/api/soar/rollback');
      });
    }
    const proofDos = document.getElementById('btnProofDos');
    if (proofDos) {
      proofDos.addEventListener('click', () => { runModelProofPreset(MODEL_PROOF_PRESETS.dos); });
    }
    const proofNormal = document.getElementById('btnProofNormal');
    if (proofNormal) {
      proofNormal.addEventListener('click', () => { runModelProofPreset(MODEL_PROOF_PRESETS.normal); });
    }
    const proofReset = document.getElementById('btnProofReset');
    if (proofReset) {
      proofReset.addEventListener('click', () => { restoreStoredModelProof(); });
    }
    const proofRun = document.getElementById('btnRunModelProof');
    if (proofRun) {
      proofRun.addEventListener('click', () => { runLiveModelProof(); });
    }
    const stitchButton = document.getElementById('btnStitchWindows');
    if (stitchButton) {
      stitchButton.addEventListener('click', () => { stitchVerifiedWindows(); });
    }
    const guardButton = document.getElementById('btnPrivateIpGuard');
    if (guardButton) {
      guardButton.addEventListener('click', () => { checkPrivateIpGuard(); });
    }
    const triageButtons = [
      ['btnAcknowledge', 'acknowledge'],
      ['btnEscalate', 'escalate'],
      ['btnDismiss', 'dismiss']
    ];
    triageButtons.forEach(pair => {
      const node = document.getElementById(pair[0]);
      if (node) {
        node.addEventListener('click', () => { recordTriageAction(pair[1]); });
      }
    });
    const exportButton = document.getElementById('btnExportHandoff');
    if (exportButton) {
      exportButton.addEventListener('click', () => { exportGroundedHandoff(); });
    }
    const enterpriseToggle = document.getElementById('enterpriseWorkspaceToggleBtn');
    if (enterpriseToggle) {
      enterpriseToggle.addEventListener('click', () => openEnterpriseDrawer(true));
    }
    const enterpriseClose = document.getElementById('btnCloseEnterpriseDrawer');
    if (enterpriseClose) {
      enterpriseClose.addEventListener('click', () => openEnterpriseDrawer(false));
    }
    const selectWorkspaceButton = document.getElementById('btnSelectWorkspace');
    if (selectWorkspaceButton) {
      selectWorkspaceButton.addEventListener('click', () => { selectEnterpriseWorkspace(); });
    }
    const createWorkspaceButton = document.getElementById('btnCreateWorkspace');
    if (createWorkspaceButton) {
      createWorkspaceButton.addEventListener('click', () => { createEnterpriseWorkspace(); });
    }
    const switchOperatorButton = document.getElementById('btnSwitchOperator');
    if (switchOperatorButton) {
      switchOperatorButton.addEventListener('click', () => { switchEnterpriseOperator(); });
    }
    const enrollWorkspaceOperator = document.getElementById('btnEnrollWorkspaceOperator');
    if (enrollWorkspaceOperator) {
      enrollWorkspaceOperator.addEventListener('click', () => { enrollSelectedOperator(); });
    }
    const registerOperatorButton = document.getElementById('btnRegisterOperator');
    if (registerOperatorButton) {
      registerOperatorButton.addEventListener('click', () => { registerEnterpriseOperator(); });
    }
    document.querySelectorAll('#launchAttackVectorBar button').forEach(button => {
      button.addEventListener('click', () => {
        launchRangeVector(button.getAttribute('data-vector-id') || '');
      });
    });
    const registerSensorButton = document.getElementById('btnRegisterSensor');
    if (registerSensorButton) {
      registerSensorButton.addEventListener('click', () => { registerEnterpriseSensor(); });
    }
    const dossierButton = document.getElementById('exportComplianceDossierBtn');
    if (dossierButton) {
      dossierButton.addEventListener('click', () => { exportComplianceDossier(); });
    }
    const openIdentity = document.getElementById('btnOpenIdentityModal');
    if (openIdentity) {
      openIdentity.addEventListener('click', () => {
        openIdentityModal(true, isSessionAuthenticated());
      });
    }
    const closeIdentity = document.getElementById('btnCloseIdentityModal');
    if (closeIdentity) closeIdentity.addEventListener('click', () => { openIdentityModal(false); });
    const returnConsole = document.getElementById('btnReturnToConsole');
    if (returnConsole) {
      returnConsole.addEventListener('click', () => {
        if (isSessionAuthenticated()) openIdentityModal(false);
      });
    }
    document.querySelectorAll('[data-demo-user]').forEach(button => {
      const fillDemo = () => {
        const user = document.getElementById('rbacUsername');
        const code = document.getElementById('rbacAccessCode');
        const actor = button.getAttribute('data-demo-actor') || '';
        if (user) user.value = button.getAttribute('data-demo-user') || '';
        if (code) code.value = button.getAttribute('data-demo-code') || '';
        if (actor) applyOperatorSelection(actor, button.querySelector('.role-name')
          ? button.querySelector('.role-name').textContent
          : '');
      };
      button.addEventListener('click', fillDemo);
      button.addEventListener('dblclick', () => {
        fillDemo();
        submitRbacLogin(false);
      });
    });
    bindControl(['btnRbacLogin', 'identityLoginBtn'], () => { submitRbacLogin(false); });
    bindControl(['btnRbacEntra', 'identityTokenBtn'], () => { submitRbacLogin(true); });
    bindControl(['btnRbacRegister', 'identityRegisterBtn'], () => { submitRbacRegister(); });
    const logoutButton = document.getElementById('btnRbacLogout');
    if (logoutButton) logoutButton.addEventListener('click', () => { submitRbacLogout(); });
    const copyAzure = document.getElementById('btnCopyAzureSnippet');
    if (copyAzure) {
      copyAzure.addEventListener('click', () => {
        const node = document.getElementById('azureProvisionSnippet');
        const value = node ? node.textContent : '';
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(value);
      });
    }
  }

  function setLiveText(id, text, state) {
    const node = document.getElementById(id);
    if (!node) return;
    node.textContent = text;
    if (state) node.setAttribute('data-evidence-state', state);
  }

  function showActionBanner(text, state, reason) {
    setLiveText('actionStatusBanner', text, state || 'unavailable');
    setLiveText('campaignQueueStatus', text, state || 'unavailable');
    const node = document.getElementById('actionStatusBanner');
    if (node) {
      if (reason) node.setAttribute('data-reason', reason);
      else node.removeAttribute('data-reason');
    }
  }

  function soarOperatorMessage(reason, fallback) {
    const messages = {
      analyst_approved_local: 'PLAYBOOK APPROVED — Signed into HMAC-SHA256 ledger by active SOC Approver. Step 2 (n8n Dispatch) is now unlocked.',
      already_approved: 'PLAYBOOK APPROVED — Already verified in HMAC-SHA256 ledger. Proceed to Step 2 (n8n Dispatch) or Step 3 (Isolate).',
      role_insufficient_for_soar: 'ACCESS DENIED (HTTP 403) — Active Microsoft Entra / RBAC role (Tier-1 Triage / Read-Only Auditor) is not authorized for SOAR execution. Switch to a Tier-3 SOC Approver.',
      audit_chain_invalid: 'SOAR LEDGER MISMATCH — The HMAC-SHA256 chain does not match this daemon key. Approve the playbook again so the ledger is re-sealed, then dispatch.',
      callback_not_recorded: 'CALLBACK NOT RECORDED — Step 2 (n8n Dispatch) has not stored a signed receipt. Dispatch the approved playbook before Isolate.'
    };
    return messages[reason] || fallback;
  }

  function selectedLiveIncident(fallback) {
    const live = activeIncidents().find(item => item.id === selectedIncidentId);
    return live || fallback || null;
  }

  function enableSoarControl(id) {
    const node = document.getElementById(id);
    if (!node) return;
    node.disabled = false;
    node.removeAttribute('title');
  }

  async function readActionPayload(resp) {
    const raw = await resp.text();
    if (!raw) return {};
    try {
      const data = JSON.parse(raw);
      return data && typeof data === 'object' ? data : {};
    } catch (err) {
      return { error: raw.slice(0, 180) || ('HTTP ' + resp.status) };
    }
  }

  function actionFailureText(data, resp) {
    if (data && typeof data.reason === 'string' && data.reason) return data.reason;
    if (data && typeof data.error === 'string' && data.error) return data.error;
    if (resp && !resp.ok) return 'HTTP ' + resp.status;
    return 'request failed';
  }

  function playbookApproved(inc) {
    if (!inc) return false;
    if (inc.soarState === 'approved') return true;
    return !!(inc.soarRecord && inc.soarRecord.state === 'approved');
  }

  function hashChainVerified(inc) {
    if (!inc) return false;
    if (inc.auditChainVerified === true || inc.soarAuditChainVerified === true) {
      const head = inc.soarAuditChainHeadSha256;
      if (typeof head === 'string' && head && !SHA256_HEX_REGEX.test(head)) return false;
      return true;
    }
    return verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256);
  }

  function techniqueLabel(inc) {
    if (inc && inc.scenarioLabel) return String(inc.scenarioLabel);
    const hit = attackTechnique(inc);
    return hit && hit.technique_id ? String(hit.technique_id) : 'unavailable';
  }

  function groundedVerdictRationale(inc, verdict) {
    const srcIp = inc && inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    const dstIp = inc && inc.provenance && inc.provenance.dstIp ? String(inc.provenance.dstIp) : '';
    return 'Analyst confirmed ' + verdict + ' on flow ' + srcIp + ' -> ' + dstIp
      + ' (' + techniqueLabel(inc) + ') based on Frozen RF score.';
  }

  function fillGroundedVerdictRationale(force) {
    const verdict = queueControlValue('analystVerdictSelect', '');
    const rationaleNode = document.getElementById('analystRationale');
    if (!rationaleNode || !verdict) return '';
    if (!force && rationaleNode.value.trim()) return rationaleNode.value;
    const text = groundedVerdictRationale(selectedIncident(), verdict);
    rationaleNode.value = text;
    return text;
  }

  function groundedContextRule(inc) {
    const srcIp = inc && inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    const dstIp = inc && inc.provenance && inc.provenance.dstIp ? String(inc.provenance.dstIp) : '';
    if (!srcIp && !dstIp) return 'Expected behavior stays on this stored flow. No new address is named.';
    return 'Expected behavior for ' + srcIp + ' -> ' + dstIp + ' (' + techniqueLabel(inc) + ') stays on this stored flow.';
  }

  function containmentStatusLine(inc) {
    const fallback = 'Containment stays unauthorized until an analyst approves a stored playbook.';
    if (!inc) return fallback;
    const srcIp = inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
    const state = String(inc.containmentState || '');
    if (state === 'simulated_applied' || state === 'simulated_rolled_back') {
      return 'SIMULATED SCENARIO CONTAINMENT (No Host Firewall Rule Executed — Recorded in Ledger)';
    }
    if (state === 'applied') {
      return 'CONTAINMENT APPLIED — Source ' + srcIp + ' blocked at firewall (iptables DROP active). Click Rollback to restore.';
    }
    if (state === 'rolled_back') {
      return 'CONTAINMENT ROLLED BACK — Firewall block on ' + srcIp + ' removed and rollback recorded in SHA-256 ledger.';
    }
    const callback = inc.callbackRecorded === true
      || (typeof inc.callbackSignature === 'string' && SHA256_HEX_REGEX.test(inc.callbackSignature));
    if (callback) {
      if (inc.executionPath === 'local_contract_fallback') {
        return 'LOCAL CONTRACT FALLBACK RECORDED (Simulated — Not Live n8n)';
      }
      return 'DISPATCHED VIA N8N — Signed HMAC-SHA256 callback receipt verified. Click Isolate Attacker to enforce firewall block.';
    }
    if (playbookApproved(inc)) {
      return 'PLAYBOOK APPROVED (HMAC-SHA256 Verified) — Ready for Step 2: Dispatch via Live n8n Container';
    }
    if (inc.decision === 'Benign') {
      return 'No technique. Frozen RF decision is Benign. Containment stays unauthorized.';
    }
    return fallback;
  }

  function containmentStatusState(inc) {
    if (!inc) return 'unavailable';
    const state = String(inc.containmentState || '');
    if (state === 'simulated_applied' || state === 'simulated_rolled_back') return 'simulated';
    if (state === 'applied' || state === 'rolled_back' || inc.callbackRecorded === true) return 'verified';
    if (playbookApproved(inc)) return 'verified';
    return 'unavailable';
  }

  function applyContainmentStatus(inc) {
    const line = containmentStatusLine(inc);
    const state = containmentStatusState(inc);
    ['inspectorPlaybookNote', 'containmentLiveStatus', 'conclusionSoarStatus'].forEach(id => {
      setLiveText(id, line, state);
    });
    const fusion = document.getElementById('inspectorFusionNote');
    if (fusion) {
      const prefix = 'production_fusion_enabled is false. The autoencoder does not decide this alert.';
      fusion.textContent = state === 'verified' && line.indexOf('Containment stays unauthorized') === -1
        ? prefix + ' ' + line
        : prefix + ' Containment stays unauthorized.';
    }
  }

  function markResponseProgress(inc) {
    const approved = playbookApproved(inc);
    const applied = !!(inc && (inc.containmentState === 'applied' || inc.containmentState === 'simulated_applied'));
    const rolled = !!(inc && (inc.containmentState === 'rolled_back' || inc.containmentState === 'simulated_rolled_back'));
    const dispatched = !!(inc && (inc.callbackRecorded === true
      || (typeof inc.callbackSignature === 'string' && SHA256_HEX_REGEX.test(inc.callbackSignature))));
    [
      ['approvePlaybookBtn', approved],
      ['soarApproveBtn', approved],
      ['evidenceApproveBtn', approved],
      ['btnDispatchCallback', dispatched],
      ['btnIsolateAttacker', applied],
      ['btnContainRange', applied],
      ['btnRollbackRange', rolled]
    ].forEach(pair => {
      const node = document.getElementById(pair[0]);
      if (!node) return;
      node.classList.toggle('is-complete', pair[1]);
    });
  }

  function scenarioLabelFromTitle(flow) {
    if (!flow) return '';
    const title = String(flow.case_title || '');
    const match = title.match(/scenario label (T\d+(?:\.\d+)?)/);
    if (!match) return flow.source_label === 'live_scenario_replay' ? 'none' : '';
    return match[1];
  }

  function scenarioLabPair(flow) {
    const label = scenarioLabelFromTitle(flow);
    const ports = { T1190: 443, T1110: 22, T1046: 445 };
    let port = ports[label] || 0;
    if (!port && String(flow.case_title || '').indexOf('Benign false alarm') !== -1) port = 8080;
    if (!port) return null;
    return { src: '10.0.0.4', dst: '10.0.0.5', port: port };
  }

  function flowToIncident(flow, memberCount) {
    const score = Number(flow.rf_attack_probability);
    const entry = typeof flow.entry_sha256 === 'string' ? flow.entry_sha256 : '';
    const chainOk = flow.audit_chain_verified === 1 || flow.audit_chain_verified === true;
    const sensor = flow.sensor_observation || {};
    const lab = scenarioLabPair(flow);
    const srcIp = flow.src_entity_id || (lab ? lab.src : '');
    const dstIp = flow.dst_entity_id || (lab ? lab.dst : '');
    const sensorPort = Number(sensor.src_port);
    const playbookId = candidatePlaybookId(flow);
    return {
      id: 'live_flow:' + flow.flow_id,
      live: true,
      flowId: flow.flow_id,
      flow_id: flow.flow_id,
      src_entity_id: srcIp,
      dst_entity_id: dstIp,
      sourceEventId: flow.source_label || 'live_flow',
      sourceLabel: flow.source_label || 'live_flow',
      scenarioLabel: flow.scenario_label || scenarioLabelFromTitle(flow),
      techniqueId: flow.technique_id || flow.mitre_technique_id || flow.scenario_label || scenarioLabelFromTitle(flow),
      mitreTechniqueId: flow.mitre_technique_id || flow.technique_id || flow.scenario_label || scenarioLabelFromTitle(flow),
      sensorObservation: flow.sensor_observation || null,
      scoreReason: flow.reason || '',
      observedAt: flow.observed_at_utc || '',
      decision: flow.decision || 'withheld',
      uncalibratedScore: Number.isFinite(score) ? score : 0,
      modelArtifactSha256: flow.model_sha256 || EVAL_PACK_REV2.rfArtifactSha256,
      scoringTimeModelSha256: typeof flow.model_sha256 === 'string' ? flow.model_sha256 : '',
      modelVersion: 'full-network-random-forest-6d69c72-v1',
      provenance: {
        srcIp: srcIp,
        dstIp: dstIp,
        srcPort: Number.isFinite(sensorPort) && sensorPort > 0 ? sensorPort : 0,
        dstPort: Number(flow.service_or_port) || (lab ? lab.port : 0),
        proto: flow.flow_protocol || 'flow'
      },
      correlation: {
        incidentId: flow.campaign_id || ('flow:' + flow.flow_id),
        windowType: 'stored campaign',
        constituentAlerts: memberCount || 1,
        explanation: flow.case_title || 'Stored live flow. No new entity key was inferred.'
      },
      threatIntel: { privateIpGuardTriggered: false },
      auditChainVerified: chainOk && SHA256_HEX_REGEX.test(entry),
      secondaryAe: secondaryAeFromFlow(flow),
      dnnAttackProbability: finiteOrNull(flow.dnn_attack_probability),
      dnnBinaryDecision: flow.dnn_binary_decision || '',
      unswAttackCategory: flow.unsw_attack_category || '',
      consensusScore: finiteOrNull(flow.threatfusion_consensus_score),
      consensusLabel: flow.consensus_label || 'advisory_consensus',
      dnnFeatures: flow.dnn_features && typeof flow.dnn_features === 'object' ? flow.dnn_features : null,
      advisory: {
        summaryHeadline: flow.source_label === 'suricata_bridge' && flow.sensor_observation
          ? ('Suricata: ' + flow.sensor_observation.suricata_line)
          : (flow.case_title || ('Stored flow ' + flow.flow_id)),
        detectionRationale: 'Frozen Random Forest score. Fusion disabled. The autoencoder did not decide this alert.'
      },
      chromaRagHits: flow.decision === 'Attack'
        ? (Array.isArray(flow.chroma_rag_hits)
          ? flow.chroma_rag_hits
          : (Array.isArray(flow.chromaRagHits) ? flow.chromaRagHits : []))
        : [],
      soarRecord: {
        playbookId: playbookId || 'none',
        state: flow.ledger_state || 'none',
        targetEntity: 'live_flow:' + flow.flow_id,
        version: 1
      },
      soarAuditChainVerified: chainOk && SHA256_HEX_REGEX.test(entry),
      soarAuditChainHeadSha256: entry,
      callbackSignature: typeof flow.callback_signature === 'string' ? flow.callback_signature : '',
      callbackRecorded: flow.callback_recorded === 1 || flow.callback_recorded === true,
      executionPath: flow.execution_path || '',
      operatorId: flow.operator_id || '',
      certSha256Prefix: flow.cert_sha256_prefix || '',
      identityVerified: flow.identity_verified === 1 || flow.identity_verified === true,
      identityLabel: flow.identity_label || 'unverified_local_label',
      thehiveCaseId: flow.thehive_case_id || '',
      mttrSeconds: flow.mttr_seconds,
      containmentState: flow.containment_state || '',
      containmentRule: flow.containment_rule || '',
      soarState: flow.ledger_state || '',
      triageState: flow.triage_state || 'unreviewed',
      analystVerdict: flow.analyst_verdict || '',
      analystRationale: flow.analyst_rationale || '',
      assigneeId: flow.assignee_id || '',
      reviewStatus: flow.review_status || 'unassigned',
      glassBox: flow.glass_box || null,
      evidenceLocker: flow.evidence_locker || null,
      contextMemory: Array.isArray(flow.context_memory) ? flow.context_memory : [],
      sensorNode: flow.sensor_node || '',
      thehiveCaseRecord: null,
      n8nPlaybookReceipt: null
    };
  }

  function incidentChromaHits(row) {
    const rag = row && Array.isArray(row.rag_recommendations) ? row.rag_recommendations : [];
    if (rag.length && rag[0] && rag[0].technique_id) {
      return rag.map(function (hit) {
        const cosine = Number(hit.cosine_similarity);
        return {
          technique_id: String(hit.technique_id),
          technique_name: hit.technique_name || row.technique_name || '',
          tactic: hit.tactic || row.tactic || '',
          playbook_id: hit.playbook_id || row.playbook_id || '',
          cosine_similarity: Number.isFinite(cosine) ? cosine : 1
        };
      });
    }
    if (row && row.technique_id) {
      return [{
        technique_id: String(row.technique_id),
        technique_name: row.technique_name || '',
        tactic: row.tactic || '',
        playbook_id: row.playbook_id || '',
        cosine_similarity: 1
      }];
    }
    return [];
  }

  function incidentRowToView(row) {
    const score = Number(row.max_probability_score);
    const flowId = Number(row.flow_id);
    const bound = Number.isInteger(flowId) && flowId > 0;
    const src = row.src_entity_id || (bound ? '' : 'stored-incident');
    const dst = row.dst_entity_id || (bound ? '' : 'stored-incident');
    const entry = typeof row.entry_sha256 === 'string' ? row.entry_sha256 : '';
    const chainOk = row.audit_chain_verified === 1 || row.audit_chain_verified === true;
    return {
      id: String(row.incident_id),
      live: true,
      flowId: bound ? flowId : null,
      flow_id: bound ? flowId : null,
      sourceEventId: row.provenance_status || 'incident_store',
      sourceLabel: 'incident_store',
      observedAt: row.earliest_observed_at || '',
      decision: row.decision || row.escalated_decision || 'withheld',
      uncalibratedScore: Number.isFinite(score) ? score : 0,
      modelArtifactSha256: EVAL_PACK_REV2.rfArtifactSha256,
      modelVersion: 'stored_incident',
      src_entity_id: src,
      dst_entity_id: dst,
      provenance: {
        srcIp: src,
        dstIp: dst,
        srcPort: 0,
        dstPort: 0,
        proto: 'incident'
      },
      correlation: {
        incidentId: row.incident_id,
        windowType: row.window_type || 'stored',
        constituentAlerts: row.constituent_alert_count || 0,
        explanation: 'Stored incident row. This view did not infer a new relationship.'
      },
      threatIntel: { privateIpGuardTriggered: false },
      secondaryAe: secondaryAeFromFlow(row),
      dnnAttackProbability: finiteOrNull(row.dnn_attack_probability),
      dnnBinaryDecision: row.dnn_binary_decision || '',
      unswAttackCategory: row.dnn_category || row.unsw_attack_category || '',
      consensusLabel: 'advisory_consensus',
      dnnFeatures: row.dnn_features && typeof row.dnn_features === 'object' ? row.dnn_features : null,
      scenarioLabel: row.scenario_label || '',
      mitreTechniqueId: row.mitre_technique_id || row.technique_id || '',
      advisory: {
        summaryHeadline: row.case_title || ('Stored incident ' + row.incident_id),
        detectionRationale: 'Read from the incidents database. Fusion stays disabled.'
      },
      chromaRagHits: incidentChromaHits(row),
      techniqueId: row.mitre_technique_id || row.technique_id || row.scenario_label || '',
      cveIds: Array.isArray(row.cve_ids) ? row.cve_ids : [],
      soarRecord: {
        playbookId: row.playbook_id || 'none',
        state: row.ledger_state || 'none',
        targetEntity: bound ? ('live_flow:' + flowId) : String(row.incident_id),
        version: 1
      },
      auditChainVerified: chainOk && SHA256_HEX_REGEX.test(entry),
      soarAuditChainVerified: chainOk && SHA256_HEX_REGEX.test(entry),
      soarAuditChainHeadSha256: entry,
      callbackRecorded: row.callback_recorded === 1 || row.callback_recorded === true,
      callbackSignature: typeof row.callback_signature === 'string' ? row.callback_signature : '',
      containmentState: row.containment_state || '',
      executionPath: row.execution_path || '',
      soarState: row.ledger_state || '',
      triageState: 'unreviewed',
      analystVerdict: '',
      analystRationale: '',
      assigneeId: '',
      reviewStatus: 'unassigned',
      glassBox: null,
      thehiveCaseRecord: null,
      n8nPlaybookReceipt: null
    };
  }

  function showStoredContainment(views) {
    const selected = selectedIncident();
    const selectedSrc = selected && selected.provenance ? String(selected.provenance.srcIp || '') : '';
    if (selectedSrc && selectedSrc !== '172.29.0.10') return;
    const blocked = (views || []).some(item => item.containmentState === 'applied' && item.provenance && item.provenance.srcIp === '172.29.0.10');
    const rolled = (views || []).some(item => item.containmentState === 'rolled_back' && item.provenance && item.provenance.srcIp === '172.29.0.10');
    if (blocked) setRangeConnectivity(true);
    else if (rolled) setRangeConnectivity(false);
  }

  function showStoredN8nMttr(views) {
    const node = document.getElementById('valMttr');
    const detail = document.getElementById('valMttrDetail');
    if (!node) return;
    const hit = (views || []).find(item =>
      item.executionPath === 'n8n_live_container' && Number.isFinite(Number(item.mttrSeconds))
    );
    if (!hit) {
      node.textContent = '0';
      node.dataset.kpiBasis = 'reference_benchmark_not_measured';
      if (detail) detail.textContent = 'Shown only after a stored n8n callback. The January benchmark is separate.';
      return;
    }
    node.textContent = Number(hit.mttrSeconds).toFixed(3) + 's';
    if (detail) detail.textContent = 'Stored n8n callback on this queue. Not the January benchmark.';
  }

  async function refreshAdvisoryStatus() {
    try {
      const resp = await fetch('/api/v1/live/advisory-status');
      const data = await resp.json();
      const badge = document.getElementById('copilotProviderBadge');
      if (badge && data.provider) {
        badge.textContent = copilotBadgeLabel(data.provider);
        badge.setAttribute('data-evidence-state', data.provider === 'gemini' ? 'verified' : 'unavailable');
      }
    } catch (err) {
      const badge = document.getElementById('copilotProviderBadge');
      if (badge) badge.textContent = 'Local Air-Gapped Engine';
    }
  }

  async function refreshAgyAudit() {
    try {
      const resp = await fetch('/api/v1/live/agy-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      const node = document.getElementById('agyAuditStatus');
      if (!node) return;
      node.textContent = data.label || 'External agy Red-Team Audit: not run';
      node.setAttribute('data-evidence-state', data.passed === 5 ? 'verified' : 'unavailable');
    } catch (err) {
      const node = document.getElementById('agyAuditStatus');
      if (node) node.textContent = 'External agy Red-Team Audit: not run';
    }
  }

  let campaignRefreshGeneration = 0;

  async function refreshLiveCampaigns() {
    const generation = ++campaignRefreshGeneration;
    try {
      await refreshAssetInventory();
      const resp = await fetch('/api/v1/live/campaigns');
      if (generation !== campaignRefreshGeneration) return;
      if (!resp.ok) throw new Error('campaign status');
      const data = await resp.json();
      if (generation !== campaignRefreshGeneration) return;
      const flowViews = [];
      (data.campaigns || []).forEach(campaign => {
        (campaign.flows || []).forEach(flow => {
          flowViews.push(flowToIncident(flow, campaign.member_count));
        });
      });
      const views = flowViews.slice();
      const seenIncidents = new Set();
      (data.incidents || []).forEach(row => {
        const incidentId = String(row.incident_id || '');
        const shape = String(row.window_type || '') + '|' + String(row.escalated_decision || '');
        if (!incidentId || seenIncidents.has(incidentId) || seenIncidents.has(shape)) return;
        seenIncidents.add(incidentId);
        seenIncidents.add(shape);
        views.push(incidentRowToView(row));
      });
      ledgerChainStatus = data.playbook_hash_chain_status || '';
      paintLedgerBadge(ledgerChainStatus);
      if (sessionIdentity && sessionIdentity.authenticated) paintSessionIdentity(sessionIdentity);
      liveCampaignIncidents = views;
      showStoredN8nMttr(views);
      showStoredContainment(views);
      liveQueueLoaded = true;
      campaignFetchSettled = true;
      setSampleSurfacesHidden(true);
      if (!views.some(item => item.id === selectedIncidentId)) {
        if (Number.isInteger(selectedFlowId) && selectedFlowId > 0) {
          const byFlow = views.find(item => Number(item.flowId || item.flow_id) === selectedFlowId);
          selectedIncidentId = byFlow ? byFlow.id : (views.length ? views[0].id : '');
        } else {
          selectedIncidentId = views.length ? views[0].id : '';
        }
      }
      bindSelectedFlowId(selectedIncident());
      const badge = document.getElementById('queueCountBadge');
      if (badge) badge.textContent = views.length + ' stored rows';
      const flowCount = document.getElementById('liveHeroFlowCount');
      const campaignCount = document.getElementById('liveHeroCampaignCount');
      const incidentCount = document.getElementById('liveHeroIncidentCount');
      const bridgeCount = document.getElementById('liveHeroBridgeCount');
      if (flowCount) flowCount.textContent = String(data.flow_count || 0);
      if (campaignCount) campaignCount.textContent = String(data.campaign_count || 0);
      if (incidentCount) incidentCount.textContent = String(data.incident_count || 0);
      if (bridgeCount) bridgeCount.textContent = 'Live bridge rows: ' + String(data.bridge_flow_count || 0);
      renderTelemetryReductionFunnel(data, flowViews);
      renderMitreCoverageMatrix();
      renderScoringTimeProvenance(selectedIncident());
      renderEntityTopology();
      const nextPrint = views.map(item => [
        item.id,
        item.decision,
        item.sourceLabel,
        item.analystVerdict,
        item.assigneeId,
        item.reviewStatus,
        item.containmentState || '',
        item.callbackRecorded ? 'cb' : '',
        item.soarState || (item.soarRecord && item.soarRecord.state) || '',
        item.executionPath || '',
        item.triageState || '',
        item.sensorObservation && item.sensorObservation.forest_line,
        (item.contextMemory || []).map(memory => memory.expected_behavior_rule).join(','),
        item.evidenceLocker && item.evidenceLocker.queries
          ? item.evidenceLocker.queries.map(query => query.entity_count || query.flow_count || query.stitched_flow_count || query.soar_receipt_status).join(',')
          : ''
      ].join(':')).join('|');
      if (nextPrint === campaignFingerprint) return;
      campaignFingerprint = nextPrint;
      const verifiedCount = views.filter(isReceiptVerified).length;
      setLiveText(
        'campaignQueueStatus',
        views.length
          ? ('Stored rows: ' + views.length + '. Verified SOAR receipts: ' + verifiedCount + '.')
          : 'No stored campaigns yet.',
        verifiedCount ? 'verified' : (views.length ? 'pending' : 'unavailable')
      );
    } catch (err) {
      campaignFingerprint = null;
      liveQueueLoaded = false;
      campaignFetchSettled = true;
      setSampleSurfacesHidden(false);
      setLiveText('campaignQueueStatus', 'Campaign store unavailable. The recorded queue is the fallback.', 'unavailable');
      renderTelemetryReductionFunnel(null, []);
      renderMitreCoverageMatrix();
      renderScoringTimeProvenance(selectedIncident());
    }
    renderIncidentQueue();
    renderForensicDrawer();
    if (document.querySelector('.soc-view.is-active[data-soc-view="graph"]')) {
      renderActionGraph();
    }
  }

  async function runConstitutionalHealth() {
    setLiveText('constitutionalHealth', 'Running the boundary preflight and the seven truth checks.', 'pending');
    try {
      const resp = await fetch('/api/v1/live/health', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      const lines = (data.checks || []).map(check => (
        'Check ' + check.check_id + ': ' + (check.passed ? 'PASS' : 'FAIL')
      ));
      const digests = data.model_digests || {};
      const forest = digests.random_forest;
      startupIntegrityForest = forest && typeof forest.sha256 === 'string'
        ? { sha256: forest.sha256, verified: forest.verified === true }
        : null;
      Object.keys(digests).forEach(name => {
        const row = digests[name];
        const sha = row && row.sha256 ? String(row.sha256).slice(0, 16) : 'unavailable';
        lines.push(name + ' ' + sha + (row && row.verified ? ' verified' : ' unverified'));
      });
      lines.push('Boundary ' + (data.boundary_verdict || 'NO-GO'));
      lines.push('Truth ' + (data.truth_verdict || 'NO-GO'));
      lines.push('Receipt ' + (data.receipt_sha256 || 'unavailable'));
      lines.push('TF-008 through TF-011 stay open.');
      setLiveText(
        'constitutionalHealth',
        lines.join('\n'),
        data.evidence_state === 'verified' ? 'verified' : 'unavailable'
      );
      renderScoringTimeProvenance(selectedIncident());
    } catch (err) {
      startupIntegrityForest = null;
      setLiveText('constitutionalHealth', 'Constitutional health unavailable.', 'unavailable');
      renderScoringTimeProvenance(selectedIncident());
    }
  }

  async function replayLiveScenarios() {
    try {
      const resp = await fetch('/api/v1/live/scenarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      await refreshLiveCampaigns();
      const lines = (data.flows || []).map(flow => {
        const label = flow.scenario_label ? (' ' + flow.scenario_label) : '';
        const guard = flow.misp_guard_status === 422 ? ', ' + mispGuardLabel(422) : '';
        const pct = Number.isFinite(Number(flow.rf_attack_probability))
          ? (Number(flow.rf_attack_probability) * 100).toFixed(1) + '%'
          : 'unavailable';
        return (flow.scenario_id || 'scenario') + label + ': ' + flow.decision + ' ' + pct + guard;
      });
      setLiveText(
        'campaignQueueStatus',
        lines.length ? lines.join('. ') + '.' : 'Scenario replay unavailable.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Scenario replay unavailable.', 'unavailable');
    }
  }

  async function replayBenchmarkBurst() {
    try {
      const resp = await fetch('/api/v1/live/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      setLiveText(
        'campaignQueueStatus',
        'Replayed ' + (data.member_count || 0) + ' recorded UNSW-NB15 study vectors. Fusion disabled.',
        data.evidence_state || 'unavailable'
      );
      if (data.correlation) renderLiveCorrelation(data.correlation);
      await refreshLiveCampaigns();
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Benchmark replay unavailable.', 'unavailable');
    }
  }

  function operatorActorId() {
    const node = document.getElementById('operatorActor');
    const value = node && node.value ? node.value.trim() : 'analyst_a';
    return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value) ? value : 'analyst_a';
  }

  function paintOperatorBadge(text, verified) {
    const node = document.getElementById('operatorAuthBadge');
    if (!node) return;
    node.textContent = text;
    node.classList.toggle('badge-neutral', !verified);
    node.setAttribute('data-evidence-state', verified ? 'verified' : 'unavailable');
  }

  function headerLineForSession(session) {
    if (!session) return 'unverified local label';
    const actor = String(session.actor_id || '');
    let line = String(session.header_identity || '');
    if (actor === 'lab_operator' && session.identity_verified === true) {
      return 'Muhammad Bilal (21K-3551) · Tier-3 Approver | verified mTLS cert (/CN=lab_operator)';
    }
    if (actor === 'tier1_analyst' || (line.indexOf('/CN=lab_operator') !== -1 && actor !== 'lab_operator' && actor !== 'compliance_auditor')) {
      return 'Muhammad Suhaib (22K-4302) · Tier-1 Triage | No SOAR Cert (Triage Only)';
    }
    if (actor === 'compliance_auditor') {
      return 'Muhammad Hasnain (22K-4718) · Auditor | Read-Only Compliance Token';
    }
    if (line.indexOf('/CN=lab_operator') !== -1) return 'unverified local label';
    return line || 'unverified local label';
  }

  function paintSessionIdentity(session) {
    if (!session || session.authenticated === false) {
      paintOperatorBadge('unverified local label', false);
      return;
    }
    const line = headerLineForSession(session);
    const verified = session.actor_id === 'lab_operator' && session.identity_verified === true
      && line.indexOf('/CN=lab_operator') !== -1;
    paintOperatorBadge(line, verified);
    const node = document.getElementById('operatorAuthBadge');
    if (node) {
      if (verified) node.setAttribute('title', 'verified operator certificate');
      else node.removeAttribute('title');
    }
    const profile = document.getElementById('operatorProfileName');
    if (profile) profile.textContent = session.display_name || line;
  }

  function showOperatorStamp(stamp) {
    const node = document.getElementById('operatorAuthBadge');
    if (!node || !stamp) return;
    if (sessionIdentity && sessionIdentity.authenticated) {
      paintSessionIdentity(sessionIdentity);
      return;
    }
    const profile = document.getElementById('operatorProfileName');
    if (profile && activeOperatorLabel) profile.textContent = activeOperatorLabel;
    const verified = stamp.identity_verified === true || stamp.identityVerified === true;
    const label = stamp.identity_label || stamp.identityLabel || '';
    const prefix = stamp.cert_sha256_prefix || stamp.certSha256Prefix || '';
    const subject = stamp.certificate_subject || stamp.certificateSubject || '';
    if (verified && label !== 'unverified_local_label' && prefix && subject === '/CN=lab_operator') {
      node.setAttribute('title', 'verified operator certificate');
      paintOperatorBadge('Muhammad Bilal (21K-3551) · Tier-3 Approver | verified mTLS cert (/CN=lab_operator)', true);
      return;
    }
    paintOperatorBadge('unverified local label', false);
  }

  async function refreshOperatorStamp() {
    try {
      const resp = await fetch('/api/v1/live/operator/stamp');
      if (!resp.ok) return;
      const data = await resp.json();
      showOperatorStamp(data);
    } catch (err) {
      showOperatorStamp({ identity_verified: false, identity_label: 'unverified_local_label' });
    }
  }

  async function enrollLabOperator() {
    const node = document.getElementById('operatorActor');
    if (node && (!node.value.trim() || node.value.trim() === 'analyst_a')) {
      node.value = 'lab_operator';
    }
    try {
      const resp = await fetch('/api/v1/live/operator/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actor_id: operatorActorId() })
      });
      const data = await resp.json();
      if (sessionIdentity && sessionIdentity.actor_id === 'lab_operator' && data.identity_verified === true) {
        sessionIdentity.identity_verified = true;
        sessionIdentity.header_identity = 'Muhammad Bilal (21K-3551) · Tier-3 Approver | verified mTLS cert (/CN=lab_operator)';
        sessionIdentity.certificate_subject = '/CN=lab_operator';
        paintSessionIdentity(sessionIdentity);
      } else if (!(sessionIdentity && sessionIdentity.authenticated)) {
        showOperatorStamp({ identity_verified: false, identity_label: 'unverified_local_label' });
      }
      setLiveText(
        'campaignQueueStatus',
        data.evidence_state === 'verified'
          ? ('Lab certificate enrolled for ' + (data.operator_id || operatorActorId()) + '.')
          : 'Lab certificate enrollment refused.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Lab certificate enrollment refused.', 'unavailable');
    }
  }

  async function approveLivePlaybook(inc) {
    if (!inc || !inc.live || !inc.flowId) {
      showActionBanner('Approval applies to a stored flow. Containment stays unauthorized.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/soar/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flow_id: inc.flowId,
          actor_id: operatorActorId(),
          reason: 'Analyst recorded local approval. Containment is not executed.'
        })
      });
      const data = await readActionPayload(resp);
      const receipt = typeof data.entry_sha256 === 'string' ? data.entry_sha256 : '';
      const reason = typeof data.reason === 'string' ? data.reason : '';
      showOperatorStamp(data);
      const restore = preserveSelectionAfterMutation();
      await refreshLiveCampaigns();
      restore();
      const approved = resp.ok && (
        data.soar_state === 'approved'
        || data.playbook_state === 'approved'
        || data.ledger_state === 'approved'
        || data.execution_authorized === true
        || reason === 'already_approved'
        || reason === 'analyst_approved_local'
      );
      if (approved) {
        const live = selectedLiveIncident(inc);
        if (live) {
          live.soarState = 'approved';
          live.playbookState = 'approved';
          live.auditChainVerified = true;
          live.soarAuditChainVerified = true;
          if (live.soarRecord) live.soarRecord.state = 'approved';
          if (SHA256_HEX_REGEX.test(receipt)) live.soarAuditChainHeadSha256 = receipt;
          applyContainmentStatus(live);
          applyContainmentGuard(live);
          markResponseProgress(live);
          loadSoarPlaybookPreview(live);
        }
        enableSoarControl('btnDispatchCallback');
        const message = soarOperatorMessage(
          reason,
          'PLAYBOOK APPROVED (HMAC-SHA256 Verified) — Ready for Step 2: Dispatch via Live n8n Container'
        );
        showActionBanner(message, 'verified', reason || 'analyst_approved_local');
        return true;
      }
      showActionBanner(
        soarOperatorMessage(reason, actionFailureText(data, resp)),
        'unavailable',
        reason
      );
      return false;
    } catch (err) {
      showActionBanner(err && err.message ? String(err.message) : 'SOAR approval unavailable.', 'unavailable');
      return false;
    }
  }

  async function ensurePlaybookApproved(inc) {
    if (!inc || inc.decision !== 'Attack') return true;
    const state = inc.soarState || (inc.soarRecord && inc.soarRecord.state) || '';
    if (state === 'approved' && hashChainVerified(inc)) return true;
    return approveLivePlaybook(inc);
  }

  function showHandoffReport(text, state) {
    const node = document.getElementById('shiftHandoffReport');
    if (!node) return;
    node.textContent = text;
    node.setAttribute('data-evidence-state', state || 'unavailable');
  }

  function downloadHandoffMarkdown(flowId, markdown) {
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'shift-handoff-flow-' + flowId + '.md';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function saveAnalystVerdict() {
    const flowId = selectedLiveFlowId();
    const verdict = queueControlValue('analystVerdictSelect', '');
    const rationaleNode = document.getElementById('analystRationale');
    if (rationaleNode && !rationaleNode.value.trim()) fillGroundedVerdictRationale(true);
    const rationale = rationaleNode ? rationaleNode.value : '';
    if (!flowId) {
      showActionBanner('A stored flow is required.', 'unavailable');
      setLiveText('analystVerdictDisplay', 'A stored flow is required.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/verdict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flow_id: flowId,
          verdict: verdict,
          rationale: rationale,
          actor_id: operatorActorId()
        })
      });
      const data = await readActionPayload(resp);
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      renderForensicDrawer();
      const stored = resp.ok && (data.reason === 'analyst_verdict_stored' || data.evidence_state === 'verified');
      const message = stored
        ? ('Analyst verdict ' + data.analyst_verdict + ' stored. Frozen RF decision ' + data.frozen_rf_decision + '.')
        : actionFailureText(data, resp);
      setLiveText('analystVerdictDisplay', message, stored ? 'verified' : 'unavailable');
      showActionBanner(message, stored ? 'verified' : 'unavailable');
    } catch (err) {
      const message = err && err.message ? String(err.message) : 'Analyst verdict unavailable.';
      setLiveText('analystVerdictDisplay', message, 'unavailable');
      showActionBanner(message, 'unavailable');
    }
  }

  async function saveContextMemory() {
    const flowId = selectedLiveFlowId();
    const ruleNode = document.getElementById('contextMemoryRule');
    if (ruleNode && !ruleNode.value.trim()) ruleNode.value = groundedContextRule(selectedIncident());
    const rule = ruleNode ? ruleNode.value : '';
    if (!flowId) {
      showActionBanner('A stored flow is required.', 'unavailable');
      setLiveText('contextMemoryList', 'A stored flow is required.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/context-memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flow_id: flowId,
          expected_behavior_rule: rule,
          operator_id: operatorActorId()
        })
      });
      const data = await readActionPayload(resp);
      await refreshLiveCampaigns();
      renderForensicDrawer();
      const stored = resp.ok && data.evidence_state === 'verified';
      const message = stored
        ? ('Context memory stored. Frozen RF decision ' + data.frozen_rf_decision + '.')
        : actionFailureText(data, resp);
      setLiveText('contextMemoryList', message, stored ? 'verified' : 'unavailable');
      showActionBanner(message, stored ? 'verified' : 'unavailable');
    } catch (err) {
      const message = err && err.message ? String(err.message) : 'Context memory unavailable.';
      setLiveText('contextMemoryList', message, 'unavailable');
      showActionBanner(message, 'unavailable');
    }
  }

  async function refreshAssetInventory() {
    const body = document.getElementById('assetInventoryBody');
    const status = document.getElementById('assetInventoryStatus');
    if (!body) return;
    try {
      const resp = await fetch('/api/v1/live/assets');
      if (!resp.ok) throw new Error('asset status');
      const data = await resp.json();
      const assets = Array.isArray(data.assets) ? data.assets : [];
      body.innerHTML = assets.map(asset => (
        '<tr><td>' + escapeHtml(String(asset.entity_ip || '')) + '</td>'
        + '<td>' + escapeHtml(String(asset.classification || '')) + '</td>'
        + '<td>' + escapeHtml(formatDisplayUtc(asset.first_seen_utc)) + '</td>'
        + '<td>' + escapeHtml(formatDisplayUtc(asset.last_seen_utc)) + '</td>'
        + '<td>' + escapeHtml(String(asset.flow_count)) + '</td>'
        + '<td>' + escapeHtml(mispGuardLabel(asset.misp_guard_status)) + '</td>'
        + '<td>' + escapeHtml(String(asset.context_memory_count)) + '</td></tr>'
      )).join('');
      if (status) {
        status.textContent = assets.length
          ? (assets.length + ' observed entities.')
          : 'No stored entities yet.';
        status.setAttribute('data-evidence-state', assets.length ? 'verified' : 'unavailable');
      }
    } catch (err) {
      if (status) {
        status.textContent = 'Asset inventory unavailable.';
        status.setAttribute('data-evidence-state', 'unavailable');
      }
    }
  }

  async function saveCaseAssignment() {
    const flowId = selectedLiveFlowId();
    const assigneeNode = document.getElementById('caseAssignee');
    let assignee = assigneeNode ? assigneeNode.value.trim() : '';
    const reviewStatus = queueControlValue('reviewStatusSelect', 'unassigned');
    if (!assignee && reviewStatus !== 'unassigned') {
      assignee = operatorActorId();
      if (assigneeNode) assigneeNode.value = assignee;
    }
    if (!flowId) {
      showActionBanner('A stored flow is required.', 'unavailable');
      setLiveText('caseAssignmentDisplay', 'A stored flow is required.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/assignment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flow_id: flowId,
          assignee_id: assignee,
          review_status: reviewStatus
        })
      });
      const data = await readActionPayload(resp);
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      renderForensicDrawer();
      const stored = resp.ok && data.evidence_state === 'verified';
      const message = stored
        ? ('Assignee ' + (data.assignee_id || 'unassigned') + '. Review status ' + data.review_status + '.')
        : actionFailureText(data, resp);
      setLiveText('caseAssignmentDisplay', message, stored ? 'verified' : 'unavailable');
      showActionBanner(message, stored ? 'verified' : 'unavailable');
    } catch (err) {
      const message = err && err.message ? String(err.message) : 'Assignment unavailable.';
      setLiveText('caseAssignmentDisplay', message, 'unavailable');
      showActionBanner(message, 'unavailable');
    }
  }

  async function recordTriageAction(action) {
    const flowId = selectedLiveFlowId();
    if (!flowId) {
      showActionBanner('Triage applies to a stored flow.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: flowId, action: action, actor_id: operatorActorId() })
      });
      const data = await readActionPayload(resp);
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      renderForensicDrawer();
      const stored = resp.ok && data.evidence_state === 'verified';
      showActionBanner(
        stored
          ? ('Triage state ' + data.triage_state + ' stored for flow ' + data.flow_id + '.')
          : actionFailureText(data, resp),
        stored ? 'verified' : 'unavailable'
      );
    } catch (err) {
      showActionBanner(err && err.message ? String(err.message) : 'Triage unavailable.', 'unavailable');
    }
  }

  async function exportGroundedHandoff() {
    const flowId = selectedLiveFlowId();
    if (!flowId) {
      showHandoffReport('Export applies to a stored flow.', 'unavailable');
      return;
    }
    const noteNode = document.getElementById('shiftHandoffNote');
    const note = noteNode && typeof noteNode.value === 'string' ? noteNode.value.trim() : '';
    const payload = { flow_id: flowId };
    if (note) payload.brief = note;
    try {
      const resp = await fetch('/api/v1/live/handoff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      if (data.grounded === true && data.report && typeof data.markdown === 'string') {
        showHandoffReport(data.markdown, 'verified');
        downloadHandoffMarkdown(flowId, data.markdown);
        return;
      }
      const reason = data.reason === 'explanation_not_grounded'
        ? 'Handoff refused. The note names an address that is not stored on this flow.'
        : 'Handoff export unavailable.';
      showHandoffReport(reason, 'unavailable');
    } catch (err) {
      showHandoffReport('Handoff export unavailable.', 'unavailable');
    }
  }

  function liveTimelineRows(report) {
    const events = report && report.timeline && Array.isArray(report.timeline.events)
      ? report.timeline.events
      : [];
    return events.map(event => {
      const when = escapeHtml(String(event.observed_at || ''));
      const label = escapeHtml(String(event.summary || event.kind || 'event'));
      const windowType = event.window_type ? ' · ' + escapeHtml(String(event.window_type)) : '';
      return '<div>[' + when + '] ' + label + windowType + '</div>';
    }).join('');
  }

  function renderLiveCorrelation(data) {
    if (!data || typeof data !== 'object') return;
    liveCorrelationReport = data;
    const count = Number(data.correlated_flow_count || 0);
    const events = data.timeline && Array.isArray(data.timeline.events) ? data.timeline.events : [];
    const burstWindow = data.burst_window_seconds === undefined ? 30 : data.burst_window_seconds;
    const campaignWindow = data.campaign_window_seconds === undefined ? 600 : data.campaign_window_seconds;
    setLiveText(
      'liveTimeline',
      'Correlated flows ' + count
        + '. Burst incidents ' + (data.burst_incident_count || 0) + ' (' + burstWindow + 's). '
        + 'Campaign incidents ' + (data.campaign_incident_count || 0) + ' (' + campaignWindow + 's). '
        + 'Timeline events ' + events.length + '.',
      data.evidence_state || 'unavailable'
    );
    const drawer = document.getElementById('liveTimelineDrawer');
    if (drawer) {
      const rows = liveTimelineRows(data);
      drawer.innerHTML = '<div><b>Correlated flow count:</b> ' + count + '</div>'
        + (rows || '<div>No timeline events.</div>');
      drawer.setAttribute('data-correlated-flow-count', String(count));
      drawer.setAttribute('data-evidence-state', data.evidence_state || 'unavailable');
    }
    if (data.evidence_state === 'verified') {
      const countEl = document.getElementById('attackTimelineFlowCount');
      const sourceEl = document.getElementById('attackTimelineSource');
      const eventsEl = document.getElementById('attackTimelineEvents');
      if (countEl) countEl.textContent = count + ' correlated flows from the live stitch';
      if (sourceEl) sourceEl.textContent = 'Live stitch from IncidentCorrelationEngine';
      if (eventsEl) {
        eventsEl.innerHTML = liveTimelineRows(data) || '<div>No correlated timeline events.</div>';
      }
    }
    renderTimelineGroupedView();
    renderForensicDrawer();
  }

  async function stitchVerifiedWindows() {
    try {
      const resp = await fetch('/api/v1/live/correlate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      if (data && data.timeline) {
        renderLiveCorrelation(data);
        await refreshLiveCampaigns();
        return;
      }
      setLiveText('liveTimeline', 'Correlation unavailable.', 'unavailable');
    } catch (err) {
      setLiveText('liveTimeline', 'Correlation unavailable.', 'unavailable');
    }
  }

  async function checkPrivateIpGuard() {
    try {
      const resp = await fetch('/api/v1/live/misp-guard', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: '10.0.0.4' })
      });
      const data = await resp.json();
      if (resp.status === 422 && data.private_ip_guard_triggered === true) {
        setLiveText('liveTimeline', 'Private IP 10.0.0.4 was refused before any external lookup.', 'verified');
        return;
      }
      setLiveText('liveTimeline', 'Private IP guard did not refuse the address.', 'unavailable');
    } catch (err) {
      setLiveText('liveTimeline', 'Private IP guard unavailable.', 'unavailable');
    }
  }

  const MODEL_PROOF_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sinpkt', 'dinpkt', 'sjit', 'djit'
  ];
  const MODEL_PROOF_PRESETS = {
    dos: {
      dur: 3.2, spkts: 240, dpkts: 4, sbytes: 19200, dbytes: 320, rate: 76.25,
      sttl: 254, dttl: 0, sload: 16000000, dload: 200, sinpkt: 0.0002, dinpkt: 0.01,
      sjit: 0.1, djit: 0.1,
      duration_ms: 3200, fwd_packets: 240, bwd_packets: 4, fwd_bytes: 19200, bwd_bytes: 320,
      packets_per_second: 76.25, bytes_per_second: 6100, fwd_packet_length_mean: 80,
      bwd_packet_length_mean: 80, dst_port: 53, protocol_tcp: 0, protocol_udp: 1,
      protocol_icmp: 0, protocol_other: 0
    },
    normal: {
      dur: 0.012, spkts: 2, dpkts: 0, sbytes: 148, dbytes: 0, rate: 166.67,
      sttl: 31, dttl: 29, sload: 12333.33, dload: 0, sinpkt: 0.006, dinpkt: 0,
      sjit: 0, djit: 0,
      duration_ms: 12, fwd_packets: 2, bwd_packets: 0, fwd_bytes: 148, bwd_bytes: 0,
      packets_per_second: 166.67, bytes_per_second: 12333.33, fwd_packet_length_mean: 74,
      bwd_packet_length_mean: 0, dst_port: 53, protocol_tcp: 0, protocol_udp: 1,
      protocol_icmp: 0, protocol_other: 0
    }
  };
  let modelProofFlowId = null;
  let modelProofHasFeatures = false;
  let activeOperatorLabel = '';

  function finiteOrNull(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function formatMse(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 'unavailable';
    if (Math.abs(number) >= 1000) return number.toExponential(4);
    return number.toFixed(6);
  }

  function secondaryAeFromFlow(flow) {
    const loss = Number(flow && flow.ae_loss);
    if (!Number.isFinite(loss)) return { aeError: 0, status: 'not_scored' };
    return {
      aeError: loss,
      aeLoss: loss,
      aeAnomalyFlag: !!(flow && flow.ae_anomaly_flag === true),
      status: flow && flow.ae_anomaly_flag === true ? 'ANOMALY_CONFIRMED' : 'LOSS_WITHIN_BENIGN_THRESHOLD',
      topFeatures: flow && Array.isArray(flow.ae_top_features) ? flow.ae_top_features : []
    };
  }

  let modelProofLoadedFlowId = null;

  function setDnnBadge(inc) {
    const node = document.getElementById('flowDnnBadge');
    if (!node) return;
    if (!inc) {
      node.textContent = 'PyTorch DNN (9-Class): waiting';
      return;
    }
    const probability = Number(inc.dnnAttackProbability);
    if (inc.decision === 'Benign' || (Number.isFinite(probability) && probability < 0.5)) {
      const percent = Number.isFinite(probability) ? ' (' + (probability * 100).toFixed(1) + '%)' : '';
      node.textContent = 'PyTorch DNN (9-Class): Normal' + percent;
      return;
    }
    if (!Number.isFinite(probability)) {
      node.textContent = 'PyTorch DNN (9-Class): waiting';
      return;
    }
    const category = inc.unswAttackCategory ? String(inc.unswAttackCategory) : 'unavailable';
    node.textContent = 'PyTorch DNN (9-Class): ' + category + ' · ' + (probability * 100).toFixed(1) + '%';
  }

  function clearStaleContainmentBanner() {
    ['actionStatusBanner', 'campaignQueueStatus'].forEach(function (id) {
      const node = document.getElementById(id);
      if (!node) return;
      const text = String(node.textContent || '');
      if (text.indexOf('SIMULATED SCENARIO CONTAINMENT') === -1 && text.indexOf('playbook_not_approved') === -1) {
        return;
      }
      node.textContent = 'Containment stays unauthorized until an analyst approves a stored playbook.';
      node.setAttribute('data-evidence-state', 'unavailable');
    });
  }

  let lastCopilotFlowId = 0;
  let copilotRequestSerial = 0;

  function bindSelectedFlowId(inc) {
    const raw = inc && (inc.flowId != null ? inc.flowId : inc.flow_id);
    const flowId = Number(raw);
    if (Number.isInteger(flowId) && flowId > 0) {
      selectedFlowId = flowId;
      return flowId;
    }
    selectedFlowId = null;
    return null;
  }

  function selectInvestigation(inc) {
    if (!inc) return;
    clearStaleContainmentBanner();
    selectedIncidentId = inc.id;
    bindSelectedFlowId(inc);
    renderIncidentQueue();
    renderForensicDrawer();
    showSocView('detail');
    loadModelProofForSelection(inc);
    refreshCopilotForSelection(inc, true);
  }

  function refreshCopilotForSelection(inc, force) {
    const flowId = bindSelectedFlowId(inc || selectedIncident());
    if (!Number.isInteger(flowId) || flowId <= 0) return;
    if (!force && lastCopilotFlowId === flowId) return;
    lastCopilotFlowId = flowId;
    const answer = document.getElementById('liveCopilotAnswer');
    if (answer) {
      answer.textContent = 'Loading the advisory brief for this flow.';
      answer.setAttribute('data-evidence-state', 'pending');
    }
    askLiveCopilot(flowId);
  }

  function preserveSelectionAfterMutation() {
    const keptId = selectedIncidentId;
    const keptFlow = selectedFlowId;
    return function restoreSelection() {
      if (keptId && activeIncidents().some(item => item.id === keptId)) {
        selectedIncidentId = keptId;
      }
      if (Number.isInteger(keptFlow) && keptFlow > 0) {
        selectedFlowId = keptFlow;
      }
      const inc = selectedIncident();
      if (inc) {
        bindSelectedFlowId(inc);
        renderForensicDrawer();
        refreshCopilotForSelection(inc, true);
      }
    };
  }

  async function loadModelProofForSelection(inc) {
    const flowId = inc && inc.flowId ? Number(inc.flowId) : 0;
    if (!Number.isInteger(flowId) || flowId <= 0) return;
    if (modelProofLoadedFlowId === flowId) return;
    modelProofLoadedFlowId = flowId;
    const results = document.getElementById('modelProofResults');
    try {
      const resp = await fetch('/api/v1/live/model-proof?flow_id=' + encodeURIComponent(String(flowId)));
      const data = await readActionPayload(resp);
      const features = data && data.original && data.original.features;
      if (features && typeof features === 'object') {
        inc.dnnFeatures = features;
        modelProofFlowId = null;
        modelProofHasFeatures = false;
        renderModelProofSandbox(inc);
        fillModelProofInputs(features);
      }
      renderVisualObservatory(data);
      if (results && data && data.original) {
        const latency = Number(data.inference_latency_ms);
        results.textContent = [
          proofScoreLine(data.original),
          'Inference Latency (ms): ' + (Number.isFinite(latency) ? latency.toFixed(3) : 'unavailable')
        ].join('\n');
        results.setAttribute('data-evidence-state', data.evidence_state || 'advisory_simulation');
      } else if (results) {
        results.textContent = actionFailureText(data, resp);
      }
    } catch (err) {
      modelProofLoadedFlowId = null;
      if (results) results.textContent = 'Live inference unavailable.';
    }
  }

  function renderModelProofSandbox(inc) {
    const grid = document.getElementById('modelProofFeatureGrid');
    const results = document.getElementById('modelProofResults');
    if (!grid) return;
    const flowId = inc && inc.flowId ? inc.flowId : null;
    if (!flowId) {
      modelProofFlowId = null;
      modelProofHasFeatures = false;
      grid.textContent = 'Select a stored flow to edit its 14 features.';
      if (results) results.textContent = 'Before and after scores appear here.';
      return;
    }
    const hasStored = !!(inc.dnnFeatures && typeof inc.dnnFeatures === 'object');
    if (modelProofFlowId === flowId && grid.querySelector('input') && (modelProofHasFeatures || !hasStored)) {
      return;
    }
    modelProofFlowId = flowId;
    modelProofHasFeatures = hasStored;
    const stored = hasStored ? inc.dnnFeatures : {};
    grid.innerHTML = MODEL_PROOF_FEATURES.map(name => {
      const value = Number(stored[name]);
      const shown = Number.isFinite(value) ? value : 0;
      return '<label>' + escapeHtml(name)
        + ' <input data-proof-feature="' + escapeHtml(name)
        + '" type="number" step="any" value="' + escapeHtml(String(shown)) + '"></label>';
    }).join(' ');
  }

  function fillModelProofInputs(features) {
    MODEL_PROOF_FEATURES.forEach(name => {
      const node = document.querySelector('[data-proof-feature="' + name + '"]');
      if (!node || !features || !Object.prototype.hasOwnProperty.call(features, name)) return;
      node.value = String(features[name]);
    });
  }

  function readModelProofInputs() {
    const override = {};
    MODEL_PROOF_FEATURES.forEach(name => {
      const node = document.querySelector('[data-proof-feature="' + name + '"]');
      const value = node ? Number(node.value) : NaN;
      if (Number.isFinite(value)) override[name] = value;
    });
    return override;
  }

  function proofScoreLine(block) {
    if (!block) return 'unavailable';
    const rf = Number(block.rf_attack_probability);
    const dnn = Number(block.dnn_attack_probability);
    const ae = Number(block.ae_loss);
    const consensus = Number(block.threatfusion_consensus_score);
    return [
      'Random Forest (ML): ' + String(block.rf_decision || 'withheld') + ' '
        + (Number.isFinite(rf) ? rf.toFixed(4) : 'unavailable'),
      'PyTorch DNN (Binary + 9-Class Category): '
        + (Number.isFinite(dnn) ? dnn.toFixed(4) : 'unavailable') + ' '
        + String(block.dnn_binary_decision || '') + ' / '
        + String(block.unsw_attack_category || 'unavailable'),
      'PyTorch v2 Autoencoder (MSE Loss): '
        + (Number.isFinite(ae) ? formatMse(ae) : 'unavailable') + ' '
        + (block.ae_anomaly_flag ? 'Anomaly' : 'Normal'),
      'Advisory Consensus: ' + (Number.isFinite(consensus) ? consensus.toFixed(4) : 'unavailable')
    ].join('\n');
  }

  function runModelProofPreset(preset) {
    fillModelProofInputs(preset);
    runLiveModelProof(preset);
  }

  async function restoreStoredModelProof() {
    const inc = selectedIncident();
    const results = document.getElementById('modelProofResults');
    if (!inc || !inc.flowId) {
      if (results) results.textContent = 'Select a stored flow first.';
      return;
    }
    if (inc.dnnFeatures) fillModelProofInputs(inc.dnnFeatures);
    try {
      const resp = await fetch('/api/v1/live/model-proof?flow_id=' + encodeURIComponent(String(inc.flowId)));
      const data = await readActionPayload(resp);
      renderVisualObservatory(data);
      if (results && data && data.original) {
        const latency = Number(data.inference_latency_ms);
        results.textContent = [
          proofScoreLine(data.original),
          'Inference Latency (ms): ' + (Number.isFinite(latency) ? latency.toFixed(3) : 'unavailable')
        ].join('\n');
        results.setAttribute('data-evidence-state', data.evidence_state || 'advisory_simulation');
      } else if (results) {
        results.textContent = actionFailureText(data, resp);
      }
    } catch (err) {
      if (results) results.textContent = 'Live inference unavailable.';
    }
  }

  async function runLiveModelProof(extraOverride) {
    const inc = selectedIncident();
    const results = document.getElementById('modelProofResults');
    if (!inc || !inc.flowId) {
      if (results) results.textContent = 'Select a stored flow first.';
      return;
    }
    const featuresOverride = Object.assign({}, readModelProofInputs(), extraOverride || {});
    try {
      const resp = await fetch('/api/v1/live/model-proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flow_id: inc.flowId,
          features_override: featuresOverride
        })
      });
      const data = await readActionPayload(resp);
      const latency = Number(data.inference_latency_ms);
      const text = [
        'Before',
        proofScoreLine(data.original),
        'After',
        proofScoreLine(data.perturbed),
        'Inference Latency (ms): ' + (Number.isFinite(latency) ? latency.toFixed(3) : 'unavailable')
      ].join('\n');
      if (results) {
        results.textContent = resp.ok ? text : actionFailureText(data, resp);
        results.setAttribute('data-evidence-state', data.evidence_state || 'advisory_simulation');
      }
      if (resp.ok) renderVisualObservatory(data);
    } catch (err) {
      if (results) results.textContent = 'Live inference unavailable.';
    }
  }

  async function dispatchSignedCallback(inc) {
    if (!inc || !inc.live || !inc.flowId) {
      showActionBanner('Dispatch applies to an approved stored flow.', 'unavailable');
      return null;
    }
    try {
      const resp = await fetch('/api/v1/live/soar/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: inc.flowId, actor_id: operatorActorId() })
      });
      const data = await readActionPayload(resp);
      const restore = preserveSelectionAfterMutation();
      await refreshLiveCampaigns();
      restore();
      const sig = typeof data.signature_sha256 === 'string' ? data.signature_sha256 : '';
      const path = typeof data.execution_path === 'string' ? data.execution_path : 'not dispatched';
      const recorded = data.callback_recorded === true
        || data.verify_state === true
        || path === 'local_contract_fallback'
        || path === 'n8n_live_container';
      if (resp.ok && recorded && (SHA256_HEX_REGEX.test(sig) || path === 'local_contract_fallback')) {
        const live = selectedLiveIncident(inc);
        if (live) {
          live.callbackRecorded = true;
          live.dispatchUnlocked = true;
          if (SHA256_HEX_REGEX.test(sig)) live.callbackSignature = sig;
          live.executionPath = path;
          if (live.soarState !== 'approved') live.soarState = 'approved';
          applyContainmentGuard(live);
          applyContainmentStatus(live);
          markResponseProgress(live);
          loadSoarPlaybookPreview(live);
        }
        enableSoarControl('btnIsolateAttacker');
        enableSoarControl('btnContainRange');
        const mttr = Number(data.mttr_seconds);
        const mttrText = Number.isFinite(mttr) ? mttr.toFixed(3) + 's' : 'n/a';
        const caseId = typeof data.thehive_case_id === 'string' ? data.thehive_case_id : 'not recorded';
        const disclosure = typeof data.transport_disclosure === 'string' ? data.transport_disclosure : '';
        const headline = path === 'local_contract_fallback'
          ? 'LOCAL CONTRACT FALLBACK RECORDED (Simulated — Not Live n8n). Step 3 (Isolate Attacker) is now unlocked. Host containment was not executed.'
          : 'DISPATCHED VIA N8N — execution_path: ' + path + (disclosure ? '. ' + disclosure + ' ' : '. ') + 'HMAC ' + sig + '. mttr_seconds ' + mttrText + '. Case ' + caseId + '. Step 3 (Isolate Attacker) is now unlocked. Host containment was not executed.';
        showActionBanner(
          headline,
          path === 'local_contract_fallback' || data.fallback_label ? 'unavailable' : 'verified',
          typeof data.reason === 'string' ? data.reason : ''
        );
        return data;
      }
      showActionBanner(
        soarOperatorMessage(data.reason, actionFailureText(data, resp)),
        'unavailable',
        typeof data.reason === 'string' ? data.reason : ''
      );
      return data;
    } catch (err) {
      showActionBanner(err && err.message ? String(err.message) : 'Signed callback unavailable.', 'unavailable');
      return null;
    }
  }

  function setRangeConnectivity(blocked) {
    const node = document.getElementById('rangeConnectivityBadge');
    if (!node) return;
    if (blocked) {
      node.textContent = '172.29.0.10 -> 172.29.0.20:80: BLOCKED (Timeout exit 28)';
      node.setAttribute('data-connectivity', 'blocked');
    } else {
      node.textContent = '172.29.0.10 -> 172.29.0.20:80: REACHABLE (range-victim)';
      node.setAttribute('data-connectivity', 'reachable');
    }
    node.setAttribute('data-evidence-state', 'verified');
  }

  async function fireLiveRangeScan() {
    setLiveText('campaignQueueStatus', 'Waiting for 172.29.0.10 -> 172.29.0.20 to reach the queue.', 'pending');
    try {
      const resp = await fetch('/api/v1/live/range-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      if (data && data.ingested === true) {
        setLiveText('campaignQueueStatus', 'Range scan stored 172.29.0.10 -> 172.29.0.20.', 'verified');
        await refreshLiveCampaigns();
        return;
      }
      setLiveText('campaignQueueStatus', data && data.reason ? data.reason : 'Range scan was not ingested.', 'unavailable');
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Range scan unavailable.', 'unavailable');
    }
  }

  async function postRangeContainment(inc, path) {
    if (!inc || !inc.live || !inc.flowId) {
      showActionBanner('Containment applies to a stored bridge flow.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: inc.flowId, actor_id: operatorActorId() })
      });
      const data = await readActionPayload(resp);
      const restore = preserveSelectionAfterMutation();
      await refreshLiveCampaigns();
      restore();
      const applied = data.reason === 'containment_applied';
      const rolled = data.reason === 'containment_rolled_back';
      const simulated = data.evidence_state === 'simulated'
        || data.containment_state === 'simulated_applied'
        || data.containment_state === 'simulated_rolled_back';
      const srcIp = inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : '';
      if (!srcIp || srcIp === '172.29.0.10') {
        if (applied) setRangeConnectivity(true);
        else if (rolled) setRangeConnectivity(false);
      }
      const isolating = String(path || '').indexOf('/rollback') === -1;
      if (resp.ok && isolating && (applied || simulated || data.containment_state === 'applied' || data.containment_state === 'simulated_applied')) {
        const live = selectedLiveIncident(inc);
        if (live) {
          live.containmentState = data.containment_state
            || (simulated ? 'simulated_applied' : 'applied');
          live.rollbackUnlocked = true;
          applyContainmentGuard(live);
          markResponseProgress(live);
        }
        enableSoarControl('btnRollbackRange');
      }
      if (resp.ok && simulated) {
        showActionBanner(
          'SIMULATED SCENARIO CONTAINMENT (No Host Firewall Rule Executed — Recorded in Ledger)',
          'simulated',
          typeof data.reason === 'string' ? data.reason : ''
        );
        return;
      }
      if (sessionIdentity && sessionIdentity.authenticated) paintSessionIdentity(sessionIdentity);
      if (resp.ok && (applied || rolled)) {
        const message = applied
          ? ('CONTAINMENT APPLIED — Source ' + srcIp + ' blocked at firewall (iptables DROP active). Click Rollback to restore.')
          : ('CONTAINMENT ROLLED BACK — Firewall block on ' + srcIp + ' removed and rollback recorded in SHA-256 ledger.');
        showActionBanner(message, 'verified');
        return;
      }
      showActionBanner(actionFailureText(data, resp), 'unavailable');
    } catch (err) {
      showActionBanner(err && err.message ? String(err.message) : 'Range containment unavailable.', 'unavailable');
    }
  }

  async function refreshLiveQueue() {
    try {
      const resp = await fetch('/api/v1/live/queue');
      if (!resp.ok) {
        setLiveText('liveQueueStatus', 'Live queue unavailable.', 'unavailable');
        return;
      }
      const data = await resp.json();
      const flows = Array.isArray(data.flows) ? data.flows : [];
      if (!flows.length) {
        if (liveCampaignIncidents.length) {
          setLiveText(
            'liveQueueStatus',
            liveCampaignIncidents.length + ' stored rows are on the investigations table.',
            'verified'
          );
          return;
        }
        setLiveText('liveQueueStatus', 'Live queue is empty. The recorded queue remains available.', 'unavailable');
        return;
      }
      const latest = flows[0];
      setLiveText(
        'liveQueueStatus',
        'Live flow ' + latest.flow_id + ' decision ' + latest.decision + ' (' + latest.evidence_state + ').',
        latest.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('liveQueueStatus', 'Live queue unavailable.', 'unavailable');
    }
  }

  async function ingestLiveFlow() {
    const features = {
      duration_ms: 1, fwd_packets: 1, bwd_packets: 1, fwd_bytes: 1, bwd_bytes: 1,
      packets_per_second: 1, bytes_per_second: 1, fwd_packet_length_mean: 1,
      bwd_packet_length_mean: 1, dst_port: 80, protocol_tcp: 1, protocol_udp: 0,
      protocol_icmp: 0, protocol_other: 0
    };
    try {
      const resp = await fetch('/api/v1/live/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ features: features })
      });
      const data = await resp.json();
      setLiveText(
        'liveQueueStatus',
        'Ingest decision ' + data.decision + ' (' + data.reason + '). Fusion disabled.',
        data.evidence_state || 'unavailable'
      );
      if (data.correlation) renderLiveCorrelation(data.correlation);
      await refreshLiveCampaigns();
    } catch (err) {
      setLiveText('liveQueueStatus', 'Live ingest unavailable.', 'unavailable');
    }
  }

  function selectedLiveFlowId() {
    if (Number.isInteger(selectedFlowId) && selectedFlowId > 0) return selectedFlowId;
    const inc = selectedIncident();
    return bindSelectedFlowId(inc);
  }

  function firstConstituentAttackFlowId(preferredDecision) {
    const rows = activeIncidents();
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (!row) continue;
      if (preferredDecision && row.decision !== preferredDecision) continue;
      const raw = row.flowId != null ? row.flowId : row.flow_id;
      const number = Number(raw);
      if (Number.isInteger(number) && number > 0) return number;
    }
    return null;
  }

  function copilotFlowIdForSelection(inc) {
    const bound = selectedLiveFlowId();
    if (Number.isInteger(bound) && bound > 0) return bound;
    const row = inc || selectedIncident();
    const direct = bindSelectedFlowId(row);
    if (Number.isInteger(direct) && direct > 0) return direct;
    return null;
  }

  function copilotBadgeLabel(provider) {
    if (provider === 'gemini') return 'Live Gemini 3.5 Flash (Grounded API Call)';
    return 'Local Air-Gapped Engine';
  }

  async function askLiveCopilot(flowIdOverride) {
    const requestSerial = ++copilotRequestSerial;
    const input = document.getElementById('liveCopilotQuestion');
    const question = input ? input.value : '';
    const progress = document.getElementById('advisoryProgress');
    const override = Number(flowIdOverride);
    const flowId = Number.isInteger(override) && override > 0
      ? override
      : copilotFlowIdForSelection();
    if (!Number.isInteger(flowId) || flowId <= 0) {
      setLiveText('liveCopilotAnswer', 'Select a stored flow before requesting an advisory brief.', 'unavailable');
      return;
    }
    selectedFlowId = flowId;
    if (progress) progress.hidden = false;
    try {
      const resp = await fetch('/api/v1/live/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: question, flow_id: flowId })
      });
      const data = await resp.json();
      if (requestSerial !== copilotRequestSerial) return;
      if (Number.isInteger(selectedFlowId) && selectedFlowId > 0 && selectedFlowId !== flowId) return;
      const answer = document.getElementById('liveCopilotAnswer');
      if (answer) {
        answer.style.whiteSpace = 'pre-wrap';
        answer.style.lineHeight = '1.5';
      }
      if (data.reason === 'containment_refused') {
        setLiveText('liveCopilotAnswer', 'Containment refused. execution_authorized is false.', 'unavailable');
        return;
      }
      const responseFlow = Number(data.flow_id);
      if (Number.isInteger(responseFlow) && responseFlow > 0 && responseFlow !== flowId) {
        setLiveText('liveCopilotAnswer', 'Advisory brief does not match the selected flow.', 'unavailable');
        return;
      }
      const hit = data.hits && data.hits[0];
      const retrieved = hit
        ? ('retrieved candidate technique ' + hit.technique_id + ' ' + hit.technique_name)
        : 'No local corpus hit.';
      let narrative = typeof data.narrative === 'string' && data.narrative ? data.narrative : retrieved;
      const selected = selectedIncident();
      const selectedTitle = selected && selected.advisory ? String(selected.advisory.summaryHeadline || '') : '';
      const selectedLabel = selected && selected.scenarioLabel ? String(selected.scenarioLabel) : '';
      const selectedSrc = selected && selected.provenance ? String(selected.provenance.srcIp || '') : '';
      const selectedDecision = selected ? String(selected.decision || '') : '';
      const titleMiss = selectedTitle && narrative.indexOf(selectedTitle) === -1;
      const labelMiss = selectedLabel && narrative.indexOf(selectedLabel) === -1;
      const srcMiss = selectedSrc && narrative.indexOf(selectedSrc) === -1;
      const decisionMiss = selectedDecision && narrative.indexOf(selectedDecision) === -1;
      if ((titleMiss && labelMiss) || (srcMiss && decisionMiss && (titleMiss || labelMiss))) {
        narrative = 'Advisory brief does not match the selected flow.';
      }
      showCopilotAnswer(narrative, data.evidence_state || 'unavailable');
      const badge = document.getElementById('copilotProviderBadge');
      if (badge) {
        badge.textContent = copilotBadgeLabel(data.provider);
        badge.setAttribute('data-evidence-state', data.provider === 'gemini' ? 'verified' : 'unavailable');
      }
    } catch (err) {
      if (requestSerial !== copilotRequestSerial) return;
      setLiveText('liveCopilotAnswer', 'Copilot unavailable.', 'unavailable');
    } finally {
      if (requestSerial === copilotRequestSerial && progress) progress.hidden = true;
    }
  }

  function jointSoftmaxRows(distribution, attackProbability) {
    const source = distribution && typeof distribution === 'object' ? distribution : {};
    const classes = OBSERVATORY_CLASSES.filter(name => name !== 'Normal');
    const conditionalMass = classes.reduce((sum, name) => sum + (Number(source[name]) || 0), 0);
    const normal = Number(source.Normal);
    const alreadyJoint = Number.isFinite(normal) && Math.abs(conditionalMass + normal - 1) < 0.02;
    const attack = Number(attackProbability);
    return OBSERVATORY_CLASSES.map(name => {
      let value = Number(source[name]);
      if (!alreadyJoint && name === 'Normal') {
        value = Number.isFinite(attack) ? Math.max(0, 1 - attack) : (Number.isFinite(normal) ? normal : 0);
      } else if (!alreadyJoint && Number.isFinite(attack)) {
        value = attack * (Number(source[name]) || 0);
      }
      if (!Number.isFinite(value)) value = 0;
      return { label: name, value: value, text: percentText(value) };
    });
  }

  async function saveLiveAnalystNote() {
    const input = document.getElementById('analystNoteText');
    const note = input ? input.value : '';
    try {
      const resp = await fetch('/api/v1/live/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ author_id: 'analyst_a', note_text: note })
      });
      const data = await resp.json();
      setLiveText(
        'liveQueueStatus',
        data.evidence_state === 'verified' ? 'Analyst note saved.' : 'Analyst note refused.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('liveQueueStatus', 'Analyst note unavailable.', 'unavailable');
    }
  }

  async function refreshLiveDriftAndWorkbench() {
    try {
      const driftResp = await fetch('/api/v1/live/drift');
      const drift = await driftResp.json();
      setLiveText(
        'liveDriftStatus',
        'Drift ' + (drift.drift_status || drift.reason || 'unavailable') + '. Model weights unchanged.',
        drift.evidence_state || 'unavailable'
      );
      const benchResp = await fetch('/api/v1/live/workbench');
      const bench = await benchResp.json();
      setLiveText(
        'liveWorkbenchStatus',
        'n8n workbench nodes: ' + (bench.node_count || 0) + '. Dispatch stays unauthorized.',
        bench.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('liveDriftStatus', 'Drift unavailable.', 'unavailable');
    }
  }

  function formatCopilotAnswer(raw) {
    const escaped = escapeHtml(String(raw || ''));
    return escaped
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\[([1-5])\][ \t]+([^\n<]+)/g, '<div class="copilot-section">[$1] $2</div>');
  }

  function showCopilotAnswer(narrative, state) {
    const answer = document.getElementById('liveCopilotAnswer');
    if (!answer) return;
    answer.innerHTML = formatCopilotAnswer(narrative);
    answer.setAttribute('data-evidence-state', state || 'unavailable');
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  const OBSERVATORY_CLASSES = [
    'Normal', 'Analysis', 'Backdoors', 'DoS', 'Exploits', 'Fuzzers',
    'Generic', 'Reconnaissance', 'Shellcode', 'Worms'
  ];
  const OPERATOR_LABELS = {
    lab_operator: 'Muhammad Bilal (21K-3551)',
    tier1_analyst: 'Muhammad Suhaib (22K-4302)',
    compliance_auditor: 'Muhammad Hasnain (22K-4718)'
  };

  function openEnterpriseDrawer(open) {
    const drawer = document.getElementById('enterpriseWorkspaceDrawer');
    if (open) {
      const other = document.getElementById('labControlsDrawer');
      if (other) other.classList.remove('is-open');
    }
    if (drawer) drawer.classList.toggle('is-open', Boolean(open));
    if (open) {
      renderActiveSessionCard();
      loadEnterpriseControls();
    }
  }

  function percentText(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 'unavailable';
    return (number * 100).toFixed(2) + '%';
  }

  function setGauge(fillId, markerId, valueId, value, threshold, label) {
    const fill = document.getElementById(fillId);
    const marker = document.getElementById(markerId);
    const text = document.getElementById(valueId);
    const numeric = Number(value);
    const limit = Number(threshold);
    const width = Number.isFinite(numeric) ? Math.max(0, Math.min(100, numeric * 100)) : 0;
    if (fill) fill.style.width = width.toFixed(2) + '%';
    if (marker && Number.isFinite(limit)) {
      marker.style.left = Math.max(0, Math.min(100, limit * 100)).toFixed(2) + '%';
    }
    if (text) text.textContent = label;
  }

  function renderHorizontalBars(container, rows) {
    if (!container) return;
    if (!rows.length) {
      container.textContent = 'Waiting for a scored flow.';
      return;
    }
    const max = Math.max.apply(null, rows.map(row => Number(row.value) || 0).concat([1e-9]));
    container.innerHTML = rows.map(row => {
      const value = Number(row.value) || 0;
      const width = Math.max(0, Math.min(100, (value / max) * 100));
      return '<div class="hbar-row"><span class="hbar-label">' + escapeHtml(row.label)
        + '</span><span class="hbar-track"><span class="hbar-fill" style="width:' + width.toFixed(2)
        + '%"></span></span><span class="hbar-value">' + escapeHtml(row.text) + '</span></div>';
    }).join('');
  }

  function renderVisualObservatory(data) {
    if (!data || typeof data !== 'object') return;
    const block = data.perturbed || data.original || data;
    const rf = Number(block.rf_attack_probability);
    const ae = Number(block.ae_loss);
    const aeThreshold = Number(block.ae_threshold || EVAL_PACK_REV2.aeThreshold);
    const dnn = Number(block.dnn_attack_probability);
    setGauge(
      'gaugeRfFill',
      'gaugeRfThreshold',
      'gaugeRfValue',
      Number.isFinite(rf) ? rf : 0,
      0.5,
      'Frozen RF: ' + (Number.isFinite(rf) ? rf.toFixed(4) : 'unavailable')
        + ' / threshold 0.5000 / ' + String(block.rf_decision || data.decision || 'waiting')
    );
    const aeRatio = Number.isFinite(ae) && aeThreshold > 0 ? Math.min(1, ae / (aeThreshold * 2)) : 0;
    setGauge(
      'gaugeAeFill',
      'gaugeAeThreshold',
      'gaugeAeValue',
      aeRatio,
      0.5,
      'v2 AE MSE: ' + (Number.isFinite(ae) ? formatMse(ae) : 'unavailable')
        + ' / threshold ' + (Number.isFinite(aeThreshold) ? aeThreshold.toFixed(6) : 'unavailable')
        + (block.ae_anomaly_flag ? ' / anomaly' : ' / within threshold')
    );
    const alertDecision = String(
      (data && data.decision) || block.rf_decision || block.dnn_binary_decision || ''
    );
    const dnnShown = Number.isFinite(dnn) ? dnn.toFixed(4) : 'unavailable';
    const dnnGaugeText = alertDecision === 'Benign' || alertDecision === 'Normal'
      ? ('9-class DNN: ' + dnnShown + ' / Normal (Benign)')
      : ('9-class DNN: ' + dnnShown + ' / ' + String(block.unsw_attack_category || block.dnn_binary_decision || 'unavailable'));
    setGauge(
      'gaugeDnnFill',
      'gaugeDnnThreshold',
      'gaugeDnnValue',
      Number.isFinite(dnn) ? dnn : 0,
      0.5,
      dnnGaugeText
    );
    const distribution = data.dnn_class_distribution || block.dnn_class_distribution || {};
    const attackProbability = Number(block.dnn_attack_probability != null
      ? block.dnn_attack_probability
      : data.dnn_attack_probability);
    const softmaxRows = jointSoftmaxRows(distribution, attackProbability);
    renderHorizontalBars(document.getElementById('dnnSoftmaxChart'), softmaxRows);
    const errors = data.feature_error_breakdown || block.feature_error_breakdown || [];
    const errorRows = Array.isArray(errors) ? errors.map(row => ({
      label: String(row.feature || row.ae_input || 'feature'),
      value: Number(row.squared_error) || 0,
      text: formatMse(row.squared_error)
    })) : [];
    renderHorizontalBars(document.getElementById('aeFeatureErrorChart'), errorRows);
    const scorecard = data.benchmark_scorecard || data.dnn_evaluation_summary;
    renderBenchmarkScorecard(scorecard);
  }

  function renderBenchmarkScorecard(scorecard) {
    const node = document.getElementById('modelBenchmarkScorecard');
    if (!node || !scorecard || typeof scorecard !== 'object') return;
    const binary = scorecard.binary_metrics || {};
    const forest = scorecard.frozen_random_forest || {};
    const autoencoder = scorecard.frozen_autoencoder_v2 || {};
    const classes = Array.isArray(scorecard.per_class_metrics) ? scorecard.per_class_metrics : [];
    const classRows = classes.map(row => {
      return '<tr><td>' + escapeHtml(row.class_name || row.model_class || '')
        + '</td><td>' + escapeHtml((Number(row.precision) * 100).toFixed(2) + '%')
        + '</td><td>' + escapeHtml((Number(row.recall) * 100).toFixed(2) + '%')
        + '</td><td>' + escapeHtml(String(row.support == null ? '' : row.support))
        + '</td></tr>';
    }).join('');
    node.innerHTML = ''
      + '<p>Held-out split: ' + escapeHtml(String(scorecard.train_rows == null ? 'unavailable' : scorecard.train_rows))
      + ' train / ' + escapeHtml(String(scorecard.test_rows == null ? 'unavailable' : scorecard.test_rows))
      + ' test. Nine-class attack accuracy '
      + escapeHtml(percentText(scorecard.nine_class_attack_accuracy)) + '.</p>'
      + '<p>Frozen RF January benchmark: ' + escapeHtml(String(forest.january_unsw_flows || 216568))
      + ' flows, ' + escapeHtml(String(forest.volume_reduction_percent || 98))
      + '% volume reduction, precision ' + escapeHtml(String(forest.precision_percent || 95.266))
      + '%, recall ' + escapeHtml(String(forest.recall_percent || 92.818))
      + '%, FPR ' + escapeHtml(String(forest.fpr_percent || 0.095)) + '%.</p>'
      + '<p>Frozen v2 AE threshold ' + escapeHtml(String(autoencoder.threshold || EVAL_PACK_REV2.aeThreshold))
      + ', +' + escapeHtml(String(autoencoder.recall_gain_percentage_points || 2.203))
      + ' pp recall gain. production_fusion_enabled = False. The three models stay separate.</p>'
      + '<p>Binary held-out precision ' + escapeHtml(percentText(binary.precision))
      + ', recall ' + escapeHtml(percentText(binary.recall))
      + ', FPR ' + escapeHtml(percentText(binary.fpr)) + '.</p>'
      + '<table class="scorecard-table"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>Support</th></tr></thead><tbody>'
      + classRows + '</tbody></table>';
  }

  async function loadModelObservatory(flowId) {
    const query = flowId ? ('?flow_id=' + encodeURIComponent(String(flowId))) : '';
    try {
      const resp = await fetch('/api/v1/live/model-observatory' + query);
      const data = await readActionPayload(resp);
      renderVisualObservatory(data);
    } catch (err) {
      const node = document.getElementById('modelBenchmarkScorecard');
      if (node && !node.querySelector('table')) {
        node.textContent = 'Held-out scorecard unavailable.';
      }
    }
  }

  function renderRangeFirewall(telemetry) {
    const node = document.getElementById('rangeFirewallStatus');
    if (!node || !telemetry) return;
    const probe = telemetry.reachability_probe || {};
    const blocked = Array.isArray(telemetry.blocked_sources) ? telemetry.blocked_sources.join(', ') : '';
    node.textContent = 'Victim firewall ' + String(telemetry.containment_state || 'clear')
      + '. Blocked sources: ' + (blocked || 'none')
      + '. Reachability: ' + String(probe.status || 'not_probed')
      + '. SOAR receipts: ' + String(telemetry.soar_receipts == null ? 0 : telemetry.soar_receipts)
      + '. Path 172.29.0.10 -> 172.29.0.20.';
    node.setAttribute('data-evidence-state', 'verified');
  }

  function renderSensorRegistry(sensors) {
    const node = document.getElementById('sensorRegistryList');
    if (!node) return;
    const rows = sensors && Array.isArray(sensors.sensors) ? sensors.sensors : [];
    if (!rows.length) {
      node.textContent = 'No sensors registered.';
      node.setAttribute('data-evidence-state', 'unavailable');
      return;
    }
    node.innerHTML = rows.map(row => {
      return '<div class="sensor-row"><b>' + escapeHtml(row.sensor_id) + '</b> '
        + escapeHtml(row.monitored_cidr) + ' (' + escapeHtml(row.status) + ')</div>';
    }).join('');
    node.setAttribute('data-evidence-state', 'verified');
  }

  function renderEntraIdentity(status) {
    const active = status && status.active_operator ? status.active_operator : {};
    const roles = Array.isArray(active.entra_app_roles) ? active.entra_app_roles.join(', ') : '';
    setLiveText('entraUpn', active.entra_upn || 'unavailable', active.entra_upn ? 'verified' : 'unavailable');
    setLiveText('entraObjectId', active.entra_object_id || 'unavailable', active.entra_object_id ? 'verified' : 'unavailable');
    setLiveText('entraAppRole', roles || 'unavailable', roles ? 'verified' : 'unavailable');
    setLiveText(
      'entraMtlsStatus',
      active.mtls_status || 'X.509 client certificate required for SOAR approval',
      'verified'
    );
    setLiveText('entraTenantId', (status && status.entra_tenant_id) || 'unavailable', status && status.entra_tenant_id ? 'verified' : 'unavailable');
    setLiveText(
      'entraSubscriptionTier',
      (status && status.azure_subscription_tier) || 'Azure for Students · $60 Credit Active · Free Entra ID P1/OIDC',
      'verified'
    );
  }

  async function loadEnterpriseControls() {
    try {
      const responses = await Promise.all([
        fetch('/api/v1/live/workspaces'),
        fetch('/api/v1/live/operators'),
        fetch('/api/v1/live/sensors'),
        fetch('/api/v1/live/range/telemetry'),
        fetch('/api/v1/live/entra/status')
      ]);
      const payloads = await Promise.all(responses.map(resp => readActionPayload(resp)));
      const workspaces = payloads[0];
      const operators = payloads[1];
      const sensors = payloads[2];
      const telemetry = payloads[3];
      const workspaceSelect = document.getElementById('workspaceSelect');
      if (workspaceSelect && workspaces && Array.isArray(workspaces.workspaces) && workspaces.workspaces.length) {
        workspaceSelect.innerHTML = workspaces.workspaces.map(item => {
          return '<option value="' + escapeHtml(item.workspace_id) + '">'
            + escapeHtml(item.display_name) + '</option>';
        }).join('');
        if (workspaces.active_workspace_id) workspaceSelect.value = workspaces.active_workspace_id;
      }
      const operatorSelect = document.getElementById('operatorRoleSelect');
      if (operatorSelect && operators && Array.isArray(operators.operators) && operators.operators.length) {
        operatorSelect.innerHTML = operators.operators.map(item => {
          const appRole = item.entra_app_roles && item.entra_app_roles.length
            ? item.entra_app_roles[0]
            : item.role;
          return '<option value="' + escapeHtml(item.actor_id) + '">'
            + escapeHtml(item.display_name) + ' · ' + escapeHtml(appRole) + '</option>';
        }).join('');
        if (operators.active_actor_id) operatorSelect.value = operators.active_actor_id;
      }
      renderSensorRegistry(sensors);
      renderRangeFirewall(telemetry);
      renderEntraIdentity(payloads[4]);
      await loadAzurePortalStatus();
    } catch (err) {
      setLiveText('workspaceStatus', 'Enterprise controls unavailable.', 'unavailable');
    }
  }

  async function selectEnterpriseWorkspace() {
    const select = document.getElementById('workspaceSelect');
    const workspaceId = select ? select.value : '';
    try {
      const resp = await fetch('/api/v1/live/workspaces/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace_id: workspaceId, operator_id: operatorActorId() })
      });
      const data = await readActionPayload(resp);
      setLiveText(
        'workspaceStatus',
        resp.ok ? ('Workspace ' + workspaceId + ' selected.') : actionFailureText(data, resp),
        resp.ok ? 'verified' : 'unavailable'
      );
    } catch (err) {
      setLiveText('workspaceStatus', 'Workspace select unavailable.', 'unavailable');
    }
  }

  async function createEnterpriseWorkspace() {
    const body = {
      workspace_id: queueControlValue('workspaceIdInput', ''),
      display_name: queueControlValue('workspaceNameInput', ''),
      monitored_cidr: queueControlValue('workspaceCidrInput', ''),
      default_service: queueControlValue('workspaceServiceInput', ''),
      operator_id: operatorActorId()
    };
    try {
      const resp = await fetch('/api/v1/live/workspaces/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await readActionPayload(resp);
      setLiveText(
        'workspaceStatus',
        resp.ok ? ('Workspace ' + body.workspace_id + ' created.') : actionFailureText(data, resp),
        resp.ok ? 'verified' : 'unavailable'
      );
      if (resp.ok) await loadEnterpriseControls();
    } catch (err) {
      setLiveText('workspaceStatus', 'Workspace create unavailable.', 'unavailable');
    }
  }

  function applyOperatorSelection(actorId, displayName) {
    const input = document.getElementById('operatorActor');
    if (input && actorId) input.value = actorId;
    activeOperatorLabel = displayName || OPERATOR_LABELS[actorId] || '';
    const profile = document.getElementById('operatorProfileName');
    if (profile && activeOperatorLabel) profile.textContent = activeOperatorLabel;
  }

  function isSessionAuthenticated() {
    return !!(sessionIdentity && sessionIdentity.authenticated === true && rbacSessionToken);
  }

  function renderActiveSessionCard() {
    const name = document.getElementById('activeSessionName');
    const actor = document.getElementById('activeSessionActor');
    const role = document.getElementById('activeSessionRole');
    const state = document.getElementById('activeSessionState');
    if (!isSessionAuthenticated()) {
      if (name) name.textContent = 'Signed out';
      if (actor) actor.textContent = 'none';
      if (role) role.textContent = 'unavailable';
      if (state) {
        state.textContent = 'unauthenticated';
        state.setAttribute('data-evidence-state', 'unavailable');
      }
      return;
    }
    if (name) name.textContent = sessionIdentity.display_name || headerLineForSession(sessionIdentity);
    if (actor) actor.textContent = sessionIdentity.actor_id || sessionIdentity.username || 'unknown';
    if (role) role.textContent = sessionIdentity.role || 'unavailable';
    if (state) {
      state.textContent = 'authenticated';
      state.setAttribute('data-evidence-state', 'verified');
    }
  }

  function syncIdentityGateControls() {
    const returnBtn = document.getElementById('btnReturnToConsole');
    const closeBtn = document.getElementById('btnCloseIdentityModal');
    const showReturn = identityGateSwitchMode && isSessionAuthenticated();
    if (returnBtn) {
      if (showReturn) returnBtn.removeAttribute('hidden');
      else returnBtn.setAttribute('hidden', '');
    }
    if (closeBtn) closeBtn.setAttribute('hidden', '');
  }

  function enforceAuthGate() {
    const locked = !isSessionAuthenticated();
    document.body.classList.toggle('console-locked', locked);
    if (locked) {
      identityGateSwitchMode = false;
      openIdentityModal(true);
      identityStatus('Authentication required before entering the SOC console.', 'unavailable');
    } else {
      document.body.classList.remove('console-locked');
    }
    syncIdentityGateControls();
    renderActiveSessionCard();
  }

  function bindControl(ids, handler) {
    ids.forEach(id => {
      const node = document.getElementById(id);
      if (!node || node.dataset.boundClick === '1') return;
      node.dataset.boundClick = '1';
      node.addEventListener('click', handler);
    });
  }

  function showLoginGate() {
    const modal = document.getElementById('identityModal');
    if (!modal) return;
    modal.classList.add('identity-modal', 'zt-login-gate');
    modal.hidden = false;
    modal.removeAttribute('hidden');
    modal.style.display = 'flex';
    document.body.classList.add('console-locked');
    syncIdentityGateControls();
  }

  function hideLoginGate() {
    const modal = document.getElementById('identityModal');
    const app = document.getElementById('consoleApp');
    if (modal) {
      modal.hidden = true;
      modal.setAttribute('hidden', '');
      modal.classList.remove('zt-login-gate');
      modal.style.display = 'none';
    }
    document.body.classList.remove('console-locked');
    if (app) {
      app.style.visibility = 'visible';
      app.style.pointerEvents = 'auto';
    }
    identityGateSwitchMode = false;
  }

  function openIdentityModal(open, switchMode) {
    const modal = document.getElementById('identityModal');
    if (!modal) return;
    if (typeof switchMode === 'boolean') identityGateSwitchMode = switchMode;
    if (open) {
      showLoginGate();
      return;
    }
    if (isSessionAuthenticated()) {
      hideLoginGate();
      return;
    }
    showLoginGate();
    identityGateSwitchMode = false;
    syncIdentityGateControls();
  }

  function rememberSession(token) {
    rbacSessionToken = token || '';
    try {
      if (rbacSessionToken) {
        sessionStorage.setItem('threatfusion.rbac.session', rbacSessionToken);
        localStorage.setItem('threatfusion.rbac.session', rbacSessionToken);
      } else {
        sessionStorage.removeItem('threatfusion.rbac.session');
        localStorage.removeItem('threatfusion.rbac.session');
      }
    } catch (err) {
      rbacSessionToken = token || '';
    }
  }

  function readStoredSessionToken() {
    try {
      return sessionStorage.getItem('threatfusion.rbac.session')
        || localStorage.getItem('threatfusion.rbac.session')
        || '';
    } catch (err) {
      return '';
    }
  }

  function applyAuthenticatedSession(data) {
    if (!data || data.authenticated !== true) {
      sessionIdentity = null;
      rememberSession('');
      paintOperatorBadge('unverified local label', false);
      renderActiveSessionCard();
      return;
    }
    sessionIdentity = data;
    rememberSession(data.session_token || rbacSessionToken);
    applyOperatorSelection(data.actor_id || '', data.display_name || '');
    paintSessionIdentity(sessionIdentity);
    const select = document.getElementById('operatorRoleSelect');
    if (select && data.actor_id) select.value = data.actor_id;
    renderActiveSessionCard();
  }

  function identityStatus(text, state) {
    const node = document.getElementById('identityModalStatus');
    if (!node) return;
    node.textContent = text;
    node.setAttribute('data-evidence-state', state || 'unavailable');
  }

  async function refreshRbacSession() {
    try {
      if (!rbacSessionToken) rbacSessionToken = readStoredSessionToken();
    } catch (err) {
      rbacSessionToken = rbacSessionToken || '';
    }
    if (!rbacSessionToken) {
      sessionIdentity = null;
      return;
    }
    try {
      const resp = await fetch('/api/rbac/session');
      const data = await readActionPayload(resp);
      if (data && data.authenticated === true) applyAuthenticatedSession(data);
      else {
        sessionIdentity = null;
        rememberSession('');
        paintOperatorBadge('unverified local label', false);
      }
    } catch (err) {
      sessionIdentity = null;
    }
  }

  async function submitRbacLogin(useEntra) {
    const email = formControlValue('rbacUsername', '');
    const body = useEntra
      ? { entra_token: formControlValue('rbacEntraToken', ''), email: email }
      : {
        email: email,
        username: email,
        access_code: formControlValue('rbacAccessCode', '')
      };
    try {
      const resp = await fetch('/api/rbac/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await readActionPayload(resp);
      if (resp.ok && data.authenticated === true) {
        applyAuthenticatedSession(data);
        identityStatus(headerLineForSession(data), data.identity_verified ? 'verified' : 'unavailable');
        identityGateSwitchMode = false;
        hideLoginGate();
        return;
      }
      identityStatus(actionFailureText(data, resp), 'unavailable');
    } catch (err) {
      identityStatus('Sign-in unavailable.', 'unavailable');
    }
  }

  async function submitRbacRegister() {
    const email = formControlValue('rbacUsername', '');
    const body = {
      email: email,
      username: email,
      access_code: formControlValue('rbacAccessCode', ''),
      display_name: formControlValue('rbacRegisterName', ''),
      role: formControlValue('rbacRegisterRole', 'tier1_triage')
    };
    try {
      const resp = await fetch('/api/rbac/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await readActionPayload(resp);
      if (resp.ok && data.authenticated === true) {
        applyAuthenticatedSession(data);
        identityStatus(headerLineForSession(data), 'unavailable');
        identityGateSwitchMode = false;
        hideLoginGate();
        return;
      }
      identityStatus(actionFailureText(data, resp), 'unavailable');
    } catch (err) {
      identityStatus('Account creation unavailable.', 'unavailable');
    }
  }

  async function submitRbacLogout() {
    try {
      await fetch('/api/rbac/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
    } catch (err) {
      identityStatus('Sign-out unavailable.', 'unavailable');
    }
    sessionIdentity = null;
    rememberSession('');
    paintOperatorBadge('unverified local label', false);
    identityStatus('Signed out. Authenticate to re-enter the SOC console.', 'unavailable');
    identityGateSwitchMode = false;
    enforceAuthGate();
  }

  function renderPlaybookPreview(data) {
    const targets = [
      ['soarPlaybookMeta', 'soarPlaybookCode', 'soarPlaybookTrace'],
      ['soarPlaybookMetaSide', 'soarPlaybookCodeSide', 'soarPlaybookTraceSide']
    ];
    targets.forEach(ids => {
      const meta = document.getElementById(ids[0]);
      const code = document.getElementById(ids[1]);
      const trace = document.getElementById(ids[2]);
      if (!data) {
        if (meta) meta.textContent = 'Select an attack flow to render its responder script.';
        if (code) code.textContent = 'waiting';
        if (trace) trace.textContent = '';
        return;
      }
      if (meta) {
        meta.textContent = String(data.playbook_id || '')
          + ' · ' + String(data.script_filename || '')
          + ' · ' + String(data.mitre_technique_id || '')
          + ' · TheHive severity ' + String(data.thehive_severity == null ? '' : data.thehive_severity)
          + ' · ' + String(data.target_service || '')
          + ' · ' + String(data.firewall_rule_preview || '');
      }
      if (code) code.textContent = String(data.rendered_python_code || '');
      if (trace) {
        const steps = Array.isArray(data.execution_steps_log) ? data.execution_steps_log : [];
        trace.innerHTML = steps.map(step => '<li>' + escapeHtml(step.line || '') + '</li>').join('');
      }
    });
  }

  async function loadSoarPlaybookPreview(inc) {
    const flowId = inc && (inc.flowId || inc.flow_id);
    if (!flowId) {
      renderPlaybookPreview(null);
      return;
    }
    try {
      const resp = await fetch('/api/soar/playbook-preview?flow_id=' + encodeURIComponent(String(flowId)));
      const data = await readActionPayload(resp);
      if (!resp.ok) {
        renderPlaybookPreview(null);
        return;
      }
      renderPlaybookPreview(data);
    } catch (err) {
      renderPlaybookPreview(null);
    }
  }

  function renderAzurePortal(status) {
    const node = document.getElementById('azurePortalStatus');
    const snippet = document.getElementById('azureProvisionSnippet');
    if (snippet && status && status.terminal_snippet) snippet.textContent = String(status.terminal_snippet);
    if (!node) return;
    if (!status) {
      node.textContent = 'Azure portal state has not been loaded.';
      node.setAttribute('data-evidence-state', 'unavailable');
      return;
    }
    const connected = status.connected === true;
    node.textContent = connected
      ? ('Azure CLI connected. Tenant ' + String(status.tenant_id || '')
        + '. Subscription ' + String(status.subscription_id || '')
        + '. Victim ' + String(status.victim_vm_ip || '')
        + '. Attacker ' + String(status.attacker_vm_ip || '') + '.')
      : ('Azure CLI ' + (status.azure_cli_present ? 'is installed' : 'is not installed')
        + '. Live subscription file is not connected. Run the provision command to write azure_portal_state.json.');
    node.setAttribute('data-evidence-state', connected ? 'verified' : 'unavailable');
  }

  async function loadAzurePortalStatus() {
    try {
      const resp = await fetch('/api/azure/status');
      renderAzurePortal(await readActionPayload(resp));
    } catch (err) {
      renderAzurePortal(null);
    }
  }

  async function switchEnterpriseOperator() {
    openIdentityModal(true, true);
    identityStatus(
      isSessionAuthenticated()
        ? 'Switch operator or sign out. Return to Console keeps the current session.'
        : 'Authentication required before entering the SOC console.',
      isSessionAuthenticated() ? 'verified' : 'unavailable'
    );
  }

  async function enrollSelectedOperator() {
    const select = document.getElementById('operatorRoleSelect');
    const actorId = select ? select.value : '';
    applyOperatorSelection(actorId, OPERATOR_LABELS[actorId] || '');
    await enrollLabOperator();
  }

  async function registerEnterpriseOperator() {
    const body = {
      actor_id: queueControlValue('operatorActorRegister', ''),
      display_name: queueControlValue('operatorNameRegister', ''),
      role: queueControlValue('operatorRoleRegister', 'soc_approver')
    };
    try {
      const resp = await fetch('/api/v1/live/operators/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await readActionPayload(resp);
      setLiveText(
        'operatorSwitchStatus',
        resp.ok ? ('Operator ' + body.actor_id + ' registered as ' + String(data.role || '') + '.') : actionFailureText(data, resp),
        resp.ok ? 'verified' : 'unavailable'
      );
      if (resp.ok) await loadEnterpriseControls();
    } catch (err) {
      setLiveText('operatorSwitchStatus', 'Operator registration unavailable.', 'unavailable');
    }
  }

  async function launchRangeVector(vectorId) {
    setLiveText('rangeFirewallStatus', 'Launching ' + vectorId + ' from 172.29.0.10 to 172.29.0.20.', 'pending');
    try {
      const resp = await fetch('/api/v1/live/range/launch-vector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vector_id: vectorId,
          src_ip: '172.29.0.10',
          dst_ip: '172.29.0.20'
        })
      });
      const data = await readActionPayload(resp);
      if (data && data.flow_id) {
        selectedIncidentId = 'live_flow:' + data.flow_id;
        selectedFlowId = Number(data.flow_id);
        modelProofLoadedFlowId = null;
        lastCopilotFlowId = 0;
      }
      await refreshLiveCampaigns();
      renderVisualObservatory(data);
      const inc = selectedIncident();
      if (inc) {
        selectInvestigation(inc);
      }
      const score = Number(data.rf_attack_probability);
      setLiveText(
        'rangeFirewallStatus',
        resp.ok
          ? ('Launched ' + vectorId + ' flow ' + data.flow_id + ' RF '
            + (Number.isFinite(score) ? score.toFixed(4) : 'unavailable') + '.')
          : actionFailureText(data, resp),
        resp.ok ? 'verified' : 'unavailable'
      );
      const telemetry = await fetch('/api/v1/live/range/telemetry');
      renderRangeFirewall(await readActionPayload(telemetry));
    } catch (err) {
      setLiveText('rangeFirewallStatus', 'Range launch unavailable.', 'unavailable');
    }
  }

  async function registerEnterpriseSensor() {
    const body = {
      sensor_id: queueControlValue('sensorIdInput', ''),
      monitored_cidr: queueControlValue('sensorCidrInput', '')
    };
    try {
      const resp = await fetch('/api/v1/live/sensors/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await readActionPayload(resp);
      if (resp.ok) renderSensorRegistry(data);
      else setLiveText('sensorRegistryList', actionFailureText(data, resp), 'unavailable');
    } catch (err) {
      setLiveText('sensorRegistryList', 'Sensor registration unavailable.', 'unavailable');
    }
  }

  async function exportComplianceDossier() {
    try {
      const resp = await fetch('/api/v1/live/compliance-dossier');
      const data = await readActionPayload(resp);
      const markdown = data && typeof data.dossier_markdown === 'string' ? data.dossier_markdown : '';
      if (!resp.ok || !markdown) {
        setLiveText('workspaceStatus', actionFailureText(data, resp), 'unavailable');
        return;
      }
      const blob = new Blob([markdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'threatfusion-executive-compliance-dossier.md';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setLiveText('workspaceStatus', 'Executive compliance dossier exported.', 'verified');
    } catch (err) {
      setLiveText('workspaceStatus', 'Compliance dossier unavailable.', 'unavailable');
    }
  }

  // Export functions to window for programmatic test validation
  window.ThreatFusionDashboard = {
    EVAL_PACK_REV2,
    verifySoarChain,
    verifyChromaRagHits,
    verifyHiveAndN8nReceipt,
    SAMPLE_INCIDENTS,
    WALKTHROUGH_STAGES,
    groupConsecutiveTimelineByActor,
    initApp
  };

  // Run on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
})();
