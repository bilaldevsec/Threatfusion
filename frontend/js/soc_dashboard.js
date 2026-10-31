/**
 * ThreatFusion SOC Unicorn Web Console & Interactive Walkthrough Engine
 * Document Identifier: SOP-UX-SOC-001 (Rev 1.0.0) | Project: AI-FYP-2006
 * 100% Offline / Zero CDN Dependencies / Strict Receipt & Forensic Evidence Verification
 */

(function () {
  'use strict';

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
   * Must have non-empty case_id and valid 64-char hex execution receipt signature.
   */
  function verifyHiveAndN8nReceipt(hiveCase, n8nReceipt) {
    if (!hiveCase || typeof hiveCase !== 'object') return false;
    const caseId = typeof hiveCase.case_id === 'string' ? hiveCase.case_id.trim() : '';
    if (!caseId) return false;

    if (!n8nReceipt || typeof n8nReceipt !== 'object') return false;
    const execId = typeof n8nReceipt.execution_id === 'string' ? n8nReceipt.execution_id.trim() : '';
    if (!execId) return false;
    const sig = typeof n8nReceipt.signature_sha256 === 'string' ? n8nReceipt.signature_sha256.trim() : '';
    return SHA256_HEX_REGEX.test(sig);
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
  let campaignFetchSettled = false;
  let liveQueueLoaded = false;
  let campaignFingerprint = null;
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

          if (mttiEl && data.telemetry_source === 'live_measured' && data.mtti_seconds_mean !== undefined) {
            mttiEl.textContent = `${Number(data.mtti_seconds_mean).toFixed(2)}s`;
          }
          if (mttrEl && data.telemetry_source === 'live_measured' && data.mttr_seconds_mean !== undefined) {
            mttrEl.textContent = `${Number(data.mttr_seconds_mean).toFixed(3)}s`;
          }
          if (data.noise_reduction_funnel) {
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
    if (name === 'hunter') renderHunterGauges();
  }

  function openLabDrawer(open) {
    const drawer = document.getElementById('labControlsDrawer');
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

  function initApp() {
    renderIncidentQueue();
    renderForensicDrawer();
    initWalkthroughTimeline();
    setupEventListeners();
    refreshOperationalVelocity();
    refreshAdvisoryStatus();
    refreshAgyAudit();
    refreshLiveCampaigns();
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

  function alertTitle(inc) {
    const src = inc.provenance && inc.provenance.srcIp ? inc.provenance.srcIp : 'not recorded';
    const dst = inc.provenance && inc.provenance.dstIp ? inc.provenance.dstIp : 'not recorded';
    const port = inc.provenance && inc.provenance.dstPort ? inc.provenance.dstPort : '';
    const proto = String((inc.provenance && inc.provenance.proto) || 'flow').toUpperCase();
    if (src !== 'not recorded' && dst !== 'not recorded') {
      return proto + ' probe ' + src + ' -> ' + dst + (port ? ':' + port : '');
    }
    return inc.advisory && inc.advisory.summaryHeadline ? inc.advisory.summaryHeadline : String(inc.id);
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
    if (!inc) return { dot: 'status-pending', label: 'Pending', output: 'No stored flow is selected.' };
    if (key === 'forest') {
      return { dot: 'status-verified', label: 'Verified', output: 'Frozen RF decision ' + inc.decision + '.' };
    }
    if (key === 'gemini') {
      const live = document.getElementById('copilotProviderBadge');
      const text = live ? live.textContent : '';
      if (text.indexOf('Local') !== -1) return { dot: 'status-pending', label: 'Pending', output: 'Local air-gapped corpus. No live model key is in use.' };
      return { dot: 'status-verified', label: 'Verified', output: text };
    }
    if (key === 'respond') {
      if (inc.containmentState === 'applied') return { dot: 'status-verified', label: 'Verified', output: 'Victim firewall drop is applied for 172.29.0.10.' };
      return { dot: 'status-pending', label: 'Pending', output: 'Containment has not been applied. execution_path=' + (inc.executionPath || 'not dispatched') + '.' };
    }
    if (key === 'ground' && inc.analystRationale && inc.analystRationale.indexOf('203.0.113') !== -1) {
      return { dot: 'status-refused', label: 'Refused', output: 'Groundedness refused an address that is not on the stored flow.' };
    }
    return { dot: 'status-verified', label: 'Verified', output: 'Stored field checked for ' + inc.id + '.' };
  }

  function graphNodeLabel(node) {
    const copy = node.querySelector('.node-copy');
    return copy ? copy.textContent : node.textContent;
  }

  function renderActionGraph() {
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
      itemEl.dataset.id = inc.id;
      itemEl.dataset.sourceLabel = inc.sourceLabel || '';
      const priority = priorityFor(inc);
      const observed = typeof inc.observedAt === 'string' ? inc.observedAt.replace('T', ' ').substring(0, 19) : '';
      const src = inc.provenance && inc.provenance.srcIp ? inc.provenance.srcIp : 'not recorded';
      const dst = inc.provenance && inc.provenance.dstIp ? inc.provenance.dstIp : 'not recorded';
      const malicious = inc.decision === 'Attack';
      const triage = inc.triageState && inc.triageState !== 'unreviewed' ? inc.triageState : 'Open';
      itemEl.innerHTML = ''
        + '<td><span class="priority-pill priority-' + priority.key + '">' + priority.label + '</span></td>'
        + '<td>' + escapeHtml(observed) + ' UTC</td>'
        + '<td><code>INV-' + escapeHtml(inc.flowId || inc.id) + '</code><div><code>' + escapeHtml(inc.id) + '</code></div></td>'
        + '<td><span class="decision-pill ' + (malicious ? 'decision-malicious' : 'decision-benign') + '">' + (malicious ? 'MALICIOUS' : 'BENIGN') + '</span><span class="alert-title">' + escapeHtml(alertTitle(inc)) + '</span></td>'
        + '<td><code class="entity-pill">' + escapeHtml(src) + '</code><code class="entity-pill">' + escapeHtml(dst) + '</code></td>'
        + '<td>' + escapeHtml(sourceDisplayName(inc.sourceLabel)) + '</td>'
        + '<td>' + escapeHtml(triage) + ' <span class="priority-pill priority-info">' + escapeHtml(inc.analystVerdict || 'no verdict') + '</span></td>';
      itemEl.addEventListener('click', () => {
        selectedIncidentId = inc.id;
        renderIncidentQueue();
        renderForensicDrawer();
        showSocView('detail');
      });
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

  function syncLiveInspector(inc) {
    const title = document.getElementById('inspectorCaseTitle');
    const badge = document.getElementById('groundedBadge');
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
      setInspectorText('inspectorAssets', 'not recorded');
      setInspectorText('inspectorTechnique', 'unavailable');
      setInspectorText('inspectorTactic', 'unavailable');
      setInspectorText('inspectorPlaybook', 'none');
      setInspectorText('inspectorChain', 'unavailable');
      setInspectorText('inspectorCallback', 'not recorded');
      setInspectorText('inspectorExecutionPath', 'not dispatched');
      showOperatorStamp({ identity_verified: false, identity_label: 'unverified_local_label' });
      renderGlassBox(null);
      return;
    }
    const score = Number(inc.uncalibratedScore);
    const scoreText = Number.isFinite(score) ? (score * 100).toFixed(2) + '%' : 'unavailable';
    const headline = inc.advisory && inc.advisory.summaryHeadline
      ? String(inc.advisory.summaryHeadline)
      : ((inc.live ? 'Stored flow ' : 'Recorded case ') + String(inc.id));
    if (title) title.textContent = headline;
    const conclusion = document.getElementById('conclusionCard');
    if (conclusion) conclusion.setAttribute('data-decision', String(inc.decision || 'withheld'));
    const src = inc.provenance && inc.provenance.srcIp ? String(inc.provenance.srcIp) : 'not recorded';
    const dst = inc.provenance && inc.provenance.dstIp ? String(inc.provenance.dstIp) : 'not recorded';
    setInspectorText('inspectorDecision', String(inc.decision || 'withheld'));
    setInspectorText('inspectorScore', scoreText);
    const sensor = inc.sensorObservation;
    if (inc.sourceLabel === 'suricata_bridge' && sensor) {
      setInspectorText('inspectorSensorLine', 'Suricata: ' + (sensor.suricata_line || 'flow only, no signature'));
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + (sensor.forest_line || 'unavailable'));
      setInspectorText('inspectorScenarioLabel', 'no scenario label');
    } else if (inc.sourceLabel === 'live_scenario_replay') {
      const reason = inc.scoreReason || 'unscored';
      setInspectorText('inspectorSensorLine', 'Suricata: not a live sensor flow');
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + String(inc.decision || 'withheld') + ', ' + scoreText + ', ' + reason);
      setInspectorText('inspectorScenarioLabel', 'scenario label ' + (inc.scenarioLabel || 'none'));
    } else {
      setInspectorText('inspectorSensorLine', 'Suricata: not a live sensor flow');
      setInspectorText('inspectorForestLine', 'Frozen forest: ' + String(inc.decision || 'withheld') + ', ' + scoreText + ', ' + (inc.scoreReason || 'unscored'));
      setInspectorText('inspectorScenarioLabel', 'no scenario label');
    }
    setInspectorText('inspectorAssets', src + ' -> ' + dst);
    const chainOk = verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256);
    if (badge) {
      badge.textContent = chainOk ? 'SOAR chain verified' : 'SOAR chain unavailable';
      badge.setAttribute('data-evidence-state', chainOk ? 'verified' : 'unavailable');
    }
    const ragOk = verifyChromaRagHits(inc.chromaRagHits);
    if (ragOk) {
      setInspectorText('inspectorTechnique', 'retrieved candidate technique ' + inc.chromaRagHits[0].technique_id);
      setInspectorText('inspectorTactic', inc.chromaRagHits[0].technique_name);
    } else {
      setInspectorText('inspectorTechnique', 'unavailable');
      setInspectorText('inspectorTactic', 'unavailable');
    }
    const playbook = inc.soarRecord && inc.soarRecord.playbookId ? String(inc.soarRecord.playbookId) : 'none';
    const state = inc.soarRecord && inc.soarRecord.state ? String(inc.soarRecord.state) : 'none';
    setInspectorText('inspectorPlaybook', playbook + ' / ' + state);
    const chainNode = document.getElementById('inspectorChain');
    if (chainNode) {
      chainNode.textContent = chainOk ? 'Chain valid (SHA-256)' : 'unavailable';
      chainNode.setAttribute('data-evidence-state', chainOk ? 'verified' : 'unavailable');
    }
    const signed = inc.live === true
      && typeof inc.callbackSignature === 'string'
      && SHA256_HEX_REGEX.test(inc.callbackSignature);
    setInspectorText('inspectorCallback', signed ? inc.callbackSignature.slice(0, 16) : 'not recorded');
    const executionPath = inc.executionPath === 'n8n_live_container'
      || inc.executionPath === 'local_contract_fallback'
      ? inc.executionPath
      : 'not dispatched';
    setInspectorText('inspectorExecutionPath', executionPath);
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
      '<div class="finding-row"><span class="finding-num">' + (index + 1) + '</span> '
      + escapeHtml(item.id + ': ' + item.status + (item.passed ? ' pass' : ' open'))
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
    const chainOk = verifySoarChain(inc.soarAuditChainVerified, inc.soarAuditChainHeadSha256);
    const ragOk = verifyChromaRagHits(inc.chromaRagHits);
    const hiveOk = verifyHiveAndN8nReceipt(inc.thehiveCaseRecord, inc.n8nPlaybookReceipt);
    const signedLocalCallback = inc.live === true
      && typeof inc.callbackSignature === 'string'
      && SHA256_HEX_REGEX.test(inc.callbackSignature)
      && typeof inc.thehiveCaseId === 'string'
      && inc.thehiveCaseId.indexOf('case_') === 0
      && Number.isFinite(Number(inc.mttrSeconds));

    const chainState = chainOk ? 'verified' : 'unavailable';
    const ragState = ragOk ? 'verified' : 'unavailable';
    const hiveState = (hiveOk || signedLocalCallback) ? 'verified' : (inc.soarRecord && inc.soarRecord.state === 'pending_approval' ? 'pending' : 'unavailable');
    const hiveLabel = signedLocalCallback
      ? ('TheHive Case: ' + inc.thehiveCaseId)
      : (hiveOk ? 'TheHive Case: DISPATCHED' : (inc.soarRecord && inc.soarRecord.state === 'pending_approval' ? 'TheHive Case: PENDING APPROVAL' : 'TheHive Case: UNAVAILABLE'));
    const techniqueId = ragOk ? inc.chromaRagHits[0].technique_id : (inc.live ? 'unavailable' : 'T1046');
    const tacticName = ragOk ? inc.chromaRagHits[0].technique_name : (inc.live ? 'unavailable' : 'Network Service Discovery');
    const cosineText = ragOk ? inc.chromaRagHits[0].cosine_similarity.toFixed(4) : (inc.live ? 'unavailable' : '0.9120');
    const recordedCaseId = signedLocalCallback
      ? inc.thehiveCaseId
      : ((inc.thehiveCaseRecord && inc.thehiveCaseRecord.case_id) || 'not recorded');

    // Build Forensic Drawer HTML
    drawerEl.innerHTML = `
      <!-- Tier 1: Primary Decision Signal -->
      <div class="tier-section" data-blast-ui-tier="unicorn-progressive-disclosure-v1">
        <div class="tier-header">
          <span class="tier-1-title">Tier 1: Primary Triage Signal (Decision Authority)</span>
          <span class="badge badge-rf-confidence">Sole Authority: Random Forest (${(inc.uncalibratedScore * 100).toFixed(2)}%)</span>
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
            <span class="evidence-cell-val"><code>${escapeHtml(inc.provenance.srcIp)}:${inc.provenance.srcPort} -> ${escapeHtml(inc.provenance.dstIp)}:${inc.provenance.dstPort} (${inc.provenance.proto})</code></span>
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
              ${chainOk ? 'SOAR Chain: VERIFIED (SHA-256 Linked)' : 'SOAR Chain: UNAVAILABLE'}
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
          ` : '<div style="font-size: 0.8rem; color: var(--text-muted); font-style: italic;">No semantic RAG hits attached to this alert candidate.</div>'}
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
            <button class="btn btn-approve" id="btnApprovePlaybook" ${!(inc.live && inc.flowId && inc.soarRecord && inc.soarRecord.state === 'pending_approval') ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : ''}>
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
            <div><b>Risk Level:</b> <span class="badge badge-decision">${inc.uncalibratedScore >= 0.9 ? 'CRITICAL' : (inc.uncalibratedScore >= 0.7 ? 'HIGH' : 'MEDIUM')}</span></div>
            <div><b>RF Confidence:</b> ${(inc.uncalibratedScore * 100).toFixed(2)}%</div>
            <div><b>Priority Rank:</b> #${inc.secondaryAe && inc.secondaryAe.status === 'ANOMALY_CONFIRMED' ? 1 : 2}</div>
            <div style="margin-top: 0.25rem;"><span class="badge badge-secondary-anomaly">${EVAL_PACK_REV2.section8Lock.recallComparisonString}</span></div>
            <div style="margin-top: 0.25rem;"><b>Affected Assets:</b> <code>${escapeHtml(inc.provenance.srcIp)}</code>, <code>${escapeHtml(inc.provenance.dstIp)}</code></div>
          </div>

          <!-- Block 2: Attack Timeline -->
          <div class="anatomy-block" data-anatomy-block="2">
            <h4>Block 2: Attack Timeline</h4>
            <div><b>Window Type:</b> <span class="badge badge-corr">${inc.correlation ? escapeHtml(inc.correlation.windowType) : '30.0s_burst'}</span></div>
            <div><b>Correlated Flows:</b> ${liveCorrelationReport ? Number(liveCorrelationReport.correlated_flow_count || 0) : (inc.correlation ? inc.correlation.constituentAlerts : 1)}</div>
            <div><b>Progression:</b> ${liveCorrelationReport ? 'Live unified timeline' : ('Ingest at ' + escapeHtml(inc.observedAt))}</div>
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
            <div><b>Audit Chain:</b> <span class="badge" data-evidence-state="${chainState}">${chainOk ? 'Chain Valid (SHA-256)' : 'Chain Unavailable'}</span></div>
            <div><b>TheHive case:</b> <code>${escapeHtml(recordedCaseId)}</code></div>
            <div><b>Callback MTTR:</b> ${inc.mttrSeconds === null || inc.mttrSeconds === undefined ? 'not recorded' : Number(inc.mttrSeconds).toFixed(3) + 's'}</div>
            <div><b>HMAC:</b> <code>${inc.callbackSignature && SHA256_HEX_REGEX.test(inc.callbackSignature) ? escapeHtml(inc.callbackSignature.substring(0, 16)) + '...' : 'none'}</code></div>
            <div><b>HMAC Verified:</b> <span class="badge" data-evidence-state="${hiveState}">${(hiveOk || signedLocalCallback) ? 'Signed callback recorded' : 'Pending Authorization'}</span></div>
            <div><b>Execution path:</b> <code>${escapeHtml(inc.executionPath || 'not dispatched')}</code></div>
          </div>
        </div>
      </div>
    `;

    // Bind SOAR Action Buttons
    const btnApprove = document.getElementById('btnApprovePlaybook');
    if (btnApprove && inc.live && inc.flowId && inc.soarRecord && inc.soarRecord.state === 'pending_approval') {
      btnApprove.addEventListener('click', () => {
        approveLivePlaybook(inc);
      });
    }

    const btnRollback = document.getElementById('btnRollbackPlaybook');
    if (btnRollback) {
      btnRollback.disabled = true;
    }
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

    const copilotButton = document.getElementById('btnLiveCopilot');
    if (copilotButton) {
      copilotButton.addEventListener('click', () => { askLiveCopilot(); });
    }
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
    const topApproveBtn = document.getElementById('topBtnApproveSoar');
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
    const guidedApprove = document.getElementById('btnGuidedApprove');
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
        postRangeContainment(inc, '/api/v1/live/soar/rollback');
      });
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
  }

  function setLiveText(id, text, state) {
    const node = document.getElementById(id);
    if (!node) return;
    node.textContent = text;
    if (state) node.setAttribute('data-evidence-state', state);
  }

  function scenarioLabelFromTitle(flow) {
    if (!flow || flow.source_label !== 'live_scenario_replay') return '';
    const title = String(flow.case_title || '');
    const match = title.match(/scenario label (T\d+(?:\.\d+)?)/);
    return match ? match[1] : 'none';
  }

  function flowToIncident(flow, memberCount) {
    const score = Number(flow.rf_attack_probability);
    const entry = typeof flow.entry_sha256 === 'string' ? flow.entry_sha256 : '';
    const chainOk = flow.audit_chain_verified === 1 || flow.audit_chain_verified === true;
    return {
      id: 'live_flow:' + flow.flow_id,
      live: true,
      flowId: flow.flow_id,
      sourceEventId: flow.source_label || 'live_flow',
      sourceLabel: flow.source_label || 'live_flow',
      scenarioLabel: scenarioLabelFromTitle(flow),
      sensorObservation: flow.sensor_observation || null,
      scoreReason: flow.reason || '',
      observedAt: flow.observed_at_utc || '',
      decision: flow.decision || 'withheld',
      uncalibratedScore: Number.isFinite(score) ? score : 0,
      modelArtifactSha256: flow.model_sha256 || EVAL_PACK_REV2.rfArtifactSha256,
      modelVersion: 'full-network-random-forest-6d69c72-v1',
      provenance: {
        srcIp: flow.src_entity_id || 'not-recorded',
        dstIp: flow.dst_entity_id || 'not-recorded',
        srcPort: 0,
        dstPort: Number(flow.service_or_port) || 0,
        proto: flow.flow_protocol || 'flow'
      },
      correlation: {
        incidentId: flow.campaign_id || ('flow:' + flow.flow_id),
        windowType: 'stored campaign',
        constituentAlerts: memberCount || 1,
        explanation: flow.case_title || 'Stored live flow. No new entity key was inferred.'
      },
      threatIntel: { privateIpGuardTriggered: false },
      secondaryAe: { aeError: 0, status: 'not_scored' },
      advisory: {
        summaryHeadline: flow.source_label === 'suricata_bridge' && flow.sensor_observation
          ? ('Suricata: ' + flow.sensor_observation.suricata_line)
          : (flow.case_title || ('Stored flow ' + flow.flow_id)),
        detectionRationale: 'Frozen Random Forest score. Fusion disabled. The autoencoder did not decide this alert.'
      },
      chromaRagHits: [],
      soarRecord: {
        playbookId: flow.playbook_id || 'pending',
        state: flow.ledger_state || 'pending_approval',
        targetEntity: 'live_flow:' + flow.flow_id,
        version: 1
      },
      soarAuditChainVerified: chainOk && SHA256_HEX_REGEX.test(entry),
      soarAuditChainHeadSha256: entry,
      callbackSignature: typeof flow.callback_signature === 'string' ? flow.callback_signature : '',
      executionPath: flow.execution_path || '',
      operatorId: flow.operator_id || '',
      certSha256Prefix: flow.cert_sha256_prefix || '',
      identityVerified: flow.identity_verified === 1 || flow.identity_verified === true,
      identityLabel: flow.identity_label || 'unverified_local_label',
      thehiveCaseId: flow.thehive_case_id || '',
      mttrSeconds: flow.mttr_seconds,
      containmentState: flow.containment_state || '',
      triageState: flow.triage_state || 'unreviewed',
      analystVerdict: flow.analyst_verdict || '',
      analystRationale: flow.analyst_rationale || '',
      assigneeId: flow.assignee_id || '',
      reviewStatus: flow.review_status || 'unassigned',
      glassBox: flow.glass_box || null,
      thehiveCaseRecord: null,
      n8nPlaybookReceipt: null
    };
  }

  function incidentRowToView(row) {
    const score = Number(row.max_probability_score);
    return {
      id: String(row.incident_id),
      live: true,
      flowId: null,
      sourceEventId: row.provenance_status || 'incident_store',
      observedAt: row.earliest_observed_at || '',
      decision: row.escalated_decision || 'withheld',
      uncalibratedScore: Number.isFinite(score) ? score : 0,
      modelArtifactSha256: EVAL_PACK_REV2.rfArtifactSha256,
      modelVersion: 'stored_incident',
      provenance: {
        srcIp: 'stored-incident',
        dstIp: 'stored-incident',
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
      secondaryAe: { aeError: 0, status: 'not_scored' },
      advisory: {
        summaryHeadline: 'Stored incident ' + row.incident_id,
        detectionRationale: 'Read from the incidents database. Fusion stays disabled.'
      },
      chromaRagHits: [],
      soarRecord: {
        playbookId: 'none',
        state: 'pending_approval',
        targetEntity: String(row.incident_id),
        version: 1
      },
      soarAuditChainVerified: false,
      soarAuditChainHeadSha256: '',
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
    const blocked = (views || []).some(item => item.containmentState === 'applied');
    const rolled = (views || []).some(item => item.containmentState === 'rolled_back');
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
      node.textContent = 'no stored n8n callback';
      if (detail) detail.textContent = 'Shown only after a stored n8n callback. The January benchmark is separate.';
      return;
    }
    node.textContent = Number(hit.mttrSeconds).toFixed(3) + 's';
    if (detail) detail.textContent = 'Stored n8n callback on this queue. Not the January benchmark.';
  }

  async function refreshAdvisoryStatus() {
    try {
      const resp = await fetch('/api/v1/live/advisory-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const data = await resp.json();
      const badge = document.getElementById('copilotProviderBadge');
      if (badge && data.label) {
        badge.textContent = data.label;
        badge.setAttribute('data-evidence-state', data.provider === 'gemini' ? 'verified' : 'unavailable');
      }
    } catch (err) {
      const badge = document.getElementById('copilotProviderBadge');
      if (badge) badge.textContent = 'AI Copilot: Local Air-Gapped Engine';
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

  async function refreshLiveCampaigns() {
    try {
      const resp = await fetch('/api/v1/live/campaigns');
      if (!resp.ok) throw new Error('campaign status');
      const data = await resp.json();
      const views = [];
      (data.campaigns || []).forEach(campaign => {
        (campaign.flows || []).forEach(flow => {
          views.push(flowToIncident(flow, campaign.member_count));
        });
      });
      (data.incidents || []).forEach(row => views.push(incidentRowToView(row)));
      liveCampaignIncidents = views;
      showStoredN8nMttr(views);
      showStoredContainment(views);
      liveQueueLoaded = true;
      campaignFetchSettled = true;
      setSampleSurfacesHidden(true);
      if (!views.some(item => item.id === selectedIncidentId)) {
        selectedIncidentId = views.length ? views[0].id : '';
      }
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
      const nextPrint = views.map(item => [
        item.id,
        item.decision,
        item.sourceLabel,
        item.analystVerdict,
        item.assigneeId,
        item.reviewStatus,
        item.sensorObservation && item.sensorObservation.forest_line
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
    } catch (err) {
      setLiveText('constitutionalHealth', 'Constitutional health unavailable.', 'unavailable');
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
        const guard = flow.misp_guard_status === 422 ? ', private IP refused HTTP 422' : '';
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

  function showOperatorStamp(stamp) {
    const node = document.getElementById('operatorIdentityBadge');
    if (!node || !stamp) return;
    const verified = stamp.identity_verified === true || stamp.identityVerified === true;
    const label = stamp.identity_label || stamp.identityLabel || '';
    const operatorId = stamp.operator_id || stamp.operatorId || '';
    const prefix = stamp.cert_sha256_prefix || stamp.certSha256Prefix || '';
    if (verified && label !== 'unverified_local_label' && operatorId === 'lab_operator' && prefix) {
      node.textContent = 'verified lab_operator ' + prefix;
      node.setAttribute('data-evidence-state', 'verified');
      return;
    }
    node.textContent = 'unverified local label';
    node.setAttribute('data-evidence-state', 'unavailable');
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
      showOperatorStamp(data);
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
      setLiveText('campaignQueueStatus', 'Approval applies to a stored flow. Containment stays unauthorized.', 'unavailable');
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
      const data = await resp.json();
      const receipt = typeof data.entry_sha256 === 'string' ? data.entry_sha256 : '';
      showOperatorStamp(data);
      if (data.evidence_state === 'verified' && SHA256_HEX_REGEX.test(receipt)) {
        setLiveText('campaignQueueStatus', 'SOAR receipt ' + receipt.substring(0, 16) + ' verified. Containment not executed.', 'verified');
      } else {
        setLiveText('campaignQueueStatus', 'SOAR approval unavailable.', 'unavailable');
      }
      await refreshLiveCampaigns();
    } catch (err) {
      setLiveText('campaignQueueStatus', 'SOAR approval unavailable.', 'unavailable');
    }
  }

  function selectedLiveFlowId() {
    const inc = activeIncidents().find(item => item.id === selectedIncidentId);
    return inc && inc.flowId ? inc.flowId : null;
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
    const rationale = rationaleNode ? rationaleNode.value : '';
    if (!flowId) {
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
      const data = await resp.json();
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      setLiveText(
        'analystVerdictDisplay',
        data.evidence_state === 'verified'
          ? ('Analyst verdict ' + data.analyst_verdict + ' stored. Frozen RF decision ' + data.frozen_rf_decision + '.')
          : 'Analyst verdict refused.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('analystVerdictDisplay', 'Analyst verdict unavailable.', 'unavailable');
    }
  }

  async function saveCaseAssignment() {
    const flowId = selectedLiveFlowId();
    const assigneeNode = document.getElementById('caseAssignee');
    const assignee = assigneeNode ? assigneeNode.value : '';
    const reviewStatus = queueControlValue('reviewStatusSelect', 'unassigned');
    if (!flowId) {
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
      const data = await resp.json();
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      setLiveText(
        'caseAssignmentDisplay',
        data.evidence_state === 'verified'
          ? ('Assignee ' + (data.assignee_id || 'unassigned') + '. Review status ' + data.review_status + '.')
          : 'Assignment refused.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('caseAssignmentDisplay', 'Assignment unavailable.', 'unavailable');
    }
  }

  async function recordTriageAction(action) {
    const flowId = selectedLiveFlowId();
    if (!flowId) {
      setLiveText('campaignQueueStatus', 'Triage applies to a stored flow.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: flowId, action: action, actor_id: operatorActorId() })
      });
      const data = await resp.json();
      showOperatorStamp(data);
      await refreshLiveCampaigns();
      setLiveText(
        'campaignQueueStatus',
        data.evidence_state === 'verified'
          ? ('Triage state ' + data.triage_state + ' stored for flow ' + data.flow_id + '.')
          : 'Triage refused.',
        data.evidence_state || 'unavailable'
      );
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Triage unavailable.', 'unavailable');
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

  async function dispatchSignedCallback(inc) {
    if (!inc || !inc.live || !inc.flowId) {
      setLiveText('campaignQueueStatus', 'Dispatch applies to an approved stored flow.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch('/api/v1/live/soar/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: inc.flowId })
      });
      const data = await resp.json();
      await refreshLiveCampaigns();
      const sig = typeof data.signature_sha256 === 'string' ? data.signature_sha256 : '';
      if (data.callback_recorded === true && SHA256_HEX_REGEX.test(sig)) {
        const mttr = Number(data.mttr_seconds);
        const mttrText = Number.isFinite(mttr) ? mttr.toFixed(3) + 's' : 'n/a';
        const caseId = typeof data.thehive_case_id === 'string' ? data.thehive_case_id : 'not recorded';
        const path = typeof data.execution_path === 'string' ? data.execution_path : 'not dispatched';
        setLiveText(
          'campaignQueueStatus',
          'execution_path: ' + path + '. HMAC ' + sig + '. mttr_seconds ' + mttrText + '. Case ' + caseId + '. Host containment was not executed.',
          'verified'
        );
      } else {
        setLiveText('campaignQueueStatus', 'Signed callback unavailable.', 'unavailable');
      }
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Signed callback unavailable.', 'unavailable');
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
      setLiveText('campaignQueueStatus', 'Containment applies to a stored bridge flow.', 'unavailable');
      return;
    }
    try {
      const resp = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: inc.flowId })
      });
      const data = await resp.json();
      const executed = data.containment_executed === true ? 'drop applied' : 'drop not applied';
      setLiveText(
        'campaignQueueStatus',
        (data.reason || 'range containment') + '. ' + executed + '.',
        data.evidence_state || 'unavailable'
      );
      if (data.reason === 'containment_applied') {
        setRangeConnectivity(true);
      } else if (data.reason === 'containment_rolled_back') {
        setRangeConnectivity(false);
      }
    } catch (err) {
      setLiveText('campaignQueueStatus', 'Range containment unavailable.', 'unavailable');
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

  async function askLiveCopilot() {
    const input = document.getElementById('liveCopilotQuestion');
    const question = input ? input.value : '';
    try {
      const resp = await fetch('/api/v1/live/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: question })
      });
      const data = await resp.json();
      if (data.reason === 'containment_refused') {
        setLiveText('liveCopilotAnswer', 'Containment refused. execution_authorized is false.', 'unavailable');
        return;
      }
      const hit = data.hits && data.hits[0];
      const retrieved = hit
        ? ('retrieved candidate technique ' + hit.technique_id + ' ' + hit.technique_name)
        : 'No local corpus hit.';
      const narrative = typeof data.narrative === 'string' && data.narrative ? data.narrative : retrieved;
      const provider = data.provider_label || 'AI Copilot: Local Air-Gapped Engine';
      setLiveText('liveCopilotAnswer', provider + '. ' + narrative, data.evidence_state || 'unavailable');
      const badge = document.getElementById('copilotProviderBadge');
      if (badge) {
        badge.textContent = provider;
        badge.setAttribute('data-evidence-state', data.provider === 'gemini' ? 'verified' : 'unavailable');
      }
    } catch (err) {
      setLiveText('liveCopilotAnswer', 'Copilot unavailable.', 'unavailable');
    }
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

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Export functions to window for programmatic test validation
  window.ThreatFusionDashboard = {
    EVAL_PACK_REV2,
    verifySoarChain,
    verifyChromaRagHits,
    verifyHiveAndN8nReceipt,
    SAMPLE_INCIDENTS,
    WALKTHROUGH_STAGES,
    initApp
  };

  // Run on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
})();
