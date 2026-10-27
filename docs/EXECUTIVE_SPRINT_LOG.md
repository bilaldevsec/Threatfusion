# ThreatFusion (`AI-FYP-2006`) — Executive CEO Sprint Log

## Mega-Milestone #38 — Fail-Closed Supply-Chain, Velocity Honesty, Durable Outbox & Unified Timeline (`COMPLETED`)
* **What We Built & Fixed**:
  1. Synced hero supply-chain Random Forest SHA-256 badge with registry digest (`bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`), enforced strict `prev_entry_sha256` hash-chain continuity, and blocked `chromadb` in Gate G9.
  2. Labeled default MTTI/MTTR velocity metrics as `Reference Benchmark (Inspected January Split)` while supporting live measured timings (`telemetry_source="live_measured"`).
  3. Added `--host` alias (default `127.0.0.1`), `1 MiB` payload cap (`HTTP 413`), SQLite-persisted idempotency keys (`HTTP 409`), `WAL` + `5000ms` busy timeout across all SQLite stores, and dead-letter persistence.
  4. Built `build_unified_incident_timeline()`, 4-stage SOAR state machine (`pending_approval`, `approved_local`, `queued_durable_outbox`, `dispatched_live`), and split `data-copy-hash` (SHA-256) from `data-copy-value` (IP/MITRE).
* **Automated Gate Scorecard**: `git diff --check` CLEAN | `pytest`: **44 passed** | `boundary_preflight`: **B0–B5 GO** | `audit_repo_truth`: **7/7 GO**.

=== 30-SECOND CEO SKIM REPORT ===
- Shipped three analyst-facing upgrades: a recoverable SOAR/RAG/outbox/dead-letter snapshot, a citation-locked case follow-up, and a shift handoff that reuses the durable outbox key.
- The follow-up refuses unknown IPs, unknown MITRE ids, and containment requests, and it never authorizes execution.
- Frozen Random Forest stays the only alert authority (`production_fusion_enabled=False`); all four model digests still match; Gate G9 still holds; TF-008 through TF-011 stay open.
- Verification this sprint: `git diff --check` clean, 47 unit tests passed, boundary preflight B0–B5 GO, repository truth audit 7/7 GO.
- Still unproven: an unseen holdout, a human cohort of at least 10, a signed jury rubric, and a live SIEM deployment.

=== 30-SECOND CEO SKIM REPORT ===
- Added boundary check B6 so a `PYTHONPATH` or `sys.path` entry inside the protected folder, or a `threatfusion` import from outside this project's `backend/src`, returns NO-GO.
- The command-line preflight now calls the same implementation as the repository-truth audit, so the two gates cannot drift.
- Frozen Random Forest authority, the four model digests, Gate G9, and the open status of TF-008 through TF-011 are unchanged. Storage-backup test failures were left for a later task.
- Verification on this tree: `git diff --check` clean, focused pytest passed (the prior 47 plus the two B6 cases, and the existing B0–B5 class), boundary preflight B0–B6 GO, repository-truth audit 7/7 GO.
- Next: TF-SecOps-QA-Sentinel re-runs those four gates read-only. The co-founder signs off after that. No new product feature until that sign-off.

=== 30-SECOND CEO SKIM REPORT ===
- Fixed snapshot restore. A WAL database no longer leaves `-wal` and `-shm` sidecars in the backup directory, which had made every snapshot look corrupt.
- All 13 storage-backup integration tests pass. The four focused gates still pass, including boundary check B6.
- Usage is about 9% of the weekly meter, with a reset in about 2 days. This is a building window. A full owner report is due when usage reaches about 95%, or when you say "weekly report".
- Frozen Random Forest authority, the four model digests, Gate G9, and TF-008 through TF-011 stay as they are.
- Next product gap: the walkthrough screen still shows sample incidents. The authenticated analyst page is the real queue.

=== 30-SECOND CEO SKIM REPORT ===
- Added a live console panel: 14-feature ingest scored only by the verified frozen Random Forest, WAL analyst notes, a local MITRE copilot, read-only drift, and a 6-node n8n workbench that does not dispatch.
- A browser check ingested a toy flow as Benign with fusion disabled, and the copilot returned T1059 from the local corpus.
- The sample campaign queue and its simulated Approve button are still on the page. TF-008 through TF-011 stay open.
- Focused tests, boundary preflight B0–B6, and the repository-truth audit passed for this slice.
- Next: replace the sample campaign queue with the stored live flows, without keeping a fake Approve button.

=== 30-SECOND CEO SKIM REPORT ===
- The campaign queue now reads stored flows and incident rows. Replay scores five recorded UNSW-NB15 study vectors with the frozen Random Forest and stores that live score.
- Approve writes a hash-chained local approval on the SOAR ledger and returns the real SHA-256 receipt. Containment is not executed. A second click returns the same receipt.
- The browser no longer invents a hash, a TheHive case, or an n8n signature. Sample incidents remain only if the campaign request cannot be reached.
- Frozen Random Forest authority, the four model digests, Gate G9, and TF-008 through TF-011 are unchanged.
- Next: show this queue on the authenticated analyst page, still without executing containment.

=== 30-SECOND CEO SKIM REPORT ===
- An approved playbook can now be checked at verify-state, written as a 4-block case, and closed with a real HMAC callback. MTTR is the callback interval.
- Host containment stays unauthorized. A missing secret or an unapproved row does not get a receipt.
- Frozen Random Forest authority, the four model digests, Gate G9, and TF-008 through TF-011 are unchanged.

=== 30-SECOND CEO SKIM REPORT ===
- The full pytest suite passed 1,527 tests in about 312 seconds after a damaged alert database was classified as corrupt instead of unavailable.
- The board report now covers the signed callback, the 30-second stitch, triage and the grounded handoff, the one-command launcher, and the local walkthrough.
- Frozen Random Forest authority, the four model digests, Gate G9, and TF-008 through TF-011 are unchanged.
- Host containment stays unauthorized. The lab HMAC and MISP defaults are not production credentials.
