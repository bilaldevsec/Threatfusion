# ThreatFusion competitor-gap backlog

**Date:** 2026-10-30
**Branch audited:** `gemini/product-20260924` at `1c945b7` (live console, four-scenario replay, constitutional health drawer)
**This document:** ranked product gaps for a follow-up implementation agent. It does not change code, models, or issue dispositions.

## How items are ranked

Each item has an analyst/manager value from 1 to 5 and an effort of S, M, or L. Effort points are S=1, M=2, L=3. Rank is value divided by effort. Equal ratios are broken toward investigation autonomy, explainability, and case management, then analyst UX and reporting.

Effort means one pull request against this repository:

- **S** — one console route or a column on the existing live SQLite file, plus the queue or inspector that already reads that file, reusing a helper that is already in the tree.
- **M** — a new stored record and a new inspector or export surface, still one pull request, with no new model and no new external service.
- **L** — a new source contract, a new model, or a live external system. Nothing in the ranked list is L.

## What the audited branch already does

The local console is `scripts/run_live_product.sh` on `127.0.0.1:8766`. These behaviors are already on the branch and are not gaps:

- `POST /api/v1/live/ingest` scores a 14-feature vector only when the frozen Random Forest artifact verifies. `production_fusion_enabled` is stored false. The autoencoder does not decide.
- The page has the top funnel, the six-stage pipeline ribbon, the campaign queue, and the five-tab inspector (Executive Summary, Attack Timeline, MITRE and Playbook, Evidence Locker, SOAR Audit Changelog) in `frontend/index.html`.
- `GET /api/v1/live/campaigns` fills the queue from the console SQLite file. Sample incidents return only when that request fails (`frontend/js/soc_dashboard.js`).
- Replay of the five recorded UNSW-NB15 study vectors and replay of four labeled scenarios (web exploit, SSH brute, internal recon, benign false alarm) both call the frozen forest. The scenario technique id is a label, not a model output.
- Approve writes a hash-chained local receipt. Dispatch posts the approved playbook through verify-state and the HMAC callback and can queue a four-block TheHive case. Host containment stays unauthorized.
- Ingest and replay call `IncidentCorrelationEngine` with a 30.0-second burst and a 600.0-second campaign window, boundaries included.
- Acknowledge, Escalate, and Dismiss append `triage_events`. The shift handoff includes that history and refuses a note that names an address outside the stored flow via `verify_explanation_groundedness()`.
- The MITRE copilot answers from the local corpus and refuses containment. Drift is read-only. The n8n workbench lists six nodes and does not dispatch.
- `POST /api/v1/live/health` runs boundary preflight B0–B6 and the seven repository-truth checks.
- Queue filters today are All, Verified Receipts, Pending Approval, and Unavailable.

## Already in flight — do not re-open these as top gaps

[PR #6](https://github.com/bilaldevsec/Threatfusion/pull/6) (`cursor/unify-live-surfaces-449d`) is open against `gemini/product-20260924`. It unifies the deltas from PRs #2–#5 and adds `GET /api/v1/live/surfaces`.

That route returns the top funnel, the six-stage pipeline ribbon, the queue, and the five inspector tabs from one SQLite file. The page stops using the hardcoded sample incident list. An empty database shows zero funnel counts and "No stored flow", not the January population 216,568 / 4,358 / 24 / 8.

Much of the ledger, stitch, triage, and launcher behavior PR #6 integrates is already described on this branch (project status milestones #50–#53). The surfaces route itself is not on `1c945b7`. A follow-up agent must not file "bind the four surfaces to one database" or "remove the sample fallback" as new work. If PR #6 has merged, call `GET /api/v1/live/surfaces` instead of adding a second funnel endpoint.

PR #6 still leaves the hero headline `99%+ Alert Noise Eliminated` in `frontend/index.html`. That remaining claim is GAP-04.

## Constitutional locks

No item below may:

- set `production_fusion_enabled` to true, or let the autoencoder decide an alert
- replace the frozen Random Forest as the sole decision authority
- change the four frozen model SHA-256 digests (`bd2853a6…`, `2cf4de66…`, `c8675d13…`, `1d02e5bb…`)
- import `threatfusion.advisory`, `gemini_client`, or `chromadb` into Stages 1–4 (Gate G9)
- mark TF-008, TF-009, TF-010, or TF-011 closed, or weaken their closure tests in `docs/issue_register.md`
- execute host containment, or turn an LLM or checklist answer into a shell command, API action, or containment operation

TF-008 stays an independent-holdout evaluation gap. TF-009 stays a human-cohort workload study. TF-010 stays the external signed jury rubric. TF-011 stays live operational SIEM and production threat-intelligence proof. A local fixture, a lab webhook row, or a shift count is not evidence that any of those four are closed.

## Ranked backlog

| Rank | ID | Title | Value | Effort | Ratio |
|---|---|---|---|---|---|
| 1 | GAP-01 | Analyst conclusion stored apart from the frozen forest decision | 5 | S | 5.0 |
| 2 | GAP-02 | Queue search, decision and triage filters, and sort | 5 | S | 5.0 |
| 3 | GAP-03 | Assignee and review status on the stored flow | 4 | S | 4.0 |
| 4 | GAP-04 | Live hero shows this queue, not the inspected January claim | 4 | S | 4.0 |
| 5 | GAP-05 | Glass-box investigation checklist answered from stored fields | 5 | M | 2.5 |
| 6 | GAP-06 | Manager shift rollup from the live queue | 5 | M | 2.5 |
| 7 | GAP-07 | Case-scoped follow-up that cites only the selected flow | 4 | M | 2.0 |
| 8 | GAP-08 | Entity notes that reappear and cannot change the score | 4 | M | 2.0 |
| 9 | GAP-09 | Recommended next actions that stay unauthorized | 4 | M | 2.0 |
| 10 | GAP-10 | One timeline of observation, triage, and SOAR rows | 4 | M | 2.0 |
| 11 | GAP-11 | Scenario-label inventory that is not a coverage claim | 2 | S | 2.0 |
| 12 | GAP-12 | Local escalation notice row with no outbound socket | 3 | M | 1.5 |

GAP-01 ranks above GAP-02 because both ratios are 5.0 and a missing analyst conclusion is a case-management hole, while the queue already has filters. GAP-03 ranks above GAP-04 on the same rule. GAP-05 ranks above GAP-06 because both ratios are 2.5 and the checklist is investigation explainability. GAP-07 through GAP-10 share ratio 2.0 and stay in that autonomy-then-case order. GAP-11 shares ratio 2.0 and ranks after them because a label inventory is the weaker product gap.

### GAP-01 — Analyst conclusion stored apart from the frozen forest decision

**Competitor evidence.** Dropzone's investigations page shows an initial conclusion on every row. From the Triage Center an analyst changes Conclusion, and a conclusion edit requires notes in Conclusion Edit Details. Review can also close an investigation when the conclusion matches the evidence. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations). Prophet ends every investigation with a determination of true positive, false positive, or inconclusive, with the evidence that explains it. Source: [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq).

**ThreatFusion today.** Acknowledge, Escalate, and Dismiss write `triage_events` and a latest triage state (`record_triage_action` in `backend/src/threatfusion/api/live_soc_console.py`). The frozen forest `decision` stays the only determination. The inspector has no analyst verdict of true positive, false positive, or inconclusive.

**User value.** A Tier-1 analyst needs to record what they decided about the case without looking like they edited the model. A manager reading the queue can separate "the forest said Attack" from "the analyst called it a false positive."

**Effort.** S. The triage route, the `triage_events` table, and `verify_explanation_groundedness()` already exist. This adds one stored verdict and a required note on that same path.

**Acceptance criteria.**

- Persist an analyst conclusion of `true_positive`, `false_positive`, or `inconclusive` on the live flow, in a field that is not `decision` and not the frozen-forest probability.
- Require a non-empty rationale. Pass that rationale through `verify_explanation_groundedness()` the same way the shift note is checked. A rationale that names an address outside the stored entity ids is refused and is not stored.
- The inspector shows "Frozen RF decision" and "Analyst conclusion" as two lines. Reload keeps the analyst conclusion.
- Setting the conclusion does not change `decision`, the score, `model_sha256`, or `production_fusion_enabled`.
- An unknown conclusion value is refused.
- Extend `backend/tests/unit/test_live_soc_console.py`. Do not change model artifacts. Do not mark TF-009 closed: this is one stored verdict, not a ten-person study.

**Constitutional-lock risk.** Low, if the new field cannot be written into `decision`. Medium if a later edit uses the analyst verdict as the alert authority. The acceptance criteria forbid that.

### GAP-02 — Queue search, decision and triage filters, and sort

**Competitor evidence.** Dropzone filters investigations with a search bar over alert keywords, entities, and tags, plus dropdowns for Conclusion, MITRE Tactic, Containment Action, Alert Type, and Source. The task view sorts by conclusion, alert title, alert time, and priority. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations). Cortex XSIAM assigns each case a SmartScore so teams open the highest-risk case first. Source: [Resolving cases with AI](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/investigation-and-response/overview-of-cases/resolving-cases-with-ai).

**ThreatFusion today.** `getFilteredIncidents()` in `frontend/js/soc_dashboard.js` filters on receipt state only: all, verified, pending approval, unavailable. There is no search box and no sort by score or time. The stored row already has `decision`, `triage_state`, entity ids, and a case title.

**User value.** During a replay of four scenarios plus the five-vector burst, the analyst cannot type an entity or show only Attack rows. The manager cannot put the highest frozen-forest probability at the top without reading every card.

**Effort.** S. Filtering and sorting happen on rows the queue already holds. No new score is computed. This is not an XSIAM SmartScore; the sort key is the stored Random Forest probability.

**Acceptance criteria.**

- Keep the existing receipt filters.
- Add a search field that matches, case-insensitively, flow id, case title, source label, and stored source and destination entity ids. An empty search shows the same rows as today.
- Add filters for frozen-forest decision (`Attack`, `Benign`, `withheld`) and for triage state.
- Add sort by observed time, stored Random Forest probability, and triage state. Default order stays the current order.
- A row with a missing probability sorts last when sorting by probability and is not given a fake score.
- Cover the three filters and the empty-search case in the existing live-console frontend or API tests. Do not add a second scoring model.

**Constitutional-lock risk.** Low. The only risk is inventing a priority score that overrides the forest. Sorting must use the stored probability and must not write a new decision.

### GAP-03 — Assignee and review status on the stored flow

**Competitor evidence.** Dropzone lists Owner/Assignee on the investigations page. The Triage Center assigns a person and moves review status through New, In Progress, On Hold, and Closed. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations).

**ThreatFusion today.** Triage stores an `actor_id` on each event, but the flow has no current assignee and no review status. Two analysts cannot see who owns a card.

**User value.** Shift handoff already exports one flow. An assignee and a status tell the next person which cards are unowned, paused, or closed, which is the case-management gap Dropzone's task view is built around.

**Effort.** S. Same SQLite file and the same actor string the triage route already requires. This does not add accounts, passwords, or a browser certificate flow.

**Acceptance criteria.**

- Store `assignee` (text, default empty) and `review_status` in `new`, `in_progress`, `on_hold`, `closed` (default `new`) on the live flow.
- A route sets them for one stored flow id. An unknown status, a blank assignee when a non-empty assignee is submitted, and an unknown flow are refused and leave the row unchanged.
- The queue card shows assignee and review status after reload. The existing receipt filters still work. Add a review-status filter.
- Do not add a login, session cookie, or client-certificate issuer. Do not mark TF-008 closed.

**Constitutional-lock risk.** Low. The risk would be treating this local actor string as operational identity proof. The copy in the inspector must call it a local assignee, not an authenticated enterprise user.

### GAP-04 — Live hero shows this queue, not the inspected January claim

**Competitor evidence.** Prophet's dashboard reports dwell time, mean time to investigate, and mean time to resolve from the investigations in that environment, and it names the noisiest alerts for tuning. Source: [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq). Dropzone's dashboard tracks time to investigate and analyst time saved for that tenant. Source: [Dropzone platform](https://docs.dropzone.ai/platform). Those products label the metrics as that tenant's activity.

**ThreatFusion today.** `frontend/index.html` opens with the headline `99%+ Alert Noise Eliminated`, the ratio `99.9889%`, and the path `216,568 → 4,358 → 24 → 8`. The velocity cards default to MTTI `1.25s` and MTTR `4.50s`. `refreshOperationalVelocity()` can overwrite counts from `/api/v1/metrics/operational-velocity` and can label `telemetry_source` as `reference_benchmark` or `live_measured`. The headline is still a claim about this screen. PR #6 changes the count placeholders to live SQLite text and still leaves `99%+ Alert Noise Eliminated`.

**User value.** A reviewer who replays four scenarios currently sees a hero that reads as if 216,568 flows were just compressed. Managers cannot tell the inspected January reference from the rows in the local database. The product charter forbids turning benchmark metrics into operational claims.

**Effort.** S. Relabel and rebind copy that is already in the hero, the velocity ribbon, and the funnel. The Evaluation Pack Rev2 banner lower on the page already carries the frozen-forest precision and the Section 8 false-positive comparison; those figures stay there, labeled as the inspected January split.

**Acceptance criteria.**

- The hero headline and the funnel badge do not contain `99%+ Alert Noise Eliminated`, `99.9889%`, or `216,568` as the description of the current queue.
- Those inspected-January figures remain only in the Evaluation Pack Rev2 metrics banner, with the existing "Inspected January Split" wording.
- When the console database has no flows, the four funnel counts are 0 and the funnel badge `data-evidence-state` is `unavailable`.
- When flows exist, the four counts are computed from stored rows (raw flows, Attack decisions, correlated campaigns, approved playbooks). If PR #6's `GET /api/v1/live/surfaces` is present, read the counts from that response. Do not add a second funnel endpoint, and do not restore the sample incident list.
- Velocity numbers that are not `telemetry_source=live_measured` stay behind the reference label and are not prefixed with a speedup multiple against a 15-minute baseline unless that label is visible in the same card.
- Do not edit the historical January metric values. Do not mark TF-009 closed.

**Constitutional-lock risk.** Low for the locks themselves. The product risk is the opposite: leaving the headline in place makes an operational claim the charter does not allow. The implementation must not "fix" the claim by enabling fusion or by publishing a new false-positive rate.

### GAP-05 — Glass-box investigation checklist answered from stored fields

**Competitor evidence.** Prophet builds an investigation plan of the questions an expert would ask, then documents every question, query, and reasoning step. Source: [Prophet AI SOC Analyst](https://www.prophetsecurity.ai/ai-soc-analyst) and [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq). Dropzone's investigation write-up includes investigation threads, key findings, and an evidence locker, and the task view has Show Reasoning. The product page states that the tools checked, the evidence found, and the reasoning stay open to correct. Sources: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations) and [Dropzone AI SOC Analyst](https://www.dropzone.ai/ai-soc-analyst).

**ThreatFusion today.** Inspector tab 4 says the 14 canonical features stay on the stored flow and names the frozen forest as the decision authority. It does not list the questions that were answered, or mark a missing technique as unavailable rather than blank. Tab 3 stays `unavailable` until a retrieval names a technique. There is no autonomous multi-tool investigation, and this item must not pretend to add one.

**User value.** The analyst can see which facts the case actually has (score, entities, stitch count, triage, technique label) and which facts are missing, before they trust or dismiss the card. That is the explainability gap relative to Dropzone's evidence locker and Prophet's documented questions.

**Effort.** M. The questions are a fixed list evaluated against columns that already exist. Persisting the answers and rendering them in tab 4 is the work. No external query is allowed, so this is not Prophet's cross-SIEM plan.

**Acceptance criteria.**

- For each stored flow, build a checklist with these questions only: Is a frozen-forest decision and a finite probability stored? Are source and destination entity ids stored? Is a correlated member count stored? Is a triage state stored? Is a technique label stored?
- Each answer is `verified` plus the stored value, or `unavailable` when the field is absent. Do not invent a packet count, a technique, or a probability.
- Show the checklist in inspector tab 4, and return the same checklist from the flow's read API after a process restart.
- Building or displaying the checklist does not change `decision`, the score, or `production_fusion_enabled`.
- The checklist code stays out of Stages 1–4. Gate G9 stays intact.
- A technique question that is unanswered stays `unavailable`. It is not a reason to call a hosted model.

**Constitutional-lock risk.** Medium if the checklist is wired to an LLM, a tool runner, or a decision override. The acceptance criteria keep it a read of stored columns. Do not import this module into Stages 1–4.

### GAP-06 — Manager shift rollup from the live queue

**Competitor evidence.** Prophet reports alert dwell time, mean time to investigate, and mean time to resolve, and it identifies the noisiest and least effective alerts. Source: [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq). Prophet's metrics note defines dwell as acknowledgement time minus activity start, and mean time to investigate as resolved time minus acknowledged time. Source: [SOC metrics that matter](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more). Dropzone's dashboard monitors investigation volume, outcomes, and time to investigate. Source: [Dropzone platform](https://docs.dropzone.ai/platform).

**ThreatFusion today.** `POST /api/v1/live/handoff` builds a four-block markdown for one flow. There is no shift document that counts the whole queue. The hero numbers in GAP-04 are reference benchmarks, not this database.

**User value.** The analyst leaving a shift can hand a manager one page: how many stored flows were Attack, how many were still unreviewed, how long flows waited for the first triage click, and which scenario label produced the most Benign decisions in this local file.

**Effort.** M. One new read of the existing tables (`live_flows` and `triage_events`) and one markdown export next to the current handoff. No new timer service.

**Acceptance criteria.**

- Add one route that reads the console SQLite file and returns markdown plus JSON.
- Include counts by frozen-forest decision and by triage state.
- Dwell for a flow is the seconds from `observed_at_utc` to the earliest `triage_events.created_at_utc` for that flow. Report the median of flows that have both timestamps. If none do, the dwell field is `unavailable` and is not shown as zero.
- Noisiest local label is the `source_label` with the largest Benign count in this file, returned with that count. If every label is absent, the field is `unavailable`.
- The markdown says "local console queue" and does not contain `99%`, `216,568`, or a claim that analyst workload was reduced.
- Do not mark TF-009 closed. Do not compare the median with the 1.25-second reference MTTI inside this report.

**Constitutional-lock risk.** Low, provided the report cannot be read as the TF-009 human study. The closure test for TF-009 remains at least ten human analyst trials. This route must not write that study cohort.

### GAP-07 — Case-scoped follow-up that cites only the selected flow

**Competitor evidence.** Dropzone chat has an investigation-scoped session that includes that investigation's context and entities, separate from a freeform session. Source: [Dropzone platform](https://docs.dropzone.ai/platform). The product page says a follow-up reads the case and the evidence already gathered, and the analyst can stop it. Source: [Dropzone AI SOC Analyst](https://www.dropzone.ai/ai-soc-analyst). Cortex XSIAM's Agentic Assistant takes a natural-language prompt with case context. The same documentation set says sensitive actions require manual approval and that executed actions are logged. Sources: [Resolving cases with AI](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/investigation-and-response/overview-of-cases/resolving-cases-with-ai) and [Agentic AI in Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Agentic-AI-in-Cortex-XSIAM). Prophet's Dig Deeper asks another question about one investigation. Source: [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq).

**ThreatFusion today.** `answer_mitre_copilot()` queries the local MITRE corpus and is not bound to the selected flow. `answer_citation_locked_followup()` in `backend/src/threatfusion/advisory/explanation_engine.py` already answers from an evidence bundle, returns `evidence_state=unavailable` for an unknown IP, an unknown MITRE id, or a containment request, and sets `execution_authorized` false. The inspector does not call it.

**User value.** The analyst can ask "what address is on this flow?" and get an answer that cites the stored entity, or a refusal when the question names something else. They do not get a corpus hit presented as if it were this case.

**Effort.** M. The answer function exists. The work is building the bundle from the selected flow only, adding the inspector control, and showing the returned evidence state. No new model client.

**Acceptance criteria.**

- The inspector sends one question about the selected stored flow to `answer_citation_locked_followup()`.
- The bundle's allowed entities, probability, and technique ids come only from that flow's stored fields. A question that names any other IP address or any MITRE id that was not stored returns `evidence_state=unavailable`, cites nothing, and is not stored as a finding.
- A question that asks to isolate, contain, quarantine, execute, block, or kill returns `execution_authorized` false and does not call approve, dispatch, or any socket.
- The reply text includes that production authority remains the frozen Random Forest and that `production_fusion_enabled` is false, which the existing function already states.
- The call stays in the console path. Stages 1–4 do not import `threatfusion.advisory`. Gate G9 stays intact.
- Do not add a hosted LLM, and do not let the reply change `decision`.

**Constitutional-lock risk.** Medium, because the helper lives under `threatfusion.advisory`. Calling it from the live console matches the MITRE copilot, which already imports advisory code. Importing it from Stages 1–4 would break Gate G9. The reply must stay advisory and non-executing.

### GAP-08 — Entity notes that reappear and cannot change the score

**Competitor evidence.** Dropzone Context Memory stores facts about users, devices, and known behaviors and applies them on later investigations. Analysts also leave notes. Sources: [Dropzone platform](https://docs.dropzone.ai/platform) and [investigation reviews](https://docs.dropzone.ai/best-practices/deep-dive-into-investigation-reviews). Prophet says nothing is learned silently: every entry's source is visible and correctable, and changes are previewed before they apply. Source: [Prophet AI SOC Analyst](https://www.prophetsecurity.ai/ai-soc-analyst).

**ThreatFusion today.** `add_analyst_note()` stores a note on one flow. A later flow that shares an entity id does not show that note. Nothing in the console updates model weights from notes. Drift is read-only.

**User value.** The analyst who marked an address as a lab scanner can see that note on the next stored flow with the same entity, including who wrote it, instead of re-discovering it. The manager can see that the note did not retune the forest.

**Effort.** M. A second table keyed by the stored entity id, written by the existing note path, and read when the inspector opens a flow. No learning step.

**Constitutional-lock risk.** Medium if a note is allowed to change a score, a threshold, or a future decision. That would also threaten TF-008, which requires an untouched evaluation. The acceptance criteria forbid any write to model artifacts or decisions.

**Acceptance criteria.**

- Store a note with entity id, author, timestamp, text, and the flow id it was written on.
- The entity id must equal a source or destination entity id already stored on that flow. Any other entity id is refused.
- When another stored flow has the same entity id, the inspector lists the note, the author, the timestamp, and the source flow id under the label "analyst memory".
- Saving a note does not change `decision`, the probability, `production_fusion_enabled`, or any file under the frozen-model registry.
- There is no silent application: the note is visible text, not a hidden rule. Do not add a custom strategy that changes the forest decision. Dropzone's custom strategies can influence conclusions; this item must not.

### GAP-09 — Recommended next actions that stay unauthorized

**Competitor evidence.** Cortex XSIAM's Resolution Center lists remediation tasks, recommendations, and progress, and playbook tasks track what is awaiting action, in progress, and completed. Source: [Resolving cases with AI](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/investigation-and-response/overview-of-cases/resolving-cases-with-ai). Palo Alto's Autonomous Playbooks post says sensitive or impactful recommended actions are highlighted for analyst approval and do not execute automatically. Source: [Autonomous Playbooks](https://www.paloaltonetworks.com/blog/security-operations/unveiling-autonomous-playbooks-immediate-threat-response-in-xsiam/). Dropzone lists recommended containment actions and can filter them by status such as Ready to Run. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations). Prophet previews scoped remediation before it runs and only takes actions the customer has approved. Source: [Prophet AI SOC Analyst](https://www.prophetsecurity.ai/ai-soc-analyst).

**ThreatFusion today.** The inspector offers Approve Playbook and Dispatch signed callback. Those routes already refuse an unapproved playbook and leave `containment_executed` false. There is no list of recommended next steps with an explicit not-authorized state. The product must not copy one-click containment or Agentic Response auto-remediation.

**User value.** The analyst sees the next legal step for this card (approve the existing playbook, or export the handoff) and sees that host containment is not available. They do not have to guess which button is a recommendation and which button sends the HMAC callback.

**Effort.** M. The list is derived from fields the flow already stores. No new execution route.

**Acceptance criteria.**

- For the selected stored flow, return a list of at most four recommendations computed from stored state. Required rows: "Approve the existing playbook" when `decision` is Attack and the ledger is not yet `approved`; "Export the grounded handoff" when a triage state is stored; "Host containment is not authorized" on every flow.
- Every row includes `execution_authorized: false`. The containment row also includes `containment_executed: false`.
- Rendering the list performs no HTTP call except the read that built it. It does not call approve, dispatch, or the HMAC callback.
- The existing Approve and Dispatch buttons keep their current behavior. This list does not add an endpoint that isolates, blocks, or quarantines a host.
- `production_fusion_enabled` stays false.

**Constitutional-lock risk.** Medium, because the competitor features execute or preview real remediation. This item is a read-only list. An implementation that adds an execute path, even behind a flag, is out of scope.

### GAP-10 — One timeline of observation, triage, and SOAR rows

**Competitor evidence.** Cortex XSIAM's May 2026 release adds a Case Timeline view: an automatically generated end-to-end timeline of every action, artifact, and piece of evidence in one place. Source: [XSIAM May 2026 release highlights](https://cortex-docs.paloaltonetworks.com/cortex-xsiam-rn/cortex-xsiam-release-information/features-introduced-in-2026-xsiam/may-2026/release-highlights). Dropzone's write-up includes a changelog from ingestion to approval. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations).

**ThreatFusion today.** Tab 2 shows the stitch timeline and each member's observed time. Triage events appear in the handoff. SOAR receipts appear in tab 5. `build_unified_incident_timeline()` already merges relationship-key members, analyst transitions, and hash-chained SOAR rows. The inspector does not show those three families as one time-ordered list for the selected live flow.

**User value.** The analyst reconstructing a replayed burst should not hunt across tab 2, the handoff, and tab 5 to see observe, acknowledge, and approve in order.

**Effort.** M. Feed stored rows into the existing timeline helper, or return the same three lists already stored, sorted by their stored timestamps. Do not synthesize steps.

**Acceptance criteria.**

- Tab 2 for a selected stored flow lists, in timestamp order: the flow's `observed_at_utc`, each correlated member's observed time, each `triage_events` row, and each SOAR ledger row already linked to that flow.
- A missing family is omitted. The UI does not insert a placeholder attack step, a sample technique, or a sample hash.
- After reload, the list matches the database. Approving the playbook adds the stored receipt line and does not rewrite earlier lines.
- The timeline does not change `decision`.

**Constitutional-lock risk.** Low. The risk is rendering an unverified receipt as verified. A SOAR line is included only when the stored receipt already passes the same `verify_audit_chain_integrity()` check the approve route uses. Otherwise the line's evidence state is `unavailable`.

### GAP-11 — Scenario-label inventory that is not a coverage claim

**Competitor evidence.** Prophet's AI Detection Engineer maps detection coverage to MITRE ATT&CK and shows what the customer is not catching. Source: [Prophet AI on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq). That full capability is out of scope here. The implementable slice is an inventory of labels this console already stores.

**ThreatFusion today.** `POST /api/v1/live/scenarios` stores technique ids T1190, T1110, and T1046 as scenario labels. The project status says the technique id is a scenario label, not a model output. The console has no count of flows per label.

**User value.** A manager can see how many stored flows carry each scenario label, and the screen says this is not a MITRE coverage map and not a statement of what the forest detects.

**Effort.** S. A `GROUP BY` on the stored scenario or source label, rendered as a small table under the queue or on the metrics banner.

**Acceptance criteria.**

- Return counts of stored flows by scenario technique label and by `source_label`.
- The heading text includes "scenario labels stored on this console" and does not include "coverage", "not catching", or "ATT&CK coverage".
- Labels that were not stored are absent, not filled in as zero for the whole ATT&CK matrix.
- Do not add a detection rule, do not edit a frozen model, and do not mark TF-008 closed.

**Constitutional-lock risk.** Medium if the table is captioned as detection coverage or if the work adds a rule or a refit. The acceptance criteria keep it a count of stored labels. Prophet's "authors and tunes the rules" step is not part of this item.

### GAP-12 — Local escalation notice row with no outbound socket

**Competitor evidence.** Prophet delivers investigations in the product and in Slack, Teams, or a customer webhook, with per-channel control. Source: [Prophet AI SOC Analyst](https://www.prophetsecurity.ai/ai-soc-analyst). Dropzone documents a notification response action when an investigation stops. Source: [Dropzone investigations](https://docs.dropzone.ai/platform/investigations). A live Slack or SIEM connection would be TF-011 evidence, which this backlog cannot close.

**ThreatFusion today.** Escalate writes a triage row. Nothing records an outbound notice, and nothing should open one. The n8n workbench does not dispatch.

**User value.** The analyst can see that an escalation was packaged as a notice for a later, separately approved connector, and can see that this process did not contact Slack or a SIEM.

**Effort.** M. One SQLite table written inside the existing escalate path, shown in tab 5. No URL is fetched.

**Acceptance criteria.**

- When a triage action stores state `escalated`, insert one `escalation_notices` row keyed by that `triage_events.event_id`, with flow id, actor, timestamp, and a JSON body of the stored entity ids and the frozen-forest decision.
- Inserting the notice opens no socket and performs no DNS lookup. Tests can prove this with a network guard or by using only the standard-library SQLite path and asserting no HTTP client was called.
- A repeated read does not insert a second notice for the same event id.
- Tab 5 shows the notice id. The copy says the notice was stored locally and was not delivered.
- Do not mark TF-011 closed. Do not add a Slack, Teams, or webhook client.

**Constitutional-lock risk.** Medium if the notice writer grows an HTTP client. TF-011 closes only on verified live enterprise telemetry. A local row is not that proof. The acceptance criteria forbid the socket.

## Explicitly out of scope

These competitor capabilities are real and are not backlog items:

- Enabling production fusion, or letting the v2 autoencoder decide alerts, to chase XSIAM analytics or a higher recall number. Section 8 stays `production_fusion_enabled=False`. The published comparison remains +2.203 percentage points of recall (92.818% to 95.021%) at 1,574 extra benign false positives.
- Replacing or refitting the frozen Random Forest, the logistic regression baseline, the v2 autoencoder, or the rate-log1p artifact.
- Closing TF-008 with any benchmark that was already inspected. Closing TF-009 with a dashboard percentage. Closing TF-010 without the external signed rubric. Closing TF-011 with a fixture, a Suricata adapter test, or GAP-12.
- Autonomous Playbooks or Agentic Response that remediate without the existing human approval, and any one-click host containment. Palo Alto documents Agentic Response as a private preview that investigates and remediates in real time ([May 2026 release highlights](https://cortex-docs.paloaltonetworks.com/cortex-xsiam-rn/cortex-xsiam-release-information/features-introduced-in-2026-xsiam/may-2026/release-highlights)). That execution model is not a ThreatFusion item.
- A 90-integration or 100-integration catalog. Dropzone documents 100+ integrations on its product page. Connecting a live SIEM is TF-011.
- A MITRE coverage program that authors new detections. See the boundary on GAP-11.
- Downloading UNSW-NB15 or any other dataset to make the seven registration tests pass.

## Sources

- Palo Alto Networks, [Resolving cases with AI](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/investigation-and-response/overview-of-cases/resolving-cases-with-ai), fetched 2026-10-30.
- Palo Alto Networks, [Agentic AI in Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Agentic-AI-in-Cortex-XSIAM), fetched 2026-10-30.
- Palo Alto Networks, [May 2026 release highlights](https://cortex-docs.paloaltonetworks.com/cortex-xsiam-rn/cortex-xsiam-release-information/features-introduced-in-2026-xsiam/may-2026/release-highlights), fetched 2026-10-30.
- Palo Alto Networks, [Unveiling Autonomous Playbooks](https://www.paloaltonetworks.com/blog/security-operations/unveiling-autonomous-playbooks-immediate-threat-response-in-xsiam/), fetched 2026-10-30.
- Dropzone AI, [Investigations](https://docs.dropzone.ai/platform/investigations), fetched 2026-10-30.
- Dropzone AI, [The Platform](https://docs.dropzone.ai/platform), fetched 2026-10-30.
- Dropzone AI, [Investigation reviews](https://docs.dropzone.ai/best-practices/deep-dive-into-investigation-reviews), fetched 2026-10-30.
- Dropzone AI, [AI SOC Analyst](https://www.dropzone.ai/ai-soc-analyst), fetched 2026-10-30.
- Prophet Security, [AI SOC Analyst](https://www.prophetsecurity.ai/ai-soc-analyst), fetched 2026-10-30.
- Prophet Security, [AWS Marketplace listing](https://aws.amazon.com/marketplace/pp/prodview-xy555gpzgrrvq), fetched 2026-10-30.
- Prophet Security, [SOC metrics that matter](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more), fetched 2026-10-30.
