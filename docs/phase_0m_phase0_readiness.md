# Phase 0M: readiness and leakage audit

Phase 0M is a final gate before any model work. Passing checksums and completing streaming
validation are necessary, but they do not prove that predictors are leakage-safe, that training
and evaluation populations are separated correctly, or that every model lane has suitable data.
The audit therefore reports `ready_for_training=false` whenever any required decision remains
unresolved.

Run the audit from the repository root:

```console
python scripts/audit_phase0_readiness.py
```

The command reuses the manifest loader and streaming SHA-256 verifier for every registered input.
It reads only existing aggregate JSON reports; it does not reprocess the datasets. It checks
completion, aggregate arithmetic, manifest or recorded streaming totals, fixed report schemas,
sensitive markers, and Git-ignore coverage. Its own sanitized result is written to
`artifacts/reports/phase0/phase0_readiness.json` and contains only safe basenames, aggregate
counts, status codes, feature-name summaries, policy checks, blockers, and warnings.

## Feature and leakage boundary

The current UNSW `flow_common_v1` model list has 12 fields: duration, forward/backward packet and
byte counts, packet and byte rates, forward/backward mean packet lengths, source and destination
ports, and protocol. The portable CIC/UNSW `network_behavior_v1` list has the same measurements
except source port, for 11 fields. This mismatch is intentional in the current documentation, but
it must be resolved by selecting one explicit training contract; a 12-input model cannot be
presented as compatible with an 11-input benchmark.

Phase 0N resolved the port decision: `dst_port` remains an allowed cross-dataset behavioral
feature because both sources provide it, while `src_port` remains only in the separate UNSW
complete-flow contract. IDs, source datasets, source
basenames, row numbers, timestamps, IP addresses, hosts, users, `ProcessGuid`, labels, attack
categories, attack names, and ATT&CK identifiers must never become predictors.

`host_event_v1` is a canonical event schema, not itself a model-feature contract. Phase 0N adds
`host_behavior_v1`, which permits only fixed derived event-type and field-presence counts.
Ingestion IDs remain provenance only.

## Dataset and split policy

CIC remains an external network benchmark and must stay outside training. Its source timestamps
remain timezone-naive because no source timezone is known; they must not be converted to UTC or
ordered against timezone-aware sources without evidence. Mordor remains attack/test-only and must
not be used as benign training data. No registered benign `synthetic_lab` host baseline exists
yet, so the host lane is incomplete.

The typed Phase 0N policy enforces all of these rules:

- Assign whole sources explicitly and keep external-test datasets out of training.
- Use chronological splits only when timestamp semantics are reliable.
- Keep each source file and correlated group wholly within one split.
- Prohibit ungrouped random row splits, which can put near-duplicate or scenario-related events on
  both sides of an evaluation.

These are configured policy constraints, not fabricated evidence that splitting has occurred.
The audit reports explicit source-group assignments separately; because none exist yet, assignment
verification is `not_verified` and remains a training blocker.

The split and feature-contract gates are now defined, but Phase 0 must not claim training readiness
until the benign host baseline is registered.

## Audit result

The Phase 0M run verified every registered checksum, input existence, and relative manifest path.
All ten existing validation/profile reports were complete, sanitized, and consistent with their
manifest totals or their recorded streaming totals. Their aggregate results were 2,540,047 UNSW
rows with 2,540,037 accepted and 10 rejected; 2,097,150 CIC rows with 2,097,145 accepted and five
rejected; and 267 Mordor rows with all 267 accepted. Git-ignore coverage passed for raw inputs,
reports, processed-data locations, and model-artifact locations.

Phase 0O registered a controlled benign `synthetic_lab` pipeline fixture. Phase 0P separates
pipeline readiness from final training readiness: the fixture passes pipeline checks, but its
42-event scale fails the documented training-quality gates. The audit therefore reports
`pipeline_ready=true` and `training_ready=false`. The current blockers are the absent explicit
split assignments and the fact that synthetic_lab is a development fixture rather than final host
training data. The 12-field/11-field relationship remains documented as separate contracts.
Warnings record that distinction, the possible CIC export row cap, the unknown CIC source
timezone, and the Mordor sample's single process event.
