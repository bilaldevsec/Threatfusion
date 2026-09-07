# Phase 0N: feature and split contracts

Phase 0N resolves which values may enter later models and how later row assignments must avoid
leakage. It changes no dataset adapter, canonical schema, raw file, or source record.

## Cross-dataset network behavior

`network_behavior_v1` is the exact common model interface for UNSW and CIC. Its deterministic
11-field order contains duration, directional packet and byte counts, packet and byte rates,
directional mean packet lengths, destination port, and normalized protocol.

Source port is excluded because the selected processed CIC exports do not contain it. Inventing a
source port would corrupt the benchmark, while silently dropping it only at evaluation time would
change the model interface. The older 12-field `flow_common_v1` projection remains unchanged and
is documented as a separate UNSW-only model contract.

Destination port is retained because both UNSW and CIC provide the same bounded destination-side
service field. It is useful behavioral evidence and is not leakage merely because it is a port.
Endpoint IPs, source identity, labels, and provenance remain excluded.

## Host behavior

`host_event_v1` contains evidence needed for correlation, but much of that evidence is unsuitable
as a predictor. The new `host_behavior_v1` contract accepts only derived counts over a
caller-defined source/session group: total events, the seven coarse event-type counts, and three
field-presence counts. It does not retain individual provider or process strings.

Record and event IDs, generated ingestion IDs, basenames, row numbers, timestamps, hosts,
usernames, command lines, secrets, IPs, ports, file and registry paths, `ProcessGuid`, ATT&CK IDs,
labels, and attack names are prohibited. Group construction and window duration are deliberately
left unresolved for the future feature-building phase rather than guessed here.

Mordor remains attack/test data only. Its generated event identifiers are ingestion provenance,
not source evidence or model features. A benign `synthetic_lab` host baseline is still required
before the host lane can train.

## Leakage-safe splitting

The typed policy separates datasets by source and keeps each source file or scenario/capture
session wholly within one split. It requires chronological splitting whenever source timestamps
are reliable and rejects ungrouped random row splitting. The validation helper rejects repeated
source-group identity across splits, unknown sources, and assignments that contradict each
source's configured use.

UNSW is the only current training/development source. CIC and Mordor default to external
evaluation and cannot become training sources without an explicit approval encoded in their
rules. CIC's timezone remains unknown, so its timestamps are not declared reliable for
cross-source chronological splitting.

`synthetic_lab` is configured as a pipeline fixture and may be assigned only to `pipeline_test`.
It cannot be assigned to training, tuning, test, or external scientific evaluation. The policy is
configured, but no real source-group split assignments exist yet; the readiness audit therefore
reports assignment verification separately and keeps training readiness false.

These contracts resolve the feature and split-policy blockers. They do not override integrity or
report-sanitization gates, and they do not make Phase 0 training-ready: the missing benign
`synthetic_lab` baseline remains a blocker.
