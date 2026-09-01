# Phase 0D fixture parity validation

Fixture parity validation uses tiny, made-up input files to check that different dataset
adapters produce the same canonical values when their source rows describe the same thing.
It gives us a repeatable safety check without downloading the real datasets.

UNSW-NB15 and CSE-CIC-IDS2018 both describe network flows, but their columns, units, labels,
and protocol formats differ. For example, UNSW records duration in seconds and TCP as text,
while CIC records duration in microseconds and TCP as protocol number 6. They cannot be
blindly joined column by column. Each row must first pass through its dataset adapter.

The parity check compares only fields with shared meaning:

- duration in milliseconds
- forward and backward packet counts
- forward and backward byte counts
- packets and bytes per second
- mean forward and backward packet lengths
- source and destination ports
- protocol
- normalized label

Dataset identity, flow ID, timestamps, attack category, and IP addresses are deliberately not
compared by default. Those values can be dataset-specific or unsuitable as shared model
features even when the underlying traffic measurements are comparable.

Mordor is different: it contains host telemetry such as process creation, users, command
lines, parent processes, and MITRE ATT&CK technique IDs. Its adapter therefore produces a
`host_event_v1` record, not a `flow_common_v1` network flow. Mordor stays in a separate host
event stream so endpoint meaning is not lost by forcing it into network columns.

These tests protect later ML and DL work by catching unit mistakes, renamed columns, label
normalization changes, and accidental mixing of unrelated telemetry before those errors can
reach feature engineering or model training.
