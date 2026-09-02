# Phase 0K: Portable CSE-CIC-IDS2018 benchmark contract

The two approved official processed CSE-CIC-IDS2018 CSVs contain useful traffic measurements and
labels, but they omit flow ID, both endpoint IP addresses, and source port. ThreatFusion therefore
does not weaken `NetworkFlow` or invent those values. The existing `flow_common_v1`, strict
UNSW adapter, and strict CIC-to-`NetworkFlow` adapter remain unchanged.

Instead, `network_behavior_v1` defines the exact 11 predictors that complete UNSW flows and these
CIC exports can both supply honestly. `NetworkBenchmarkRecord` carries those predictors together
with non-predictive evaluation provenance. It cannot represent an incident-correlation event and
must not enter the correlation pipeline.

The processed-CIC reader accepts strict UTF-8, removes surrounding header whitespace, and requires
the exact 80 unique, nonblank official headers. It yields one row at a time in source order and
adds only the source file basename and one-based data-row number. Wrong headers and row widths
raise structural errors containing locations and counts, never complete source rows.

The benchmark adapter converts source duration from microseconds to milliseconds, validates the
destination port and numeric measurements, uses the shared protocol normalization and aggregate
formulas, and maps `BENIGN` case-insensitively to `Normal`. For the two approved files, the exact
allowed attacks are `FTP-BruteForce`, `SSH-Bruteforce`, `DoS attacks-GoldenEye`, and
`DoS attacks-Slowloris`; all other labels are rejected. An accepted attack retains its exact
source label as its attack name. The adapter returns `NetworkBenchmarkRecord`, never
`NetworkFlow`.

## Timezone limitation

All timestamps in the two selected files match `%d/%m/%Y %H:%M:%S`. The benchmark adapter accepts
only that exact format, parses it as a timezone-naive source time, and does not assign UTC or infer
another zone. Their ordering within a source file remains useful, but they must not be compared to
timezone-aware telemetry without an explicit, evidence-backed timezone policy.

The reader reports only source basenames in structural errors. It closes files on exhaustion,
failure, or generator closure; callers that retain a partially consumed iterator must explicitly
close it.

## Export-size limitation

Each selected CSV has exactly 1,048,575 data rows. With its header, that is 1,048,576 CSV rows,
which may indicate a spreadsheet export limit. ThreatFusion must describe benchmark results as
covering these acquired exports rather than claiming they contain every flow captured that day.

Phase 0K-c2 defines and tests the contract using tiny synthetic fixtures only. It does not read the
downloaded raw files, create a dataset manifest, process the complete dataset, create training
splits, or train a model.
