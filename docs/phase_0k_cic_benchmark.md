# Phase 0K: Portable CSE-CIC-IDS2018 benchmark contract

The two approved official processed CSE-CIC-IDS2018 CSVs contain useful traffic measurements and
labels, but they omit flow ID, both endpoint IP addresses, and source port. ThreatFusion therefore
does not weaken `NetworkFlow` or invent those values. The existing `flow_common_v1`, strict
UNSW adapter, and strict CIC-to-`NetworkFlow` adapter remain unchanged.

Instead, `network_behavior_v1` defines the exact 11 predictors that complete UNSW flows and these
CIC exports can both supply honestly. `NetworkBenchmarkRecord` carries those predictors together
with non-predictive evaluation provenance. It cannot represent an incident-correlation event and
must not enter the correlation pipeline.

The predictors, in contract order, are:

1. `duration_ms`
2. `fwd_packets`
3. `bwd_packets`
4. `fwd_bytes`
5. `bwd_bytes`
6. `packets_per_second`
7. `bytes_per_second`
8. `fwd_packet_length_mean`
9. `bwd_packet_length_mean`
10. `dst_port`
11. `protocol`

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

## Registered benchmark files

`data/manifests/cse_cic_ids2018.yaml` registers the approved files as external validation inputs:

| File | Bytes | Data rows | SHA-256 |
| --- | ---: | ---: | --- |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | 1,048,575 | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | 1,048,575 | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` |

The manifest verifier checks the registered paths and SHA-256 digests before benchmark validation
starts. The streaming validation then enforces the manifest's exact row counts. The command is run
from the repository root:

```console
python scripts/validate_cic_benchmark.py
```

It streams both CSVs through `CicProcessedReader` and the strict feature-only adapter. Accepted
records are discarded immediately. Only aggregate counts and at most 20 sanitized rejection
examples are retained by the batch-quality reporter. Reports are written beneath
`artifacts/reports/cse_cic_ids2018/`; neither reports nor raw files are tracked by Git.

## Full validation results

The Phase 0K-d full streaming run produced:

| File | Total | Accepted | Rejected | Rejection rate | Completed |
| --- | ---: | ---: | ---: | ---: | --- |
| Wednesday | 1,048,575 | 1,048,570 | 5 | 0.00047684% | `true` |
| Thursday | 1,048,575 | 1,048,575 | 0 | 0% | `true` |

All five Wednesday rejections identify `Flow Duration` with the sanitized reason “must be finite
and within allowed numeric bounds.” The bounded examples contain row numbers and the rejected
field name, but not raw values or complete rows. Thursday had no rejection reasons.

The generated reports are:

- `artifacts/reports/cse_cic_ids2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter_quality.json`
- `artifacts/reports/cse_cic_ids2018/Thursday-15-02-2018_TrafficForML_CICFlowMeter_quality.json`

This registration validates the acquired exports as external feature-benchmark data. It does not
turn CIC into incident-correlation data, create processed datasets or training splits, or train a
model.
