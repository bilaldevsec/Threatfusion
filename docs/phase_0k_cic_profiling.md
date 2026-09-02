# Phase 0K-e: CSE-CIC-IDS2018 benchmark profiling

Profiling describes the acquired benchmark before any training decisions are made. It exposes the
label balance, protocol mix, feature ranges, timestamp coverage, and invalid-row count so later
work does not silently train on misunderstood data. This phase does not balance classes, resample
rows, drop features, build training splits, or train a model. Those choices require evidence from
the profile and belong to a later phase.

CSE-CIC-IDS2018 remains external network benchmark data. Its processed exports can test portable
network-behavior features, but they omit the endpoint evidence needed for ThreatFusion's incident
correlation pipeline.

## Safe streaming approach

Run the profiler from the repository root:

```console
python scripts/profile_cic_benchmark.py
```

The script verifies the registered files, reads each CSV one row at a time with
`CicProcessedReader`, and adapts each row through the strict feature-only CIC adapter. Accepted
records update fixed-size counters, numeric ranges, and timestamp bounds and are then discarded.
Rejected rows update `BatchQualityReport`, which retains at most 20 sanitized examples. This
constant-memory approach avoids placing two multi-hundred-megabyte CSVs or millions of records in
memory and is safe for the project's 16 GB development laptop.

The single aggregate-only report is written to
`artifacts/reports/cse_cic_ids2018/cse_cic_ids2018_profile.json`. It contains safe source
basenames, never complete rows, IP addresses, endpoint identifiers, source ports, full filesystem
paths, or rejected raw values. Both the raw data and generated report remain ignored by Git.

## Feature contract

The profiler uses `network_behavior_v1` in its exact contract order:

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

The five known source labels in these selected exports are `Benign`, `FTP-BruteForce`,
`SSH-Bruteforce`, `DoS attacks-GoldenEye`, and `DoS attacks-Slowloris`. The adapter normalizes
`Benign` to `Normal`, normalizes the four attacks to `Attack`, and preserves each original attack
name for category counts.

## Full profiling results

The complete streaming run produced these quality totals:

| Scope | Total rows | Accepted | Rejected | Rejection rate | Completed |
| --- | ---: | ---: | ---: | ---: | --- |
| Wednesday | 1,048,575 | 1,048,570 | 5 | 0.00047684% | `true` |
| Thursday | 1,048,575 | 1,048,575 | 0 | 0% | `true` |
| Combined | 2,097,150 | 2,097,145 | 5 | 0.00023842% | `true` |

The five rejected Wednesday rows are rows 410957 through 410960 and row 412185. Every rejection
identifies `Flow Duration` with the sanitized reason “must be finite and within allowed numeric
bounds.” The source values are non-finite and are not retained in the report.

Combined normalized label counts:

| Label | Count |
| --- | ---: |
| Normal | 1,663,698 |
| Attack | 433,447 |

Combined original attack-category counts:

| Attack category | Count |
| --- | ---: |
| FTP-BruteForce | 193,360 |
| SSH-Bruteforce | 187,589 |
| DoS attacks-GoldenEye | 41,508 |
| DoS attacks-Slowloris | 10,990 |

Combined protocol counts:

| Protocol | Count |
| --- | ---: |
| tcp | 1,513,795 |
| udp | 552,908 |
| icmp | 0 |
| other | 30,442 |

Combined numeric feature ranges over accepted records:

| Feature | Minimum | Maximum |
| --- | ---: | ---: |
| `duration_ms` | 0.0 | 120,000.0 |
| `fwd_packets` | 1 | 9,021 |
| `bwd_packets` | 0 | 19,181 |
| `fwd_bytes` | 0 | 8,737,314 |
| `bwd_bytes` | 0 | 27,905,234 |
| `packets_per_second` | 0.0 | 4,000,000.0 |
| `bytes_per_second` | 0.0 | 1,298,500,000.0 |
| `fwd_packet_length_mean` | 0.0 | 16,529.313840155944 |
| `bwd_packet_length_mean` | 0.0 | 1,459.2404947320201 |
| `dst_port` | 0 | 65,534 |

The earliest accepted source timestamp is `2018-02-14T01:00:00`; the latest is
`2018-02-15T12:59:59`. These values deliberately have no UTC offset. CIC's source timezone is
unknown, so the timestamps remain timezone-naive and must not be presented as UTC.

Each selected CSV contains exactly 1,048,575 data rows, or 1,048,576 CSV rows when its header is
included. That shape may reflect an export limit. The profile therefore describes only the
acquired exports and does not claim that they contain every flow from the original captures.
