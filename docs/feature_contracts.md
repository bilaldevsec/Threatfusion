# ThreatFusion Feature Contracts

ThreatFusion uses explicit feature contracts so that model training, dataset adapters and live
packet capture produce comparable inputs.

The key rule is simple: datasets are not merged just because column names look similar. A feature
is shared only when its meaning, unit and direction are documented.

## flow_common_v1

`flow_common_v1` is the canonical network-flow contract used before ML/DL inference.

It is used by:

- UNSW-NB15 adapter
- CSE-CIC-IDS2018 adapter
- live sensor flow extractor
- classical ML models
- deep-learning anomaly models
- correlation and risk engine

## Accepted Common Features

| Feature | Type | Unit | Meaning |
|---|---:|---:|---|
| `duration_ms` | float | milliseconds | Flow duration from first packet to last packet |
| `fwd_packets` | integer | count | Packets from source to destination |
| `bwd_packets` | integer | count | Packets from destination back to source |
| `fwd_bytes` | integer | bytes | Bytes from source to destination |
| `bwd_bytes` | integer | bytes | Bytes from destination back to source |
| `packets_per_second` | float | packets/sec | Total packets divided by duration |
| `bytes_per_second` | float | bytes/sec | Total bytes divided by duration |
| `fwd_packet_length_mean` | float | bytes | Average forward packet size |
| `bwd_packet_length_mean` | float | bytes | Average backward packet size |
| `src_port` | integer | port | Source port |
| `dst_port` | integer | port | Destination port |
| `protocol` | category | tcp/udp/icmp/other | Transport/network protocol group |

## Deliberately Excluded From Common Contract

These are not part of `flow_common_v1` unless later parity tests prove equivalence:

| Feature family | Why excluded |
|---|---|
| TTL fields | UNSW and CIC do not expose these in directly equivalent ways |
| TCP window fields | Not available consistently across all sources |
| Connection state | Not the same as raw TCP flag counts |
| Dataset ID | Would cause dataset leakage |
| Attack label | Target only, never input feature |
| Generated risk score | Created after inference, not before inference |

## Dataset Alignment Rule

UNSW-NB15 and CSE-CIC-IDS2018 are heterogeneous network-flow datasets. ThreatFusion therefore uses
separate dataset adapters. Each adapter converts only semantically valid fields into
`flow_common_v1`.

If a feature cannot be mapped honestly, it must remain dataset-specific.

## network_behavior_v1

`network_behavior_v1` is the portable model-input contract for evaluation across a complete
`NetworkFlow` and a feature-only external benchmark record. It contains exactly 11 predictors in
this order:

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

It deliberately excludes `src_port`. The selected official CSE-CIC-IDS2018 processed exports do
not contain source ports, source or destination IP addresses, or flow identifiers. No 12-input
model trained with `flow_common_v1` may be evaluated as though an 11-input CIC row satisfied that
contract.

The feature-only `NetworkBenchmarkRecord` keeps source dataset, file basename, one-based row
number, source timestamp, normalized label, and attack name as evaluation provenance. Those
fields—as well as identifiers, IP addresses, source port, timestamps, and labels—are forbidden
model inputs. A benchmark record is not a correlatable incident flow.

## Academic Claim Boundary

Allowed claim:

> ThreatFusion evaluates a SOC triage pipeline across heterogeneous datasets using explicit
> feature contracts and adapter-level validation.

Not allowed claim:

> UNSW-NB15 and CSE-CIC-IDS2018 are directly merged into one naturally compatible dataset.
