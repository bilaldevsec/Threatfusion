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

## Academic Claim Boundary

Allowed claim:

> ThreatFusion evaluates a SOC triage pipeline across heterogeneous datasets using explicit
> feature contracts and adapter-level validation.

Not allowed claim:

> UNSW-NB15 and CSE-CIC-IDS2018 are directly merged into one naturally compatible dataset.
