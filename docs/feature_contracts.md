# ThreatFusion Feature Contracts

ThreatFusion uses explicit feature contracts to define model inputs. Matching a contract's field
shape does not prove that dataset adapters or live packet capture produce comparable measurements.

The key rule is simple: datasets are not merged just because column names look similar. A feature
is shared only when its meaning, unit and direction are documented.

## Supported product inference boundary

Product inference is source-specific. Only the verified
`unsw_nb15.argus.raw_49.transaction_bytes.v1` representation is supported by the frozen UNSW model
bundle through [`network_behavior_v1`](unsw_network_inference_boundary.md). Matching field names or
shapes do not grant compatibility. The registered CICFlowMeter representation remains rejected by the
compatibility gate and preserved only as historical research evidence.
Representation declarations are trusted-adapter attestations, not authentication of arbitrary caller
measurements; see the [inference trust boundary](unsw_network_inference_boundary.md#security-and-scientific-claim-boundary).

## flow_common_v1

`flow_common_v1` is the complete canonical network-flow contract. Its 12-field model projection is
an UNSW-only contract for the currently registered datasets because it includes `src_port`, which
the selected processed CIC exports do not provide. It must not be presented as the common
UNSW/CIC model interface.

It is used by:

- UNSW-NB15 adapter
- CSE-CIC-IDS2018 adapter
- live sensor flow extractor
- UNSW-only or complete-flow models
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
separate dataset adapters. Historical projection code is retained, but its availability does not approve
inference: the registered CIC byte mapping is incompatible with the frozen UNSW representation.

If a feature cannot be mapped honestly, it must remain dataset-specific.

## network_behavior_v1

`network_behavior_v1` is the frozen model-input projection accepted from a complete `NetworkFlow`
or a feature-only external benchmark record. Projection availability is not evidence that two
source representations measure every field equivalently and does not itself approve cross-source
inference. It contains exactly 11 predictors in this order:

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

`dst_port` remains in the historical model projection because both inputs provide a bounded
destination port. Its cross-source directional meaning is conditional on exporter orientation; a
matching integer bound alone does not prove semantic equivalence. It remains behavior rather than
identity/provenance, and any learned transformation must still be fitted on training data only.

## Cross-source compatibility gate

Compatibility is a separate typed decision keyed by the input representation, fitted-source
representation, contract version, and exact model/preprocessing requirements. The current
UNSW-NB15 Argus-derived raw representation is supported for the same-source UNSW-trained classical
pipeline. This is a narrow inference-use decision, not production or global readiness.

The registered processed CICFlowMeter-V3 representation is **demonstrably incompatible** with
that pipeline for `fwd_bytes`, `bwd_bytes`, `bytes_per_second`,
`fwd_packet_length_mean`, and `bwd_packet_length_mean`: UNSW uses Argus transaction bytes while
the inspected CIC implementation accumulates transport payload bytes. Direction, duration, flow
termination, and historical configurations remain unresolved. Missing, unknown, or mismatched
compatibility evidence is never approved by default. See the
[`network feature comparability audit`](network_feature_comparability_audit.md).

The CIC evaluator enforces this decision after verifying registered source, preprocessing, and
model provenance but before transforming/predicting or creating a run directory. There is no CLI
bypass. Historical completed CIC reports remain immutable/readable, but their legacy
`semantic_feature_compatibility_verified=true` field records the earlier shape/formula assertion;
it is not current compatibility approval. Completion and compatibility must be read separately.
The gate changes no model, preprocessing state, feature order, or accuracy.

## host_behavior_v1

`host_event_v1` holds canonical event evidence, including sensitive and provenance fields, so its
fields are not automatically model predictors. `host_behavior_v1` instead reduces a caller-defined
source/session group to an exact ordered vector of coarse event-type counts and safe presence
counts. It never retains individual events or uses event IDs, timestamps, hosts, users, command
lines, IPs, file paths, registry keys, ATT&CK IDs, labels, or ingestion provenance.

The exact host predictors are total event count; process, network, authentication, file, registry,
privilege, and other event counts; and counts of events where provider, process name, or parent
process name is present. The source/session grouping and observation window remain responsibilities
of the leakage-safe split and feature-building phase; the contract does not invent either.

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
