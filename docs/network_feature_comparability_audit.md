# UNSW/CIC network feature comparability audit

## Scope and conclusion

This is a bounded evidence review at baseline
`f49e7de5b64f274bc080d6fb9e93e43bc8689790`. It reuses the completed CIC
pipeline-correctness audit: model identity, feature order, one-time scaling,
class mapping, rejection alignment, and bounded prediction replay were not
retested. No model, adapter, contract, dataset, or artifact was changed.

The implementation maps the declared fields and formulas exactly as written,
but `network_behavior_v1` gives incompatible byte measurements the same
canonical meaning. UNSW `sbytes`/`dbytes` are Argus *transaction bytes*, while
the inspected CICFlowMeter code builds its directional length totals from
transport payload length for TCP and UDP. Argus documents application bytes as
separate fields. This is a demonstrated cross-source contract/mapping defect,
not a probability-column, scaling, or row-alignment defect. It also affects the
two byte-derived means and `bytes_per_second`.

Packet direction, duration, packet counts, destination port, and packet rate
are at best conditionally comparable because the historical Argus flow policy
and CICFlowMeter-V3 revision/configuration are not bound by the registered
artifacts. Protocol equivalence is supported only for the four deliberately
coarse normalized groups. Weak transfer is observed; neither domain shift nor
overfitting is established as its cause.

## Implemented projection

The exact predictor order is:

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

The [contract][tf-contract] declares this order. The [UNSW adapter][tf-unsw]
maps `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `dsport`, and `proto`; the
[CIC adapter][tf-cic] maps `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`,
`TotLen Fwd Pkts`, `TotLen Bwd Pkts`, `Dst Port`, and `Protocol`. Both adapters
recompute total rates and directional means through the same [local
helpers][tf-helpers]. A non-positive duration yields a zero rate, and a
non-positive directional packet count yields a zero mean.

## Source and version evidence

- The local registered `NUSW-NB15_features.csv` defines `dur` as record total
  duration; `spkts`/`dpkts` as source-to-destination/destination-to-source
  packet counts; and `sbytes`/`dbytes` as transaction bytes in those
  directions. The [official UNSW page][unsw-site] says Argus and Bro plus
  twelve algorithms generated 49 features from the capture. It does not state
  the Argus release, configuration, snap length, timeout/status-report policy,
  or post-processing revision.
- The [Argus `ra(1)` manual][argus-ra] used for semantic interpretation is
  version 3.0.8. It distinguishes transaction `bytes`/`sbytes`/`dbytes` from
  application `appbytes`/`sappbytes`/`dappbytes`, defines directional packet
  counts, and reports retransmission/loss separately. The [Argus configuration
  manual][argus-conf] documents configurable bidirectional keys and periodic
  flow status reporting. Those manuals are relevant primary documentation,
  but they do not prove that UNSW used that exact version or its defaults.
- The [official CIC-IDS2018 page][cic-2018] identifies CICFlowMeter-V3,
  first-packet forward direction, bidirectional flows, TCP teardown, and
  configurable timeout. It does not bind the exported files to a source commit
  or record the effective timeout. Current official upstream `master`,
  inspected on 2026-09-08, is cited below: [BasicFlow][cfm-basic-flow] records
  first/last timestamps, first-packet direction, counts, and directional
  lengths; [PacketReader][cfm-packet-reader] supplies separate payload and
  header lengths; [FlowGenerator][cfm-flow-generator] implements bidirectional
  keys and termination. Current `master` is not assumed to be the historical
  2018 exporter.

## Field-by-field evidence

“Smallest action” means a future corrective or evidentiary action, not a change
made by this audit.

| Canonical feature | UNSW source/formula and unit | CIC source/formula and unit | Packet/byte accounting | Direction | Evidence | Verdict | Likely consequence | Smallest justified action |
|---|---|---|---|---|---|---|---|---|
| `duration_ms` | `dur * 1000`; `dur` is record total duration in seconds | `Flow Duration / 1000`; source value is microseconds; inspected code uses `lastSeen - start` | First-to-last timing within each exporter's flow record; no bytes involved | Applies to the bidirectional record | [UNSW metadata][unsw-features], [Argus `ra`][argus-ra], [CIC documentation][cic-2018], [BasicFlow][cfm-basic-flow], [adapters][tf-unsw] | **Conditional equivalence** | Different termination, timeout, periodic reporting, or timestamp precision can split the same packets into different durations | Bind both historical exporter configurations; test identical packet sequences including idle gaps and teardown |
| `fwd_packets` | `spkts`, source to destination, count | `Tot Fwd Pkts`, count | Argus calls this transaction packet count; inspected CIC code counts every added forward packet, including zero-payload packets. Exact malformed, truncated, retransmitted, and capture-loss treatment is not historically bound | UNSW source→destination; CIC first packet fixes forward | [UNSW metadata][unsw-features], [Argus `ra`][argus-ra], [CIC application][cic-app], [BasicFlow][cfm-basic-flow] | **Conditional equivalence** | Direction or flow segmentation differences alter counts even for the same conversation | Same-PCAP parity cases for retransmission, loss, truncation, midstream starts, and timeouts |
| `bwd_packets` | `dpkts`, destination to source, count | `Tot Bwd Pkts`, count | Same packet-accounting qualification as forward count | UNSW destination→source; CIC reverse of the first packet | Same as `fwd_packets` | **Conditional equivalence** | A direction reversal swaps forward/backward evidence and can change tree decisions | Include reversed and midstream-start flows in the parity cases |
| `fwd_bytes` | `sbytes`, source-to-destination **transaction bytes** | `TotLen Fwd Pkts`; inspected code sums TCP/UDP transport `getPayloadLength()`, bytes | Argus distinguishes transaction bytes from application bytes; inspected CIC keeps payload and header bytes separately | Subject to the source/first-packet qualification | [UNSW metadata][unsw-features], [Argus `ra`][argus-ra], [BasicFlow][cfm-basic-flow], [PacketReader][cfm-packet-reader] | **Demonstrated mismatch** (historical CIC revision still unbound) | Header-only packets and protocol headers contribute differently, shifting this feature systematically | Mark this mapping non-equivalent; define a versioned common byte layer and regenerate from packets with one pinned extractor before reuse |
| `bwd_bytes` | `dbytes`, destination-to-source transaction bytes | `TotLen Bwd Pkts`; same inspected payload accumulator, bytes | Same mismatch as forward bytes | Same directional qualification as backward packets | Same as `fwd_bytes` | **Demonstrated mismatch** (historical CIC revision still unbound) | Reverse traffic byte totals are not measurements of the same quantity | Apply the same versioned byte-layer correction in both directions |
| `packets_per_second` | `(spkts + dpkts) / dur`, packets/s, recomputed locally | `(Tot Fwd Pkts + Tot Bwd Pkts) / Flow Duration`, packets/s, recomputed locally | Identical local arithmetic; inherits packet inclusion and flow-boundary differences | Bidirectional total, so swapping direction alone has no effect | [helpers][tf-helpers], [adapters][tf-unsw], [CIC documentation][cic-2018] | **Conditional equivalence** | Short or differently split flows amplify small count/duration differences | Validate counts and duration first; retain the shared formula |
| `bytes_per_second` | `(sbytes + dbytes) / dur`, bytes/s, recomputed locally | `(TotLen Fwd Pkts + TotLen Bwd Pkts) / Flow Duration`, bytes/s, recomputed locally | Identical arithmetic over incompatible byte quantities | Bidirectional total | [helpers][tf-helpers], [adapters][tf-cic], byte evidence above | **Demonstrated mismatch** | The denominator may differ and the numerator definitely has different documented semantics | Recompute only after a common byte layer and flow policy are established |
| `fwd_packet_length_mean` | `sbytes / spkts`, bytes, recomputed; the available UNSW `smeansz` field is not used | `TotLen Fwd Pkts / Tot Fwd Pkts`, bytes, recomputed | Transaction bytes/packet versus inspected transport-payload bytes/packet | Forward qualification applies | [UNSW metadata][unsw-features], [helpers][tf-helpers], byte evidence above | **Demonstrated mismatch** | Header-only packets can be nonzero for UNSW and zero in the inspected CIC byte numerator | Derive the mean only from byte and packet fields with proven common semantics |
| `bwd_packet_length_mean` | `dbytes / dpkts`, bytes, recomputed; `dmeansz` is not used | `TotLen Bwd Pkts / Tot Bwd Pkts`, bytes, recomputed | Same mismatch as forward mean | Backward qualification applies | Same as `fwd_packet_length_mean` | **Demonstrated mismatch** | Direction and header-only traffic compound the discrepancy | Use the same common-byte correction and direction parity evidence |
| `dst_port` | `dsport`, integer 0–65535 | `Dst Port`, integer 0–65535 | Transport service endpoint; no packet/byte accounting | UNSW record destination versus CIC first packet's destination | [UNSW metadata][unsw-features], [CIC documentation][cic-2018], [FlowGenerator][cfm-flow-generator], [adapters][tf-cic] | **Conditional equivalence** | If origins differ, a service port and an ephemeral port can exchange roles | Establish initiator/destination orientation from identical SYN-led and midstream packet cases before treating it as portable |
| `protocol` | Argus `proto` transaction protocol; name normalized to `tcp`, `udp`, `icmp`, or `other` | IP `Protocol`; numeric 6, 17, 1 normalized to the same groups; all other values become `other` | Protocol identity, not payload accounting | Direction-independent | [Argus `ra`][argus-ra], [CIC documentation][cic-2018], [normalizer][tf-helpers] | **Supported equivalence** for the declared coarse groups | `other` intentionally loses distinctions; spelling/number variants outside the allowlist also collapse | Retain the four fixed groups; add a fixture only when a newly observed source representation needs evidence |

## Classification of findings

### Demonstrated implementation/mapping defect

The adapters correctly execute their code, but their common semantic mapping
is defective for `fwd_bytes`, `bwd_bytes`, `bytes_per_second`, and both packet
length means. “Transaction bytes” and the inspected CIC transport-payload
accumulator are not interchangeable. The existing synthetic parity fixture
checks adapter arithmetic on invented equal values; it cannot establish that
the historical extractors measured those values equivalently.

### Differences inherent to collection/export

Argus and CICFlowMeter independently construct bidirectional records and have
configurable reporting/termination behavior. CIC explicitly uses the first
packet for forward direction and normally FIN/timeout termination. Argus can
use configurable flow keys, bidirectional tracking, idle handling, and
periodic status records. Capture position, snap length, loss, retransmissions,
midstream starts, and exporter flow boundaries therefore can change packet
counts, direction, duration, ports, and rates without an adapter bug.

### Unresolved evidence

The registered evidence does not establish the UNSW Argus version,
configuration, byte layer, snap length, direction assignment, or flow
post-processing; nor does it establish the exact CICFlowMeter-V3 commit and
timeout settings used for the 2018 CSVs. Current upstream code clarifies its
present implementation but is not proof of historical behavior. Capture-level
directional equivalence and retransmission/loss accounting remain unresolved.

### Observed population differences

The official sources describe different capture years, testbeds, traffic, and
attack programs: UNSW used an IXIA PerfectStorm-generated mixture processed by
Argus/Bro, while CIC-IDS2018 used a separate organizational testbed and attack
schedule. The prior bounded diagnostic also observed different transformed
duration/rate ranges, protocol frequencies, and score distributions. Those
are sample observations, not full-dataset estimates or proof that domain shift
or overfitting caused the weak transfer. Possible row-capped CIC exports and
the source timezone remain additional population/provenance qualifications.

## Prioritized improvement path

Before changing a model, fix the demonstrated semantic defect at the contract
boundary. Pre-register a small same-PCAP extractor-parity study spanning
TCP/UDP/ICMP, header-only packets, retransmission, idle timeout, FIN/RST,
zero-duration, and midstream direction cases. Pin both extractor revisions and
all capture/flow settings. Use it to define a versioned byte-accounting layer;
then either re-extract both datasets with one pinned implementation or prevent
the five byte-based fields from entering a cross-source contract until an
equivalent source field is demonstrated. The official [CIC-UNSW-NB15
project][cic-unsw] illustrates the general approach of re-extracting UNSW
packets with CICFlowMeter, but it does not by itself validate these registered
files or erase historical/configuration uncertainty.

CIC outcomes are already known. If they influence extractor, contract,
feature, or model choices, CIC becomes development evidence rather than an
independent test. Any resulting system needs a protocol frozen in advance and
evaluation on a genuinely uninspected capture or dataset with independently
verified labels, common extractor semantics, comparable collection metadata,
and no overlap or near-duplicate leakage. The acceptable operational
false-positive rate and associated costs remain a product decision; this audit
does not invent a target. Global readiness is unchanged and deep-learning work
remains paused.

[tf-contract]: ../backend/src/threatfusion/features/network_behavior.py
[tf-unsw]: ../backend/src/threatfusion/datasets/adapters/unsw_nb15.py
[tf-cic]: ../backend/src/threatfusion/datasets/adapters/cic_ids2018_benchmark.py
[tf-helpers]: ../backend/src/threatfusion/datasets/adapters/base.py
[unsw-features]: ../data/raw/unsw_nb15/official/NUSW-NB15_features.csv
[unsw-site]: https://research.unsw.edu.au/projects/unsw-nb15-dataset
[argus-ra]: https://qosient.com/argus/man/man1/ra.1.pdf
[argus-conf]: https://qosient.com/argus/man/man5/argus.conf.5.pdf
[cic-2018]: https://www.unb.ca/cic/datasets/ids-2018.html
[cic-app]: https://www.unb.ca/cic/research/applications.html
[cfm-basic-flow]: https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java
[cfm-packet-reader]: https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java
[cfm-flow-generator]: https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java
[cic-unsw]: https://www.unb.ca/cic/datasets/cic-unsw-nb15.html
