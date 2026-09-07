# Frozen February classical-network evaluation protocol

This protocol was frozen before computing February model predictions. It evaluates only the assigned later-period UNSW TEST records (18 February 2015) with the two already-saved classical baselines. February aggregate labels and the assignment's duplication/collision statistics had already been inspected. Future model development must disclose that February results are known.

## Frozen evidence

- Assignment report: `6913c1f2ef974d0b969506daf2b091a740fbf0d6b43d231a6f64f30841436857`; archive: `154829274f1a2d594086c6a73db6fce7b585ffeba58632dfce08422c1b187dc9`; preflight report: `f805424dc5f39ca41f7b1935b25938307d2e15c18caa008b3a1ca9250b8ab384`.
- TRAIN-fitted preprocessing state: `30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49`; configuration: `70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a`; report: `d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a`.
- Logistic model: `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`.
- Random Forest model: `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`.

The transformed order is: `duration_ms__zscore`, `fwd_packets__zscore`, `bwd_packets__zscore`, `fwd_bytes__zscore`, `bwd_bytes__zscore`, `packets_per_second__zscore`, `bytes_per_second__zscore`, `fwd_packet_length_mean__zscore`, `bwd_packet_length_mean__zscore`, `dst_port__zscore`, `protocol=tcp`, `protocol=udp`, `protocol=icmp`, `protocol=other`.

Normal is 0 and Attack is 1. Both models predict Attack when `P(Attack) >= 0.5`. The saved preprocessing is applied unchanged. There is no February-based fitting, refitting, calibration, model selection, feature selection, threshold selection, or tuning.

Expected TEST evidence is 1,452,844 records: 1,153,776 Normal and 299,068 Attack. Existing collision evidence includes exact-vector duplication across assigned splits and conflicting labels; near-duplicate and capture/session provenance risks remain unresolved. Aggregate performance changes cannot establish a single cause. CIC and host data remain out of scope, and global readiness remains unchanged.
