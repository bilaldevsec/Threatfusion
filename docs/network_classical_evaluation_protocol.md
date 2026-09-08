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

## Frozen CIC external-evaluation extension

This extension was frozen before CIC predictions. Prior aggregate CIC profiles, labels, rejection counts, feature ranges, and duplication limitations had already been inspected. The primary results are per acquired export; pooled results are secondary and are recomputed from pooled labels and continuous scores rather than averaged from file metrics. Future development must disclose that CIC results are known.

The registered inputs are `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` (`acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147`) and `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` (`fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b`). The manifest hash is `7f0bc2989cd956ebdc446230bece8bebc3f2b52b7dc04cbc9589e298afb61eaf`; the completed quality-report hashes are `966063ea56ef60b7496c041c6062a64d4001dbc1a5d56651579f00d316ff6727` and `17d2aa25ae671b30c6b4a2a7872b47b261f76fe1a9b7888fad44f3aa8ddbc9ee`; the inspected profile hash is `daaffab6d5e3fa09faf0ebeae90973454d69cb84093c2f6a4939505963fbf271`.

The unchanged UNSW TRAIN-fitted preprocessing state is `30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49`. The saved logistic model is `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`; the saved Random Forest is `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`. Both use Normal=0, Attack=1 and classify `P(Attack) >= 0.5`. The transformed order remains the same 14 features listed above.

Compatibility is semantic: CIC flow duration is converted from microseconds to milliseconds; forward/backward packet and byte directions are preserved; rates and packet-length means are recomputed from those directional totals; destination port and protocol use the shared definitions. Only the feature-only benchmark record is accepted. Source filename/row, timezone-naive timestamp, label, and attack name remain evaluation metadata and never enter predictors.

No CIC fitting, calibration, model or feature selection, threshold change, imputation, clipping, rebalancing, or learned preprocessing is permitted. Each acquired CSV has 1,048,575 data rows and may be a row-capped export. The source timezone is unknown. Results describe these exports only, do not establish future or operational performance, and do not change host or global readiness.

## Targeted post-evaluation audit

The read-only audit found no implementation defect in the inspected prediction path or bounded replay; it does not prove that every possible defect is absent. It checked the saved model and preprocessing identities, transformed feature order, positive-class probability mapping, single application of scaling, and output alignment across the five rejected Wednesday source rows.

The replay matched stored transformed features exactly for 989 accepted Wednesday samples and 1,000 Thursday samples. Direct `predict_proba` calls and the evaluator path differed by at most `1.67e-16`, consistent with floating-point roundoff, and produced no threshold disagreements. Pooled confusion counts reconcile with the per-file counts. Code inspection confirms that pooled average precision and ROC-AUC are computed from pooled continuous scores rather than averaged file metrics. Individual score arrays were intentionally not retained, so the audit did not independently reconstruct the full pooled average precision or ROC-AUC.

Weak cross-dataset transfer is observed, particularly for the Random Forest. It does not establish domain shift as the sole cause. Capture-level directional equivalence, capture conditions, row-cap effects, timezone, and other semantic or population comparability remain incompletely established. CIC outcomes are now known, and every future experiment must disclose that exposure. All previously reported metrics and frozen protocol decisions remain unchanged.

## Post-audit compatibility enforcement

The later feature-comparability audit demonstrated that the five byte-dependent CIC predictors do
not share the UNSW/Argus byte-accounting semantics. New use of these CIC exports with the saved
UNSW-trained models is therefore rejected with
`cross_source_byte_semantics_incompatible` after source, preprocessing, and model provenance are
verified but before CIC transformation, prediction, or run-directory creation. Unknown or missing
representation/contract/requirements evidence also fails closed. There is no permissive CLI flag.

The historical v1 run above remains completed execution evidence and its files/hashes are unchanged.
Its legacy `semantic_feature_compatibility_verified=true` check described the earlier field
shape/unit/formula assertion and must not be interpreted as approval under the current typed
compatibility decision. The historical-report reader exposes `completed` and current
compatibility separately and classifies this exact representation as
`demonstrated_incompatibility`. Any future report uses the v2 schema with an explicit compatibility
decision rather than sharing the legacy schema. This safeguard does not improve either model's
accuracy, establish compatible measurements, resolve weak transfer, or change any readiness gate.
