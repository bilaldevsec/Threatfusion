# January v2 autoencoder residual-contribution audit

## Frozen audit protocol

This is one bounded diagnostic of the already-frozen experimental v2 autoencoder against the frozen
Random Forest on the existing January VALIDATION partition. January labels and outcomes informed
development and autoencoder calibration, so every result is calibration-informed development evidence,
not independent evaluation. The audit does not train, fit, recalibrate, tune, change a threshold or
architecture, create a fusion rule, approve a product path, or access February or CIC data.

### Population and cohorts

The population is all 216,568 rows, in saved order, from the verified
`full-train-only-0141bde-v1/X_validation.npy` and `y_validation.npy` artifacts: 4,358 Attack (`1`) and
212,210 Normal (`0`). Membership uses the frozen decisions `AE score > 0.1181361214680695` and Random
Forest `P(Attack) >= 0.5`. The four disjoint requested cohorts are:

1. `ae_only_attack`: label 1, AE anomaly, RF not Attack;
2. `ae_only_benign_false_positive`: label 0, AE anomaly, RF not Attack;
3. `both_detected_attack`: label 1, AE anomaly, RF Attack;
4. `neither_rejected_benign`: label 0, AE within threshold, RF not Attack.

Before aggregation, their counts must equal the saved v2 overlap evidence: 96, 1,574, 1,892, and
210,435 respectively. The full January AE and RF confusion matrices and all eight label-specific overlap
cells must also reproduce the saved reports. Any disagreement fails the audit without publishing
completed findings.

### Exact scoring and residual arithmetic

The audit verifies and reloads artifact identity
`bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a` and uses
`unsw_autoencoder_per_record_scoring_v2`. For transformed float64 row `x_i`, each feature is converted
elementwise to float32 as `q_ij = float32(x_ij)`. A shape `(1, 14)` CPU float32 forward produces
`r_ij = float32_model(q_i)_j`. The feature residual contribution is
`c_ij = (float64(q_ij) - float64(r_ij))^2`. The score is the fixed-order NumPy float64 sum
`s_i = sum_j(c_ij, dtype=float64) / float64(14)`. Each reconstructed row is evaluated alone; outer
chunking changes iteration only. The audit requires its reconstructed scores and strict threshold
decisions to be exactly equal to the existing v2 scorer. It additionally requires
`sum_j(c_ij) == 14 * s_i` within a reported roundoff bound justified by the identical operands,
feature order, and float64 reduction.

The Random Forest is verified against its saved configuration, report, model hash, preprocessing
binding, class order, and 14-feature order, then scored once in existing bounded batches. Its inclusive
0.5 decision is preserved exactly.

### Feature order and descriptive groups

The fixed preprocessing order is:

1. `duration_ms__zscore`
2. `fwd_packets__zscore`
3. `bwd_packets__zscore`
4. `fwd_bytes__zscore`
5. `bwd_bytes__zscore`
6. `packets_per_second__zscore`
7. `bytes_per_second__zscore`
8. `fwd_packet_length_mean__zscore`
9. `bwd_packet_length_mean__zscore`
10. `dst_port__zscore`
11. `protocol=tcp`
12. `protocol=udp`
13. `protocol=icmp`
14. `protocol=other`

For readable descriptive summaries only, the preregistered groups are: duration (1), packet counts
(2–3), byte counts (4–5), rates (6–7), mean packet lengths (8–9), destination port (10), and protocol
indicators (11–14). Groups do not change scoring and are not causal or semantic equivalence claims.

### Aggregate statistics and outputs

For every cohort, including an explicit representation for any empty cohort, report its record count;
per-feature mean and median squared residual; each feature's fraction of the cohort's total squared
residual; analogous group sums/fractions; and AE score count, minimum, mean, standard deviation,
quartiles, 90th/95th/99th percentiles, and maximum. Fractions use the sum of `c_ij` over cohort rows as
the denominator. A zero-total cohort reports fractions as null rather than inventing a value. No raw
rows or individual predictions are retained.

The reproducible script writes aggregate JSON and long-form CSV plus one readable feature-contribution
chart beneath ignored `artifacts/reports/network_autoencoder_residual_audit/`. The tracked findings
section will state only what residual attribution supports: which transformed inputs account for the
frozen model's reconstruction error in these cohorts. It cannot identify causal reasons that an event
is malicious, validate feature semantics, establish independent accuracy, or authorize fusion.

### Resource bounds and failure behavior

Only January `X_validation.npy`/`y_validation.npy` may be opened; TRAIN, February, CIC, raw data, and
assignment rows are unnecessary and out of scope. Inputs remain memory-mapped. The audit permits one
AE pass and one RF pass over 216,568 rows, per-record shape `(1, 14)` AE forwards, RF batches no larger
than 25,000, and bounded aggregate arrays. Peak RSS must remain below 2 GiB, at least 2 GiB reported
memory and filesystem space must be available before scoring, output must remain below 32 MiB, and
wall time must remain below 600 seconds. The script records monotonic runtime, Linux peak RSS, output
bytes, and observed preflight memory/disk availability. Missing/mismatched evidence, non-finite values,
resource failure, score/residual mismatch, cohort mismatch, or report mismatch fails closed with a
sanitized error and no completed aggregate result.

## Findings

The first audit attempt completed scoring and aggregation and reached publication, but the publication
field-name defect discarded the in-memory aggregates before any aggregate result was retained. No
scientific result is reported from that attempt. The owner explicitly authorized one additional
January scoring pass after the defect. Before that second pass, the publication regression was extended
to exercise the actual atomic JSON, CSV, and SVG path with synthetic aggregates and the corrected
feature `index` and `name` fields. A forced publication failure also proved that aggregate-only recovery
survives without raw records or secrets and that a retry does not reopen scoring inputs.

The explicitly authorized second pass completed on 2026-09-19. It retained the aggregate
[`JSON`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-vs-rf-f71a5e7/aggregate.json),
long-form
[`CSV`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-vs-rf-f71a5e7/feature_contributions.csv),
and
[`SVG chart`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-vs-rf-f71a5e7/feature_contributions.svg)
under the ignored report directory. The aggregate-only ignored recovery file was written before
publication; publication succeeded, so no retry or further scoring occurred. The retained report
reproduces the frozen January AE and RF confusion matrices, all eight overlap cells, and the four
preregistered cohort counts: 96 AE-only attacks, 1,574 AE-only benign false positives, 1,892 attacks
detected by both, and 210,435 benign rows rejected by neither. Residual-to-score reconciliation is
exact with maximum absolute difference `0.0`.

The pooled residual attribution differs materially by cohort. Every percentage below is a feature or
group's fraction of the sum of squared residuals over all rows in that cohort. It is not a fraction of
records and does not say that the stated percentage of records exhibited that pattern:

- For the 96 AE-only attacks, the two rate features account for 93.78% of total squared residual:
  `packets_per_second__zscore` contributes 46.95% and `bytes_per_second__zscore` 46.83%. The next group,
  mean packet lengths, contributes 4.68%.
- For the 1,574 AE-only benign false positives, rates contribute 38.75%, byte counts 38.44%, and packet
  counts 13.15%. Individually, forward bytes contribute 25.88%, packets/second 19.54%, bytes/second
  19.21%, forward packets 12.76%, and backward bytes 12.56%.
- For the 1,892 attacks detected by both models, byte counts contribute 76.39% of total squared
  residual, almost entirely forward bytes at 76.27%; packet counts contribute 9.94% and rates 8.39%.
  This cohort is highly right-skewed: median AE score is 0.2157, mean is 13.2726, and maximum is
  11,654.3336, so its summed fractions are sensitive to large residual outliers.
- For the 210,435 benign rows rejected by neither model, mean packet lengths contribute 29.71%, byte
  counts 25.32%, and packet counts 24.95%. The largest individual contributions are forward mean packet
  length at 26.77%, forward packets at 23.23%, and backward bytes at 18.69%.

The retained means, medians, and score quantiles qualify any typical-record interpretation. In the
AE-only attack cohort, the marginal median squared residuals for packets/second (`7.27`) and bytes/second
(`7.36`) are much larger than every other feature median (the next is `0.51`), so the feature-wise
medians support the limited qualitative statement that rate residuals were commonly large in this
small cohort. They do not establish that a typical record assigned 93.78% of its own error to rates:
the audit did not retain per-record group fractions, and marginal feature medians need not belong to
the same record.

The other flagged cohorts show stronger evidence that pooled totals are not typical-record summaries.
For AE-only benign false positives, the score mean is `1.39` versus median `0.38`; the mean/median
squared residuals are `3.81`/`0.023` for packets/second, `3.74`/`0.0027` for bytes/second, and
`5.04`/`0.119` for forward bytes. For attacks detected by both models, the score mean is `13.27` versus
median `0.216` and maximum `11,654.33`; forward-byte squared residual has mean `141.72` but median
`0.00077`. Those gaps demonstrate severe skew and show that a comparatively small set of large values
can dominate pooled fractions. The retained aggregate quantiles do not reveal how many records account
for each feature's pooled total or whether the same records dominate several features. The benign
neither-rejected cohort is also right-skewed (score mean `0.0090`, median `0.0041`), and its pooled
fractions likewise are not typical-record percentages.

The pass took 27.30 seconds, peaked at 505,634,816 bytes RSS, used shape `(1, 14)` for all 216,568 AE
forwards and RF batches no larger than 25,000, and retained 50,849 output bytes. Its report explicitly
records no TRAIN, February, or CIC access. These are transformed-input reconstruction-error
descriptions for a calibration-informed January development partition. They do not establish causal
malicious indicators, feature-semantic validity, independent accuracy, a threshold or model change,
fusion value, or product approval. Because no per-record contribution distribution or prospective
decision analysis is retained, the aggregates do not define a useful feature-based decision rule or
justify a specific next model experiment. More diagnosis would be required under a separately reviewed
protocol before making either decision.

## Completion review

The bounded checkpoint review confirmed that labels and both decision arrays are positional outputs for
the same verified January matrix, the RF batch helper preserves row order, and the four masks reconcile
to the frozen label-specific overlap cells. Source comparison confirmed that per-feature contributions
use the exact v2 float32 conversion, one-row model forward, float64 residual, fixed-order sum, and strict
AE threshold. The chart labels the values as reconstruction-error fractions and explicitly disclaims
causal interpretation.

The review found and corrected one recovery-integrity defect: a structurally valid recovery file could
have had a numeric aggregate changed before retry. Recovery now stores a canonical SHA-256 binding of
the exact aggregate payload and revalidates the frozen thresholds, population, feature/group order,
confusion matrices, overlap cells, cohort counts, score reconciliation, resource/access flags, and
feature identities before publishing. The recovery branch executes before any scoring-input access, so
a valid retry cannot silently rescore. Focused tests also verify that generic CLI exceptions return
status 1 with only the sanitized `audit_failed` code. Ten focused tests, audit-file Ruff, and
source/document whitespace checks pass. The bounded local Black check reported both files unchanged
but required timeout termination after emitting that result. Generated JSON/CSV/SVG/recovery files
remain ignored, and the existing FYP demonstration files are unchanged.
