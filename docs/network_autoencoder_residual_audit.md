# January v2 autoencoder residual-contribution audit

## Frozen record-concentration follow-up protocol, 2026-09-19

This final bounded diagnostic extends the existing audit without changing its model, thresholds,
population, feature order, loading boundary, or four cohorts. It was frozen before reopening January
data. For record `i` and transformed feature `j`, contribution remains
`c_ij = (float64(float32(x_ij)) - float64(r_ij))^2` and score remains the fixed-order float64 value
`sum_j(c_ij) / 14`, using one shape-`(1, 14)` CPU float32 forward. The existing groups remain duration,
packet counts, byte counts, rates, mean packet lengths, destination port, and protocol indicators.
The cohorts remain `ae_only_attack`, `ae_only_benign_false_positive`, `both_detected_attack`, and
`neither_rejected_benign`, with required counts 96, 1,574, 1,892, and 210,435.

For each record, a group's share is its group contribution divided by that record's total contribution.
The report gives linear-interpolated 10th, 25th, 50th, 75th, 90th, and 99th percentiles over records
with positive total error. Zero-total records have null shares, are counted separately, and are excluded
from share percentiles and dominance. A group is dominant when its contribution exactly equals the
largest group contribution. The report gives both unique-dominant counts and dominant counts including
ties; it also gives the number of tied-dominance records, so inclusive group counts need not sum to the
cohort size.

Score and per-group error distributions use the same six quantiles, plus minimum, mean, population
standard deviation, and maximum. Concentration is the fraction of total cohort error contributed by
the largest `ceil(p * n)` records for `p` equal to 1%, 5%, and 10%, with at least one record when the
cohort is nonempty. The same ordering-and-ceiling rule is applied separately to each group's per-record
error. A zero denominator yields null. The two AE-only cohorts are compared descriptively using their
score quantiles, means, medians, maxima, and concentration values; no significance test, cutoff search,
or causal claim is permitted.

The existing limits remain one January-only AE pass and one RF pass, 216,568 per-record forwards,
RF batches no larger than 25,000, memory-mapped inputs, less than 2 GiB peak RSS, 2 GiB preflight memory
and disk reserves, less than 32 MiB output, and less than 600 seconds. TRAIN, February, CIC, fitting,
calibration, tuning, dependency/model/threshold changes, fusion, product/demo work, and raw or per-record
outputs remain prohibited. Aggregate recovery must be saved and cryptographically bound before final
JSON/CSV/SVG publication. These calibration-informed January descriptions can support at most one
fixed candidate intervention as a hypothesis; they cannot establish causality, independent validation,
statistical significance, operational value, or guaranteed improvement. TF-006 and TF-007 remain open.

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

## Record-concentration follow-up findings and decision, 2026-09-19

The single authorized follow-up pass completed without retry. It retained aggregate-only
[`JSON`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-record-concentration-b5e6e5d/aggregate.json),
feature
[`CSV`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-record-concentration-b5e6e5d/feature_contributions.csv),
record-diagnostic
[`CSV`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-record-concentration-b5e6e5d/record_diagnostics.csv),
and the existing readable
[`SVG`](../artifacts/reports/network_autoencoder_residual_audit/january-v2-record-concentration-b5e6e5d/feature_contributions.svg).
It again reconciled all four cohort counts and exact v2 score arithmetic. Every record had positive
total error; no dominance ties occurred. Complete six-quantile group shares, group-error distributions,
dominance counts, and ceiling-rounded group concentration values are in the aggregate JSON and
record-diagnostic CSV.

The largest ceiling-rounded 1%, 5%, and 10% of record scores contributed respectively 5.92%, 23.10%,
and 40.97% of AE-only-attack error; 35.54%, 62.87%, and 69.94% of AE-only-benign-false-positive error;
91.43%, 95.77%, and 97.53% of both-detected-attack error; and 10.99%, 33.88%, and 50.95% of
neither-rejected-benign error. The both-detected pooled result is therefore extremely outlier-dominated,
while AE-only attacks are not dominated by a similarly tiny set.

Rate dominance is widespread in AE-only attacks: rates are the unique dominant group for 85 of 96
records, and their per-record shares have p10/p25/median/p75/p90/p99 values of
17.43%/76.18%/94.26%/96.36%/97.59%/98.02%. The largest 1%/5%/10% of rate errors contribute only
6.23%/23.53%/41.61% of the cohort's rate error. In the 1,574 AE-only benign false positives, rates are
dominant for 274 records and their share quantiles are 0.13%/0.28%/0.42%/1.03%/80.47%/96.99%.
The largest 1%/5%/10% of benign-false-positive rate errors contribute 47.16%/86.80%/95.68% of that
group error. Byte counts instead dominate 783 benign false positives, with a 48.93% median share;
packet counts dominate 334. Thus the earlier 38.75% pooled benign rate fraction describes a concentrated
tail, whereas the 93.78% pooled attack rate fraction describes most individual AE-only attacks.

AE-only attacks have score p10/median/p90/p99 of 0.1686/1.1938/12.3645/18.0174; AE-only benign false
positives have 0.1315/0.3846/1.8102/33.3416. Attack scores have the higher median and p90, but benign
false positives have the higher p99 and maximum. This overlap and tail reversal do not define a safe
record cutoff and were not used to search for one.

**Decision A: one specific candidate intervention is supported as a hypothesis.** A future separately
authorized experiment may apply `log1p` only to the two nonnegative raw rate predictors
(`packets_per_second` and `bytes_per_second`) before the existing TRAIN-only z-score fit, then train the
same 14-8-3-8-14 autoencoder. This fixed rate-tail compression follows from widespread rate dominance
among AE-only attacks but highly concentrated rate error among AE-only benign false positives. It does
not assert that extreme rates cause either label, and a larger network is not proposed.

All other controls must remain unchanged: same verified split assignments, 847,837 benign TRAIN rows,
feature order and other feature formulas, architecture, initialization seed, optimizer, batch size,
30 epochs, CPU runtime, per-record v2 MSE scoring, strict threshold rule, Random Forest comparator,
resource/failure gates, and artifact/provenance checks. Calibration must use the same 212,210 January
benign rows and frozen higher-99th-percentile rule. The full January partition is the
calibration-informed development comparison. If used, February must be a frozen secondary
`later_period_development_informed` comparison because its outcomes are already known. Confirmatory
evaluation must use a preregistered, compatible, genuinely uninspected source; none is currently
available under TF-007.

The primary development metric is the ratio of AE-only attacks recovered versus Random Forest to
AE-only benign false positives added, with the two counts always reported separately. Before execution,
acceptance is fixed as: at least 96 AE-only January attacks, no more than 1,574 AE-only January benign
false positives, ratio at least 0.075 (baseline 96/1,574 = 0.0610), and no worsening of total January
AE false-positive rate above 0.007672. Failure of any condition preserves the v2 baseline. Passing is
only sufficient to retain the candidate for later independent evaluation; it cannot establish an
improvement because January informed calibration and intervention choice, February has already been
inspected, and TF-006 provenance/near-duplicate risk remains open. No experiment is executed here.

The audit recorded 24.61 seconds internal runtime (29.5 seconds observed command wall time),
585,666,560 bytes peak RSS, 25,000 maximum RF batch size, and 110,380 published bytes. It explicitly
records no TRAIN, February, or CIC access. Twelve focused tests, relevant Ruff, recovery-integrity load,
JSON contract checks, and whitespace checks pass. Black reported both Python files unchanged before its
known delayed shutdown required timeout termination. The report directory and 84,397-byte recovery
file are ignored; the five source/document changes are left unstaged. The full backend suite was not
repeated because no shared production component changed.
