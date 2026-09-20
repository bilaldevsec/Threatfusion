# January-only two-rate log1p autoencoder experiment

## Frozen protocol, 2026-09-19

This protocol freezes one exploratory, calibration-informed development experiment before fitting.
January residual evidence selected the intervention, and January benign rows calibrate its threshold.
The result cannot establish independent improvement, operational acceptance, statistical significance,
fusion value, product approval, or issue closure. February outcomes were previously inspected and are
excluded; CIC is excluded.

An admission process verifies registered UNSW source hashes and the complete assignment, traverses the
registered rows in global ordinal order, and retains only exact raw-derived rate pairs and record
ordinals for 865,480 TRAIN and 216,568 January VALIDATION rows. It retains no February feature or label.
The separate experiment process enters a Linux Landlock filesystem sandbox before importing experiment
code. Its allowlist contains the admitted January bundle, frozen baseline TRAIN/January preprocessing,
frozen Random Forest, selected source/runtime files, and fresh output roots. Raw UNSW, February matrices
and labels, and CIC paths are absent. Real-path denial probes must pass before preprocessing or fitting.

The sole intervention is float64 natural `log1p` on `packets_per_second` and `bytes_per_second`, before
population z-scoring fitted on all 865,480 TRAIN rows (847,837 Normal plus 17,643 Attack). Rates retain
the canonical formulas `(spkts+dpkts)/(duration_ms/1000)` and
`(sbytes+dbytes)/(duration_ms/1000)` and become zero when duration is zero. Missing, negative, or
non-finite values are rejected; zero variance uses scale one. The other eight numeric columns and four
protocol indicators must be byte-identical to the baseline matrices. Candidate rate names are
`packets_per_second__log1p__zscore` and `bytes_per_second__log1p__zscore`.

Weights fit only the 847,837 benign TRAIN rows: benign-only weight training with all-TRAIN
preprocessing. Controls are 14-8-3-8-14, seed 42, the baseline initialization, Adam at 0.001 with
betas 0.9/0.999 and epsilon 1e-8, batch size 1,024, deterministic epoch shuffling, no loader workers,
and exactly 30 epochs. Scoring remains canonical v2: one `(1,14)` float32 forward per record, float64
residuals against the converted input, fixed-order squared-residual sum divided by 14. The candidate has
distinct preprocessing, model, score, and threshold identities.

The threshold is NumPy's higher empirical 99th percentile of all 212,210 benign January scores;
Anomaly is strictly `score > threshold`. RF uses only its verified baseline January matrix and frozen
model with `P(Attack) >= 0.5`; labels and assignment order must match the candidate.

Let A be AE-only attacks and B AE-only benign false positives. Passing requires A >= 96, B <= 1,574,
`40*A >= 3*B` when B is positive, and total AE false positives <= 1,628. If B=0 and A>0 the ratio gate
passes with explicit nonnumeric zero-denominator metadata; A=B=0 fails. Report both confusion matrices,
precision, recall, F1, FPR, all eight overlap cells, each gate, and any loss of recall or both-detected
attacks. These are development retention criteria, not operational targets.

Before fitting, snapshot this protocol and the exact dirty bytes of the candidate module, runner,
adapter, preprocessing, canonical scorer, and RF verifier with a digest manifest. Bind admitted inputs,
assignment evidence, matrices, preprocessing, weights, threshold, reports, feature order, runtime, and
identities. Candidate/baseline substitution fails closed. The candidate stays outside the product
registry and cannot alter the demo.

The process uses four PyTorch intra-op threads, one inter-op thread, zero loader workers, and RF batches
of at most 25,000. It requires 2 GiB memory and disk reserves, limits peak RSS to 2 GiB, total elapsed
time to 3,600 seconds, and candidate preprocessing/model artifacts to 256 MiB. Integrity, access,
population, finite-value, reload, resource, or publication-recovery failures stop the run with sanitized
incomplete evidence. There is one fit only: no retry, sweep, threshold alternative, seed change, or
result-driven revision. The completed JSON report is persisted before markdown/SVG rendering, so a
presentation failure cannot cause retraining or rescoring.

## Execution evidence, 2026-09-19

The one authorized attempt completed without retry, sweep, or control change. A separate admission pass
verified the registered source and global assignment and retained exact raw-derived rate pairs and
ordinals for 865,480 TRAIN and 216,568 January rows. It retained zero February feature or label values.
The experiment then ran under Landlock ABI 8 with `no_new_privs`; real open probes against one UNSW raw
file, both February matrix/label files, and one CIC raw file each failed with errno 13 before candidate
preprocessing or fitting.

Candidate preprocessing fitted the rate-log means and population scales on all 865,480 TRAIN rows.
Exactly 847,837 benign TRAIN rows reached every one of 30 optimizer epochs; 17,643 TRAIN attacks reached
preprocessing statistics but not weight fitting. The higher 99th percentile of all 212,210 benign
January scores produced threshold `0.08645885557604867`, with one score equal to the threshold and
strict `>` retained.

The candidate confusion counts were TP/FP/TN/FN 945/2,122/210,088/3,413, with precision 0.308119,
recall 0.216843, F1 0.254545, and FPR 0.00999953. RF overlap was: attacks both 886, AE-only 59,
RF-only 3,159, neither 254; benign both false-positive 42, AE-only false-positive 2,080, RF-only
false-positive 159, both correctly unflagged 209,929. All four frozen gates failed: A was 59 (<96), B
was 2,080 (>1,574), `40*A >= 3*B` failed (ratio 0.0283654), and total AE false positives were 2,122
(>1,628). Overall recall fell by 0.239330, TP fell by 1,043, and attacks detected by both models fell by
1,006. The disposition is **FAIL — preserve the baseline**.

Fit time was 535.854 seconds and total experiment time was 559.896 seconds. Peak RSS was 872,030,208
bytes; the RF batch limit was 25,000; no loader workers were used. Bound candidate inputs,
preprocessing, model, evidence, and presentation files occupy 148,479,647 bytes before the completion
manifest, below 256 MiB. The candidate artifact identity is
`910d2977c93285f54c33408268bb316c5a8f9093042927a77de5ba6fe5fb36f4`. The candidate remains ignored,
outside the product registry, and unavailable to the demo. January remains calibration-informed and
adaptively selected; no February or CIC evaluation occurred, and no fusion, approval, or issue closure
follows.

## Completion-review correction, 2026-09-20

The completed numerical result above is retained, but it does **not** satisfy this protocol. The input
admission process called the ordinary global source/assignment iterator and adapted all registered
rows before discarding TEST outputs. Its retained report explicitly records 1,452,844 TEST rows seen.
Landlock was applied only to the later preprocessing/training process, so the real-path denial probes
do not establish that preparation lacked February access. This violates the required end-to-end
January-only access boundary and cannot be corrected retroactively without another preparation and fit,
which are not authorized and would violate the one-attempt rule.

This access finding does not establish that February rows entered optimizer batches. The retained fit
accounting still reports exactly 847,837 benign TRAIN rows per epoch and zero declared TEST fit rows.
It establishes that the required preparation isolation failed, which is independently sufficient to
block the experiment.

The completion review also found that preparation recorded time and peak RSS only after traversal, the
candidate artifact budget was checked after fitting rather than projected before it, execution peak RSS
was checked only after fitting/scoring, and generic CLI exceptions could emit exception-derived failure
codes rather than a strict allowlist. Observed preparation/experiment time, RSS, disk reserve, and
artifact size were within the numerical limits, but those observations are not the frozen hard
enforcement required by this protocol.

The superseding disposition is **BLOCKED — preserve the baseline**. Candidate metrics remain readable
as protocol-invalid development evidence and must not be called the result of a conforming isolated
experiment. The tracked historical runner rejects both preparation and execution with
`experiment_closed_blocked_no_reuse`; rendering an already completed report remains available. It is
unsuitable for reuse until the documented access and enforcement defects are corrected under new
authorization. No retry, rescoring, alternate intervention, or diagnostic audit follows.
