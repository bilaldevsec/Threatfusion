# Network training split design

## Scope and readiness boundary

This document designs the first executable, leakage-resistant UNSW-NB15 network split. It does
not create assignments, processed data, preprocessing artifacts, or models. It does not change
`network_behavior_v1`, the Phase 0 split policy, or the readiness audit. Global
`training_ready=false` remains correct: explicit split assignments do not yet exist, and the host
lane still lacks a real benign Windows training corpus.

## Verified facts

### Registered sources and contracts

- `data/manifests/unsw_nb15.yaml` registers two published pre-partitioned CSVs, one 49-field
  metadata file, and four headerless raw CSVs. The raw data files contain 2,540,047 rows in total.
- The completed raw validation/profile accepted 2,540,037 rows and rejected 10. It observed
  2,218,754 `Normal` and 321,283 `Attack` rows, with timestamps from
  `2015-01-22T11:49:37+00:00` through `2015-02-18T12:21:08+00:00`.
- The raw reader streams one 49-value record at a time. It generates `flow_id` from safe file-row
  provenance because the source has no row identifier. That ID is not telemetry or a predictor.
- The raw fields include `stime`, `ltime`, duration, endpoint IPs and ports, protocol, label, and
  attack category. There is no explicit capture or session field.
- `network_behavior_v1` is the required portable predictor contract: ten numeric/port fields plus
  normalized protocol. It excludes source port, IPs, timestamps, labels, attack categories,
  dataset identity, filenames, row numbers, and ingestion IDs.
- CIC is registered as external evaluation only. Its timestamps are timezone-naive with unknown
  source timezone, and its acquired exports may be row-capped.

The published UNSW train/test representation omits fields needed for the proposed time and entity
checks. It must not be combined with the raw representation.

### Bounded exploratory check

After using the stored aggregate reports, a split-critical check streamed only the first 1,000
rows of each raw file. All 4,000 sampled rows adapted successfully. The sample found no capture or
session field, 158--176 timestamp-order inversions per file, 282 repeated logical source rows, and
666 repeated `network_behavior_v1` vectors. No sampled feature vector had conflicting labels.
These observations rule out row-order splitting and show that duplicate analysis is necessary;
they do **not** prove full-dataset duplicate, label, entity, or capture separation.

The previously observed pandas warnings occur when fixture/Mordor ISO timestamp strings reach the
generic parser with `dayfirst=True`. UNSW raw `stime` values are numeric epoch seconds and take the
parser's numeric path before pandas. The warnings therefore do not alter the proposed UNSW
ordering. The implementation must nevertheless test numeric epoch parsing explicitly and fail on
missing, nonnumeric, or out-of-range timestamps.

## Proposed decisions

### Source selection

Use only `UNSW-NB15_1.csv` through `UNSW-NB15_4.csv`, mapped by
`NUSW-NB15_features.csv`, through `UnswRawReader` and `adapt_unsw_row`. Train and evaluate the
portable `network_behavior_v1` binary `Normal`/`Attack` interface so the frozen model pipeline can
later be evaluated on CIC. Do not read the published UNSW training/testing CSVs in this experiment.

CIC must never participate in fitting, preprocessing, feature selection, hyperparameter tuning,
threshold selection, calibration, split revision, or early stopping. It is evaluated once with
the frozen pipeline after UNSW validation decisions and held-out UNSW testing are complete.

### Time cutoffs

Use two explicit UTC instants in a versioned configuration:
`train_end_utc` and `validation_end_utc`, with `train_end_utc < validation_end_utc`. Do not infer
sequence from file or row order. No numeric cutoffs or split percentages are selected here because
the existing report has only global endpoints and the bounded sample shows sparse, nonmonotonic
file segments. A full timestamp/class census is required first.

Cutoffs must be selected once, before preprocessing or model results, from a sanitized UTC time
histogram. Prefer calendar boundaries between observed activity blocks. Record the rationale and
freeze the configuration hash. If the frozen split fails an acceptance gate, stop and version a
new design/configuration; do not repeatedly move boundaries to improve held-out performance.

Given frozen cutoffs, provisional row buckets are exact:

- `train` when the complete canonical flow interval ends before or at `train_end_utc`;
- `validation` when it starts at or after `train_end_utc` and ends before or at
  `validation_end_utc`;
- `test` when it starts at or after `validation_end_utc`;
- `boundary_quarantine` when its interval crosses either cutoff.

Use canonical `timestamp_start` and duration-derived `timestamp_end`. Profile raw `ltime` versus
the canonical end as an aggregate diagnostic; do not silently replace either semantic if they
disagree.

### Separate preflight diagnostics and deferred grouping decisions

Filenames are provenance only and are not capture boundaries. The preflight reports three
independent diagnostics:

1. exact logical source-record duplicate groups and their excess rows;
2. repeated label-free `network_behavior_v1` vectors, their excess rows, and groups containing
   both labels; and
3. connected interval-overlap groups for the same direction-normalized endpoint-pair/protocol
   identity.

These counts may overlap but are not merged. In particular, identical feature vectors are
potential leakage links, not proof of the same source event. The preflight does not build hard
connected components, quarantine records, resolve conflicts, relabel records, or create split
dispositions. Those decisions require a separately reviewed assignment design after the diagnostic
evidence exists.

The direction-normalized identity orders the two internal `(IP, port)` endpoints lexicographically
and adds normalized protocol. Closed canonical intervals overlap when the next start is less than
or equal to the running component end; touching intervals therefore overlap. It is used only
inside the ignored indexing job. No IP, tuple, raw fingerprint, or group identifier enters
predictors or the public report.

Timestamp/class distributions are feasibility evidence only. The preflight neither proposes nor
optimizes cutoffs from those distributions.

### Exact fingerprints

- Source-record fingerprint: SHA-256 over a length-prefixed, ordered encoding of the 49 decoded
  source fields. Exclude only reader-generated `flow_id`. This tests exact logical records and
  includes source labels and endpoint fields.
- Model-vector fingerprint: SHA-256 over the exact ordered `network_behavior_v1` projection.
  Encode integers as signed fixed-width bytes, finite floats as IEEE-754 binary64, and protocol as
  a length-prefixed UTF-8 category. Exclude labels, attack categories, timestamps, IPs, source
  ports, filenames, row numbers, and all ingestion/provenance IDs.
- Track label counts beside each model fingerprint. Never include the label in that fingerprint.

Hashes and row-level associations remain internal ignored artifacts. Public reports contain only
aggregate counts. Exact-source fingerprints include all 49 source fields, including their label,
but exclude the reader-injected `flow_id`. Feature fingerprints never include labels, attack
categories, provenance, endpoints, timestamps, or fields outside the model contract. No numeric
value is rounded and no near-duplicate heuristic is applied.

## Diagnostic invocation

From the repository root, first run a bounded smoke check:

```bash
.venv/bin/python scripts/preflight_unsw_split.py \
  --run-id smoke-v1 --max-rows-per-file 1000
```

Only after manifest verification and smoke success, run the full diagnostic:

```bash
.venv/bin/python scripts/preflight_unsw_split.py --run-id full-v1
```

Each command requires a fresh run ID and writes its SQLite database and JSON report beneath
`data/interim/unsw_split_preflight/<run-id>/`, which Git ignores. The default hard working-artifact
budget is 8 GiB with a 2 GiB free-space reserve, 10,000-row transactions, and a 256 MiB SQLite
cache. Smoke reports always use `run_scope=partial` and `completed=false`, even if a small input
happens to be exhausted. Full `completed=true` requires verified registration, expected row counts,
complete input exhaustion, reconciled accounting, all diagnostic queries, and the disk-budget gate.
Neither mode creates assignments.

## Bounded implementation design

Stream the four raw files once and use an ignored SQLite database beneath `data/interim/`.
Configure `temp_store=FILE`, a bounded cache, explicit transactions, and fixed insertion batches.
Suggested tables hold safe file-row provenance, canonical start/end, label metadata, the two
fingerprints, a hashed direction-normalized tuple, and final disposition. Indexed group queries
and interval ordering occur on disk; Python retains only one row, one batch, fixed counters, and
bounded error samples.

Do not expose row assignments publicly. An internal assignment artifact may retain safe basename
and row number for reproducibility. Its companion public split report must contain only:

- report/config/schema versions and generating commit;
- input manifest SHA-256 values and ordered raw basenames;
- feature-contract name and ordered feature names;
- approved cutoff instants and canonical time semantics;
- fingerprint encoding and hard-group rule versions;
- total, accepted, rejected, deduplicated, quarantined, and assigned counts;
- counts by split, binary label, attack category, protocol, and UTC time bucket;
- per-split time bounds and group counts;
- source/model duplicate multiplicity histograms with finite buckets;
- conflicting-label, boundary-crossing, and cross-bucket group counts;
- internal assignment artifact SHA-256, but no IPs, IDs, row pointers, group hashes, or examples;
- `completed`, arithmetic checks, privacy checks, and acceptance-gate results.

The assignment configuration must include all decisions above, the two cutoffs, ordered input
files, manifest digest, feature-contract version, SQLite/batch settings, and a fixed random seed of
`null` because assignment is deterministic and nonrandom. Repeated runs with the same inputs and
configuration must produce byte-identical public reports and identical assignment-artifact hashes.

Estimated resources, not measurements: 2.54 million indexed rows should require roughly 2--6 GB
of temporary SQLite/index space. A 10,000-row write batch and approximately 256 MB SQLite cache
should keep application plus database working memory comfortably below 1 GB, excluding the Python
runtime. The implementation must measure peak RSS and actual disk use and fail early if configured
free-space or memory limits are unavailable.

## Preprocessing and evaluation discipline

Fit every learned transform on `train` only. Preserve the exact feature order. Strict ingestion
already rejects missing/nonfinite required values, so do not invent imputation. A future pipeline
may apply a predeclared nonnegative transform to skewed numeric fields, fit numeric scaling on
training, and encode only the four documented protocol categories. Fit feature selection,
calibration, and the decision threshold using training/validation only. Apply the frozen objects to
held-out UNSW test and then CIC.

Publish class, attack-category, protocol, time, and group coverage after the assignment is frozen.
Coverage gates are data-quality gates, not optimization targets. Do not inspect test or CIC scores
to revise split boundaries, duplicate rules, transforms, features, or thresholds.

## Acceptance tests for the future implementation

1. Only the four registered raw data files are eligible; published train/test files and CIC are
   rejected as fitting inputs.
2. Missing/malformed timestamps, manifest mismatches, partial consumption, or report arithmetic
   contradictions fail closed.
3. Permuting file and row iteration order leaves diagnostic aggregate report content unchanged.
4. Direction-reversed identities with intervals that overlap or touch are counted without a
   pairwise self-join; separated intervals are not counted as one component.
5. Exact source duplicates are counted separately from exact model-vector duplicates.
6. Labels and provenance changes do not change model fingerprints; predictor changes do.
7. Conflicting labels on one model fingerprint are reported without relabeling or disposition.
8. IPs may affect internal group hashes but never predictors or public report content.
9. Preprocessing fit calls receive training rows only; held-out UNSW and CIC are transform-only.
10. Memory remains bounded on a large synthetic iterator, and rejection/detail histograms retain
    configured finite cardinality.
11. Partial, interrupted, manifest-invalid, row-count-invalid, or disk-budget-failed runs cannot
    produce a completed report.
12. No preflight output is presented to `PHASE0_SPLIT_POLICY.validate_assignments`; policy
    configuration alone remains distinct from future assignment verification.

## Unresolved questions

- The exact `train_end_utc` and `validation_end_utc` require the full timestamp/class census and
  explicit approval before assignment.
- No registered field or existing report proves capture/session boundaries or that different raw
  filenames are independent. Collector documentation may resolve this; otherwise the limitation
  remains explicit.
- Full-dataset source duplicates, feature duplicates, conflicting labels, and endpoint-pair overlap
  must be taken only from a completed full preflight report. Cross-boundary groups and quarantine
  rates remain unknown until cutoffs and disposition policies are separately approved.
- The relationship between raw `ltime` and canonical duration-derived end time needs aggregate
  verification.
- Near-duplicate thresholds are not justified by current evidence. A full pass should report
  cross-split endpoint/five-tuple overlap and feature-distance distributions, but no threshold may
  be adopted or claimed effective without a separately reviewed, resolution-based rule fixed
  before model evaluation.

## Next implementation scope

After the diagnostic implementation has completed a full pass, review its sanitized evidence and
propose concrete UTC cutoffs plus explicit policies for each diagnostic category. A later,
separately approved implementation may create assignments only after those choices are frozen.

## Frozen initial development-split policy

The January 22 time-only validation candidate is rejected because its later segment has no attack
records. No alternative chronological cutoff may be searched for this experiment. The initial
assignment uses grouped development validation and preserves February as a chronological test:

- development starts are in the half-open UTC interval
  `[2015-01-22T00:00:00Z, 2015-01-24T00:00:00Z)`;
- held-out test starts are in
  `[2015-02-18T00:00:00Z, 2015-02-19T00:00:00Z)`;
- a canonical interval must also end within its start period; otherwise its complete enforced
  leakage group is quarantined;
- CIC remains external evaluation only and cannot affect this assignment or later fitting choices.

Accepted records are grouped transitively by exact-source equality and connected overlap of the
direction-normalized endpoint-pair/protocol identity. Exact-source equality retains its preflight
meaning: all 49 ordered CSV-decoded source fields are equal, including source labels, while the
injected `flow_id` is excluded. Overlap uses closed canonical start/duration-derived-end intervals,
so touching intervals connect. Identical `network_behavior_v1` vectors are diagnostic collisions,
not mandatory grouping relationships.

Group identifiers derive only from the smallest registered file/row ordinal in each connected
component and a domain-separated SHA-256 encoding; labels do not enter the identifier. Development
groups use the fixed seed `threatfusion-unsw-dev-split-v1`. Let `score` be the unsigned integer
represented by the first 64 bits of
`SHA-256(domain || length-prefixed seed || group identifier)`. A group validates when
`score < floor(2^64 / 5)` and trains otherwise. This targets 20/80 of groups, not rows, and the seed
must not be retried for class balance.

Raw `Stime`, `Ltime`, and `dur` consistency is retained per record in ignored SQLite state during
one verified streaming pass. `exact` and `within_one_second_quantization` are initially eligible;
the latter is a working tolerance, not proven timestamp precision. Any unexplained, reversed, or
unparseable interval quarantines its whole enforced group without repairing values. A group with
both development and February members is also quarantined completely; February records are never
moved into development.

The ignored assignment artifact covers every registered row exactly once as train, validation,
test, quarantine, or rejected. A sanitized audit must reconcile counts, prove enforced groups do
not cross model splits, invoke the Phase 0 assignment validator in bounded batches, and require
both benign and attack records in train and validation. Feature-vector sharing and label conflicts
remain separately reported and do not trigger label-dependent exclusion.

The inspected preflight evidence contains 1,052,853 accepted January 22 starts, 34,340 benign-only
January 23 starts, and 1,452,844 accepted February 18 starts. It also reports 4,265 unexplained
interval discrepancies, 40,860 model-vector groups shared across the candidate periods, and two
overlap components crossing candidate period boundaries. The preflight index cannot locate the
timing discrepancies, which is why the single raw timing pass is required.

Capture/session provenance and near-duplicate risk remain unresolved. Every learned preprocessing,
encoding, scaling, feature-selection, calibration, and threshold step must be fit using train only
(with validation used only for declared development choices); held-out UNSW test and CIC are
transform-only. This network assignment does not make host training ready, does not create a benign
host corpus, and does not by itself make global training readiness true.
