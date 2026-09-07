# Phase 0P: synthetic fixture versus training readiness

The generated `synthetic_lab` data is intentionally small: 3 independent sessions, 14 events per
session, and 42 events total. It is a deterministic development/pipeline fixture for exercising
the host-event reader, validation, profiling, and readiness audit. It is not sufficient final
host-model training data.

The audit now reports two separate states:

- `pipeline_ready=true` means manifest integrity, input existence, schema validation, report
  sanitization, and complete streaming checks pass.
- `training_ready=true` additionally requires the project-selected minimum training evidence. The
  current fixture therefore has `training_ready=false` even though it is pipeline-ready.

The selected minimum training gates are deliberately project gates, not universal claims of model
quality: at least 5 sessions, 500 total accepted events, 50 accepted events per session, a
7-day overall timestamp span, all 7 event types, and no artificially uniform event frequencies.
The last gate detects generated schedules where every event type occurs equally often. Every
threshold is configurable through `scripts/validate_synthetic_lab.py`; changing one must be
documented and rerun through the audit.

The current profile fails the final-training gates because it has 3 sessions, 42 events, a span of
about 2 days, and equal six-count frequencies for all seven event types. These failures are
reported as aggregate gate results only. The fixture remains benign, contains no attack
simulation, and its `Normal` labels are metadata only. Mordor remains attack/test data and CIC
remains external evaluation data.

Its manifest role is `development_fixture`, and the split policy permits only `pipeline_test`.
Passing fixture-quality gates establishes pipeline behavior only; it cannot make the fixture
eligible for model training, tuning, or scientific evaluation.

No model training, balancing, resampling, or processed-data creation is authorized by this phase.
Later work must add a substantially larger, independently designed benign host corpus before
claiming host-model training readiness. It must also create and verify explicit leakage-safe split
assignments; configured policy alone is not evidence that assignment occurred.
