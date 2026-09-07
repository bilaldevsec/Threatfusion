# Phase 0O: benign synthetic_lab host baseline

The public Mordor sample is attack/test telemetry and cannot establish normal host behavior.
Phase 0O therefore adds an isolated, controlled `synthetic_lab` baseline. It contains no attack
simulation and no public or personal source data.

The deterministic generator writes three independent NDJSON session files. Each session contains
14 benign `host_event_v1` events spanning 13 minutes and covers process, network, authentication,
file, registry, privilege, and other event types twice. Hosts, providers, and process names use
obvious synthetic placeholders. Users, command lines, IP addresses, ports, secrets, file paths,
registry paths, and ATT&CK annotations are absent.

Generate the exact baseline from the repository root:

```console
python scripts/generate_synthetic_lab_baseline.py
```

The generator writes one JSON object at a time and atomically replaces each destination. Event IDs
are the safe session basename plus the one-based row number. These IDs and session filenames are
deterministic ingestion provenance, not model features. Every event has a `Normal` label for
quality accounting, but labels remain metadata only and never enter `host_behavior_v1`.

## Registration and streaming validation

`data/manifests/synthetic_lab.yaml` registers all three generated files with the explicit
`development_fixture` role, not a training role or final training data,
including exact row counts and SHA-256 checksums. Validation reuses the manifest verifier, reads
each NDJSON line incrementally, validates the existing `host_event_v1` shape and deterministic
provenance, and immediately reduces accepted events to bounded aggregates.

Run validation and profiling together:

```console
python scripts/validate_synthetic_lab.py
```

It writes three quality reports and one combined profile beneath
`artifacts/reports/synthetic_lab/`. Reports contain safe basenames, counts, duration coverage,
quality-gate results, and bounded sanitized rejection reasons. They never contain complete events,
hosts, process/provider values, commands, IPs, usernames, secrets, arbitrary raw values, or
absolute paths.

## Documented configurable gates

The defaults deliberately match the minimum shape of this first baseline rather than claiming
statistical sufficiency:

- at least 3 independent session files;
- all 7 canonical event types represented;
- at least 14 accepted events per session;
- at least 780 seconds of timestamp coverage per session;
- all accepted labels equal `Normal` and every stream completes.

Each numeric minimum has a corresponding command-line option. Raising a threshold produces a
completed profile with `quality_gates.passed=false`; the readiness audit must then keep training
readiness false. Later phases may strengthen the thresholds using evidence, but must document the
change rather than silently altering the baseline definition.

This fixture closes the missing-benign-data pipeline gate but does not authorize model training or
claim production representativeness. Its split-policy use is limited to `pipeline_test`, and
generic `train` role selection excludes it. Final host training also requires a real benign corpus
and the separate training-quality gates described below. Mordor remains attack/test-only and CIC
remains external network evaluation data.

The completed run verified all three checksums and streamed 42 events. It accepted all 42,
rejected none, completed every session, observed each of the seven event types six times, and
passed every pipeline-quality gate. The final-training gates fail because the fixture has only
three sessions and 42 total events, spans less than seven days, and has artificially uniform event
frequencies. The refreshed Phase 0 audit therefore reports `pipeline_ready=true` and
`training_ready=false`; absent explicit split assignments are a separate training blocker. No
training was performed.
