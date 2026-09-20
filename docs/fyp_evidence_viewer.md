# Offline FYP evidence viewer

This is a read-only, self-contained presentation of retained ThreatFusion FYP evidence. It is not a
SOC dashboard, a product service, a live-traffic display, or a model runner. It reads only sanitized
aggregate reports and writes one ignored HTML file; it does not open datasets, matrices, credentials,
private keys, or model binaries.

## Generate and open

From the repository root, with the already synchronized project environment:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/generate_fyp_evidence_viewer.py
xdg-open artifacts/reports/fyp_evidence_viewer/threatfusion_fyp_evidence.html
```

The HTML contains all CSS and JavaScript and has no CDN, web-server, or external-request dependency.
It may be opened directly in an installed browser. The generator exits nonzero with a sanitized reason
and does not publish if required input is missing, malformed, incomplete, mismatched against the
code-owned v2 AE binding, or mismatched against the residual audit recovery binding. Other source
digests are fingerprints, not proof of authenticity, where no pre-existing trusted binding exists.

## Presentation sequence (5–7 minutes)

1. State the scope: retained recorded UNSW replay, not live traffic or an operational dashboard.
2. Show completed producer modules and name absent dashboard/worker/correlation capabilities.
3. Show the two deliberately selected records: known labels beside—not merged with—RF predictions.
4. Show exact replay and invalid-request rejection counts. The viewer itself never runs a demo.
5. Compare January evidence, then identify February as previously inspected and development-informed.
6. Show the January 96/1,574 complementarity finding and residual interpretation limits.
7. Expand the BLOCKED candidate, then close on limitations and roadmap.

The separate live rehearsal command is not run by the viewer:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run_fyp_progress_demo.py
```

## Evidence and limitations

Required inputs are the saved sanitized FYP demo report, RF report, corrected v2 AE report, January
residual aggregate plus recovery binding, and rate-log1p candidate report. The page shows identities and
SHA-256 values in expandable details. No optional evidence is substituted or fabricated. It excludes raw
records, datasets, models, keys, endpoints, and host paths.

TF-006 through TF-012 remain applicable as documented: development exposure, unresolved
provenance/comparability, missing host evidence, no dashboard/worker acceptance, no authoritative jury
list, and no user-value validation. The candidate is protocol-invalid and authorizes neither retry,
fusion, approval, nor a baseline change.
