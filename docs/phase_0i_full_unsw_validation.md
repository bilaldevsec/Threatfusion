# Phase 0I: Full UNSW-NB15 streaming quality validation

Phase 0I validates every row in the four official headerless raw partitions:
`UNSW-NB15_1.csv` through `UNSW-NB15_4.csv`. The command reads the ordered column names from
`NUSW-NB15_features.csv`, maps one CSV row at a time with the existing raw reader, and passes each
named row through the strict UNSW adapter and streaming batch-quality reporter.

Run it from the repository root:

```bash
python scripts/validate_unsw_raw.py
```

Accepted canonical flows are immediately discarded. They are never accumulated or written, so
the command's memory use does not grow with the number of accepted rows and no processed dataset
is created. The command does not train a model and does not alter or remove the source archive.

One sanitized JSON report per partition is written beneath the ignored
`artifacts/reports/unsw_nb15/` directory. Reports contain aggregate counts and at most 20 rejected
row examples. Examples contain only row numbers, field names, and allow-listed or generalized
validation reasons; source-row values are excluded.

For each partition, the command prints its byte size, SHA-256 checksum, row counts, rejection
rate, sanitized sampled reasons, and report path. It also updates the tracked
`data/manifests/unsw_nb15.yaml` using the existing manifest schema. The manifest retains the
registered train/test files and records the feature mapping plus all four raw partitions with
their row counts and SHA-256 checksums. File size is printed rather than added to the manifest
because the current schema has no size field.

Any malformed feature mapping or raw row width is a structural error and stops validation. In
that case an incomplete quality report is not written and the manifest is not updated. This keeps
the tracked receipt from representing a validation run that did not finish all four inputs.
