# Phase 0L-e: Mordor registration, validation, and profiling

This phase registers the extracted `cmd_sharpview_pcre_net` NDJSON file that ThreatFusion actually
streams. It is a small, official Mordor attack/test sample from the OTRF Security-Datasets
repository. It is not benign training data and must not be treated as a representative host
baseline. The approved `synthetic_lab` lane supplies benign host activity.

The manifest records one 415,506-byte NDJSON file with 267 events and SHA-256
`b3df9616bb41ee1b464595eb0d5a5b612f475d34d78429786a6fa8ee8a16be9d`. Its role is `test` and
its classification is attack/test-only. OTRF Security-Datasets carries the MIT License in its
checked-in repository license. The incompatible PowerShell candidate is not registered.

Validation first uses the existing manifest verifier to check the registered SHA-256. It then
streams every line through `MordorNdjsonReader`, the unchanged Mordor mapping behavior, and the
bounded batch-quality reporter. Accepted records are discarded immediately. The JSON quality
report contains counts, rates, completion state, and at most 20 sanitized rejection details.

Profiling is also one-pass and aggregate-only. It retains at most 64 first-seen EventID categories,
an overflow count for events with additional previously unseen codes, allowlisted structural
field-presence counts, accepted timestamp bounds, the process-event total, and bounded rejection
details. Retained EventID counts plus overflow reconcile to total input rows. It never retains or
reports events, command lines, IP addresses, usernames, secrets, raw values, or full filesystem
paths. Raw and report directories remain ignored by Git; no processed CSV, Parquet, or model file
is produced.

The reader-generated event identifier combines the safe source basename with the one-based input
row number. This identifier records ingestion provenance only. It is not a source field and is
never a model feature. `EventID` remains an event-type code and is not used as an identifier.

The archive contains only one EventID 1 process event. This attack/test sample is useful for
compatibility and pipeline validation, but its single process-creation event makes it unsuitable
as standalone process-model training data.

The completed manifest-backed run verified the checksum, read 267 events, accepted 267, rejected
zero, and reported `completed=true` with no rejection examples. The accepted timestamp range was
2020-10-29T08:23:18.073000+00:00 through 2020-10-30T00:23:23.120000+00:00. Validation and profile
JSON files were written only beneath `artifacts/reports/mordor/`, which is ignored by Git.
