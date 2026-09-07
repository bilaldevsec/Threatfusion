# Phase 0L-d: Mordor raw-event compatibility

The inspected SharpView archive contains 267 newline-delimited JSON events. All 267 have a
nonblank string `Hostname`, and every event has a timestamp accepted through the existing
`UtcTime`, `@timestamp`, or `TimeCreated` aliases. It is therefore evidence-based to map
`Hostname` to the canonical `host` field and retain the existing timestamp behavior.

The source does not contain `RecordID`, `EventRecordID`, or `event_id`. `EventID` describes the
Windows or Sysmon event type and must not identify an event instance. `ProcessGuid` is also
unsuitable: it is present in only 131 of 267 events and has only five distinct values.

`MordorNdjsonReader` reads one UTF-8 JSON object per line and never accumulates the file. It adds a
reserved ingestion identifier made from the safe source basename and one-based physical row
number, for example `dataset.json:1`. The reader rejects source objects that already contain its
reserved field, so source data cannot impersonate ingestion provenance. Structural errors contain
only the source basename, row number, issue category, and a static reason; they never include an
event or raw value.

Profiling retains at most 64 distinct sanitized EventID categories in first-seen order. Events
whose previously unseen codes arrive after that limit are counted in a single overflow aggregate,
so retained cardinality is finite and retained counts plus overflow always reconcile to input rows.

This generated identifier records ingestion provenance. It is not an original Mordor field, an
ATT&CK label, or a model feature. Original source identifiers remain preferred when a future
dataset supplies one. `EventID` remains available as `event_code` and for event-type
classification.

The compatibility layer does not weaken `host_event_v1`, infer missing values from event content,
or use process, command, user, or network values to manufacture identity. It only adds the proven
`Hostname` alias and the reader-owned deterministic fallback identifier.

The complete inspected file contains one Sysmon Event ID 1 process event. A bounded validation
streamed all 267 events through the reader, Mordor adapter, and batch-quality layer. It accepted
267, rejected zero, produced no rejection examples, and reported `completed=true`. Event ID counts
were: 1 (1), 3 (1), 5 (1), 7 (85), 10 (49), 11 (4), 12 (12), 13 (23), 22 (3), 23 (1), 1102 (1),
4656 (17), 4658 (34), 4663 (6), 4673 (1), 4688 (1), 4689 (1), 4690 (17), 5156 (3), and 5158
(6). Overflow was zero, so this below-limit distribution remains exact. These are event-type
aggregates, not identifiers. Raw Mordor archives and extracted JSON remain excluded from Git.
