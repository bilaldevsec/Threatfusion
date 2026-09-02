# Phase 0H: Streaming the headerless UNSW-NB15 files

The four official raw UNSW-NB15 CSV files have values but no header row. A separate official
feature file provides the 49 names in the same order. The reader first skips that feature file's
descriptive header, cleans each name in one consistent way, and requires exactly 49 unique names.
It never guesses a missing name.

For each raw file, Python's CSV reader reads one row at a time. The reader requires exactly 49
values and matches each value to the feature name in the same position. Files are visited in the
order supplied by the caller, and rows stay in their original order. A complete raw file is never
held in memory.

The raw files have no ID column, so the reader adds a stable `flow_id` such as
`UNSW-NB15_1:1`. It contains only the raw filename and one-based row number. This is a bookkeeping
identifier for tracing a row; it is not invented network telemetry.

Named rows then pass to the existing UNSW adapter and streaming batch-quality layer. The reader
does not invent IP addresses, ports, timestamps, labels, or measurements, and it does not weaken
the canonical `NetworkFlow` checks. Structural errors identify the file and row number where
available, but never copy the complete raw row into the error.

The official raw files sometimes write a source or destination port in hexadecimal form, such as
`0xc0a8` for port 49320. The UNSW adapter recognizes only the strict `0x` hexadecimal form or the
existing decimal form, converts it to an integer, and still enforces the valid port range from 0
through 65535. This source-specific normalization is not enabled for other datasets.

Phase 0H performs only a bounded compatibility smoke check. It does not process the complete raw
dataset, write processed data, or train a model. Raw inputs and any generated reports remain
ignored by Git.
