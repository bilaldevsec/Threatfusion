# Phase 0F: Streaming batch adaptation and data quality

Strict row validation is useful only when rejections are visible. A pipeline
that silently drops malformed records can produce a clean-looking training
table while changing class balance, host coverage, time coverage, or attack
representation. Phase 0F therefore counts every processed, accepted, and
rejected row, calculates the rejection rate, and preserves a bounded sample of
non-sensitive failure summaries. The summaries identify the one-based row
number, affected fields, and reason without copying the raw row or its values.
This makes source drift and systematic parsing failures measurable without
turning quality reports into another store of potentially sensitive data.

Adaptation is streaming: the input is an iterable, and each valid canonical
record is yielded as soon as its source row has been processed. Accepted records
are never accumulated by the batch layer. Only counters and the configured
maximum number of rejection examples remain in memory, so memory use does not
grow with dataset size. Callers must also consume rows through a streaming
reader and process or persist yielded records incrementally. Together, those
constraints protect the 16 GB development laptop from loading a full source
dataset or a second full canonical copy into memory.

Reports start with `completed=false` and remain incomplete while their output
iterator is being consumed. `completed` becomes true only when the input
iterable is exhausted normally, including for empty input. It remains false if
the caller stops consuming early or an unexpected exception propagates.
Incomplete reports cannot be written, preventing partial counts from being
mistaken for final batch results.

Expected source-contract and Pydantic schema failures are counted as data
quality rejections. Unexpected exceptions are allowed to propagate because
treating programming defects as bad data would hide broken adapters. JSON
rejection reasons are restricted to the known static validation messages.
Dynamic bounds failures are reduced to fixed categories, and unknown or custom
reasons are recorded as `source row validation failed`; exception strings and
raw row values are never copied into reports. JSON
reports are written only to a path selected by the caller, with missing parent
directories created as needed. Phase 0F does not add dataset downloads, CSV
bulk loading, model training, or dataset pooling.
