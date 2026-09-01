# Phase 0E: Strict source-row validation

Phase 0E makes dataset ingestion fail closed for fields required by the current
UNSW-NB15, CSE-CIC-IDS2018, and Mordor adapters.

Fail-open validation lets a malformed row continue by inventing a usable-looking
value, such as zero for a broken count, `0.0.0.0` for a missing address,
`unknown` for an identifier, or the current time for an invalid timestamp. This
keeps a pipeline running, but erases the distinction between observed data and
adapter-generated fallback data. Fail-closed validation instead rejects the row
with the source, field or alias set, and reason in the error. Optional source
fields remain optional; in particular, a valid normal UNSW-NB15 row need not
have `attack_cat`. A non-empty source protocol outside TCP, UDP, and ICMP is
valid input and is retained through canonicalization as protocol `other`; it is
not rejected merely because the common schema has no more-specific category.

For ML/DL training, strict validation prevents fabricated values from becoming
features, labels, identities, or temporal ordering signals. It blocks silent
class-label corruption, artificial clusters around zero/default values,
incorrect flow rates and packet-size statistics, false host correlations,
timestamp leakage or reordering caused by ingestion time, and misleading sample
counts. Rejected rows can be measured and investigated rather than silently
changing the learned distribution. This protects input integrity; it does not
by itself prove that a dataset is representative, unbiased, correctly labeled,
or suitable for a particular model.

Phase 0D established fixture-level parity for the canonical features shared by
the two network adapters. That comparison does **not** justify pooling raw
UNSW-NB15 and CIC rows into one multiclass training dataset. Their raw schemas,
capture environments, collection periods, traffic distributions, attack
taxonomies, and label meanings differ. A combined multiclass dataset would need
an explicit ontology and label mapping, feature and unit harmonization,
provenance retention, duplicate/leakage controls, dataset-aware splitting, and
distribution-shift evaluation. Phase 0E only enforces each adapter's source-row
contract before canonicalization.
