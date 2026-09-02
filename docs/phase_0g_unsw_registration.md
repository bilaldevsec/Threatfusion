# Phase 0G: UNSW-NB15 registration and preflight

This phase registers the two local official UNSW-NB15 train and test CSV files without putting
their raw contents in Git.

The dataset manifest is a receipt proving the exact dataset files used. It records each file's
role, local path, row count, and fingerprint, together with the official source and license note.
The tracked receipt is `data/manifests/unsw_nb15.yaml`; the large raw files remain ignored.

A SHA-256 checksum is a fingerprint of a file's bytes. If a download is corrupted, replaced, or
edited, its checksum changes. ThreatFusion reuses its existing checksum and manifest verification
code to detect that difference.

Preflight is a small compatibility check before expensive processing. It reads the CSV header,
checks at most 10 sample row shapes, and counts rows as a stream, so the whole file is never held
in memory. It reports the headers, required adapter fields or aliases that are missing, the row
count, and whether the file is ready for streaming adaptation.

The official pre-split CSV headers do not contain the IP address, port, or timestamp fields that
the current UNSW adapter requires. Preflight therefore reports these files as not ready for that
adapter. This is a useful compatibility result, not a checksum failure.

This phase does not adapt the full dataset, create processed data, or train a model.
