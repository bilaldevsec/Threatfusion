# Dataset manifests

Dataset manifests provide a reproducible record of the exact input files intended for a
ThreatFusion dataset. Each YAML manifest records the dataset name and version, source and
licensing information, notes, and a list of files. Each file entry records its project-relative
path, role, optional row count, and SHA-256 fingerprint.

Raw dataset files must never be committed to Git. They may be large, may have redistribution or
licensing restrictions, and do not belong in source-control history. Manifests preserve the
metadata and fingerprints needed to identify those local files without distributing the data.

Integrity verification checks that every declared local file exists and matches its recorded
SHA-256 digest. Model training will later refuse to use inputs that have not passed this
verification.
