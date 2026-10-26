# ThreatFusion Bugbot Rules
Flag blocking High-Severity bugs for:
1. Touching `/home/muhammad-bilal/projects/threatfusion`.
2. Importing advisory/gemini/chromadb in Stages 1-4 (Gate G9).
3. Altering frozen model SHA-256 digests or enabling OR-fusion in production.
4. Emitting `data-evidence-state="verified"` without verified cryptographic receipts.
5. Breaking `data-copy-hash` or 3-layer DOM parity.
