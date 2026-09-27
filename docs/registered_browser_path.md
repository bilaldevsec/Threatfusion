# One registered alert to the read-only browser boundary

## Acceptance criteria and scope

This bounded TF-008 milestone uses one deliberately selected, already registered UNSW-NB15 input:
member SHA-256 `7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511`,
one-based row 21. It is recorded replay, not live telemetry or an accuracy sample. The frozen Random
Forest remains the sole product inference model; the experimental v2 autoencoder is neither scored nor
fused by this runner. Previously inspected February UNSW and CIC outcomes remain development-informing.

The local path passes only when all of these conditions hold:

1. A single registered reference traverses the existing producer TLS listener, admission, replay
   journal, terminating inference worker, and Attack-only alert repository, returning HTTP 200 and one
   `created` RF Attack disposition.
2. Reopening the alert SQLite repository finds exactly one durable candidate. Its candidate ID, RF
   decision, score, and approved artifact identity agree with the producer response.
3. The existing analyst repository and view model return the same candidate ID and decision with
   implicit analyst state `new`, version 0, and no transition history.
4. A separate ephemeral human CA and viewer certificate authenticate to the read-only browser
   listener over real loopback TLS 1.3. The queue returns HTTP 200 with a selectable full-ID link;
   the detail route returns HTTP 200 and visibly renders that candidate ID, decision, and state.
5. A clearly injected view-model failure makes the authenticated queue return a sanitized HTTP 503
   `Unavailable` page, without the candidate ID. Browser audit records `internal_failure`, and the
   persisted analyst detail remains unchanged. This tests failure presentation, not recovery from a
   real SQLite outage.

## Reproduce locally

From the Gemini repository root, with `openssl` available, the registered UNSW manifest/member and
unchanged approved preprocessing/RF artifacts at their configured ignored paths, and IPv4 loopback
binding allowed:

```bash
PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/run_registered_browser_path.py
```

The runner reuses producer request, credential, service, and exchange helpers from
`scripts/run_fyp_progress_demo.py`; it does not execute that script's two-row demonstration or its
autoencoder stage. It creates separate one-use producer and human credentials and SQLite databases in
one mode-0700 temporary runtime, checks the browser over an automated TLS client, closes both
listeners, and removes the runtime. Successful stdout is one sanitized JSON object with the source
and alert IDs, model decision, state, and HTTP statuses. Failure stdout contains a fixed sanitized
reason and exits nonzero. No database, key, raw row, prediction matrix, or HTML report is retained.

The automated TLS exchange verifies the browser listener and rendered HTML. No human-operated browser
was opened or tested. Browser trust-store enrollment, certificate selection, accessibility, future
write authentication/CSRF design, full explanation, operational recovery, and endurance remain open
under TF-008 and TF-009. This path derives no relationship key and makes no incident or cross-source
claim.
