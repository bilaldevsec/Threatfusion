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

The automated TLS exchange verifies the browser listener, rendered HTML, and the CSRF-hardened
browser state transition workflow (`POST /v1/analyst/alerts/<id>/transitions`). No human-operated browser
was opened or tested for this milestone. Automated operator NSS profile provisioning (`threatfusion.operations.human_browser_provisioning`),
same-origin verification, and HMAC-SHA256 CSRF protection are implemented. Accessibility, operational recovery,
live telemetry, and long-term endurance remain open under TF-008 and TF-009. This path derives no relationship
key and makes no incident or cross-source claim.

## Bounded manual inspection launcher (2026-09-27)

Manual browser acceptance is **pending user observations**. The launcher reuses the
same producer and one registered row, then holds the already checked browser listener
open. It performs one frozen RF inference, no training/evaluation or experimental AE
scoring. Explanation availability is checked before opening the inspection window.

Prerequisites: the existing registered inputs/artifacts, OpenSSL, installed Firefox,
a graphical desktop, and permission to bind IPv4 loopback. No installation is needed.
Run in a desktop terminal:

```bash
cd /home/muhammad-bilal/projects/threatfusion-gemini
PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/launch_browser_demo.py --seconds 900
```

The inspection budget starts after producer and automated browser checks finish;
allowed values are 30–1800 seconds. The existing setup/producer operations retain their
own timeouts. The launcher chooses `/snap/bin/firefox` when installed, avoiding Ubuntu's
`/usr/bin/firefox` migration wrapper. It creates a mode-0700 runtime under ignored
`artifacts/reports/browser-manual-demo/`, accessible to Snap's home confinement, with
separate producer/human credentials, SQLite databases and a new Firefox profile.
The viewer PKCS#12 bundle is mode 0600, has an empty import password, and must never
be copied elsewhere. Only paths and public explanation evidence are printed, not keys.

Use only the newly opened Firefox window. Do not sign in, sync, import a normal
profile or make it the default browser. In `about:support`, confirm **Profile Directory**
exactly matches the printed `profile` path before importing certificates. Firefox is
started with an explicit profile and `--no-remote`; see Mozilla's
[command-line contract](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).

1. Open Settings → Privacy & Security → Certificates → **View Certificates**
   (the launcher opens `about:preferences#privacy`; searching settings for
   “certificates” also finds it).
2. In **Authorities**, click Import and select the printed `import_authority` PEM
   path. Enable trust for identifying websites in this temporary profile only.
   Do not import anything into system trust or your ordinary browser profile.
3. In **Your Certificates**, click Import and select the printed
   `import_personal_certificate` (`viewer.p12`). Leave the password blank if asked.
   This is a personal mTLS identity, not an authority; Mozilla distinguishes these
   [certificate-manager tabs](https://bugzilla.mozilla.org/show_bug.cgi?id=2024861).
4. Paste the printed `queue_url` into this window. Use `https://localhost:<port>/`
   exactly; the certificate is for `localhost`, not `127.0.0.1`. Select the temporary
   viewer certificate if prompted. Do not add a certificate exception or bypass a
   warning. A warning, rejected certificate, missing profile or unexpected page is
   a failed/pending demonstration observation, not a pass.
5. Expect an active queue with one Attack alert and state `new`. Click its truncated
   candidate-ID link. Confirm the full ID on the detail page:
   `alert_candidate_v1:4c785c6418ff70c92a635785f5954355b6222f324d1314565b624affe771a8f7`.
   The printed `detail_url` opens the same detail directly.
6. Expect RF model `network_random_forest_baseline_v1`, decision `Attack`, state
   `new` (v0), no transitions, and **Factual explanation (alert_explanation_v1)**,
   **Status: available**. The exact retained score appears in the printed
   `expected_explanation.summary` and page: “Stored frozen-RF score … meets the
   inclusive threshold 0.5, consistent with the stored Attack decision.” Verify
   that feature attribution, causal explanation and source details explicitly say
   unavailable. The score is uncalibrated. This is a known registered replay, not
   live traffic, causal attribution or a new accuracy result.
7. Record browser version, certificate/profile checks, queue/detail observations,
   explanation text/status and any error. Only user-supplied observations can establish
   a manual result; automated TLS checks do not do so.

Shutdown: press Ctrl+C in the launcher terminal, close the demo Firefox, or let the
budget expire. SIGTERM also unwinds cleanup. The listener stops accepting requests
and closes any incomplete connection. The launcher terminates/reaps its separate
browser process group (TERM, then KILL if needed), cancels its timer, closes producer
resources and removes the temporary runtime including imported trust/identity and
profile. It prints `stopped` with `manual_result=pending_user_observations` on normal
shutdown; this is a lifecycle result only. Confirm the printed profile directory no
longer exists and reloading the old URL fails. Existing normal browser windows must
remain unaffected. An empty ignored parent directory may remain.

SIGKILL, power loss or a browser process escaping its process group cannot guarantee
cleanup. If interrupted that way, inspect the exact printed runtime/process before
removing anything; never broadly delete profiles or kill unrelated Firefox processes.
Snap/desktop integration, certificate import and actual browser lifecycle are pending
manual verification. The single-request listener is not a concurrent browser service
or an endurance-tested daemon. TF-008 and TF-009 remain open.

### Failed Firefox trial and handshake repair (2026-09-27)

User observation: during a `--seconds 1800` run, the correct temporary Firefox
profile imported the demo CA and viewer identity, selected viewer at
`https://localhost:46087/`, and displayed “The connection has timed out”. This is
**failed/pending manual evidence**, not a pass. The port was no longer listening
when diagnosed and no runtime database remained. The exact chooser duration and
wire exchange from that attempt were not captured, so its precise cause cannot
be established retrospectively.

A concrete compatible defect was reproduced before repair: the browser reused the
analyst API's 3-second TLS handshake budget. A real TLS 1.3 MemoryBIO client held
its certificate/Finished flight for 3.3 seconds after receiving the server flight;
the listener closed with no HTTP response. The immediate-certificate control with
the same browser-style headers returned 200. Thus the reproduced failure precedes
HTTP parsing; the 1800-second launcher lifetime does not extend a TLS deadline.
No evidence established malformed Firefox framing or premature launcher shutdown
in the reported attempt. The control is representative HTTP headers, not a capture
of that Firefox request.

The browser now has a fixed **60-second total TLS handshake budget**, including
certificate selection. Select viewer within that budget; after exceeding it, a
fresh navigation is needed. It is intentionally not tied to the demo lifetime.
The analyst API remains at 3 seconds; the browser's subsequent HTTP read deadline
remains 5 seconds. Unauthenticated connections are still bounded, do not dispatch
views or claim completed audit events, and close/launcher expiry interrupts the
handshake. A single stalled connection can occupy this serial demo listener for
up to 60 seconds; concurrency/endurance remain unproven under TF-009.

Automated delayed-certificate, bounded-expiry and close-during-handshake tests
verify the repair, not a successful Firefox demonstration. **Stop for review
before another manual attempt.** No system trust, certificate validation, human
identity checks or request framing rules were relaxed.

### User-observed Firefox result and layout follow-up (2026-09-27)

The user reports that a subsequent run on port 33991 used viewer mTLS and showed
one Attack alert in `new`; selecting the queue link opened the full candidate detail
URL, where factual explanation was available with its limitations. Ctrl+C printed
`{"status":"stopped","manual_result":"pending_user_observations"}`. That
launcher message is fixed lifecycle output; the user-supplied browser observations
are the manual evidence. Read-only follow-up found no listener on port 33991 and
confirmed the reported temporary Firefox profile had been removed.

The screenshot also showed Candidate ID, Source Event ID and Created At text
colliding in the detail panel. The detail grid now lets tracks shrink with the
viewport and wraps long values inside their own cells. Automated markup/CSS and
browser-listener tests pass; **at that checkpoint the corrected layout had not yet
been visually checked** in Firefox at desktop and narrow widths. No additional
manual run was performed for this layout repair. Keep TF-008 and TF-009 open.

### Mobile viewport observation and responsive table repair (2026-09-27)

The user confirmed the detail overlap is fixed at desktop width, but a reloaded
390×844 Firefox Responsive Design viewport showed the entire desktop page scaled
down, with unreadable queue and detail text. This is a **failed mobile check**
at that checkpoint; the later owner observation below supersedes it. The page lacked
`<meta name="viewport" content="width=device-width, initial-scale=1">`, while
its seven-column queue and five-column history had enough intrinsic width to
make the page wider than a phone. The renderer now declares the device viewport
and contains both tables in labeled, keyboard-focusable horizontal scroll
regions. At narrow widths, the alert ID link is the first queue column; swipe
or focus/scroll the region to inspect the remaining columns. Full IDs and all
evidence remain in the detail panel. Desktop tables retain their layout. Automated
markup and TLS checks verify the contract, but do not establish readable Firefox
pixels. TF-008 and TF-009 remain open.

### Superseding owner Firefox screenshots (2026-09-27)

The owner reports a repaired desktop layout and a readable 390×844 Firefox
Responsive Design view. The queue alert link is visible; scrolling the queue
horizontally reveals the score, decision and state columns; the full detail IDs
and factual explanation are readable without overlap. This supersedes the
earlier failed mobile scaling check, retained above as historical evidence.
The screenshots verify those visual observations only. They do not establish
keyboard or screen-reader accessibility, endurance, or full product acceptance.

The latest report includes no final launcher output or exact temporary runtime
path. Cleanup for this latest run is unverified. The prior read-only check of
port 33991 and its temporary profile applies to that earlier run only. Continue
to require a defensible distinct-alert relationship key, operational browser
credential provisioning, and long-term endurance proofs; TF-008 and TF-009 remain open.
