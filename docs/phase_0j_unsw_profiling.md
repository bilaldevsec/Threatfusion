# Phase 0J: Full UNSW-NB15 streaming profile

Phase 0J describes the records that pass ThreatFusion's strict UNSW adapter. The profiler reads
the four official raw files in order using the feature-name mapping, adapts one row at a time, and
immediately reduces each accepted flow into counts and running ranges. It never builds a list of
flows, creates a processed dataset, makes a training split, or trains a model.

Run it from the repository root:

```bash
python scripts/profile_unsw_raw.py
```

The ignored report is written to
`artifacts/reports/unsw_nb15/unsw_nb15_profile.json`. It contains counters, numeric endpoints,
timestamps, sanitized rejection summaries, and at most 20 label-inconsistency pointers. It does
not contain IP addresses or complete raw rows.

## What the full profile found

The profiler read 2,540,047 rows. The existing strict adapter accepted 2,540,037 and rejected 10,
matching Phase 0I. Of the accepted flows, 2,218,754 are canonically labelled `Normal` and 321,283
are labelled `Attack`. The raw numeric labels agree exactly: the same counts appear for `0` and
`1`. Every normal row has a blank optional attack category, and every attack row has a category,
so neither label-inconsistency rule found a mismatch.

Attack-category counts are:

| Category | Rows |
|---|---:|
| Analysis | 2,677 |
| Backdoor | 1,795 |
| Backdoors | 534 |
| DoS | 16,353 |
| Exploits | 44,525 |
| Fuzzers | 24,246 |
| Generic | 215,481 |
| Reconnaissance | 13,987 |
| Shellcode | 1,511 |
| Worms | 174 |

`Backdoor` and `Backdoors` remain separate because both spellings occur in the source data; the
profiler reports categories and does not rewrite them. The blank optional attack-category count is
2,218,754.

Canonical protocol counts are 1,495,074 TCP, 990,435 UDP, 516 ICMP, and 54,012 other. Service
counts are `-` 1,246,387; DNS 781,668; HTTP 206,273; FTP-data 125,783; SMTP 81,645; FTP 49,090;
SSH 47,160; POP3 1,533; DHCP 172; SSL 142; SNMP 113; RADIUS 40; and IRC 31. A service value of `-`
is counted as the source category rather than guessed or coerced.

Connection-state counts are FIN 1,478,689; CON 560,588; INT 490,469; REQ 9,043; RST 528; ECO
337; CLO 161; URH 108; ACC 43; PAR 28; ECR 8; TST 8; MAS 7; URN 7; `no` 7; and TXD 6. These are
dataset-specific profile values, not additions to the common feature contract.

## Numeric and time coverage

The ranges below describe accepted canonical flows. Duration is therefore in milliseconds, and
source/destination correspond to the canonical forward/backward directions.

| Value | Minimum | Maximum |
|---|---:|---:|
| Duration (ms) | 0 | 8,786,637.695 |
| Source bytes | 0 | 14,355,774 |
| Destination bytes | 0 | 14,657,531 |
| Source packets | 0 | 10,646 |
| Destination packets | 0 | 11,018 |
| Source port | 0 | 65,535 |
| Destination port | 0 | 65,535 |

The earliest valid flow start is `2015-01-22T11:49:37+00:00`; the latest is
`2015-02-18T12:21:08+00:00`. These endpoints describe source timestamps and do not imply when the
files were downloaded or validated.
