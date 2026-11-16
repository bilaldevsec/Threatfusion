# Security Policy: ThreatFusion

## Supported Versions

ThreatFusion enforces cryptographic verification, boundary preflight isolation, and strict role separation for security operations. The following versions receive active security updates:

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `1.1.x` | :white_check_mark: | Active release track with MCP server & Telemetry Shield |
| `< 1.1.0` | :x: | Legacy development snapshots |

## Reporting a Vulnerability

The ThreatFusion team takes security and vulnerability reports seriously. If you discover a security vulnerability in ThreatFusion, please disclose it responsibly.

### Contact Information
- **Security Contact:** `bilaljvd2000@gmail.com`
- **Subject Line:** `[Vulnerability Report] ThreatFusion - <Component>`

### Response SLA
- **Initial Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Status Update:** Within **5 business days** with reproduction status and severity classification.
- **Remediation & Advisory:** Security patches will be issued and credited upon verification.

## Scope

### In Scope
- Core API endpoints (`/api/v1/live/*`, contract servers).
- Model Context Protocol (MCP) server (`scripts/threatfusion_mcp_server.py`) and tool boundaries.
- Telemetry Shield, evidence fencing, and SimHash burst compressors (`threatfusion.advisory.telemetry_shield`).
- SOAR HMAC-SHA256 ledger integrity and containment authorization mechanisms.
- Boundary preflight checks (`B0` through `B6`) and Gate `G9` decoupling.

### Out of Scope
- Denial of service attacks against local development instances.
- Vulnerabilities requiring root/physical access to the host machine.
- Theoretical attacks without actionable proof of concept.

## Safe Harbor Statement

We consider security research conducted under this policy to be authorized. We will not pursue civil or criminal action against researchers who:
1. Make a good faith effort to avoid privacy violations, data destruction, and service interruptions.
2. Provide a reasonable time window for remediation before public disclosure.
3. Keep details of vulnerabilities confidential until a fix is published.
