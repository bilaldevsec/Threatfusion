# Contributing to ThreatFusion

Thank you for your interest in contributing to ThreatFusion! ThreatFusion is a deterministic-first AI Security Operations Center (SOC) platform designed to eliminate alert fatigue while maintaining strict cryptographic boundaries.

## Development Environment Setup

ThreatFusion relies on Python 3.11+ and isolated virtual environments.

### 1. Prerequisites
- Python 3.11 (`uv python install 3.11`)
- Git 2.30+
- Linux (Ubuntu 24.04 LTS recommended)

### 2. Environment Initialization
```bash
# Clone the repository
git clone https://github.com/bilaldevsec/Threatfusion.git
cd Threatfusion

# Create and sync the dedicated virtual environment
uv venv threatfusion-venv --python 3.11
UV_PROJECT_ENVIRONMENT=threatfusion-venv uv sync --locked --dev
```

## Mandatory Verification Gates

Before submitting any Pull Request, your branch must satisfy all deterministic architectural gates:

### 1. Boundary Preflight Isolation (B0–B6)
All workspace boundaries, symlink escapes, virtualenv isolation, and import path guards must pass with a `GO` decision:
```bash
threatfusion-venv/bin/python3 scripts/boundary_preflight.py
```
Expected output:
```text
TOTAL FINDINGS: 0
BOUNDARY DECISION VERDICT: GO
```

### 2. Full Test Suite Regression
The test suite baseline must execute cleanly without regressions:
```bash
threatfusion-venv/bin/pytest -q -o cache_dir=/tmp/.pytest_cache
```
Expected baseline: `1,726+ tests collected, 0 failed; 1–11 environment-gated skips depending on local/Docker fixtures`.

## Architectural Guidelines

1. **Deterministic Alert Authority:**
   - The frozen Random Forest (`artifacts/models/frozen_random_forest/rf_model.joblib`) remains the sole alert authority.
   - `production_fusion_enabled` MUST remain `False`. Secondary autoencoder or DNN models are strictly advisory or queue-ranking components.
2. **Gate G9 Decoupling:**
   - Advisory components (`threatfusion.advisory.*`) and the MCP server must NEVER write alert decisions.
3. **SOAR Containment Safety:**
   - Any containment action requires an approved HMAC-SHA256 hash-chained ledger entry and a verified callback. Containment is reversible with verified rollback.
4. **Secret Sanitization:**
   - Never commit API keys, cloud tokens, `.env` files, or production credentials. Use `.env.example` placeholders.

## Pull Request Process

1. Fork the repository and create a descriptive feature branch from `main`.
2. Follow standard conventional commits (e.g., `feat(soc):`, `fix(api):`, `docs:`).
3. Ensure both `boundary_preflight.py` and `pytest` pass with 100% success.
4. Submit the PR with a clear summary of changes, motivation, and test verification output.
