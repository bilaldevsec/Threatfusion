#!/usr/bin/env bash
# scripts/prepare_threatfusion_oss.sh
# Reversible OpenAI Codex for OSS preparation & FYP-II baseline snapshot engine.
#
# Usage:
#   ./scripts/prepare_threatfusion_oss.sh [--snapshot]
#   ./scripts/prepare_threatfusion_oss.sh --revert
#
# Constitutional Rules:
# - Strictly preserves academic FYP-II baseline and provides 1-command complete revert.
# - Never touches backend/, frontend/, artifacts/, docker/, or tests/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="${REPO_ROOT}/.git/threatfusion_fyp_baseline.state"
REMOTE_REPO="bilaldevsec/Threatfusion"

cd "${REPO_ROOT}"

action="${1:---snapshot}"

case "${action}" in
  --snapshot|default)
    echo "================================================================================"
    echo "  THREATFUSION FYP-II BASELINE SNAPSHOT: CREATING STATE"
    echo "================================================================================"
    
    BASELINE_BRANCH="gemini/product-20260924"
    BASELINE_COMMIT="$(git rev-parse "${BASELINE_BRANCH}")"
    MAIN_COMMIT="$(git rev-parse main)"
    DEFAULT_BRANCH="$(gh repo view "${REMOTE_REPO}" --json defaultBranchRef -q .defaultBranchRef.name)"
    VISIBILITY="$(gh repo view "${REMOTE_REPO}" --json visibility -q .visibility)"
    TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    
    cat > "${STATE_FILE}" <<EOF
# ThreatFusion FYP-II Baseline State Snapshot
# Generated: ${TIMESTAMP}
BASELINE_BRANCH="${BASELINE_BRANCH}"
BASELINE_COMMIT="${BASELINE_COMMIT}"
MAIN_COMMIT="${MAIN_COMMIT}"
DEFAULT_BRANCH="${DEFAULT_BRANCH}"
VISIBILITY="${VISIBILITY}"
SNAPSHOT_TIMESTAMP="${TIMESTAMP}"
EOF

    echo "[PASS] Snapshot written to ${STATE_FILE}:"
    cat "${STATE_FILE}"
    echo "================================================================================"
    ;;

  --revert)
    echo "================================================================================"
    echo "  THREATFUSION FYP-II BASELINE REVERT: RESTORING ORIGINAL STATE"
    echo "================================================================================"

    if [[ ! -f "${STATE_FILE}" ]]; then
      echo "[ERROR] State file ${STATE_FILE} does not exist. Cannot revert safely." >&2
      exit 1
    fi

    # Load baseline state variables
    # shellcheck source=/dev/null
    source "${STATE_FILE}"

    echo "Loaded baseline state:"
    echo "  BASELINE_BRANCH : ${BASELINE_BRANCH}"
    echo "  BASELINE_COMMIT : ${BASELINE_COMMIT}"
    echo "  MAIN_COMMIT     : ${MAIN_COMMIT}"
    echo "  DEFAULT_BRANCH  : ${DEFAULT_BRANCH}"
    echo "  VISIBILITY      : ${VISIBILITY}"
    echo ""

    # 1. Delete GitHub release v1.1.0 if present
    echo "[-] Step 1: Removing GitHub Release v1.1.0..."
    gh release delete v1.1.0 --repo "${REMOTE_REPO}" --yes 2>/dev/null || true

    # 2. Delete remote and local git tag v1.1.0
    echo "[-] Step 2: Removing git tag v1.1.0 (remote & local)..."
    git push origin --delete v1.1.0 2>/dev/null || true
    git tag -d v1.1.0 2>/dev/null || true

    # 3. Restore GitHub default branch
    echo "[-] Step 3: Restoring GitHub default branch to ${DEFAULT_BRANCH}..."
    gh repo edit "${REMOTE_REPO}" --default-branch "${DEFAULT_BRANCH}"

    # 4. Force-restore main branch to original MAIN_COMMIT
    echo "[-] Step 4: Restoring local and remote 'main' to ${MAIN_COMMIT}..."
    git branch -f main "${MAIN_COMMIT}"
    git push origin "${MAIN_COMMIT}:main" --force

    # 5. Restore baseline branch and reset working tree
    echo "[-] Step 5: Checking out ${BASELINE_BRANCH} and resetting to ${BASELINE_COMMIT}..."
    git checkout "${BASELINE_BRANCH}"
    git reset --hard "${BASELINE_COMMIT}"
    git push origin "${BASELINE_BRANCH}" --force

    # 6. Restore repository visibility if it was PRIVATE
    echo "[-] Step 6: Verifying / restoring visibility to ${VISIBILITY}..."
    if [[ "${VISIBILITY}" == "PRIVATE" ]]; then
      gh repo edit "${REMOTE_REPO}" --visibility private
    fi

    # 7. Run boundary preflight and pytest verification
    echo "[-] Step 7: Verifying boundary preflight (B0-B6)..."
    "${REPO_ROOT}/threatfusion-venv/bin/python3" "${REPO_ROOT}/scripts/boundary_preflight.py"

    echo "[-] Step 8: Running full pytest regression suite..."
    "${REPO_ROOT}/threatfusion-venv/bin/pytest" -q -o cache_dir=/tmp/.pytest_cache

    echo "================================================================================"
    echo "  [SUCCESS] THREATFUSION FYP-II REVERT COMPLETED SUCCESSFULLY"
    echo "================================================================================"
    ;;

  *)
    echo "Usage: $0 [--snapshot | --revert]" >&2
    exit 1
    ;;
esac
