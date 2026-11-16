#!/bin/sh
# Lightweight runtime for threatfusion_misp_connector and threatfusion_callback.
# python:3.11-slim has no third-party packages. Install pydantic (and the
# wheels it pulls) once into a shared directory, then start the contract server.
# The same wheels exist for amd64 and arm64.
set -eu

deps_dir="${THREATFUSION_PYDEPS:-/opt/tf-pydeps}"
mkdir -p "$deps_dir"
export PYTHONPATH="${deps_dir}${PYTHONPATH:+:$PYTHONPATH}"

python_has_pydantic() {
  python -c 'import pydantic' >/dev/null 2>&1
}

if ! python_has_pydantic; then
  lock="${deps_dir}/.install.lock"
  waited=0
  while ! mkdir "$lock" 2>/dev/null; do
    if python_has_pydantic; then
      break
    fi
    waited=$((waited + 1))
    if [ "$waited" -ge 180 ]; then
      echo "Timed out waiting for the shared pydantic install." >&2
      exit 1
    fi
    sleep 1
  done
  if ! python_has_pydantic; then
    python -m pip install --disable-pip-version-check --no-cache-dir \
      --target "$deps_dir" 'pydantic>=2,<3'
  fi
  if [ -d "$lock" ]; then
    rmdir "$lock" 2>/dev/null || true
  fi
fi

if ! python_has_pydantic; then
  echo "pydantic is not importable after installation." >&2
  exit 1
fi

exec "$@"
