#!/bin/sh
# Offline fail-closed runtime entrypoint for threatfusion_misp_connector and threatfusion_callback.
# Expects pydantic pre-installed (see docker/Dockerfile.contract) or an explicit offline wheelhouse.
set -eu

deps_dir="${THREATFUSION_PYDEPS:-/opt/tf-pydeps}"
if [ -d "$deps_dir" ]; then
  export PYTHONPATH="${deps_dir}${PYTHONPATH:+:$PYTHONPATH}"
fi

python_has_pydantic() {
  python -c 'import pydantic' >/dev/null 2>&1
}

if ! python_has_pydantic; then
  wheelhouse="${THREATFUSION_WHEELHOUSE:-}"
  if [ -n "$wheelhouse" ] && [ -d "$wheelhouse" ]; then
    mkdir -p "$deps_dir"
    export PYTHONPATH="${deps_dir}${PYTHONPATH:+:$PYTHONPATH}"
    python -m pip install --no-index --find-links "$wheelhouse" \
      --disable-pip-version-check --no-cache-dir --target "$deps_dir" pydantic
  else
    echo "pydantic is not pre-installed in the contract runtime image and THREATFUSION_WHEELHOUSE is not set." >&2
    exit 1
  fi
fi

if ! python_has_pydantic; then
  echo "pydantic is not importable in the contract runtime." >&2
  exit 1
fi

exec "$@"
