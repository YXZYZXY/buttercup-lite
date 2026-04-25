#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/home/buttercup2/miniconda3/bin/python}"
CMD="${1:-status}"
shift || true

cd "${REPO_ROOT}"
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"
export DATA_ROOT="${REPO_ROOT}/data/tasks"
exec "${PYTHON_BIN}" scripts/start_medium_validation.py "${CMD}" --adapter source "$@"
