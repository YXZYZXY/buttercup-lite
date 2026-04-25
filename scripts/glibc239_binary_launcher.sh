#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_GLIBC_DIR="${SCRIPT_DIR%/scripts}/runtime/glibc239/rootfs/usr/lib/x86_64-linux-gnu"
GLIBC_DIR="${GLIBC_RUNTIME_ROOT:-${DEFAULT_GLIBC_DIR}}"
LOADER="${GLIBC_DIR}/ld-linux-x86-64.so.2"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary_path> [args...]" >&2
  exit 2
fi

if [[ ! -x "${LOADER}" ]]; then
  echo "missing glibc loader at ${LOADER}" >&2
  exit 3
fi

BINARY_PATH="$1"
shift

exec "${LOADER}" --library-path "${GLIBC_DIR}" "${BINARY_PATH}" "$@"
