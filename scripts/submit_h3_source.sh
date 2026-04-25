#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

API_PORT="${API_PORT:-8000}"
HOST_HOME="${HOST_HOME:-$(cd "${PROJECT_ROOT}/../.." && pwd)}"
SOURCE_URL="${SOURCE_URL:-https://github.com/uber/h3.git}"
FUZZ_TOOLING_URL="${FUZZ_TOOLING_URL:-file:///data/validation/oss-fuzz}"

curl -sS -X POST "http://127.0.0.1:${API_PORT}/tasks" \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": {
      \"adapter_type\": \"ossfuzz\",
      \"uri\": \"${SOURCE_URL}\",
      \"ref\": null
    },
    \"metadata\": {
      \"project\": \"h3\",
      \"benchmark\": \"h3_source\",
      \"expected_harness\": \"fuzzerCellArea\",
      \"challenge_repo_url\": \"${SOURCE_URL}\",
      \"challenge_branch\": null,
      \"fuzz_tooling_url\": \"${FUZZ_TOOLING_URL}\",
      \"fuzz_tooling_ref\": \"master\",
      \"fuzz_tooling_project_name\": \"h3\"
    }
  }"
