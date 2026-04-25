#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

API_PORT="${API_PORT:-8000}"
HOST_HOME="${HOST_HOME:-$(cd "${PROJECT_ROOT}/../.." && pwd)}"
SOURCE_URL="${SOURCE_URL:-https://github.com/libexpat/libexpat.git}"
SOURCE_REF="${SOURCE_REF:-master}"
FUZZ_TOOLING_URL="${FUZZ_TOOLING_URL:-file:///data/validation/oss-fuzz}"

curl -sS -X POST "http://127.0.0.1:${API_PORT}/tasks" \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": {
      \"adapter_type\": \"ossfuzz\",
      \"uri\": \"${SOURCE_URL}\",
      \"ref\": \"${SOURCE_REF}\"
    },
    \"metadata\": {
      \"project\": \"expat\",
      \"benchmark\": \"expat_source\",
      \"expected_harness\": \"xml_parse_fuzzer_ISO-8859-1\",
      \"challenge_repo_url\": \"${SOURCE_URL}\",
      \"challenge_branch\": \"${SOURCE_REF}\",
      \"fuzz_tooling_url\": \"${FUZZ_TOOLING_URL}\",
      \"fuzz_tooling_ref\": \"master\",
      \"fuzz_tooling_project_name\": \"expat\"
    }
  }"
