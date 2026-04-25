#!/usr/bin/env bash
set -euo pipefail

API_PORT="${API_PORT:-8000}"
HOST_HOME="${HOST_HOME:-$HOME}"
SOURCE_URL="${SOURCE_URL:-file://${HOST_HOME}/Project/benchmarks/cjson-injected}"
FUZZ_TOOLING_URL="${FUZZ_TOOLING_URL:-file://${HOST_HOME}/Project/oss-fuzz/oss-fuzz}"

curl -sS -X POST "http://127.0.0.1:${API_PORT}/tasks" \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": {
      \"adapter_type\": \"ossfuzz\",
      \"uri\": \"${SOURCE_URL}\",
      \"ref\": \"fix/buttercup-build\"
    },
    \"metadata\": {
      \"project\": \"cjson\",
      \"benchmark\": \"cjson_injected\",
      \"challenge_repo_url\": \"https://github.com/baiyujun/cjson.git\",
      \"challenge_branch\": \"fix/buttercup-build\",
      \"fuzz_tooling_url\": \"${FUZZ_TOOLING_URL}\",
      \"fuzz_tooling_ref\": \"main\",
      \"fuzz_tooling_project_name\": \"cjson\"
    }
  }"
