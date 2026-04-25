#!/usr/bin/env bash
set -euo pipefail

API_PORT="${API_PORT:-8000}"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
HOST_HOME="${HOST_HOME:-$HOME}"
SOURCE_TASK_ID="${SOURCE_TASK_ID:-d15e7148-1f38-4536-9487-d6346e07afb6}"
BINARY_PATH="${BINARY_PATH:-${PROJECT_ROOT}/data/tasks/${SOURCE_TASK_ID}/build/out/cjson_read_fuzzer}"
ANALYSIS_PATH="${ANALYSIS_PATH:-${PROJECT_ROOT}/data/tasks/cabab73c-7ac5-49c9-b6d6-9e16a6c627a9/binary}"

curl -sS -X POST "http://127.0.0.1:${API_PORT}/tasks" \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": {
      \"adapter_type\": \"binary\",
      \"uri\": \"${BINARY_PATH}\"
    },
    \"execution_mode\": \"hybrid\",
    \"metadata\": {
      \"benchmark\": \"binary_imported_cjson_fuzzer\",
      \"binary_target_name\": \"cjson_read_fuzzer\",
      \"existing_binary_path\": \"${BINARY_PATH}\",
      \"existing_binary_analysis_path\": \"${ANALYSIS_PATH}\",
      \"existing_src_path\": \"${HOST_HOME}/Project/benchmarks/cjson-injected\",
      \"existing_seed_path\": \"${PROJECT_ROOT}/data/tasks/${SOURCE_TASK_ID}/seed/generated\",
      \"existing_corpus_path\": \"${PROJECT_ROOT}/data/tasks/${SOURCE_TASK_ID}/corpus/active\",
      \"existing_crashes_path\": \"${PROJECT_ROOT}/data/tasks/${SOURCE_TASK_ID}/crashes/raw\",
      \"existing_harness_dir\": \"${HOST_HOME}/Project/benchmarks/cjson-injected/fuzzing\",
      \"existing_dict_path\": \"${HOST_HOME}/Project/benchmarks/cjson-injected/fuzzing/json.dict\",
      \"existing_options_path\": \"${PROJECT_ROOT}/data/tasks/${SOURCE_TASK_ID}/build/out/cjson_read_fuzzer.options\"
    }
  }"
