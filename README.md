# buttercup-lite

`buttercup-lite` is a lightweight orchestration layer for Buttercup-style source and pure-binary tasks. It currently supports:

- URL or local-directory source ingress
- optional URL or local-directory fuzz-tooling ingress
- source, pure-binary, and protocol adapter planning
- import-assisted and fresh/source-localized planning
- source indexing, build registration, seed generation, fuzz/trace/repro, and binary analysis/execution lanes

## Quick start

```bash
cd "${PROJECT_ROOT:-$(pwd)}"
HOST_HOME="${HOST_HOME:-$HOME}" docker compose up -d --build \
  redis api-server downloader-worker scheduler-worker program-model-worker builder-worker
```

## Task ingress contract

`POST /tasks` accepts:

- `source.uri`
  - local directory path, or
  - supported git URL such as `https://...`, `ssh://...`, or `file://...`
- `source.ref`
  - optional git branch/tag/commit-ish
- `metadata.fuzz_tooling_url`
  - optional local path or git URL
- `metadata.fuzz_tooling_ref`
  - optional git ref for fuzz tooling
- `metadata.fuzz_tooling_project_name`
  - optional project name used to localize `projects/<name>` inside oss-fuzz style repos

Invalid local paths or unsupported URIs now fail in downloader and do not advance to `READY`.

## URL-style source task example

```bash
HOST_HOME="${HOST_HOME:-$HOME}"
curl -X POST http://127.0.0.1:8000/tasks \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": {
      \"adapter_type\": \"ossfuzz\",
      \"uri\": \"file://${HOST_HOME}/Project/benchmarks/cjson-injected\",
      \"ref\": \"fix/buttercup-build\"
    },
    \"metadata\": {
      \"project\": \"cjson\",
      \"benchmark\": \"cjson_injected\",
      \"fuzz_tooling_url\": \"file://${HOST_HOME}/Project/oss-fuzz/oss-fuzz\",
      \"fuzz_tooling_ref\": \"main\",
      \"fuzz_tooling_project_name\": \"cjson\"
    }
  }"
```

## Inspect a task

```bash
TASK_ID=<task_id>
curl "http://127.0.0.1:8000/tasks/${TASK_ID}"
jq . "data/tasks/${TASK_ID}/task.json"
jq . "data/tasks/${TASK_ID}/runtime/execution_plan.json"
jq . "data/tasks/${TASK_ID}/runtime/import_manifest.json"
docker compose logs --tail=100 downloader-worker scheduler-worker builder-worker
```
