COMPOSE ?= docker compose

.PHONY: up down logs logs-program-model logs-builder logs-seed logs-fuzzer logs-tracer logs-reproducer logs-binary logs-binary-seed logs-binary-execution logs-protocol logs-patch submit test

up:
	$(COMPOSE) up -d redis api-server downloader-worker scheduler-worker binary-analysis-worker binary-seed-worker binary-execution-worker protocol-execution-worker patch-worker program-model-worker builder-worker seed-worker fuzzer-worker tracer-worker reproducer-worker

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f api-server downloader-worker scheduler-worker binary-analysis-worker binary-seed-worker binary-execution-worker protocol-execution-worker patch-worker program-model-worker builder-worker seed-worker fuzzer-worker tracer-worker reproducer-worker

logs-program-model:
	$(COMPOSE) logs -f program-model-worker

logs-builder:
	$(COMPOSE) logs -f builder-worker

logs-binary:
	$(COMPOSE) logs -f binary-analysis-worker

logs-binary-seed:
	$(COMPOSE) logs -f binary-seed-worker

logs-binary-execution:
	$(COMPOSE) logs -f binary-execution-worker

logs-protocol:
	$(COMPOSE) logs -f protocol-execution-worker

logs-patch:
	$(COMPOSE) logs -f patch-worker

logs-seed:
	$(COMPOSE) logs -f seed-worker

logs-fuzzer:
	$(COMPOSE) logs -f fuzzer-worker

logs-tracer:
	$(COMPOSE) logs -f tracer-worker

logs-reproducer:
	$(COMPOSE) logs -f reproducer-worker

submit:
	API_PORT=$${API_PORT:-8000}; \
	HOST_HOME=$${HOST_HOME:-$$HOME}; \
	SOURCE_URL=$${SOURCE_URL:-file://$$HOST_HOME/Project/benchmarks/cjson-injected}; \
	FUZZ_TOOLING_URL=$${FUZZ_TOOLING_URL:-file://$$HOST_HOME/Project/oss-fuzz/oss-fuzz}; \
	curl -X POST http://127.0.0.1:$$API_PORT/tasks \
		-H 'Content-Type: application/json' \
		-d "$$(cat <<EOF
{
  \"source\": {
    \"adapter_type\": \"ossfuzz\",
    \"uri\": \"$$SOURCE_URL\",
    \"ref\": \"fix/buttercup-build\"
  },
  \"metadata\": {
    \"project\": \"cjson\",
    \"benchmark\": \"cjson_injected\",
    \"duration_seconds\": 180,
    \"fuzz_tooling_url\": \"$$FUZZ_TOOLING_URL\",
    \"fuzz_tooling_ref\": \"main\",
    \"fuzz_tooling_project_name\": \"cjson\"
  }
}
EOF
)"

test:
	$(COMPOSE) run --rm api-server python -m unittest discover -s tests -p 'test_*.py'
