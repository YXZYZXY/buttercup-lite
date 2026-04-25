#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/buttercup2/Project/buttercup-lite"
CONTROL_DIR="${ROOT}/runtime/campaign_control/source_10h"
PID_FILE="${CONTROL_DIR}/worker.pid"
TASK_FILE="${CONTROL_DIR}/task_id"
LOG_FILE="${CONTROL_DIR}/campaign.log"
PYTHON_BIN="/home/buttercup2/miniconda3/bin/python"
export PYTHONPATH="${ROOT}"
export DATA_ROOT="${ROOT}/data/tasks"

mkdir -p "${CONTROL_DIR}"

is_running() {
  [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null
}

create_task() {
  "${PYTHON_BIN}" - <<'PY'
from core.models.task import TaskSource, TaskSpec, AdapterType, TaskStatus
from core.state.task_state import TaskStateStore

store = TaskStateStore()
spec = TaskSpec(
    source=TaskSource(adapter_type=AdapterType.OSSFUZZ, uri="campaign://cjson_injected_source_10h"),
    metadata={
        "benchmark": "cjson_injected_source",
        "target_mode": "source",
        "base_task_id": "d15e7148-1f38-4536-9487-d6346e07afb6",
        "ground_truth_path": "/home/buttercup2/Project/buttercup-lite/benchmarks/cjson_injected/ground_truth.json",
        "campaign_duration_seconds": 36000,
        "FUZZ_MAX_TOTAL_TIME_SECONDS": 300,
    },
)
record = store.create_task(spec, status=TaskStatus.CAMPAIGN_QUEUED)
print(record.task_id)
PY
}

show_status() {
  local task_id=""
  [[ -f "${TASK_FILE}" ]] && task_id="$(cat "${TASK_FILE}")"
  echo "mode=source"
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "task_id=${task_id}"
  if is_running; then
    echo "worker_pid=$(cat "${PID_FILE}")"
    echo "worker_running=true"
  else
    echo "worker_running=false"
  fi
  if [[ -n "${task_id}" ]]; then
    "${PYTHON_BIN}" - <<PY
import json
from pathlib import Path
task_id = "${task_id}"
task_path = Path("${ROOT}/data/tasks") / task_id / "task.json"
if task_path.exists():
    payload = json.loads(task_path.read_text(encoding="utf-8"))
    runtime = payload.get("runtime", {})
    print(f"task_status={payload.get('status')}")
    print(f"campaign_started_at={runtime.get('campaign_started_at')}")
    print(f"campaign_deadline_at={runtime.get('campaign_deadline_at')}")
    print(f"campaign_heartbeat_at={runtime.get('campaign_heartbeat_at')}")
    print(f"campaign_last_round_finished_at={runtime.get('campaign_last_round_finished_at')}")
    print(f"campaign_iterations_total={runtime.get('campaign_iterations_total')}")
    print(f"campaign_manifest_path={runtime.get('campaign_manifest_path')}")
PY
  fi
}

case "${1:-start}" in
  start)
    if is_running; then
      echo "already running"
      show_status
      exit 0
    fi
    task_id="$(create_task)"
    echo "${task_id}" > "${TASK_FILE}"
    setsid env PYTHONPATH="${PYTHONPATH}" DATA_ROOT="${DATA_ROOT}" CAMPAIGN_TASK_ID="${task_id}" CAMPAIGN_POLL_SECONDS="60" \
      "${PYTHON_BIN}" -m apps.workers.campaign.main > "${LOG_FILE}" 2>&1 < /dev/null &
    echo $! > "${PID_FILE}"
    show_status
    ;;
  status|progress)
    show_status
    ;;
  stop)
    if is_running; then
      kill "$(cat "${PID_FILE}")"
      echo "stopped pid=$(cat "${PID_FILE}")"
    else
      echo "worker not running"
    fi
    ;;
  *)
    echo "usage: $0 {start|status|progress|stop}" >&2
    exit 1
    ;;
esac
