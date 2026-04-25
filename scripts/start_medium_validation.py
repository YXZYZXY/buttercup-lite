from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from core.models.task import ExecutionMode, TaskSource, TaskSpec, TaskStatus
from core.state.task_state import TaskStateStore
from core.storage.layout import campaign_checkpoint_path, campaign_manifest_path, task_json_path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "runtime" / "medium_validation"
GROUND_TRUTH_PATH = str(REPO_ROOT / "benchmarks" / "cjson_injected" / "ground_truth.json")
SOURCE_BASE_TASK_ID = "d15e7148-1f38-4536-9487-d6346e07afb6"
PURE_BINARY_BASE_TASK_ID = "ee48d355-ce4c-4417-87a4-81fb415c4fd2"


def _label_suffix(label: str | None) -> str:
    return str(label or "2h").strip().replace("/", "_")


def _control_path(adapter: str, label: str | None) -> Path:
    return CONTROL_ROOT / f"{adapter}_{_label_suffix(label)}.json"


def _log_path(adapter: str, label: str | None) -> Path:
    return CONTROL_ROOT / f"{adapter}_{_label_suffix(label)}.log"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _default_metadata(adapter: str, duration_seconds: int, round_seconds: int, label: str | None) -> dict[str, Any]:
    label_suffix = _label_suffix(label)
    if adapter == "source":
        return {
            "benchmark": f"cjson_injected_source_{label_suffix}",
            "base_task_id": SOURCE_BASE_TASK_ID,
            "ground_truth_path": GROUND_TRUTH_PATH,
            "target_mode": "source",
            "campaign_duration_seconds": duration_seconds,
            "campaign_enable_seed_tasks": True,
            "FUZZ_MAX_TOTAL_TIME_SECONDS": round_seconds,
            "FUZZ_TIMEOUT_SECONDS": min(round_seconds, 10),
            "SEED_GENERATION_BACKEND": "heuristic_fallback",
        }
    return {
        "benchmark": f"cjson_pure_binary_{label_suffix}",
        "base_task_id": PURE_BINARY_BASE_TASK_ID,
        "ground_truth_path": GROUND_TRUTH_PATH,
        "target_mode": "binary",
        "campaign_duration_seconds": duration_seconds,
        "campaign_enable_seed_tasks": True,
        "SEED_GENERATION_BACKEND": "heuristic_fallback",
        "binary_mode": "pure_binary",
        "binary_provenance": "pure_binary_input",
        "binary_input_contract": "file",
        "binary_input_contract_source": "manual_input_contract",
    }


def _create_campaign_task(adapter: str, duration_seconds: int, round_seconds: int, label: str | None) -> str:
    task_store = TaskStateStore()
    metadata = _default_metadata(adapter, duration_seconds, round_seconds, label)
    source = TaskSource(
        adapter_type="binary" if adapter == "pure_binary" else "ossfuzz",
        uri=f"medium-validation://{adapter}",
        ref=_label_suffix(label),
    )
    spec = TaskSpec(source=source, execution_mode=ExecutionMode.HYBRID, metadata=metadata)
    record = task_store.create_task(spec, status=TaskStatus.CAMPAIGN_QUEUED)
    task_store.update_runtime(
        record.task_id,
        {
            "campaign_duration_seconds": duration_seconds,
            "campaign_adapter": adapter,
            "campaign_poll_seconds": 5,
            "campaign_label": _label_suffix(label),
        },
    )
    return record.task_id


def _spawn_campaign_daemon(adapter: str, task_id: str, label: str | None) -> int:
    CONTROL_ROOT.mkdir(parents=True, exist_ok=True)
    log_path = _log_path(adapter, label)
    log_file = log_path.open("a", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["DATA_ROOT"] = str(REPO_ROOT / "data" / "tasks")
    env["CAMPAIGN_TASK_ID"] = task_id
    env["CAMPAIGN_POLL_SECONDS"] = "5"
    process = subprocess.Popen(
        [sys.executable, "-m", "apps.workers.campaign.main"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    _write_json(
        _control_path(adapter, label),
        {
            "adapter": adapter,
            "label": _label_suffix(label),
            "task_id": task_id,
            "pid": process.pid,
            "log_path": str(log_path),
        },
    )
    return process.pid


def _task_snapshot(task_id: str) -> dict[str, Any]:
    task_payload = _load_json(task_json_path(task_id))
    checkpoint = _load_json(campaign_checkpoint_path(task_id))
    manifest = _load_json(campaign_manifest_path(task_id))
    return {
        "task_id": task_id,
        "status": task_payload.get("status"),
        "heartbeat_at": task_payload.get("runtime", {}).get("campaign_heartbeat_at"),
        "checkpoint_path": str(campaign_checkpoint_path(task_id)),
        "manifest_path": str(campaign_manifest_path(task_id)),
        "iterations_total": manifest.get("iterations_total"),
        "lifecycle_state": manifest.get("lifecycle_state") or checkpoint.get("lifecycle_state"),
        "last_round_finished_at": task_payload.get("runtime", {}).get("campaign_last_round_finished_at"),
    }


def start(adapter: str, duration_seconds: int, round_seconds: int, label: str | None) -> None:
    task_id = _create_campaign_task(adapter, duration_seconds, round_seconds, label)
    pid = _spawn_campaign_daemon(adapter, task_id, label)
    print(
        json.dumps(
            {
                "adapter": adapter,
                "label": _label_suffix(label),
                "task_id": task_id,
                "pid": pid,
                "log_path": str(_log_path(adapter, label)),
                "control_path": str(_control_path(adapter, label)),
            },
            indent=2,
        ),
    )


def status(adapter: str, label: str | None) -> None:
    control = _load_json(_control_path(adapter, label))
    if not control:
        print(json.dumps({"adapter": adapter, "label": _label_suffix(label), "status": "NOT_STARTED"}, indent=2))
        return
    snapshot = _task_snapshot(control["task_id"])
    print(json.dumps({**control, **snapshot}, indent=2))


def stop(adapter: str, label: str | None) -> None:
    control = _load_json(_control_path(adapter, label))
    if not control:
        print(json.dumps({"adapter": adapter, "label": _label_suffix(label), "status": "NOT_STARTED"}, indent=2))
        return
    pid = int(control["pid"])
    try:
        os.killpg(pid, signal.SIGTERM)
        stopped = True
    except ProcessLookupError:
        stopped = False
    print(
        json.dumps(
            {
                "adapter": adapter,
                "label": control.get("label", _label_suffix(label)),
                "task_id": control["task_id"],
                "pid": pid,
                "stopped": stopped,
            },
            indent=2,
        ),
    )


def logs(adapter: str, label: str | None) -> None:
    control = _load_json(_control_path(adapter, label))
    if not control:
        print(json.dumps({"adapter": adapter, "label": _label_suffix(label), "status": "NOT_STARTED"}, indent=2))
        return
    print(control["log_path"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["start", "status", "stop", "logs"])
    parser.add_argument("--adapter", choices=["source", "pure_binary"], required=True)
    parser.add_argument("--duration-seconds", type=int, default=7200)
    parser.add_argument("--round-seconds", type=int, default=20)
    parser.add_argument("--label", default="2h")
    args = parser.parse_args()

    if args.command == "start":
        start(args.adapter, args.duration_seconds, args.round_seconds, args.label)
    elif args.command == "status":
        status(args.adapter, args.label)
    elif args.command == "stop":
        stop(args.adapter, args.label)
    else:
        logs(args.adapter, args.label)


if __name__ == "__main__":
    main()
