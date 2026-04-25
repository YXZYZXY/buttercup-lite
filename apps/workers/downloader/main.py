import logging
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.buttercup_compat.workspace import write_workspace_manifest
from core.models.task import TaskStatus
from core.program_model.importer import import_source_tree
from core.queues.redis_queue import QueueNames, RedisQueue
from core.source_resolution import resolve_source_project, write_source_resolution_manifest
from core.source_task import write_source_task_normalization_manifest
from core.state.task_state import TaskStateStore
from core.storage.layout import create_task_layout
from core.utils.settings import expand_local_path, is_remote_uri, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("downloader-worker")


def _clone_repository(
    uri: str,
    destination: Path,
    *,
    ref: str | None = None,
    sparse_paths: list[str] | None = None,
) -> Path:
    if destination.exists() and any(destination.iterdir()):
        return destination
    git_prefix = ["git", "-c", "safe.directory=*"]
    if sparse_paths:
        command = git_prefix + ["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", uri, str(destination)]
    else:
        command = git_prefix + ["clone", "--depth", "1"]
        if ref:
            command.extend(["--branch", ref])
        command.extend([uri, str(destination)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        if not sparse_paths and ref:
            fallback = subprocess.run(
                git_prefix + ["clone", "--depth", "1", uri, str(destination)],
                capture_output=True,
                text=True,
                check=False,
            )
            if fallback.returncode != 0:
                raise RuntimeError(f"git clone failed for {uri}: {fallback.stderr.strip() or fallback.stdout.strip()}")
            checkout = subprocess.run(
                git_prefix + ["-C", str(destination), "checkout", ref],
                capture_output=True,
                text=True,
                check=False,
            )
            if checkout.returncode != 0:
                fetch = subprocess.run(
                    git_prefix + ["-C", str(destination), "fetch", "--depth", "1", "origin", ref],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if fetch.returncode != 0:
                    raise RuntimeError(f"git fetch failed for {uri}@{ref}: {fetch.stderr.strip() or fetch.stdout.strip()}")
                checkout = subprocess.run(
                    git_prefix + ["-C", str(destination), "checkout", "FETCH_HEAD"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if checkout.returncode != 0:
                    raise RuntimeError(
                        f"git checkout failed for {uri}@{ref}: {checkout.stderr.strip() or checkout.stdout.strip()}",
                    )
            return destination
        raise RuntimeError(f"git clone failed for {uri}: {completed.stderr.strip() or completed.stdout.strip()}")
    if sparse_paths:
        init_sparse = subprocess.run(
            git_prefix + ["-C", str(destination), "sparse-checkout", "init", "--cone"],
            capture_output=True,
            text=True,
            check=False,
        )
        if init_sparse.returncode != 0:
            raise RuntimeError(f"git sparse-checkout init failed for {uri}: {init_sparse.stderr.strip()}")
        set_sparse = subprocess.run(
            git_prefix + ["-C", str(destination), "sparse-checkout", "set", *sparse_paths],
            capture_output=True,
            text=True,
            check=False,
        )
        if set_sparse.returncode != 0:
            raise RuntimeError(f"git sparse-checkout set failed for {uri}: {set_sparse.stderr.strip()}")
        checkout_ref = ref or "HEAD"
        checkout = subprocess.run(
            git_prefix + ["-C", str(destination), "checkout", checkout_ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if checkout.returncode != 0 and ref:
            fetch = subprocess.run(
                git_prefix + ["-C", str(destination), "fetch", "--depth", "1", "origin", ref],
                capture_output=True,
                text=True,
                check=False,
            )
            if fetch.returncode != 0:
                raise RuntimeError(f"git fetch failed for {uri}@{ref}: {fetch.stderr.strip() or fetch.stdout.strip()}")
            checkout = subprocess.run(
                git_prefix + ["-C", str(destination), "checkout", "FETCH_HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
        if checkout.returncode != 0:
            raise RuntimeError(f"git checkout failed for {uri}@{checkout_ref}: {checkout.stderr.strip()}")
    return destination


def _file_uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    return expand_local_path(parsed.path)


def _localize_source(task, layout: dict[str, str], task_store: TaskStateStore) -> dict[str, Any]:
    runtime_patch: dict[str, Any] = {}
    uri = task.source.uri
    source_destination = Path(layout["src"])
    if uri.startswith("file://"):
        local_source_path = _file_uri_to_path(uri)
        if not local_source_path.exists() or not local_source_path.is_dir():
            raise RuntimeError(f"invalid source.uri: {uri!r} does not resolve to an existing directory")
        imported_root = import_source_tree(local_source_path, source_destination)
        runtime_patch.update(
            {
                "source_contract_kind": "file_url",
                "source_localized_from": uri,
                "source_localized_at": task_store.now(),
                "source_root": str(imported_root),
            },
        )
        return runtime_patch
    if is_remote_uri(uri):
        imported_root = _clone_repository(uri, source_destination, ref=task.source.ref)
        runtime_patch.update(
            {
                "source_contract_kind": "remote_git",
                "source_localized_from": uri,
                "source_localized_at": task_store.now(),
                "source_root": str(imported_root),
            },
        )
        return runtime_patch

    local_source_path = expand_local_path(uri)
    if not local_source_path.exists() or not local_source_path.is_dir():
        raise RuntimeError(f"invalid source.uri: {uri!r} is not a supported repository URL or existing directory")

    imported_root = import_source_tree(local_source_path, source_destination)
    runtime_patch.update(
        {
            "source_contract_kind": "local_directory",
            "source_localized_from": str(local_source_path),
            "source_localized_at": task_store.now(),
            "source_root": str(imported_root),
        },
    )
    return runtime_patch


def _localize_fuzz_tooling(task, layout: dict[str, str], task_store: TaskStateStore) -> dict[str, Any]:
    metadata = task.metadata
    fuzz_tooling_url = metadata.get("fuzz_tooling_url") or metadata.get("fuzz_tooling_repo_url")
    if not fuzz_tooling_url:
        return {}

    project_name = str(
        metadata.get("fuzz_tooling_project_name")
        or metadata.get("project")
        or "",
    ).strip()
    sparse_paths = [f"projects/{project_name}"] if project_name else None
    ref = metadata.get("fuzz_tooling_ref") or metadata.get("fuzz_tooling_branch")
    destination = Path(layout["fuzz_tooling"])
    if str(fuzz_tooling_url).startswith("file://"):
        local_path = _file_uri_to_path(str(fuzz_tooling_url))
        if not local_path.exists() or not local_path.is_dir():
            raise RuntimeError(f"invalid fuzz_tooling_url: {fuzz_tooling_url!r} does not resolve to an existing directory")
        localized_root = import_source_tree(local_path, destination)
        contract_kind = "file_url"
    elif is_remote_uri(str(fuzz_tooling_url)):
        localized_root = _clone_repository(str(fuzz_tooling_url), destination, ref=ref, sparse_paths=sparse_paths)
        contract_kind = "remote_git"
    else:
        local_path = expand_local_path(str(fuzz_tooling_url))
        if not local_path.exists() or not local_path.is_dir():
            raise RuntimeError(f"invalid fuzz_tooling_url: {fuzz_tooling_url!r} is not a supported repository URL or directory")
        localized_root = import_source_tree(local_path, destination)
        contract_kind = "local_directory"

    runtime_patch: dict[str, Any] = {
        "fuzz_tooling_contract_kind": contract_kind,
        "fuzz_tooling_localized_from": str(fuzz_tooling_url),
        "fuzz_tooling_localized_at": task_store.now(),
        "fuzz_tooling_root": str(localized_root),
    }
    if project_name:
        project_root = localized_root / "projects" / project_name
        if project_root.exists():
            runtime_patch["existing_oss_fuzz_project_path"] = str(project_root)
            project_yaml = project_root / "project.yaml"
            if project_yaml.exists():
                runtime_patch["existing_project_yaml_path"] = str(project_yaml)
    return runtime_patch


def process_task(task_id: str, task_store: TaskStateStore, queue: RedisQueue) -> None:
    logger.info("picked task %s from %s", task_id, QueueNames.DOWNLOAD)
    task_store.update_status(
        task_id,
        TaskStatus.DOWNLOADING,
        runtime_patch={"download_started_at": task_store.now()},
    )
    layout = create_task_layout(task_id)
    task = task_store.load_task(task_id)
    runtime_patch: dict[str, Any] = {
        "ready_at": task_store.now(),
        "ready_queue_name": QueueNames.READY,
    }
    runtime_patch.update(_localize_source(task, layout, task_store))
    metadata_patch: dict[str, Any] = {}
    resolution_manifest: dict[str, Any] | None = None
    if task.source.adapter_type.value == "ossfuzz":
        explicit_project = str(task.metadata.get("project") or "").strip() or None
        explicit_project_root = str(task.metadata.get("existing_oss_fuzz_project_path") or "").strip() or None
        explicit_project_yaml = str(task.metadata.get("existing_project_yaml_path") or "").strip() or None
        project_hint = (
            task.metadata.get("oss_fuzz_project_hint")
            or explicit_project
            or (Path(explicit_project_root).name if explicit_project_root else None)
            or (Path(explicit_project_yaml).parent.name if explicit_project_yaml else None)
        )
        resolution = resolve_source_project(
            repo_url=task.metadata.get("repo_url") or task.source.uri,
            source_root=runtime_patch.get("source_root") or layout["src"],
            oss_fuzz_project_hint=project_hint,
        )
        if explicit_project:
            resolution["selected_oss_fuzz_project"] = explicit_project
            resolution["selected_oss_fuzz_project_path"] = explicit_project_root or resolution.get(
                "selected_oss_fuzz_project_path",
            )
            resolution["metadata_patch"]["project"] = explicit_project
            resolution["metadata_patch"]["selected_oss_fuzz_project"] = explicit_project
        if explicit_project_root:
            resolution["selected_oss_fuzz_project_path"] = explicit_project_root
            resolution["metadata_patch"]["existing_oss_fuzz_project_path"] = explicit_project_root
        if explicit_project_yaml:
            resolution["selected_project_yaml_path"] = explicit_project_yaml
            resolution["metadata_patch"]["existing_project_yaml_path"] = explicit_project_yaml
        resolution_manifest = write_source_resolution_manifest(
            task_id,
            generated_at=task_store.now(),
            resolution=resolution,
        )
        metadata_patch.update(resolution.get("metadata_patch", {}))
        runtime_patch.update(
            {
                "source_resolution_manifest_path": resolution_manifest["source_resolution_manifest_path"],
                "source_resolution_class": resolution.get("resolution_class"),
                "selected_oss_fuzz_project": resolution.get("selected_oss_fuzz_project"),
                "selected_build_strategy": resolution.get("selected_build_strategy"),
                "selected_harness_strategy": resolution.get("selected_harness_strategy"),
                "discovered_harnesses": resolution.get("discovered_harnesses", []),
                "tracer_build_strategy": resolution.get("tracer_build_strategy"),
                "coverage_build_strategy": resolution.get("coverage_build_strategy"),
            },
        )
        if resolution.get("selected_oss_fuzz_project_path"):
            runtime_patch["existing_oss_fuzz_project_path"] = resolution["selected_oss_fuzz_project_path"]
        if resolution.get("selected_project_yaml_path"):
            runtime_patch["existing_project_yaml_path"] = resolution["selected_project_yaml_path"]
        if explicit_project:
            metadata_patch["project"] = explicit_project
            metadata_patch["selected_oss_fuzz_project"] = explicit_project
            runtime_patch["selected_oss_fuzz_project"] = explicit_project
        if explicit_project_root:
            metadata_patch["existing_oss_fuzz_project_path"] = explicit_project_root
            runtime_patch["existing_oss_fuzz_project_path"] = explicit_project_root
        if explicit_project_yaml:
            metadata_patch["existing_project_yaml_path"] = explicit_project_yaml
            runtime_patch["existing_project_yaml_path"] = explicit_project_yaml

    task_for_workspace = task.model_copy(update={"metadata": {**task.metadata, **metadata_patch}})
    runtime_patch.update(_localize_fuzz_tooling(task_for_workspace, layout, task_store))
    normalization_manifest = write_source_task_normalization_manifest(
        task_for_workspace,
        generated_at=task_store.now(),
        layout=layout,
        runtime=runtime_patch,
        metadata=metadata_patch,
        resolution=resolution_manifest,
    )
    runtime_patch["source_task_normalization_manifest_path"] = normalization_manifest[
        "source_task_normalization_manifest_path"
    ]
    workspace_manifest = write_workspace_manifest(
        task_for_workspace,
        layout=layout,
        runtime=runtime_patch,
        generated_at=task_store.now(),
    )
    runtime_patch.update(
        {
            "workspace_manifest_path": workspace_manifest["workspace_manifest_path"],
            "task_meta_path": workspace_manifest["task_meta_path"],
            "buttercup_workspace_semantics": "src/fuzz-tooling/diff/task_meta normalized",
        },
    )
    record = task_store.update_task(
        task_id,
        status=TaskStatus.READY,
        layout=layout,
        runtime=runtime_patch,
        metadata=metadata_patch,
    )
    queue.push(QueueNames.READY, task_id)
    queue.ack(QueueNames.DOWNLOAD, task_id)
    logger.info("task %s is %s and pushed to %s", task_id, record.status, QueueNames.READY)


def main() -> None:
    queue = RedisQueue(settings.redis_url)
    task_store = TaskStateStore()
    logger.info("downloader worker started")
    while True:
        task_id = queue.pop(QueueNames.DOWNLOAD, timeout=settings.queue_block_timeout)
        if task_id is None:
            time.sleep(0.5)
            continue
        try:
            process_task(task_id, task_store, queue)
        except Exception as exc:  # pragma: no cover
            logger.exception("downloader failed for task %s: %s", task_id, exc)
            task_store.update_status(
                task_id,
                TaskStatus.FAILED,
                runtime_patch={
                    "download_error": str(exc),
                    "failed_at": task_store.now(),
                },
            )


if __name__ == "__main__":
    main()
