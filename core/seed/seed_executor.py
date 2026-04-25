from __future__ import annotations

import logging
import multiprocessing as mp
from pathlib import Path
from typing import Any

from core.seed.models import ParsedSeedModule
from core.storage.layout import task_root
from core.utils.settings import settings

logger = logging.getLogger(__name__)

SAFE_BUILTINS = {
    "abs": abs,
    "bool": bool,
    "bytes": bytes,
    "bytearray": bytearray,
    "dict": dict,
    "enumerate": enumerate,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "str": str,
    "sum": sum,
    "tuple": tuple,
}


def _invoke_function(code: str, function_name: str, max_bytes: int, output_queue: mp.Queue) -> None:
    namespace: dict[str, Any] = {"__builtins__": SAFE_BUILTINS}
    try:
        exec(code, namespace, namespace)
        result = namespace[function_name]()
        if not isinstance(result, (bytes, bytearray)):
            output_queue.put({"ok": False, "error": f"{function_name} did not return bytes"})
            return
        payload = bytes(result)
        if len(payload) > max_bytes:
            output_queue.put({"ok": False, "error": f"{function_name} exceeded max seed size"})
            return
        output_queue.put({"ok": True, "data": payload})
    except Exception as exc:  # pragma: no cover
        output_queue.put({"ok": False, "error": f"{function_name} raised {exc}"})


def _unique_output_path(output_dir: Path, file_name: str) -> Path:
    target_path = output_dir / file_name
    suffix = 1
    while target_path.exists():
        target_path = output_dir / f"{Path(file_name).stem}_{suffix}{Path(file_name).suffix}"
        suffix += 1
    return target_path


def _is_low_entropy_large_seed(seed_bytes: bytes) -> bool:
    return len(seed_bytes) > 512 and len(set(seed_bytes)) < 8


def execute_seed_functions(
    task_id: str,
    module: ParsedSeedModule,
    output_dir: Path,
    *,
    max_bytes: int | None = None,
    function_timeout_seconds: int | None = None,
) -> tuple[list[str], list[str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    discarded_dir = task_root(task_id) / "corpus" / "discarded"
    discarded_dir.mkdir(parents=True, exist_ok=True)
    written_files: list[str] = []
    errors: list[str] = []
    effective_max_bytes = settings.seed_max_bytes if max_bytes is None else max_bytes
    effective_timeout = (
        settings.seed_function_timeout_seconds
        if function_timeout_seconds is None
        else function_timeout_seconds
    )
    for function_name in module.function_names:
        queue: mp.Queue = mp.Queue()
        process = mp.Process(
            target=_invoke_function,
            args=(module.code, function_name, effective_max_bytes, queue),
        )
        process.start()
        process.join(effective_timeout)
        if process.is_alive():
            process.terminate()
            process.join()
            errors.append(f"{function_name} timed out")
            continue
        if queue.empty():
            errors.append(f"{function_name} produced no result")
            continue
        result = queue.get()
        if not result.get("ok"):
            errors.append(result.get("error", f"{function_name} failed"))
            continue

        file_name = f"{function_name}.seed"
        seed_bytes = result["data"]
        if _is_low_entropy_large_seed(seed_bytes):
            discarded_path = _unique_output_path(discarded_dir, file_name)
            discarded_path.write_bytes(seed_bytes)
            logger.warning(
                "丢弃低熵 seed：%s bytes，唯一字节数=%s，函数=%s，输出=%s",
                len(seed_bytes),
                len(set(seed_bytes)),
                function_name,
                discarded_path,
            )
            continue
        target_path = _unique_output_path(output_dir, file_name)
        target_path.write_bytes(seed_bytes)
        written_files.append(str(target_path))

    return written_files, errors
