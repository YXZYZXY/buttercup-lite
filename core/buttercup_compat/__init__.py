"""Small compatibility layer for original Buttercup execution semantics."""

from core.buttercup_compat.scheduler import build_scheduler_fanout, write_scheduler_fanout_manifest
from core.buttercup_compat.workspace import write_workspace_manifest

__all__ = [
    "build_scheduler_fanout",
    "write_scheduler_fanout_manifest",
    "write_workspace_manifest",
]
