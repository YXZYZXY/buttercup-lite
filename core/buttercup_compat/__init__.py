"""Small compatibility layer for original Buttercup execution semantics."""

def build_scheduler_fanout(*args, **kwargs):
    from core.buttercup_compat.scheduler import build_scheduler_fanout as _build_scheduler_fanout

    return _build_scheduler_fanout(*args, **kwargs)


def write_scheduler_fanout_manifest(*args, **kwargs):
    from core.buttercup_compat.scheduler import write_scheduler_fanout_manifest as _write_scheduler_fanout_manifest

    return _write_scheduler_fanout_manifest(*args, **kwargs)


def write_workspace_manifest(*args, **kwargs):
    from core.buttercup_compat.workspace import write_workspace_manifest as _write_workspace_manifest

    return _write_workspace_manifest(*args, **kwargs)

__all__ = [
    "build_scheduler_fanout",
    "write_scheduler_fanout_manifest",
    "write_workspace_manifest",
]
