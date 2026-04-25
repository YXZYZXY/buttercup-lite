from __future__ import annotations


def run_campaign(*args, **kwargs):
    from core.campaign.scheduler import run_campaign as _run_campaign

    return _run_campaign(*args, **kwargs)

__all__ = ["run_campaign"]
