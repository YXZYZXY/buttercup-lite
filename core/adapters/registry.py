from __future__ import annotations

from core.adapters.base import AdapterDefinition
from core.adapters.protocol_adapter import build_protocol_adapter
from core.adapters.pure_binary_adapter import build_pure_binary_adapter
from core.adapters.source_adapter import build_source_adapter
from core.models.task import AdapterType


def get_adapter_definition(adapter_type: AdapterType) -> AdapterDefinition:
    if adapter_type == AdapterType.BINARY:
        return build_pure_binary_adapter()
    if adapter_type == AdapterType.PROTOCOL:
        return build_protocol_adapter()
    return build_source_adapter()

