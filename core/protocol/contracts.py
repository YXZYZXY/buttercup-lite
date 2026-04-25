from __future__ import annotations

from typing import Any


def build_protocol_contract(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_name": metadata.get("protocol_name", "unknown_protocol"),
        "protocol_input_contract": metadata.get("protocol_input_contract", {}),
        "seed_contract": {
            "supported": False,
            "status": "placeholder",
            "expected_future_outputs": ["protocol_seed_manifest.json", "corpus/active"],
        },
        "execution_contract": {
            "supported": False,
            "status": "placeholder",
            "expected_future_outputs": ["runtime/protocol_execution_manifest.json"],
        },
        "trace_contract": {
            "supported": False,
            "status": "placeholder",
        },
        "coverage_contract": {
            "supported": False,
            "status": "placeholder",
        },
    }

