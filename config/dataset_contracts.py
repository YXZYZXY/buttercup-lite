from __future__ import annotations

from typing import Any


def shape_binary_seed_payload(
    payload: bytes,
    *,
    seed_index: int,
    dataset_contract_context: dict[str, Any],
) -> tuple[bytes, list[str]]:
    hints = [str(item) for item in (dataset_contract_context.get("contract_hints") or []) if item]
    joined_hints = "\n".join(hints).lower()
    notes: list[str] = []
    shaped = payload

    if "4 ascii control flag bytes" in joined_hints:
        if not (len(shaped) >= 4 and all(byte in b"01" for byte in shaped[:4])):
            prefixes = (b"1111", b"1010", b"0101", b"0001")
            prefix = prefixes[seed_index % len(prefixes)]
            shaped = prefix + shaped
            notes.append("prepended_flag_prefix_from_contract_hint")
    if "nul terminator" in joined_hints and not shaped.endswith(b"\x00"):
        shaped = shaped + b"\x00"
        notes.append("appended_nul_terminator_from_contract_hint")

    return shaped, notes
