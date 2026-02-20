from __future__ import annotations

from typing import Any


def ddb_str_list(item: dict[str, Any], key: str) -> list[str]:
    val = item.get(key)
    if not isinstance(val, dict):
        return []

    out: list[str] = []
    if "SS" in val and isinstance(val["SS"], list):
        out.extend(str(v).strip() for v in val["SS"])

    deduped: list[str] = []
    seen: set[str] = set()
    for value in out:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
