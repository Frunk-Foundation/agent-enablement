from __future__ import annotations

def event_bus_name_from_arn(arn: str) -> str:
    s = (arn or "").strip()
    if not s:
        return ""
    resource = s.split(":", 5)[-1] if ":" in s else s
    if "/" in resource:
        return resource.split("/", 1)[1].strip()
    return resource.strip()
