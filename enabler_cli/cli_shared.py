from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - exercised only when deps are missing
    boto3 = None


class EnablerOpsError(Exception):
    pass


class UsageError(EnablerOpsError):
    pass


class OpError(EnablerOpsError):
    pass


ENABLER_COGNITO_USERNAME = "ENABLER_COGNITO_USERNAME"
ENABLER_COGNITO_PASSWORD = "ENABLER_COGNITO_PASSWORD"
ENABLER_ADMIN_COGNITO_USERNAME = "ENABLER_ADMIN_COGNITO_USERNAME"
ENABLER_ADMIN_COGNITO_PASSWORD = "ENABLER_ADMIN_COGNITO_PASSWORD"
ENABLER_API_KEY = "ENABLER_API_KEY"
ENABLER_CREDENTIALS_ENDPOINT = "ENABLER_CREDENTIALS_ENDPOINT"
ENABLER_CREDS_CACHE = "ENABLER_CREDS_CACHE"
ENABLER_NO_AUTO_REFRESH_CREDS = "ENABLER_NO_AUTO_REFRESH_CREDS"
ENABLER_ADMIN_HANDOFF_KIND = "enabler.admin.handoff.v1"
ENABLER_ADMIN_HANDOFF_SCHEMA_VERSION = "2026-02-24"


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


@dataclass(frozen=True)
class GlobalOpts:
    stack: str
    pretty: bool
    quiet: bool
    creds_cache_path: str = ""
    auto_refresh_creds: bool = True


def _env_or_none(*names: str) -> str | None:
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return None


def _require_str(val: str | None, name: str, *, hint: str) -> str:
    v = (val or "").strip()
    if not v:
        raise UsageError(f"missing {name} ({hint})")
    return v


def _require_boto3() -> Any:
    if boto3 is None:
        raise UsageError(
            "missing dependency: boto3 (install requirements.txt and run with .venv/bin/python)"
        )
    return boto3


def _aws_profile_region_from_env() -> tuple[str, str]:
    profile = (os.environ.get("AWS_PROFILE") or "").strip()
    region = (os.environ.get("AWS_REGION") or "").strip()
    if not profile:
        raise UsageError("missing AWS_PROFILE (set env or pass --profile)")
    if not region:
        raise UsageError("missing AWS_REGION (set env or pass --region)")
    return profile, region


def _account_session() -> Any:
    _require_boto3()
    profile, region = _aws_profile_region_from_env()
    return boto3.session.Session(profile_name=profile, region_name=region)


def _cf_outputs(session: Any, *, stack: str) -> list[dict[str, Any]]:
    cf = session.client("cloudformation")
    try:
        resp = cf.describe_stacks(StackName=stack)
    except Exception as e:
        raise OpError(f"cloudformation describe-stacks failed for stack {stack!r}: {e}") from e
    stacks = resp.get("Stacks") or []
    if not stacks:
        raise OpError(f"stack not found: {stack}")
    outputs = stacks[0].get("Outputs") or []
    if not isinstance(outputs, list):
        return []
    return [o for o in outputs if isinstance(o, dict)]


def _stack_output_value(session: Any, *, stack: str, key: str) -> str | None:
    for o in _cf_outputs(session, stack=stack):
        if str(o.get("OutputKey", "")).strip() == key:
            v = str(o.get("OutputValue", "")).strip()
            return v if v else ""
    return None


def _require_stack_output(session: Any, *, stack: str, key: str) -> str:
    v = _stack_output_value(session, stack=stack, key=key)
    if v is None:
        raise OpError(f"missing CloudFormation output {key!r} on stack {stack!r}")
    return v


def _print_json(obj: Any, *, pretty: bool) -> None:
    if pretty:
        sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = (token or "").split(".")
    if len(parts) < 2:
        raise OpError("invalid JWT: expected at least 2 dot-separated parts")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        val = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise OpError(f"invalid JWT payload: {e}") from e
    if not isinstance(val, dict):
        raise OpError("invalid JWT payload: expected JSON object")
    return val


def _load_json_object(*, raw: str, label: str) -> dict[str, Any]:
    try:
        val = json.loads(raw)
    except Exception as e:
        raise UsageError(f"invalid {label}: {e}") from e
    if not isinstance(val, dict):
        raise UsageError(f"invalid {label}: expected JSON object")
    return val


def _parse_groups_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    out: list[str] = []
    for part in raw.split(","):
        v = part.strip()
        if v:
            out.append(v)
    seen: set[str] = set()
    uniq: list[str] = []
    for g in out:
        if g in seen:
            continue
        seen.add(g)
        uniq.append(g)
    return uniq


def _inbox_queue_name(agent_id: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    suffix = "".join((c if c in allowed else "-") for c in agent_id)
    suffix = suffix[:60]
    if not suffix:
        suffix = "agent"
    return f"agent-inbox-{suffix}"


def _write_secure_json(*, path: Path, obj: dict[str, Any]) -> None:
    _write_secure_text(path=path, text=json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _write_secure_text(*, path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception as e:
        raise OpError(f"failed to apply 0600 permissions to {path}: {e}") from e
