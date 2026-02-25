from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

import click
import typer
from rich.console import Console

from .. import __version__
from .. import auth_inputs
from ..admin_commands import (
    cmd_agent_decommission,
    _parse_stage_from_api_key_param_name,
    _ssm_key_name_agent,
    _ssm_key_name_shared,
    cmd_agent_handoff_create,
    cmd_agent_handoff_print_env,
    cmd_agent_onboard,
    cmd_agent_seed_profile,
    cmd_cognito_create_user,
    cmd_cognito_id_token,
    cmd_cognito_remove_user,
    cmd_cognito_rotate_password,
    cmd_ssm_api_key,
    cmd_ssm_key_base_paths,
    cmd_ssm_key_get_agent,
    cmd_ssm_key_get_shared,
    cmd_ssm_key_put_agent,
    cmd_ssm_key_put_shared,
    cmd_stack_output,
)
from ..agent_commands import event_bus_name_from_arn
from ..cli_shared import ENABLER_ADMIN_COGNITO_PASSWORD
from ..cli_shared import ENABLER_ADMIN_COGNITO_USERNAME
from ..cli_shared import ENABLER_API_KEY
from ..cli_shared import ENABLER_AGENT_ID
from ..cli_shared import ENABLER_COGNITO_PASSWORD
from ..cli_shared import ENABLER_COGNITO_USERNAME
from ..cli_shared import ENABLER_CREDENTIALS_ENDPOINT
from ..cli_shared import ENABLER_CREDS_CACHE
from ..cli_shared import ENABLER_NO_AUTO_REFRESH_CREDS
from ..cli_shared import ENABLER_SESSION_ROOT
from ..cli_shared import GlobalOpts
from ..cli_shared import OpError as SharedOpError
from ..cli_shared import UsageError as SharedUsageError
from ..cli_shared import _account_session
from ..cli_shared import _aws_profile_region_from_env
from ..cli_shared import _cf_outputs
from ..cli_shared import _print_json
from ..cli_shared import _require_stack_output
from ..cli_shared import _stack_output_value
from ..cli_shared import _write_secure_json
from ..cli_shared import _write_secure_text
from ..id58 import uuid4_base58_22

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover - exercised only when deps are missing
    load_dotenv = None

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - exercised only when deps are missing
    boto3 = None


# Compatibility aliases: keep exception identity aligned across split modules.
UsageError = SharedUsageError
OpError = SharedOpError

_MESSAGES_RECV_MAX_BATCHES = 100
_MESSAGES_RECV_ACK_ALL_MAX_BATCHES = 100


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


class _InsertionOrderTyperGroup(typer.core.TyperGroup):
    def list_commands(self, ctx: click.Context) -> list[str]:
        names = list(self.commands)
        lead = [n for n in ("stack-output",) if n in names]
        head = [n for n in names if n not in set(lead)]
        return lead + head


def _require_boto3() -> Any:
    if boto3 is None:
        raise UsageError(
            "missing dependency: boto3 (install requirements.txt and run with .venv/bin/python)"
        )
    return boto3


def _env_or_none(*names: str) -> str | None:
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return None


def _bootstrap_env() -> None:
    if load_dotenv is None:
        raise UsageError(
            "missing dependency: python-dotenv (install requirements.txt and run with .venv/bin/python)"
        )
    # Use python-dotenv package defaults: discover and load .env without
    # overriding already-exported process environment values.
    load_dotenv()


def _require_str(val: str | None, name: str, *, hint: str) -> str:
    v = (val or "").strip()
    if not v:
        raise UsageError(f"missing {name} ({hint})")
    return v


def _basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout_seconds: int = 30,
) -> tuple[int, dict[str, str], bytes]:
    req = Request(url, data=body, method=str(method).upper())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}
            data = resp.read()
            return int(status), hdrs, data
    except HTTPError as e:
        hdrs = {k.lower(): v for k, v in dict(e.headers).items()}
        data = e.read() if hasattr(e, "read") else b""
        return int(getattr(e, "code", 0) or 0), hdrs, data
    except URLError as e:
        raise OpError(f"http request failed: {e}") from e


def _http_post_json(
    *,
    url: str,
    headers: dict[str, str],
    body: bytes = b"",
    timeout_seconds: int = 30,
) -> tuple[int, dict[str, str], bytes]:
    return _http_request(
        method="POST",
        url=url,
        headers=headers,
        body=body,
        timeout_seconds=timeout_seconds,
    )


def _runtime_credentials_endpoint(doc: dict[str, Any]) -> str:
    auth = doc.get("auth")
    if isinstance(auth, dict):
        endpoint = str(auth.get("credentialsEndpoint") or "").strip()
        if endpoint:
            return endpoint
    refs = doc.get("references")
    if isinstance(refs, dict):
        for key in ("credentials", "auth"):
            item = refs.get(key)
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("invokeUrl") or item.get("endpoint") or "").strip()
            if endpoint:
                return endpoint
    return ""


def _load_json_object(*, raw: str, label: str) -> dict[str, Any]:
    try:
        val = json.loads(raw)
    except Exception as e:
        raise UsageError(f"invalid {label}: {e}") from e
    if not isinstance(val, dict):
        raise UsageError(f"invalid {label}: expected JSON object")
    return val


def _credentials_cache_file(g: GlobalOpts) -> Path:
    raw = (g.creds_cache_path or "").strip() or _default_credentials_cache_path_for_agent(g.agent_id)
    return Path(raw).expanduser().resolve()


def _artifact_root(g: GlobalOpts) -> Path:
    return _credentials_cache_file(g).parent


def _references_from_runtime_doc(args: argparse.Namespace, g: GlobalOpts) -> dict[str, Any]:
    root_doc = _resolve_runtime_credentials_doc(args, g)
    refs = root_doc.get("references")
    if isinstance(refs, dict):
        return refs
    active_doc = _select_runtime_agent_doc(root_doc)
    refs = active_doc.get("references")
    if isinstance(refs, dict):
        return refs
    return {}


def _taskboard_endpoint_from_runtime_refs(args: argparse.Namespace, g: GlobalOpts) -> str:
    refs = _references_from_runtime_doc(args, g)
    taskboard = refs.get("taskboard")
    if isinstance(taskboard, dict):
        return str(taskboard.get("invokeUrl") or taskboard.get("endpoint") or "").strip()
    return ""


def _shortlinks_create_url_from_runtime_refs(args: argparse.Namespace, g: GlobalOpts) -> str:
    refs = _references_from_runtime_doc(args, g)
    shortlinks = refs.get("shortlinks")
    if isinstance(shortlinks, dict):
        return str(shortlinks.get("createUrl") or "").strip()
    return ""


def _shortlinks_redirect_base_url_from_runtime_refs(args: argparse.Namespace, g: GlobalOpts) -> str:
    refs = _references_from_runtime_doc(args, g)
    shortlinks = refs.get("shortlinks")
    if isinstance(shortlinks, dict):
        return str(shortlinks.get("redirectBaseUrl") or "").strip()
    return ""


def _files_public_base_url_from_runtime_refs(args: argparse.Namespace, g: GlobalOpts) -> str:
    refs = _references_from_runtime_doc(args, g)
    files = refs.get("files")
    if isinstance(files, dict):
        return str(files.get("publicBaseUrl") or "").strip()
    return ""


def _parse_iso8601(val: str) -> datetime | None:
    s = (val or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _select_runtime_agent_doc(doc: dict[str, Any]) -> dict[str, Any]:
    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        chosen = sets.get("agentEnablement")
        if isinstance(chosen, dict):
            return chosen
    return doc


def _credentials_doc_expired(doc: dict[str, Any], *, skew_seconds: int = 60) -> bool:
    candidates: list[str] = []
    expires_at = str(doc.get("expiresAt") or "").strip()
    if expires_at:
        candidates.append(expires_at)
    active_doc = _select_runtime_agent_doc(doc)
    creds = active_doc.get("credentials")
    if isinstance(creds, dict):
        exp = str(creds.get("expiration") or "").strip()
        if exp:
            candidates.append(exp)

    for raw in candidates:
        dt = _parse_iso8601(raw)
        if dt is None:
            continue
        return dt <= (datetime.now(timezone.utc) + timedelta(seconds=max(skew_seconds, 0)))
    return False


def _write_credentials_cache_from_text(*, g: GlobalOpts, raw_text: str) -> Path:
    path = _credentials_cache_file(g)
    _write_secure_text(path=path, text=raw_text.rstrip("\n") + "\n")
    return path


def _env_region_from_doc(doc: dict[str, Any]) -> str:
    refs = doc.get("references")
    refs = refs if isinstance(refs, dict) else {}
    region = str(refs.get("awsRegion") or "").strip() or str(doc.get("awsRegion") or "").strip()
    if not region:
        region = str(os.environ.get("AWS_REGION") or "").strip()
    return region


def _sts_env_text_from_doc(doc: dict[str, Any]) -> str:
    creds = doc.get("credentials")
    if not isinstance(creds, dict):
        raise UsageError("invalid credentials response: missing credentials object")
    access_key_id = str(creds.get("accessKeyId") or "").strip()
    secret_access_key = str(creds.get("secretAccessKey") or "").strip()
    session_token = str(creds.get("sessionToken") or "").strip()
    if not access_key_id or not secret_access_key or not session_token:
        raise UsageError(
            "invalid credentials response: missing accessKeyId/secretAccessKey/sessionToken"
        )

    region = _env_region_from_doc(doc)
    if not region:
        raise UsageError("missing region (ensure creds references.awsRegion, awsRegion, or AWS_REGION exists)")
    return "\n".join(
        [
            f"AWS_ACCESS_KEY_ID={access_key_id}",
            f"AWS_SECRET_ACCESS_KEY={secret_access_key}",
            f"AWS_SESSION_TOKEN={session_token}",
            f"AWS_REGION={region}",
        ]
    ) + "\n"


def _safe_env_suffix(name: str) -> str:
    out = []
    for ch in str(name or "").strip():
        if ch.isalnum():
            out.append(ch.lower())
        else:
            out.append("-")
    collapsed = "".join(out).strip("-")
    while "--" in collapsed:
        collapsed = collapsed.replace("--", "-")
    return collapsed or "set"


def _write_sts_env_files_from_doc(*, g: GlobalOpts, root_doc: dict[str, Any]) -> dict[str, str]:
    root = _artifact_root(g)
    out: dict[str, str] = {}

    active_doc = _select_runtime_agent_doc(root_doc)
    default_path = (root / "sts.env").resolve()
    _write_secure_text(path=default_path, text=_sts_env_text_from_doc(active_doc))
    out["default"] = str(default_path)

    sets = root_doc.get("credentialSets")
    if isinstance(sets, dict):
        for set_name, set_doc in sets.items():
            if not isinstance(set_doc, dict):
                continue
            if not isinstance(set_doc.get("credentials"), dict):
                continue
            suffix = _safe_env_suffix(str(set_name))
            set_path = (root / f"sts-{suffix}.env").resolve()
            _write_secure_text(path=set_path, text=_sts_env_text_from_doc(set_doc))
            out[str(set_name)] = str(set_path)
    return out


def _cognito_tokens_from_doc(doc: dict[str, Any]) -> dict[str, Any]:
    raw = doc.get("cognitoTokens")
    if isinstance(raw, dict) and any(
        str(raw.get(k) or "").strip()
        for k in ("idToken", "accessToken", "refreshToken", "tokenType", "expiresIn")
    ):
        return raw
    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        for item in sets.values():
            if not isinstance(item, dict):
                continue
            found = _cognito_tokens_from_doc(item)
            if found:
                return found
    return {}


def _write_cognito_env_file_from_doc(*, g: GlobalOpts, root_doc: dict[str, Any]) -> Path:
    tokens = _cognito_tokens_from_doc(root_doc)
    if not tokens:
        raise UsageError("invalid credentials response: missing cognitoTokens")
    id_token = str(tokens.get("idToken") or "").strip()
    access_token = str(tokens.get("accessToken") or "").strip()
    refresh_token = str(tokens.get("refreshToken") or "").strip()
    token_type = str(tokens.get("tokenType") or "").strip()
    expires_in = str(tokens.get("expiresIn") or "").strip()
    if not id_token:
        raise UsageError("invalid credentials response: missing cognitoTokens.idToken")
    out_path = (_artifact_root(g) / "cognito.env").resolve()
    lines = [
        f"ID_TOKEN={id_token}",
        f"ACCESS_TOKEN={access_token}",
        f"REFRESH_TOKEN={refresh_token}",
        f"TOKEN_TYPE={token_type}",
        f"EXPIRES_IN={expires_in}",
        f"COGNITO_ID_TOKEN={id_token}",
        f"COGNITO_ACCESS_TOKEN={access_token}",
        f"COGNITO_REFRESH_TOKEN={refresh_token}",
    ]
    _write_secure_text(path=out_path, text="\n".join(lines) + "\n")
    return out_path


def _credentials_expires_at(doc: dict[str, Any]) -> str:
    expires_at = str(doc.get("expiresAt") or "").strip()
    if expires_at:
        return expires_at
    active_doc = _select_runtime_agent_doc(doc)
    creds = active_doc.get("credentials")
    if isinstance(creds, dict):
        exp = str(creds.get("expiration") or "").strip()
        if exp:
            return exp
    return ""


def _credentials_freshness(expires_at: str) -> tuple[str, int | None]:
    dt = _parse_iso8601(expires_at)
    if dt is None:
        return "unknown", None
    seconds = int((dt - datetime.now(timezone.utc)).total_seconds())
    if seconds <= 0:
        return "expired", seconds
    if seconds <= 300:
        return "expiring_soon", seconds
    return "fresh", seconds


def _credential_set_doc(*, root_doc: dict[str, Any], set_name: str) -> dict[str, Any]:
    selected = str(set_name or "").strip()
    if not selected:
        raise UsageError("missing credential set name")

    sets = root_doc.get("credentialSets")
    if isinstance(sets, dict):
        entry = sets.get(selected)
        if isinstance(entry, dict):
            return entry
        raise UsageError(f"missing credential set: {selected}")

    if selected == "agentEnablement":
        creds = root_doc.get("credentials")
        if isinstance(creds, dict):
            return root_doc

    raise UsageError(f"missing credential set: {selected}")


def _credential_process_doc_to_output(doc: dict[str, Any]) -> dict[str, Any]:
    creds = doc.get("credentials")
    if not isinstance(creds, dict):
        raise UsageError("invalid credential set: missing credentials object")
    access_key_id = str(creds.get("accessKeyId") or "").strip()
    secret_access_key = str(creds.get("secretAccessKey") or "").strip()
    session_token = str(creds.get("sessionToken") or "").strip()
    if not access_key_id or not secret_access_key or not session_token:
        raise UsageError("invalid credential set: missing accessKeyId/secretAccessKey/sessionToken")
    out: dict[str, Any] = {
        "Version": 1,
        "AccessKeyId": access_key_id,
        "SecretAccessKey": secret_access_key,
        "SessionToken": session_token,
    }
    expiration = str(creds.get("expiration") or doc.get("expiresAt") or "").strip()
    if expiration:
        out["Expiration"] = expiration
    return out


def _credentials_location_manifest(
    *,
    g: GlobalOpts,
    doc: dict[str, Any],
    sts_env_paths: dict[str, str],
    cognito_env_path: str,
) -> dict[str, Any]:
    root = _artifact_root(g)
    credentials_path = _credentials_cache_file(g)
    default_sts_env_path = (root / "sts.env").resolve()
    expires_at = _credentials_expires_at(doc)
    freshness_status, seconds_to_expiry = _credentials_freshness(expires_at)
    return {
        "kind": "enabler.agent.credentials-locations.v1",
        "requestId": doc.get("requestId"),
        "expiresAt": expires_at,
        "freshness": {
            "status": freshness_status,
            "secondsToExpiry": seconds_to_expiry,
        },
        "paths": {
            "credentialsJson": str(credentials_path),
            "stsDefaultEnv": str(default_sts_env_path),
            "stsSetEnvs": {k: v for k, v in sts_env_paths.items() if k != "default"},
            "cognitoEnv": cognito_env_path or str((root / "cognito.env").resolve()),
        },
        "exists": {
            "credentialsJson": credentials_path.exists(),
            "stsDefaultEnv": default_sts_env_path.exists(),
            "cognitoEnv": Path(cognito_env_path).exists() if cognito_env_path else (root / "cognito.env").exists(),
        },
        "contains": {
            "credentialsJson": "Full credentials broker response and cached runtime auth material.",
            "stsDefaultEnv": "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN/AWS_REGION.",
            "stsSetEnvs": "Per-credential-set AWS_* env files when credentialSets are present.",
            "cognitoEnv": "ID/ACCESS/REFRESH token env vars with COGNITO_* aliases.",
        },
    }


def _print_credentials_location_manifest_human(manifest: dict[str, Any]) -> None:
    paths = manifest.get("paths") if isinstance(manifest.get("paths"), dict) else {}
    exists = manifest.get("exists") if isinstance(manifest.get("exists"), dict) else {}
    freshness = manifest.get("freshness") if isinstance(manifest.get("freshness"), dict) else {}

    status = str(freshness.get("status") or "unknown")
    seconds_to_expiry = freshness.get("secondsToExpiry")
    expires_at = str(manifest.get("expiresAt") or "")

    sys.stdout.write("Credentials Artifacts\n")
    sys.stdout.write(f"- credentials.json: {paths.get('credentialsJson', '')}\n")
    sys.stdout.write(f"  contains: Full broker payload + cached runtime references.\n")
    sys.stdout.write(f"- sts.env: {paths.get('stsDefaultEnv', '')} (exists={exists.get('stsDefaultEnv', False)})\n")
    sys.stdout.write(f"  contains: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN/AWS_REGION.\n")

    sts_set_envs = paths.get("stsSetEnvs") if isinstance(paths.get("stsSetEnvs"), dict) else {}
    if sts_set_envs:
        sys.stdout.write("- sts credential-set env files:\n")
        for set_name in sorted(sts_set_envs):
            sys.stdout.write(f"  - {set_name}: {sts_set_envs[set_name]}\n")

    sys.stdout.write(f"- cognito.env: {paths.get('cognitoEnv', '')} (exists={exists.get('cognitoEnv', False)})\n")
    sys.stdout.write("  contains: ID/ACCESS/REFRESH token vars (+ COGNITO_* aliases).\n")
    sys.stdout.write(f"- expiresAt: {expires_at or '(unknown)'}\n")
    if isinstance(seconds_to_expiry, int):
        sys.stdout.write(f"- freshness: {status} ({seconds_to_expiry}s)\n")
    else:
        sys.stdout.write(f"- freshness: {status}\n")


def _refresh_token_from_doc(doc: dict[str, Any]) -> str:
    cognito_tokens = doc.get("cognitoTokens")
    if isinstance(cognito_tokens, dict):
        tok = str(cognito_tokens.get("refreshToken") or "").strip()
        if tok:
            return tok

    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        for entry in sets.values():
            if not isinstance(entry, dict):
                continue
            tok = _refresh_token_from_doc(entry)
            if tok:
                return tok
    return ""


def _renewal_policy(doc: dict[str, Any] | None) -> tuple[int, int, list[int]]:
    refresh_before_seconds = 60
    max_renew_attempts = 3
    backoff_seconds = [1, 2, 4]

    if not isinstance(doc, dict):
        return refresh_before_seconds, max_renew_attempts, backoff_seconds
    auth = doc.get("auth")
    if not isinstance(auth, dict):
        return refresh_before_seconds, max_renew_attempts, backoff_seconds
    policy = auth.get("renewalPolicy")
    if not isinstance(policy, dict):
        return refresh_before_seconds, max_renew_attempts, backoff_seconds

    try:
        refresh_before_seconds = int(policy.get("refreshBeforeSeconds"))
    except Exception:
        refresh_before_seconds = 60
    try:
        max_renew_attempts = int(policy.get("maxRenewAttempts"))
    except Exception:
        max_renew_attempts = 3
    raw_backoff = policy.get("backoffSeconds")
    parsed_backoff: list[int] = []
    if isinstance(raw_backoff, list):
        for raw in raw_backoff:
            try:
                parsed_backoff.append(int(raw))
            except Exception:
                continue
    if parsed_backoff:
        backoff_seconds = parsed_backoff

    refresh_before_seconds = max(refresh_before_seconds, 0)
    max_renew_attempts = max(max_renew_attempts, 1)
    backoff_seconds = [max(v, 0) for v in backoff_seconds if isinstance(v, int)]
    if not backoff_seconds:
        backoff_seconds = [0]
    return refresh_before_seconds, max_renew_attempts, backoff_seconds


def _derive_credentials_refresh_endpoint(credentials_endpoint: str) -> str:
    raw = str(credentials_endpoint or "").strip()
    if not raw:
        raise UsageError("missing credentials endpoint")
    parsed = urlparse(raw)
    path = str(parsed.path or "").rstrip("/")
    if not path.endswith("/v1/credentials"):
        raise UsageError(
            "cannot derive refresh endpoint from credentials endpoint "
            f"{raw!r} (expected path ending with /v1/credentials)"
        )
    refresh_path = f"{path}/refresh"
    return urlunparse(parsed._replace(path=refresh_path))


def _credentials_endpoint_for_refresh(
    *,
    current_doc: dict[str, Any] | None = None,
) -> str:
    endpoint = ""
    if isinstance(current_doc, dict):
        endpoint = _runtime_credentials_endpoint(current_doc)
    if not endpoint:
        endpoint = str(_env_or_none(ENABLER_CREDENTIALS_ENDPOINT) or "").strip()
    if not endpoint:
        raise UsageError(
            "missing credentials endpoint in cached credentials auth block and env "
            f"{ENABLER_CREDENTIALS_ENDPOINT}"
        )
    return endpoint


def _request_credentials_doc_text(
    *,
    endpoint: str,
    headers: dict[str, str],
    error_prefix: str,
) -> tuple[str, dict[str, Any]]:
    status, _hdrs, data = _http_post_json(
        url=endpoint,
        headers=headers,
        body=b"",
    )
    body_text = data.decode("utf-8", errors="replace")
    if status < 200 or status >= 300:
        raise OpError(f"{error_prefix}: status={status} body={body_text}")
    parsed = _load_json_object(raw=body_text, label="credentials response")
    return body_text, parsed


def _fetch_credentials_doc_text_for_cache_using_refresh_token(
    *,
    current_doc: dict[str, Any],
    api_key: str,
) -> tuple[str, dict[str, Any]]:
    refresh_token = _refresh_token_from_doc(current_doc)
    if not refresh_token:
        raise UsageError("cached credentials missing cognitoTokens.refreshToken")
    endpoint = _credentials_endpoint_for_refresh(current_doc=current_doc)
    refresh_endpoint = _derive_credentials_refresh_endpoint(endpoint)
    return _request_credentials_doc_text(
        endpoint=refresh_endpoint,
        headers={
            "x-api-key": api_key,
            "x-enabler-refresh-token": refresh_token,
        },
        error_prefix="credentials refresh request failed",
    )


def _fetch_credentials_doc_text_for_cache_using_basic_auth(
    *,
    endpoint: str,
    api_key: str,
) -> tuple[str, dict[str, Any]]:
    try:
        basic = auth_inputs.resolve_basic_credentials(
            username=None,
            password=None,
            env_or_none=_env_or_none,
            username_env_names=(ENABLER_COGNITO_USERNAME,),
            password_env_names=(ENABLER_COGNITO_PASSWORD,),
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e
    return _request_credentials_doc_text(
        endpoint=endpoint,
        headers={
            "authorization": _basic_auth_header(basic.username, basic.password),
            "x-api-key": api_key,
        },
        error_prefix="credentials request failed",
    )


def _fetch_credentials_doc_text_for_cache(
    g: GlobalOpts,
    *,
    current_doc: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    del g
    endpoint = _credentials_endpoint_for_refresh(current_doc=current_doc)
    api_key = str(_env_or_none(ENABLER_API_KEY) or "").strip()
    if not api_key:
        raise UsageError(f"missing api key (set {ENABLER_API_KEY})")

    refresh_error = ""
    if isinstance(current_doc, dict) and _refresh_token_from_doc(current_doc):
        try:
            return _fetch_credentials_doc_text_for_cache_using_refresh_token(
                current_doc=current_doc,
                api_key=api_key,
            )
        except (UsageError, OpError) as e:
            refresh_error = str(e)

    try:
        return _fetch_credentials_doc_text_for_cache_using_basic_auth(
            endpoint=endpoint,
            api_key=api_key,
        )
    except (UsageError, OpError) as basic_error:
        if refresh_error:
            raise OpError(f"refresh-token renewal failed: {refresh_error}; basic fallback failed: {basic_error}") from basic_error
        raise


def _resolve_runtime_credentials_doc(args: argparse.Namespace, g: GlobalOpts) -> dict[str, Any]:
    del args

    cache_path = _credentials_cache_file(g)
    cache_expired = False
    cached_doc: dict[str, Any] | None = None
    refresh_before_seconds = 60
    max_renew_attempts = 3
    backoff_seconds = [1, 2, 4]
    if cache_path.exists():
        try:
            cached_doc = _load_json_object(
                raw=cache_path.read_text(encoding="utf-8"),
                label=f"cached credentials JSON at {cache_path}",
            )
            refresh_before_seconds, max_renew_attempts, backoff_seconds = _renewal_policy(
                cached_doc
            )
            if not _credentials_doc_expired(
                cached_doc, skew_seconds=refresh_before_seconds
            ):
                return cached_doc
            cache_expired = True
        except UsageError:
            if not g.auto_refresh_creds:
                raise

    if not g.auto_refresh_creds:
        if cache_expired:
            raise UsageError(
                f"cached credentials expired: {cache_path} (omit --no-auto-refresh-creds or refresh manually)"
            )
        raise UsageError("missing credentials cache (run 'enabler-creds summary' or omit --no-auto-refresh-creds)")

    last_err = ""
    for attempt in range(1, max_renew_attempts + 1):
        try:
            body_text, parsed = _fetch_credentials_doc_text_for_cache(g, current_doc=cached_doc)
            path = _write_credentials_cache_from_text(g=g, raw_text=body_text)
            if not g.quiet:
                _eprint(f"refreshed credentials cache: {path}")
            return parsed
        except (UsageError, OpError) as e:
            last_err = str(e)
            if attempt == max_renew_attempts:
                break
            backoff = (
                backoff_seconds[attempt - 1]
                if attempt - 1 < len(backoff_seconds)
                else backoff_seconds[-1]
            )
            if backoff > 0:
                time.sleep(backoff)
    raise OpError(
        f"credential auto-refresh failed after {max_renew_attempts} attempts: {last_err}"
    )


def _issued_session_from_doc(
    *,
    doc: dict[str, Any],
) -> tuple[Any, dict[str, Any], str]:
    _require_boto3()
    creds = doc.get("credentials")
    if not isinstance(creds, dict):
        raise UsageError("invalid creds JSON: missing credentials object")

    access_key_id = str(creds.get("accessKeyId") or "").strip()
    secret_access_key = str(creds.get("secretAccessKey") or "").strip()
    session_token = str(creds.get("sessionToken") or "").strip()
    if not access_key_id or not secret_access_key or not session_token:
        raise UsageError("invalid creds JSON: missing accessKeyId/secretAccessKey/sessionToken")

    refs = doc.get("references")
    refs = refs if isinstance(refs, dict) else {}
    region = str(refs.get("awsRegion") or "").strip() or str(doc.get("awsRegion") or "").strip()
    if not region:
        region = str(os.environ.get("AWS_REGION") or "").strip()
    if not region:
        raise UsageError("missing region (ensure creds references.awsRegion, awsRegion, or AWS_REGION exists)")

    sess = boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region,
    )
    return sess, refs, region


def _event_bus_name_from_arn(arn: str) -> str:
    return event_bus_name_from_arn(arn)


def _parse_json_arg(raw: str | None, *, label: str) -> Any:
    s = (raw or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception as e:
        raise UsageError(f"invalid {label}: {e}") from e


def _parse_groups_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    out: list[str] = []
    for part in raw.split(","):
        v = part.strip()
        if v:
            out.append(v)
    # Stable order, but preserve first occurrence for deterministic writes
    seen: set[str] = set()
    uniq: list[str] = []
    for g in out:
        if g in seen:
            continue
        seen.add(g)
        uniq.append(g)
    return uniq


def _inbox_queue_name(agent_id: str) -> str:
    # Mirror Justfile logic:
    #   tr -c 'A-Za-z0-9_-' '-' | cut -c1-60
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    suffix = "".join((c if c in allowed else "-") for c in agent_id)
    suffix = suffix[:60]
    if not suffix:
        suffix = "agent"
    return f"agent-inbox-{suffix}"


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _default_credentials_cache_path() -> str:
    agent_id = str(_env_or_none(ENABLER_AGENT_ID) or "default").strip() or "default"
    return _default_credentials_cache_path_for_agent(agent_id)


def _default_credentials_cache_path_for_agent(agent_id: str) -> str:
    resolved_agent_id = str(agent_id or "").strip() or "default"
    return str((_default_session_root() / "sessions" / resolved_agent_id / "session.json").resolve())


def _default_session_root() -> Path:
    raw = str(_env_or_none(ENABLER_SESSION_ROOT) or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    xdg_state_home = str(_env_or_none("XDG_STATE_HOME") or "").strip()
    if xdg_state_home:
        return (Path(xdg_state_home).expanduser().resolve() / "enabler")
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Application Support" / "enabler").resolve()
    return (Path.home() / ".local" / "state" / "enabler").resolve()


def _cli_role() -> str:
    role = (os.environ.get("ENABLER_CLI_ROLE") or "agent").strip().lower()
    return "admin" if role == "admin" else "agent"


def _help_credentials_banner_enabled() -> bool:
    raw = os.environ.get("ENABLER_HELP_CREDENTIALS_BANNER")
    if raw is None:
        return True
    return _truthy(raw)


def _help_global_opts(*, role: str | None = None) -> GlobalOpts:
    resolved_role = "admin" if role == "admin" else _cli_role()
    creds_cache: str | None
    auto_refresh = True
    if resolved_role == "admin":
        creds_cache = os.devnull
        auto_refresh = False
    else:
        creds_cache = None
    return _apply_global_env(
        _namespace(
            profile=None,
            region=None,
            stack=None,
            creds_cache=creds_cache,
            auto_refresh_creds=auto_refresh,
            plain_json=False,
            quiet=True,
        )
    )


def _help_cached_credentials_doc(g: GlobalOpts) -> dict[str, Any] | None:
    path = _credentials_cache_file(g)
    if not path.exists():
        return None
    try:
        return _load_json_object(
            raw=path.read_text(encoding="utf-8"),
            label=f"cached credentials JSON at {path}",
        )
    except UsageError:
        return None


def _doc_has_aws_session_credentials(doc: dict[str, Any]) -> bool:
    creds = doc.get("credentials")
    if isinstance(creds, dict):
        access_key_id = str(creds.get("accessKeyId") or "").strip()
        secret_access_key = str(creds.get("secretAccessKey") or "").strip()
        session_token = str(creds.get("sessionToken") or "").strip()
        if access_key_id and secret_access_key and session_token:
            return True

    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        for entry in sets.values():
            if isinstance(entry, dict) and _doc_has_aws_session_credentials(entry):
                return True
    return False


def _aws_source_from_profile_region() -> str:
    profile = str(_env_or_none("AWS_PROFILE") or "").strip()
    region = str(_env_or_none("AWS_REGION") or "").strip()
    if profile and region:
        return f"profile({profile}/{region})"
    if profile:
        return f"profile({profile})"
    return ""


def _resolve_aws_credential_source_local(g: GlobalOpts) -> str:
    # Explicit env credentials always win in boto3's provider chain.
    access_key_id = str(_env_or_none("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY") or "").strip()
    secret_access_key = str(_env_or_none("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY") or "").strip()
    if access_key_id and secret_access_key:
        return "env(AWS_ACCESS_KEY_ID)"

    if _env_or_none("AWS_WEB_IDENTITY_TOKEN_FILE") or _env_or_none("AWS_ROLE_ARN"):
        return "web-identity"

    if _env_or_none(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "ECS_CONTAINER_METADATA_URI",
        "ECS_CONTAINER_METADATA_URI_V4",
    ):
        return "container-role"

    parts: list[str] = []
    profile_source = _aws_source_from_profile_region()
    if profile_source:
        parts.append(profile_source)

    cached = _help_cached_credentials_doc(g)
    if isinstance(cached, dict) and _doc_has_aws_session_credentials(cached):
        parts.append("session-token-file")

    if parts:
        return "+".join(parts)
    return "unknown"


def _doc_find_id_token(doc: dict[str, Any]) -> str:
    cognito_tokens = doc.get("cognitoTokens")
    if isinstance(cognito_tokens, dict):
        tok = str(cognito_tokens.get("idToken") or "").strip()
        if tok:
            return tok

    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        for entry in sets.values():
            if not isinstance(entry, dict):
                continue
            tok = _doc_find_id_token(entry)
            if tok:
                return tok
    return ""


def _clip_help_value(value: str, *, max_len: int = 36) -> str:
    s = str(value or "").strip()
    if len(s) <= max_len:
        return s
    return f"{s[: max_len - 3]}..."


def _help_role_from_context(ctx: click.Context) -> str:
    try:
        root = ctx.find_root()
        info_name = str(getattr(root, "info_name", "") or "").strip().lower()
        if "admin" in info_name:
            return "admin"
    except Exception:
        pass
    return _cli_role()


def _help_admin_stack_from_context(ctx: click.Context) -> tuple[str, str]:
    try:
        root = ctx.find_root()
        params = getattr(root, "params", {}) or {}
        if isinstance(params, dict):
            explicit = str(params.get("stack") or "").strip()
            if explicit:
                return explicit, "--stack"
    except Exception:
        pass

    stack_env = str(_env_or_none("STACK") or "").strip()
    if stack_env:
        return stack_env, "env(STACK)"
    return "AgentEnablementStack", "default"


def _help_param_from_context(ctx: click.Context | None, *names: str) -> str:
    cur = ctx
    while cur is not None:
        params = getattr(cur, "params", {}) or {}
        if isinstance(params, dict):
            for name in names:
                value = str(params.get(name) or "").strip()
                if value:
                    return value
        cur = cur.parent
    return ""


def _help_admin_stack_output_value(*, stack: str, key: str) -> str:
    try:
        session = _account_session()
        value = _stack_output_value(session, stack=stack, key=key)
    except Exception:
        return ""
    return str(value or "").strip()


def _agent_cache_status(g: GlobalOpts) -> str:
    doc = _help_cached_credentials_doc(g)
    if doc is None:
        path = _credentials_cache_file(g)
        if path.exists():
            return "invalid-json"
        return "missing"

    has_sts = _doc_has_aws_session_credentials(doc)
    has_id_token = bool(_doc_find_id_token(doc))
    if has_sts and has_id_token:
        return "sts+id-token"
    if has_sts:
        return "sts-only"
    if has_id_token:
        return "id-token-only"
    return "present"


def _help_agent_cache_source(ctx: click.Context | None) -> tuple[str, str]:
    explicit = _help_param_from_context(ctx, "creds_cache")
    if explicit:
        return explicit, "--creds-cache"
    env_path = str(_env_or_none(ENABLER_CREDS_CACHE) or "").strip()
    if env_path:
        return env_path, f"env({ENABLER_CREDS_CACHE})"
    return _default_credentials_cache_path(), "default"


def _build_help_credentials_banner_agent(*, ctx: click.Context | None) -> str:
    username = str(_env_or_none(ENABLER_COGNITO_USERNAME) or "").strip()
    username_display = _clip_help_value(username, max_len=28) if username else "missing"
    password_state = "set" if _env_or_none(ENABLER_COGNITO_PASSWORD) else "missing"
    api_key_state = "set" if _env_or_none(ENABLER_API_KEY) else "missing"

    cache_path, cache_source = _help_agent_cache_source(ctx)
    try:
        g = _help_global_opts(role="agent")
        cache_status = _agent_cache_status(g)
    except Exception:
        cache_status = "unknown"

    lines = [
        (
            "Credentials: cognito.username="
            + username_display
            + f" (env {ENABLER_COGNITO_USERNAME}); "
            + f"password={password_state}; apiKey={api_key_state}"
        ),
        "Cache: " + cache_path + f" (source={cache_source}; status={cache_status})",
    ]
    return "\n".join(f"\b{line}" for line in lines)


def _build_help_credentials_banner(*, role: str | None = None, ctx: click.Context | None = None) -> str:
    resolved_role = "admin" if role == "admin" else "agent"
    if resolved_role != "admin":
        return _build_help_credentials_banner_agent(ctx=ctx)

    try:
        g = _help_global_opts(role=resolved_role)
        aws_source = _resolve_aws_credential_source_local(g)
        cognito_identity = "n/a"
    except Exception:
        aws_source = "unknown"
        cognito_identity = "unknown"

    base = f"Credentials: aws={aws_source}; cognito={cognito_identity}"
    if ctx is None:
        stack_name = str(_env_or_none("STACK") or "").strip() or "AgentEnablementStack"
        stack_source = "env(STACK)" if _env_or_none("STACK") else "default"
    else:
        stack_name, stack_source = _help_admin_stack_from_context(ctx)
    lines = [base, f"Stack: {stack_name} (source={stack_source})"]

    path = str(getattr(ctx, "command_path", "") or "").strip().lower() if ctx is not None else ""
    explicit_pool_id = _help_param_from_context(ctx, "user_pool_id")
    if " cognito" in f" {path} ":
        if explicit_pool_id:
            lines.append(f"PoolId: {explicit_pool_id} (source=--user-pool-id)")
        else:
            pool_id = _help_admin_stack_output_value(stack=stack_name, key="UserPoolId")
            if pool_id:
                lines.append("PoolId: " + pool_id + " (source=stack output UserPoolId)")
            else:
                lines.append("PoolId: unknown (source=stack output UserPoolId)")

    # Use Click's '\b' paragraph marker so each line stays on its own line.
    return "\n".join(f"\b{line}" for line in lines)


def _format_help_with_credentials_banner(
    *,
    obj: Any,
    ctx: click.Context,
    formatter: click.HelpFormatter,
    original: Any,
) -> Any:
    if not _help_credentials_banner_enabled():
        return original(obj, ctx, formatter)

    original_help = getattr(obj, "help", None)
    banner = _build_help_credentials_banner(role=_help_role_from_context(ctx), ctx=ctx)
    if original_help:
        obj.help = f"{banner}\n\n{original_help}"
    else:
        obj.help = banner
    try:
        return original(obj, ctx, formatter)
    finally:
        obj.help = original_help


_ORIGINAL_TYPER_GROUP_FORMAT_HELP = typer.core.TyperGroup.format_help
_ORIGINAL_TYPER_COMMAND_FORMAT_HELP = typer.core.TyperCommand.format_help


def _typer_group_format_help_with_banner(
    self: typer.core.TyperGroup,
    ctx: click.Context,
    formatter: click.HelpFormatter,
) -> Any:
    return _format_help_with_credentials_banner(
        obj=self,
        ctx=ctx,
        formatter=formatter,
        original=_ORIGINAL_TYPER_GROUP_FORMAT_HELP,
    )


def _typer_command_format_help_with_banner(
    self: typer.core.TyperCommand,
    ctx: click.Context,
    formatter: click.HelpFormatter,
) -> Any:
    return _format_help_with_credentials_banner(
        obj=self,
        ctx=ctx,
        formatter=formatter,
        original=_ORIGINAL_TYPER_COMMAND_FORMAT_HELP,
    )


typer.core.TyperGroup.format_help = _typer_group_format_help_with_banner
typer.core.TyperCommand.format_help = _typer_command_format_help_with_banner


def _apply_global_env(args: argparse.Namespace) -> GlobalOpts:
    if getattr(args, "profile", None):
        os.environ["AWS_PROFILE"] = str(args.profile).strip()
    if getattr(args, "region", None):
        os.environ["AWS_REGION"] = str(args.region).strip()
    # If the user didn't explicitly pass --stack, defer to env.
    stack = (getattr(args, "stack", None) or _env_or_none("STACK") or "AgentEnablementStack").strip()
    agent_id = str(getattr(args, "agent_id", None) or _env_or_none(ENABLER_AGENT_ID) or "").strip()
    creds_cache_path = (
        getattr(args, "creds_cache", None)
        or _env_or_none(ENABLER_CREDS_CACHE)
        or _default_credentials_cache_path_for_agent(agent_id)
    )
    auto_refresh_creds = bool(
        getattr(args, "auto_refresh_creds", not _truthy(os.environ.get(ENABLER_NO_AUTO_REFRESH_CREDS)))
    )
    return GlobalOpts(
        stack=stack,
        pretty=not bool(getattr(args, "plain_json", False)),
        quiet=bool(getattr(args, "quiet", False)),
        creds_cache_path=str(creds_cache_path).strip(),
        auto_refresh_creds=auto_refresh_creds,
        agent_id=agent_id,
    )


def _apply_admin_global_env(args: argparse.Namespace) -> GlobalOpts:
    ns = _namespace(
        profile=getattr(args, "profile", None),
        region=getattr(args, "region", None),
        stack=getattr(args, "stack", None),
        creds_cache=os.devnull,
        auto_refresh_creds=False,
        plain_json=bool(getattr(args, "plain_json", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )
    return _apply_global_env(ns)


def cmd_agent_credentials(args: argparse.Namespace, g: GlobalOpts) -> int:
    try:
        basic = auth_inputs.resolve_basic_credentials(
            username=args.username,
            password=args.password,
            env_or_none=_env_or_none,
            username_env_names=(ENABLER_COGNITO_USERNAME,),
            password_env_names=(ENABLER_COGNITO_PASSWORD,),
        )
        resolved = auth_inputs.resolve_agent_request_auth_client(
            endpoint=args.endpoint,
            endpoint_env_names=(ENABLER_CREDENTIALS_ENDPOINT,),
            api_key=args.api_key,
            api_key_env_names=(ENABLER_API_KEY,),
            env_or_none=_env_or_none,
            missing_endpoint_error=(
                f"missing credentials endpoint (pass --endpoint or set {ENABLER_CREDENTIALS_ENDPOINT})"
            ),
            missing_api_key_error=f"missing api key (pass --api-key or set {ENABLER_API_KEY})",
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e

    status, hdrs, data = _http_post_json(
        url=resolved.endpoint,
        headers={
            "authorization": _basic_auth_header(basic.username, basic.password),
            "x-api-key": resolved.api_key,
        },
        body=b"",
    )

    body_text = data.decode("utf-8", errors="replace")
    if status < 200 or status >= 300:
        raise OpError(f"credentials request failed: status={status} body={body_text}")
    parsed_json: Any | None = None
    parsed_obj: dict[str, Any] | None = None
    try:
        parsed_json = json.loads(body_text)
        parsed_obj = _load_json_object(raw=body_text, label="credentials response")
        _ = _write_credentials_cache_from_text(g=g, raw_text=body_text)
    except UsageError:
        if not g.quiet:
            _eprint("warning: skipped credentials cache update because response was not valid JSON")
    except Exception:
        parsed_json = None

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        _write_secure_text(path=out_path, text=body_text.rstrip("\n") + "\n")

    if not isinstance(parsed_obj, dict):
        parsed_obj = _load_json_object(raw=body_text, label="credentials response")
    sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=parsed_obj)
    sts_env_path = sts_env_paths.get("default", "")
    cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=parsed_obj))

    if args.include_headers:
        try:
            parsed = json.loads(body_text)
        except Exception:
            parsed = body_text
        _print_json(
            {"statusCode": status, "headers": hdrs, "body": parsed},
            pretty=g.pretty,
        )
        return 0

    json_output = bool(getattr(args, "json_output", False))
    summary_output = bool(getattr(args, "summary", False)) or not json_output
    if summary_output:
        parsed = parsed_obj or _load_json_object(raw=body_text, label="credentials response")
        manifest = _credentials_location_manifest(
            g=g,
            doc=parsed,
            sts_env_paths=sts_env_paths,
            cognito_env_path=cognito_env_path,
        )
        _print_credentials_location_manifest_human(manifest)
        return 0

    if parsed_json is not None:
        _print_json(parsed_json, pretty=g.pretty)
        return 0
    sys.stdout.write(body_text.rstrip("\n") + "\n")
    return 0


def cmd_agent_credential_process(args: argparse.Namespace, g: GlobalOpts) -> int:
    try:
        basic = auth_inputs.resolve_basic_credentials(
            username=args.username,
            password=args.password,
            env_or_none=_env_or_none,
            username_env_names=(ENABLER_COGNITO_USERNAME,),
            password_env_names=(ENABLER_COGNITO_PASSWORD,),
        )
        resolved = auth_inputs.resolve_agent_request_auth_client(
            endpoint=args.endpoint,
            endpoint_env_names=(ENABLER_CREDENTIALS_ENDPOINT,),
            api_key=args.api_key,
            api_key_env_names=(ENABLER_API_KEY,),
            env_or_none=_env_or_none,
            missing_endpoint_error=(
                f"missing credentials endpoint (pass --endpoint or set {ENABLER_CREDENTIALS_ENDPOINT})"
            ),
            missing_api_key_error=f"missing api key (pass --api-key or set {ENABLER_API_KEY})",
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e

    status, _hdrs, data = _http_post_json(
        url=resolved.endpoint,
        headers={
            "authorization": _basic_auth_header(basic.username, basic.password),
            "x-api-key": resolved.api_key,
        },
        body=b"",
    )
    body_text = data.decode("utf-8", errors="replace")
    if status < 200 or status >= 300:
        raise OpError(f"credentials request failed: status={status} body={body_text}")

    parsed = _load_json_object(raw=body_text, label="credentials response")
    _ = _write_credentials_cache_from_text(g=g, raw_text=body_text)

    selected_set = str(getattr(args, "set_name", "") or getattr(args, "set", "")).strip()
    selected_doc = _credential_set_doc(root_doc=parsed, set_name=selected_set)
    process_obj = _credential_process_doc_to_output(selected_doc)
    sys.stdout.write(json.dumps(process_obj, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


def _messages_ref_from_refs(refs: dict[str, Any]) -> dict[str, Any]:
    messages_ref = refs.get("messages")
    if isinstance(messages_ref, dict):
        return messages_ref
    return {}


def _resources_from_grants_for_service(doc: dict[str, Any], *, service: str) -> list[str]:
    out: list[str] = []
    grants = doc.get("grants")
    if not isinstance(grants, list):
        return out
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        if str(grant.get("service") or "").strip() != service:
            continue
        resources = grant.get("resources")
        if not isinstance(resources, list):
            continue
        for raw in resources:
            v = str(raw or "").strip()
            if v:
                out.append(v)
    return out


def _event_bus_arn_from_doc(doc: dict[str, Any], refs: dict[str, Any]) -> str:
    messages_ref = _messages_ref_from_refs(refs)
    event_bus_arn = str(messages_ref.get("eventBusArn") or "").strip()
    if event_bus_arn:
        return event_bus_arn
    eventbridge = refs.get("eventbridge")
    if isinstance(eventbridge, dict):
        event_bus_arn = str(eventbridge.get("eventBusArn") or "").strip()
        if event_bus_arn:
            return event_bus_arn
    resources = _resources_from_grants_for_service(doc, service="events")
    return resources[0] if resources else ""


def _inbox_queue_arn_from_doc(doc: dict[str, Any], refs: dict[str, Any]) -> str:
    messages_ref = _messages_ref_from_refs(refs)
    inbox_arn = str(messages_ref.get("inboxQueueArn") or "").strip()
    if inbox_arn:
        return inbox_arn
    resources = _resources_from_grants_for_service(doc, service="sqs")
    for arn in resources:
        if ":queue/" in arn:
            # Non-standard ARN shape safeguard.
            return arn
        if ":sqs:" in arn and ":agent-inbox-" in arn:
            return arn
    for grant in doc.get("grants") or []:
        if not isinstance(grant, dict) or str(grant.get("service") or "").strip() != "sqs":
            continue
        actions = {str(a).strip() for a in (grant.get("actions") or [])}
        if "sqs:ReceiveMessage" not in actions:
            continue
        resources = grant.get("resources") or []
        if isinstance(resources, list):
            for raw in resources:
                arn = str(raw or "").strip()
                if arn:
                    return arn
    return ""


def _queue_name_from_arn(queue_arn: str) -> str:
    arn = str(queue_arn or "").strip()
    if not arn:
        return ""
    parts = arn.split(":")
    if len(parts) < 6:
        return ""
    return parts[5].strip()


def _queue_url_from_arn(*, sess: Any, queue_arn: str) -> str:
    queue_name = _queue_name_from_arn(queue_arn)
    if not queue_name:
        return ""
    try:
        sqs = sess.client("sqs")
        return str(sqs.get_queue_url(QueueName=queue_name).get("QueueUrl") or "").strip()
    except Exception:
        return ""


def _message_ack_token_encode(*, queue_url: str, receipt_handle: str) -> str:
    payload = json.dumps(
        {
            "queueUrl": queue_url,
            "receiptHandle": receipt_handle,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _message_ack_token_decode(token: str) -> tuple[str, str]:
    raw = (token or "").strip()
    if not raw:
        raise UsageError("missing ack token")
    try:
        padded = raw + ("=" * (-len(raw) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        parsed = json.loads(decoded)
    except Exception as e:
        raise UsageError(f"invalid ack token: {e}") from e
    if not isinstance(parsed, dict):
        raise UsageError("invalid ack token: expected JSON object")
    queue_url = str(parsed.get("queueUrl") or "").strip()
    receipt_handle = str(parsed.get("receiptHandle") or "").strip()
    if not queue_url or not receipt_handle:
        raise UsageError("invalid ack token: missing queueUrl or receiptHandle")
    return queue_url, receipt_handle


def cmd_messages_send(args: argparse.Namespace, g: GlobalOpts) -> int:
    _require_boto3()
    root_doc = _resolve_runtime_credentials_doc(args, g)
    active_doc = _select_runtime_agent_doc(root_doc)
    sess, refs, _region = _issued_session_from_doc(doc=active_doc)

    messages_ref = _messages_ref_from_refs(refs)
    event_bus_arn = (args.event_bus_arn or _event_bus_arn_from_doc(active_doc, refs)).strip()
    if not event_bus_arn:
        raise UsageError("missing event bus ARN (pass --event-bus-arn or ensure events grant is present)")

    to_username = str(args.to or "").strip()
    if not to_username:
        raise UsageError("missing --to")
    if ":" in to_username:
        raise UsageError("--to must be a Cognito username (not agent:/group: syntax)")

    message: dict[str, Any]
    kind = ""
    if args.message_json:
        parsed_message = _parse_json_arg(args.message_json, label="message JSON")
        if not isinstance(parsed_message, dict):
            raise UsageError("message JSON must be an object")
        message = parsed_message
        kind = str(args.kind or "").strip() or "json.v1"
    else:
        text = str(args.text or "").strip()
        if not text:
            raise UsageError("provide --text or --message-json")
        message = {"text": text}
        kind = str(args.kind or "").strip() or "text.v1"

    meta = _parse_json_arg(args.meta_json, label="meta JSON")
    if meta is not None and not isinstance(meta, dict):
        raise UsageError("meta JSON must be an object")

    principal = root_doc.get("principal")
    principal = principal if isinstance(principal, dict) else {}
    sub = str(principal.get("sub") or "").strip()
    if not sub:
        raise UsageError("missing principal.sub in creds JSON")
    sender_username = str(principal.get("username") or "").strip()

    detail: dict[str, Any] = {
        "toUsername": to_username,
        "kind": kind,
        "message": message,
    }
    if sender_username:
        detail["senderUsername"] = sender_username
    if meta:
        detail["meta"] = meta

    bus_name = str(messages_ref.get("eventBusName") or "").strip() or _event_bus_name_from_arn(event_bus_arn)
    entry = {
        "EventBusName": bus_name or event_bus_arn,
        "Source": f"agents.messages.sub.{sub}",
        "DetailType": "agent.message.v2",
        "Detail": json.dumps(detail, separators=(",", ":")),
    }

    events = sess.client("events")
    try:
        resp = events.put_events(Entries=[entry])
    except Exception as e:
        raise OpError(f"events put-events failed: {e}") from e

    result_entry = {}
    entries = resp.get("Entries")
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        result_entry = entries[0]
    err_code = str(result_entry.get("ErrorCode") or "").strip()

    out = {
        "kind": "enabler.messages.send.v1",
        "ok": not bool(err_code),
        "request": {
            "toUsername": to_username,
            "source": entry["Source"],
            "detailType": entry["DetailType"],
            "eventBus": entry["EventBusName"],
            "kind": kind,
        },
        "result": result_entry,
        "failedEntryCount": int(resp.get("FailedEntryCount") or 0),
    }
    _print_json(out, pretty=g.pretty)
    return 0


def cmd_messages_recv(args: argparse.Namespace, g: GlobalOpts) -> int:
    _require_boto3()
    root_doc = _resolve_runtime_credentials_doc(args, g)
    active_doc = _select_runtime_agent_doc(root_doc)
    sess, refs, _region = _issued_session_from_doc(doc=active_doc)

    messages_ref = _messages_ref_from_refs(refs)
    queue_url = (args.queue_url or str(messages_ref.get("inboxQueueUrl") or "")).strip()
    if not queue_url:
        queue_arn = _inbox_queue_arn_from_doc(active_doc, refs)
        queue_url = _queue_url_from_arn(sess=sess, queue_arn=queue_arn)
    if not queue_url:
        raise UsageError(
            "missing queue url (pass --queue-url or ensure references.messages.inboxQueueUrl "
            "or inbox SQS grant is present)"
        )

    max_number = int(args.max_number)
    wait_seconds = int(args.wait_seconds)
    if max_number < 1 or max_number > 10:
        raise UsageError("--max-number must be between 1 and 10")
    if wait_seconds < 0 or wait_seconds > 20:
        raise UsageError("--wait-seconds must be between 0 and 20")

    req: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max_number,
        "WaitTimeSeconds": wait_seconds,
        "MessageAttributeNames": ["All"],
        "AttributeNames": ["All"],
    }
    if args.visibility_timeout is not None:
        vt = int(args.visibility_timeout)
        if vt < 0:
            raise UsageError("--visibility-timeout must be >= 0")
        req["VisibilityTimeout"] = vt

    sqs = sess.client("sqs")
    ack_all = bool(args.ack_all)
    out_messages: list[dict[str, Any]] = []
    batches = 0
    truncated = False
    max_batches = _MESSAGES_RECV_ACK_ALL_MAX_BATCHES if ack_all else _MESSAGES_RECV_MAX_BATCHES

    while True:
        if batches >= max_batches:
            truncated = True
            break

        req_now = dict(req)
        if batches > 0:
            # After first long poll, continue scanning visible backlog immediately.
            req_now["WaitTimeSeconds"] = 0

        try:
            resp = sqs.receive_message(**req_now)
        except Exception as e:
            raise OpError(f"sqs receive-message failed: {e}") from e
        batches += 1

        batch_messages = [m for m in (resp.get("Messages") or []) if isinstance(m, dict)]
        if not batch_messages:
            break

        for m in batch_messages:
            raw_body = str(m.get("Body") or "")
            parsed_body: Any = raw_body
            try:
                parsed_body = json.loads(raw_body)
            except Exception:
                parsed_body = raw_body

            receipt = str(m.get("ReceiptHandle") or "").strip()
            ack_token = _message_ack_token_encode(queue_url=queue_url, receipt_handle=receipt) if receipt else ""
            ack_obj: dict[str, Any] = {}
            if ack_token:
                ack_obj["token"] = ack_token
            if ack_all and receipt:
                try:
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
                    ack_obj["deleted"] = True
                except Exception as e:
                    ack_obj["deleted"] = False
                    ack_obj["deleteError"] = str(e)

            if isinstance(parsed_body, dict):
                body_out = dict(parsed_body)
            else:
                body_out = {"message": parsed_body}
            body_out["_ack"] = ack_obj
            out_messages.append(body_out)

    payload: dict[str, Any] = {
        "kind": "enabler.messages.recv.v1",
        "ok": True,
        "received": len(out_messages),
        "ackAllRequested": ack_all,
        "messages": out_messages,
    }
    if ack_all:
        payload["drain"] = {
            "enabled": True,
            "batches": batches,
            "truncated": truncated,
        }
    _print_json(payload, pretty=g.pretty)
    return 0


def cmd_messages_ack(args: argparse.Namespace, g: GlobalOpts) -> int:
    _require_boto3()
    root_doc = _resolve_runtime_credentials_doc(args, g)
    active_doc = _select_runtime_agent_doc(root_doc)
    sess, refs, _region = _issued_session_from_doc(doc=active_doc)

    queue_url = ""
    receipt_handle = ""
    ack_token = str(args.ack_token or "").strip()
    if ack_token:
        queue_url, receipt_handle = _message_ack_token_decode(ack_token)
    else:
        receipt_handle = str(args.receipt_handle or "").strip()
        if not receipt_handle:
            raise UsageError("missing receipt handle (pass --ack-token or --receipt-handle)")
        messages_ref = _messages_ref_from_refs(refs)
        queue_url = (args.queue_url or str(messages_ref.get("inboxQueueUrl") or "")).strip()
        if not queue_url:
            queue_arn = _inbox_queue_arn_from_doc(active_doc, refs)
            queue_url = _queue_url_from_arn(sess=sess, queue_arn=queue_arn)
        if not queue_url:
            raise UsageError(
                "missing queue url (pass --queue-url or ensure references.messages.inboxQueueUrl "
                "or inbox SQS grant is present)"
            )

    sqs = sess.client("sqs")
    try:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
    except Exception as e:
        raise OpError(f"sqs delete-message failed: {e}") from e

    _print_json(
        {
            "kind": "enabler.messages.ack.v1",
            "ok": True,
            "queueUrl": queue_url,
        },
        pretty=g.pretty,
    )
    return 0


def _s3_upload_scope_from_grants(doc: dict[str, Any]) -> tuple[str, str]:
    grants = doc.get("grants")
    if not isinstance(grants, list):
        return "", ""
    for grant in grants:
        if not isinstance(grant, dict) or str(grant.get("service") or "").strip() != "s3":
            continue
        resources = grant.get("resources")
        if not isinstance(resources, list):
            continue
        for raw in resources:
            resource = str(raw or "").strip()
            marker = "arn:aws:s3:::"
            if not resource.startswith(marker):
                continue
            tail = resource[len(marker):]
            if "/" not in tail:
                continue
            bucket, key_expr = tail.split("/", 1)
            if not bucket:
                continue
            prefix = key_expr.rstrip("*")
            return bucket, prefix
    return "", ""


def cmd_files_share(args: argparse.Namespace, g: GlobalOpts) -> int:
    _require_boto3()
    local_path = Path(str(args.file_path)).expanduser().resolve()
    if not local_path.exists() or not local_path.is_file():
        raise UsageError(f"file not found: {local_path}")

    root_doc = _resolve_runtime_credentials_doc(args, g)
    active_doc = _select_runtime_agent_doc(root_doc)

    region = str(
        (root_doc.get("references") or {}).get("awsRegion") or root_doc.get("awsRegion") or ""
    ).strip()
    if not region:
        raise UsageError("missing awsRegion in credentials references")
    active_refs = active_doc.get("references")
    if not isinstance(active_refs, dict):
        active_refs = {}
        active_doc["references"] = active_refs
    if not str(active_refs.get("awsRegion") or "").strip():
        active_refs["awsRegion"] = region
    public_base_url = _files_public_base_url_from_runtime_refs(args, g)

    sess, _refs, _session_region = _issued_session_from_doc(doc=active_doc)

    bucket, allowed_prefix = _s3_upload_scope_from_grants(active_doc)
    if not bucket or not allowed_prefix:
        raise UsageError("missing runtime S3 upload scope in credentials grants")

    object_uuid = uuid4_base58_22()
    filename = str(args.name or local_path.name or "file").strip()
    key = f"{allowed_prefix.rstrip('/')}/{object_uuid}/{filename}".lstrip("/")

    s3 = sess.client("s3")
    try:
        s3.upload_file(str(local_path), bucket, key)
    except Exception as e:
        raise OpError(f"failed to upload file to s3://{bucket}/{key}: {e}") from e

    s3_uri = f"s3://{bucket}/{key}"
    public_url = f"{public_base_url.rstrip('/')}/{key.lstrip('/')}" if public_base_url else ""

    if bool(getattr(args, "json_output", False)):
        _print_json(
            {
                "kind": "enabler.files.upload.v1",
                "s3Uri": s3_uri,
                "publicUrl": public_url,
                "publicBaseUrl": public_base_url,
                "bucket": bucket,
                "key": key,
            },
            pretty=g.pretty,
        )
    else:
        sys.stdout.write((public_url or s3_uri) + "\n")
    return 0


def cmd_shortlinks_create(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint = _shortlinks_create_url_from_runtime_refs(args, g)
    if not endpoint:
        raise UsageError("missing shortlinks create endpoint in credentials references")
    redirect_base_url = _shortlinks_redirect_base_url_from_runtime_refs(args, g)
    if not redirect_base_url:
        raise UsageError("missing shortlinks redirect base url in credentials references")
    root_doc = _resolve_runtime_credentials_doc(args, g)
    id_token = _doc_find_id_token(root_doc)
    if not id_token:
        raise UsageError("cached credentials missing cognitoTokens.idToken (run 'enabler-creds summary')")
    try:
        preflight = auth_inputs.preflight_cognito_http_request(
            endpoint=endpoint,
            id_token=id_token,
            endpoint_name="shortlinks create endpoint",
            token_name="Cognito ID token",
            expected_base_path="/v1/links",
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e

    body_obj: dict[str, Any] = {"targetUrl": str(args.target_url)}
    alias = str(args.alias or "").strip()
    if alias:
        body_obj["alias"] = alias

    status, _hdrs, data = _http_post_json(
        url=preflight.endpoint,
        headers={
            "authorization": f"Bearer {preflight.id_token}",
            "content-type": "application/json",
        },
        body=json.dumps(body_obj, separators=(",", ":")).encode("utf-8"),
    )
    body_text = data.decode("utf-8", errors="replace")
    if status < 200 or status >= 300:
        raise OpError(f"shortlinks create failed: status={status} body={body_text}")
    try:
        parsed = json.loads(body_text)
    except Exception:
        sys.stdout.write(body_text.rstrip("\n") + "\n")
        return 0

    if not isinstance(parsed, dict):
        _print_json(parsed, pretty=g.pretty)
        return 0

    short_path = str(parsed.get("shortPath") or "").strip()
    if not short_path:
        code = str(parsed.get("code") or "").strip()
        if code:
            short_path = f"/l/{code}"

    base = redirect_base_url.rstrip("/")
    short_url = base
    if short_path:
        normalized_path = short_path.lstrip("/")
        if base.endswith("/l") and normalized_path.startswith("l/"):
            normalized_path = normalized_path[2:].lstrip("/")
        short_url = f"{base}/{normalized_path}"

    out: dict[str, Any] = {
        "shortUrl": short_url,
        "redirectBaseUrl": redirect_base_url,
    }
    for key, value in parsed.items():
        if key == "createdBy":
            continue
        out[key] = value

    if bool(getattr(args, "json_output", False)):
        if g.pretty:
            sys.stdout.write(json.dumps(out, indent=2) + "\n")
        else:
            sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
        return 0

    code = str(out.get("code") or "").strip()
    if not code and short_path:
        normalized_path = short_path.strip().lstrip("/")
        if normalized_path.startswith("l/"):
            code = normalized_path[2:].lstrip("/")
        elif normalized_path:
            code = normalized_path.rsplit("/", 1)[-1]

    sys.stdout.write(f"code: {code}\n")
    sys.stdout.write(f"shortURL: {short_url}\n")
    return 0


def cmd_shortlinks_resolve_url(args: argparse.Namespace, g: GlobalOpts) -> int:
    base_url = _shortlinks_redirect_base_url_from_runtime_refs(args, g)
    if not base_url:
        raise UsageError("missing shortlinks redirect base url in credentials references")
    code = str(args.code or "").strip()
    if not code:
        raise UsageError("missing code")
    sys.stdout.write(f"{base_url.rstrip('/')}/{code.lstrip('/')}\n")
    return 0


def _taskboard_endpoint_for_args(args: argparse.Namespace, g: GlobalOpts) -> str:
    endpoint = _taskboard_endpoint_from_runtime_refs(args, g)
    if not endpoint:
        raise UsageError("missing taskboard endpoint in credentials references")
    return endpoint


def _taskboard_id_token_for_args(args: argparse.Namespace, g: GlobalOpts) -> str:
    root_doc = _resolve_runtime_credentials_doc(args, g)
    tok = _doc_find_id_token(root_doc)
    if not tok:
        raise UsageError("cached credentials missing cognitoTokens.idToken (run 'enabler-creds summary')")
    return tok


def _taskboard_id_token_from_cache(g: GlobalOpts) -> str:
    return _taskboard_id_token_for_args(_namespace(), g)


def _taskboard_auth_for_args(args: argparse.Namespace, g: GlobalOpts) -> tuple[str, str]:
    endpoint = _taskboard_endpoint_for_args(args, g)
    id_token = _taskboard_id_token_for_args(args, g)
    try:
        preflight = auth_inputs.preflight_cognito_http_request(
            endpoint=endpoint,
            id_token=id_token,
            endpoint_name="taskboard endpoint",
            token_name="Cognito ID token",
            expected_base_path="/v1/taskboard",
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e
    return preflight.endpoint, preflight.id_token


def _taskboard_request(
    *,
    method: str,
    endpoint: str,
    id_token: str,
    path: str,
    query: dict[str, Any] | None = None,
    body_obj: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ep = endpoint.rstrip("/")
    p = path if path.startswith("/") else f"/{path}"
    query_clean = {
        k: str(v)
        for k, v in (query or {}).items()
        if v is not None and str(v).strip() != ""
    }
    url = f"{ep}{p}"
    if query_clean:
        url += f"?{urlencode(query_clean)}"

    body_bytes = None
    headers = {
        "authorization": f"Bearer {id_token}",
    }
    if body_obj is not None:
        body_bytes = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        headers["content-type"] = "application/json"

    status, _hdrs, data = _http_request(
        method=method,
        url=url,
        headers=headers,
        body=body_bytes,
    )
    text = data.decode("utf-8", errors="replace")
    parsed: Any
    try:
        parsed = json.loads(text) if text else {}
    except Exception:
        parsed = {"raw": text}

    if status < 200 or status >= 300:
        if isinstance(parsed, dict):
            msg = str(parsed.get("message") or parsed.get("error") or text).strip()
        else:
            msg = str(parsed)
        if "Invalid key=value pair" in msg and "Authorization header" in msg:
            msg = (
                f"{msg} "
                "(endpoint likely is not a Cognito-authorized taskboard route; "
                "verify credentials references)"
            )
        raise OpError(f"taskboard request failed: status={status} method={method} path={p} message={msg}")

    if isinstance(parsed, dict):
        return parsed
    return {"result": parsed}


def _taskboard_target(task_id: str | None, query: str | None, target: str | None) -> dict[str, str]:
    tid = str(task_id or "").strip()
    if tid:
        return {"taskId": tid}
    q = str(query or "").strip() or str(target or "").strip()
    if not q:
        raise UsageError("provide --task-id or a query (--q or positional target)")
    return {"q": q}


def _taskboard_wants_json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json_output", False))


def _taskboard_cell(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    return text


def _taskboard_local_short_timestamp(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"
    dt = _parse_iso8601(raw)
    if dt is None:
        return raw
    try:
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw


def _taskboard_print_table(*, headers: list[str], rows: list[list[str]], empty_message: str) -> None:
    if not rows:
        sys.stdout.write(f"{empty_message}\n")
        return
    widths: list[int] = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    divider_line = "  ".join("-" * widths[i] for i in range(len(headers)))
    sys.stdout.write(header_line + "\n")
    sys.stdout.write(divider_line + "\n")
    for row in rows:
        sys.stdout.write("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))) + "\n")


def _taskboard_print_next_token_hint(next_token: str, *, command_hint: str) -> None:
    tok = str(next_token or "").strip()
    if not tok:
        return
    sys.stdout.write(f"next-token: {tok}\n")
    sys.stdout.write(f"rerun with: {command_hint} --next-token '{tok}'\n")


def cmd_taskboard_create(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    out = _taskboard_request(
        method="POST",
        endpoint=endpoint,
        id_token=id_token,
        path="/boards",
        body_obj={"name": str(args.name or "")},
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    board_id = str(out.get("boardId") or "").strip()
    name = str(out.get("name") or "").strip()
    request_id = str(out.get("requestId") or "").strip()
    msg = f"created board {board_id or '(unknown)'}"
    if name:
        msg += f' name="{name}"'
    if request_id:
        msg += f" requestId={request_id}"
    sys.stdout.write(msg + "\n")
    return 0


def cmd_taskboard_add(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)

    lines: list[str] = []
    if args.file:
        for raw in Path(args.file).read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if s:
                lines.append(s)
    elif args.lines:
        for raw in args.lines:
            s = str(raw).strip()
            if s:
                lines.append(s)
    elif not sys.stdin.isatty():
        for raw in sys.stdin.read().splitlines():
            s = raw.strip()
            if s:
                lines.append(s)

    if not lines:
        raise UsageError("no task lines provided (pass lines, --file, or stdin)")

    out = _taskboard_request(
        method="POST",
        endpoint=endpoint,
        id_token=id_token,
        path=f"/boards/{args.board_id}/tasks",
        body_obj={"lines": lines},
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    board_id = str(out.get("boardId") or args.board_id or "").strip()
    task_ids = out.get("taskIds")
    task_id_count = len(task_ids) if isinstance(task_ids, list) else 0
    try:
        added = int(str(out.get("added") or "").strip())
    except Exception:
        added = task_id_count
    msg = f"added {max(added, 0)} task(s) to board {board_id or '(unknown)'}"
    if task_id_count == 1:
        msg += f" taskId={_taskboard_cell(task_ids[0])}"
    sys.stdout.write(msg + "\n")
    return 0


def cmd_taskboard_list(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    out = _taskboard_request(
        method="GET",
        endpoint=endpoint,
        id_token=id_token,
        path=f"/boards/{args.board_id}/tasks",
        query={
            "q": args.query or args.search,
            "status": args.status,
            "limit": args.limit,
            "nextToken": args.next_token,
        },
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    count = 0
    items = out.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            count += 1
            task_id = _taskboard_cell(item.get("taskId"))
            status = _taskboard_cell(item.get("status"))
            owner = _taskboard_cell(item.get("claimedByUsername") or item.get("addedByUsername"))
            summary = _taskboard_cell(item.get("line"))
            updated = _taskboard_local_short_timestamp(item.get("updatedAt") or item.get("addedAt"))
            sys.stdout.write(
                f"- {task_id} [{status}] owner={owner} updated={updated} summary={summary}\n"
            )
    if count == 0:
        sys.stdout.write("No tasks.\n")
    sys.stdout.write(f"items: {count}\n")
    _taskboard_print_next_token_hint(
        str(out.get("nextToken") or ""),
        command_hint=f"enabler taskboard list {args.board_id}",
    )
    return 0


def _cmd_taskboard_mutate(args: argparse.Namespace, g: GlobalOpts, action: str) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    target = _taskboard_target(args.task_id, args.query, args.target)
    out = _taskboard_request(
        method="PATCH",
        endpoint=endpoint,
        id_token=id_token,
        path=f"/boards/{args.board_id}/tasks/{action}",
        body_obj=target,
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    task = out.get("task")
    task_dict = task if isinstance(task, dict) else {}
    board_id = str(task_dict.get("boardId") or args.board_id or "").strip()
    task_id = str(task_dict.get("taskId") or "").strip()
    status = str(task_dict.get("status") or "").strip()
    verb = {
        "claim": "claimed",
        "unclaim": "unclaimed",
        "done": "done",
        "fail": "failed",
    }.get(action, action)
    msg = f"{verb} task {task_id or '(unknown)'} on board {board_id or '(unknown)'}"
    if status:
        msg += f" status={status}"
    sys.stdout.write(msg + "\n")
    return 0


def cmd_taskboard_claim(args: argparse.Namespace, g: GlobalOpts) -> int:
    return _cmd_taskboard_mutate(args, g, "claim")


def cmd_taskboard_unclaim(args: argparse.Namespace, g: GlobalOpts) -> int:
    return _cmd_taskboard_mutate(args, g, "unclaim")


def cmd_taskboard_done(args: argparse.Namespace, g: GlobalOpts) -> int:
    return _cmd_taskboard_mutate(args, g, "done")


def cmd_taskboard_fail(args: argparse.Namespace, g: GlobalOpts) -> int:
    return _cmd_taskboard_mutate(args, g, "fail")


def cmd_taskboard_status(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    out = _taskboard_request(
        method="GET",
        endpoint=endpoint,
        id_token=id_token,
        path=f"/boards/{args.board_id}/status",
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    board_id = str(out.get("boardId") or args.board_id or "").strip()
    board_name = str(out.get("name") or "").strip()
    total = str(out.get("total") if out.get("total") is not None else "0").strip() or "0"
    sys.stdout.write(f"board: {board_id or '(unknown)'}\n")
    if board_name:
        sys.stdout.write(f'name: "{board_name}"\n')
    headers = ["status", "count"]
    rows = [
        ["pending", str(out.get("pending") if out.get("pending") is not None else 0)],
        ["claimed", str(out.get("claimed") if out.get("claimed") is not None else 0)],
        ["done", str(out.get("done") if out.get("done") is not None else 0)],
        ["failed", str(out.get("failed") if out.get("failed") is not None else 0)],
    ]
    _taskboard_print_table(headers=headers, rows=rows, empty_message="No status counters.")
    sys.stdout.write(f"total: {total}\n")
    return 0


def cmd_taskboard_audit(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    out = _taskboard_request(
        method="GET",
        endpoint=endpoint,
        id_token=id_token,
        path=f"/boards/{args.board_id}/audit",
        query={
            "taskId": args.task_id,
            "limit": args.limit,
            "nextToken": args.next_token,
        },
    )
    _print_json(out, pretty=g.pretty)
    return 0


def cmd_taskboard_my_activity(args: argparse.Namespace, g: GlobalOpts) -> int:
    endpoint, id_token = _taskboard_auth_for_args(args, g)
    path = "/my/activity"
    if args.board_id:
        path = f"/my/activity/{args.board_id}"
    out = _taskboard_request(
        method="GET",
        endpoint=endpoint,
        id_token=id_token,
        path=path,
        query={
            "limit": args.limit,
            "nextToken": args.next_token,
        },
    )
    if _taskboard_wants_json(args):
        _print_json(out, pretty=g.pretty)
        return 0
    headers = ["timestamp", "action", "boardId", "taskId", "line"]
    rows: list[list[str]] = []
    items = out.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    _taskboard_local_short_timestamp(item.get("timestamp")),
                    _taskboard_cell(item.get("action")),
                    _taskboard_cell(item.get("boardId")),
                    _taskboard_cell(item.get("taskId")),
                    _taskboard_cell(item.get("line")),
                ]
            )
    _taskboard_print_table(headers=headers, rows=rows, empty_message="No activity events.")
    sys.stdout.write(f"items: {len(rows)}\n")
    cmd_hint = "enabler taskboard my-activity"
    if args.board_id:
        cmd_hint += f" {args.board_id}"
    _taskboard_print_next_token_hint(
        str(out.get("nextToken") or ""),
        command_hint=cmd_hint,
    )
    return 0


_ERROR_CONSOLE = Console(stderr=True)


def _rich_error(msg: str) -> None:
    _ERROR_CONSOLE.print(f"[bold red]error:[/bold red] {msg}")


def _root_help_text(*, root_app: typer.Typer, prog_name: str) -> str:
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            try:
                root_app(args=["--help"], prog_name=prog_name, standalone_mode=False)
            except (typer.Exit, click.ClickException):
                pass
    except Exception:
        return ""
    return str(buf.getvalue() or "").strip()


def _render_usage_error_with_help(
    *,
    message: str,
    ctx: click.Context | None = None,
    fallback_help: str = "",
) -> None:
    _rich_error(message)
    help_text = ""
    if isinstance(ctx, click.Context):
        try:
            help_text = str(ctx.get_help() or "").strip()
        except Exception:
            help_text = ""
    if not help_text:
        help_text = str(fallback_help or "").strip()
    if help_text:
        _eprint("")
        _eprint(help_text)


def _namespace(**kwargs: Any) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"enabler {__version__}")
        raise typer.Exit(code=0)


app = typer.Typer(
    name="enabler",
    help="What could go wrong?",
    no_args_is_help=True,
    add_completion=False,
)

admin_app = typer.Typer(
    name="enabler-admin",
    help="What could go wrong?",
    no_args_is_help=True,
    add_completion=False,
    cls=_InsertionOrderTyperGroup,
)

ssm_app = typer.Typer(help="Shared secrets for agents to use", no_args_is_help=True)
cognito_app = typer.Typer(help="Agent authentication", no_args_is_help=True)
agent_admin_app = typer.Typer(
    help="Agent admin helpers (onboarding, profile seeding)",
    no_args_is_help=True,
)
handoff_admin_app = typer.Typer(
    help="Bootstrap handoff helpers",
    no_args_is_help=True,
)
messages_app = typer.Typer(help="Message helpers (issued STS creds, no profile)", no_args_is_help=True)
files_app = typer.Typer(help="File share helpers", no_args_is_help=True)
shortlinks_app = typer.Typer(help="Shortlink helpers", no_args_is_help=True)
taskboard_app = typer.Typer(
    help="Taskboard helpers (default: human-readable output; use --json for raw API responses)",
    no_args_is_help=True,
)

# Agent CLI surface.
app.add_typer(files_app, name="files")
app.add_typer(messages_app, name="messages")
app.add_typer(shortlinks_app, name="shortlinks")
app.add_typer(taskboard_app, name="taskboard")

# Admin CLI surface.
admin_app.add_typer(ssm_app, name="ssm")
admin_app.add_typer(cognito_app, name="cognito")
admin_app.add_typer(agent_admin_app, name="agent")
agent_admin_app.add_typer(handoff_admin_app, name="handoff")


@app.callback()
def app_callback_agent(
    ctx: typer.Context,
    creds_cache: str | None = typer.Option(
        None,
        "--creds-cache",
        help=f"Path to cached credentials JSON (default: .enabler/credentials.json; env override: {ENABLER_CREDS_CACHE})",
    ),
    no_auto_refresh_creds: bool = typer.Option(
        False,
        "--no-auto-refresh-creds",
        help="Disable automatic refresh from /v1/credentials when cache is missing/expired",
    ),
    plain_json: bool = typer.Option(False, "--plain-json", help="Emit compact JSON output"),
    quiet: bool = typer.Option(False, "--quiet", help="Reduce stderr logging"),
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    del version
    os.environ["ENABLER_CLI_ROLE"] = "agent"
    ns = _namespace(
        profile=None,
        region=None,
        stack=None,
        creds_cache=creds_cache,
        auto_refresh_creds=not (
            no_auto_refresh_creds or _truthy(os.environ.get(ENABLER_NO_AUTO_REFRESH_CREDS))
        ),
        plain_json=plain_json,
        quiet=quiet,
    )
    try:
        g = _apply_global_env(ns)
    except UsageError as e:
        _render_usage_error_with_help(message=str(e), ctx=ctx)
        raise typer.Exit(code=2)
    ctx.obj = {"g": g}


@admin_app.callback()
def app_callback_admin(
    ctx: typer.Context,
    profile: str | None = typer.Option(None, "--profile", help="AWS CLI profile name (sets AWS_PROFILE)"),
    region: str | None = typer.Option(None, "--region", help="AWS region (sets AWS_REGION)"),
    stack: str | None = typer.Option(
        None,
        "--stack",
        help="CloudFormation stack name (default: env STACK or AgentEnablementStack)",
    ),
    plain_json: bool = typer.Option(False, "--plain-json", help="Emit compact JSON output"),
    quiet: bool = typer.Option(False, "--quiet", help="Reduce stderr logging"),
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    del version
    os.environ["ENABLER_CLI_ROLE"] = "admin"
    ns = _namespace(
        profile=profile,
        region=region,
        stack=stack,
        plain_json=plain_json,
        quiet=quiet,
    )
    try:
        g = _apply_admin_global_env(ns)
    except UsageError as e:
        _render_usage_error_with_help(message=str(e), ctx=ctx)
        raise typer.Exit(code=2)
    ctx.obj = {"g": g}


@taskboard_app.callback()
def taskboard_callback(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit raw JSON output for taskboard commands",
    ),
) -> None:
    if not isinstance(ctx.obj, dict):
        ctx.obj = {}
    ctx.obj["taskboard_json_output"] = bool(json_output)


def _ctx_global(ctx: typer.Context) -> GlobalOpts:
    if isinstance(ctx.obj, dict) and isinstance(ctx.obj.get("g"), GlobalOpts):
        return ctx.obj["g"]
    try:
        role = _cli_role()
        if role == "admin":
            return _apply_admin_global_env(
                _namespace(
                    profile=None,
                    region=None,
                    stack=None,
                    plain_json=False,
                    quiet=False,
                )
            )
        return _apply_global_env(
            _namespace(
                profile=None,
                region=None,
                stack=None,
                creds_cache=None,
                auto_refresh_creds=True,
                plain_json=False,
                quiet=False,
            )
        )
    except UsageError as e:
        _render_usage_error_with_help(message=str(e), ctx=ctx)
        raise typer.Exit(code=2)


def _invoke(ctx: typer.Context, func: Any, **kwargs: Any) -> None:
    g = _ctx_global(ctx)
    args = _namespace(**kwargs)
    try:
        code = int(func(args, g))
    except (UsageError, SharedUsageError) as e:
        _render_usage_error_with_help(message=str(e), ctx=ctx)
        raise typer.Exit(code=2)
    except (OpError, SharedOpError) as e:
        _rich_error(str(e))
        raise typer.Exit(code=1)

    if code:
        raise typer.Exit(code=code)


def _invoke_from_locals(
    ctx: typer.Context,
    func: Any,
    local_vars: dict[str, Any],
    *,
    drop: tuple[str, ...] = ("ctx",),
) -> None:
    _invoke(ctx, func, **{k: v for k, v in local_vars.items() if k not in drop})


def _taskboard_json_from_ctx(ctx: typer.Context) -> bool:
    obj = ctx.obj
    if isinstance(obj, dict):
        return bool(obj.get("taskboard_json_output", False))
    return False


def _invoke_taskboard(ctx: typer.Context, func: Any, **kwargs: Any) -> None:
    _invoke(ctx, func, json_output=_taskboard_json_from_ctx(ctx), **kwargs)


@admin_app.command("stack-output", help="Print CloudFormation stack outputs or a single output value.")
def stack_output(
    ctx: typer.Context,
    output_key: str | None = typer.Argument(None, help="Optional CloudFormation output key"),
) -> None:
    _invoke_from_locals(ctx, cmd_stack_output, locals())


@ssm_app.command(
    "api-key",
    help="Print JSON with the shared API key SSM parameter name and decrypted value.",
)
def ssm_api_key(ctx: typer.Context, name: str | None = typer.Option(None, "--name", help="Override parameter name (otherwise stack output ApiKeyParameterName)")) -> None:
    _invoke_from_locals(ctx, cmd_ssm_api_key, locals())


@ssm_app.command(
    "base-paths",
    help="Print JSON base paths for shared and per-agent SSM keys.",
)
def ssm_key_base_paths(ctx: typer.Context, stage: str | None = typer.Option(None, "--stage", help="Override stage (default: derived from ApiKeyParameterName)")) -> None:
    _invoke_from_locals(ctx, cmd_ssm_key_base_paths, locals())


@ssm_app.command(
    "put-shared",
    help="Write a shared SSM parameter under /agent-enablement/<stage>/shared/.",
)
def ssm_key_put_shared(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Key name (appended under /agent-enablement/<stage>/shared/)"),
    value: str | None = typer.Option(None, "--value", help="Parameter value"),
    value_file: str | None = typer.Option(None, "--value-file", help="Read value from file (utf-8)"),
    description: str | None = typer.Option(None, "--description", help="SSM parameter description"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if the parameter exists"),
    type: str = typer.Option("SecureString", "--type", help="Parameter type (default: SecureString)"),
    stage: str | None = typer.Option(None, "--stage", help="Override stage (default: derived from ApiKeyParameterName)"),
) -> None:
    _invoke(
        ctx,
        cmd_ssm_key_put_shared,
        key=key,
        value=value,
        value_file=value_file,
        description=description,
        overwrite=overwrite,
        type=type,
        stage=stage,
    )


@ssm_app.command(
    "put-agent",
    help="Write an agent-scoped SSM parameter under /agent-enablement/<stage>/agent/<sub>/.",
)
def ssm_key_put_agent(
    ctx: typer.Context,
    sub: str = typer.Argument(..., help="Cognito sub for the agent"),
    key: str = typer.Argument(..., help="Key name (appended under /agent-enablement/<stage>/agent/<sub>/)"),
    value: str | None = typer.Option(None, "--value", help="Parameter value"),
    value_file: str | None = typer.Option(None, "--value-file", help="Read value from file (utf-8)"),
    description: str | None = typer.Option(None, "--description", help="SSM parameter description"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite if the parameter exists"),
    type: str = typer.Option("SecureString", "--type", help="Parameter type (default: SecureString)"),
    stage: str | None = typer.Option(None, "--stage", help="Override stage (default: derived from ApiKeyParameterName)"),
) -> None:
    _invoke(
        ctx,
        cmd_ssm_key_put_agent,
        sub=sub,
        key=key,
        value=value,
        value_file=value_file,
        description=description,
        overwrite=overwrite,
        type=type,
        stage=stage,
    )


@ssm_app.command(
    "get-shared",
    help="Read and print a shared SSM parameter value.",
)
def ssm_key_get_shared(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Key name under /agent-enablement/<stage>/shared/"),
    stage: str | None = typer.Option(None, "--stage", help="Override stage (default: derived from ApiKeyParameterName)"),
) -> None:
    _invoke_from_locals(ctx, cmd_ssm_key_get_shared, locals())


@ssm_app.command(
    "get-agent",
    help="Read and print an agent-scoped SSM parameter value.",
)
def ssm_key_get_agent(
    ctx: typer.Context,
    sub: str = typer.Argument(..., help="Cognito sub for the agent"),
    key: str = typer.Argument(..., help="Key name under /agent-enablement/<stage>/agent/<sub>/"),
    stage: str | None = typer.Option(None, "--stage", help="Override stage (default: derived from ApiKeyParameterName)"),
) -> None:
    _invoke_from_locals(ctx, cmd_ssm_key_get_agent, locals())


@cognito_app.command("create-user", help="Create (or update password for) a Cognito user.")
def cognito_create_user(
    ctx: typer.Context,
    username: str | None = typer.Option(None, "--username", help=f"Cognito username (or env {ENABLER_ADMIN_COGNITO_USERNAME})"),
    password: str | None = typer.Option(None, "--password", help=f"Cognito password (or env {ENABLER_ADMIN_COGNITO_PASSWORD})"),
    user_pool_id: str | None = typer.Option(None, "--user-pool-id", help="Override user pool id (otherwise stack output UserPoolId)"),
) -> None:
    _invoke_from_locals(ctx, cmd_cognito_create_user, locals())


@cognito_app.command("rotate-password", help="Rotate a Cognito user's permanent password.")
def cognito_rotate_password(
    ctx: typer.Context,
    username: str = typer.Argument(...),
    new_password: str = typer.Argument(...),
    user_pool_id: str | None = typer.Option(None, "--user-pool-id", help="Override user pool id (otherwise stack output UserPoolId)"),
) -> None:
    _invoke(
        ctx,
        cmd_cognito_rotate_password,
        username=username,
        new_password=new_password,
        user_pool_id=user_pool_id,
    )


@cognito_app.command("remove-user", help="Remove a Cognito user.")
def cognito_remove_user(
    ctx: typer.Context,
    username: str = typer.Argument(...),
    user_pool_id: str | None = typer.Option(None, "--user-pool-id", help="Override user pool id (otherwise stack output UserPoolId)"),
) -> None:
    _invoke_from_locals(ctx, cmd_cognito_remove_user, locals())


@cognito_app.command("id-token", help="Authenticate a Cognito user and print token output.")
def cognito_id_token(
    ctx: typer.Context,
    username: str | None = typer.Option(None, "--username", help=f"Cognito username (or env {ENABLER_ADMIN_COGNITO_USERNAME})"),
    password: str | None = typer.Option(None, "--password", help=f"Cognito password (or env {ENABLER_ADMIN_COGNITO_PASSWORD})"),
    client_id: str | None = typer.Option(None, "--client-id", help="Override client id (otherwise stack output UserPoolClientId)"),
    raw: bool = typer.Option(False, "--raw", help="Print full InitiateAuth response JSON"),
    json_out: bool = typer.Option(False, "--json", help="Print compact JSON with token fields"),
) -> None:
    _invoke(
        ctx,
        cmd_cognito_id_token,
        username=username,
        password=password,
        client_id=client_id,
        raw=raw,
        json=json_out,
    )


@agent_admin_app.command("seed-profile", help="Seed or update an agent profile in DynamoDB.")
def agent_seed_profile(
    ctx: typer.Context,
    username: str | None = typer.Option(None, "--username", help=f"Cognito username (or env {ENABLER_ADMIN_COGNITO_USERNAME})"),
    password: str | None = typer.Option(None, "--password", help=f"Cognito password (or env {ENABLER_ADMIN_COGNITO_PASSWORD})"),
    credential_scope: str | None = typer.Option(None, "--credential-scope", help="Credential scope to write (or env CREDENTIAL_SCOPE; default runtime)"),
    profile_type: str = typer.Option("named", "--profile-type", help="Profile type: named or ephemeral (default named)"),
    agent_id: str | None = typer.Option(None, "--agent-id", help="Override agentId stored in profile (default: username)"),
    groups: str | None = typer.Option(None, "--groups", help="Comma-separated group IDs (or env AGENT_GROUPS)"),
    client_id: str | None = typer.Option(None, "--client-id", help="Override Cognito client id (otherwise stack output UserPoolClientId)"),
    create_inbox: bool = typer.Option(True, "--create-inbox/--no-create-inbox", help="Create inbox queue (default true)"),
    inbox_queue_name: str | None = typer.Option(None, "--inbox-queue-name", help="Override inbox queue name"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print actions without writing"),
) -> None:
    _invoke(
        ctx,
        cmd_agent_seed_profile,
        username=username,
        password=password,
        credential_scope=credential_scope,
        profile_type=profile_type,
        agent_id=agent_id,
        groups=groups,
        create_inbox=create_inbox,
        inbox_queue_name=inbox_queue_name,
        dry_run=dry_run,
        client_id=client_id,
    )


@agent_admin_app.command("onboard", help="Create a user and seed the corresponding agent profile.")
def agent_onboard(
    ctx: typer.Context,
    username: str = typer.Argument(...),
    password: str = typer.Argument(...),
    user_pool_id: str | None = typer.Option(None, "--user-pool-id", help="Override user pool id (otherwise stack output UserPoolId)"),
    credential_scope: str | None = typer.Option(None, "--credential-scope", help="Credential scope to write (or env CREDENTIAL_SCOPE; default runtime)"),
    profile_type: str = typer.Option("named", "--profile-type", help="Profile type: named or ephemeral (default named)"),
    agent_id: str | None = typer.Option(None, "--agent-id", help="Override agentId stored in profile (default: username)"),
    groups: str | None = typer.Option(None, "--groups", help="Comma-separated group IDs (or env AGENT_GROUPS)"),
    client_id: str | None = typer.Option(None, "--client-id", help="Override Cognito client id (otherwise stack output UserPoolClientId)"),
    create_inbox: bool = typer.Option(True, "--create-inbox/--no-create-inbox", help="Create inbox queue (default true)"),
    inbox_queue_name: str | None = typer.Option(None, "--inbox-queue-name", help="Override inbox queue name"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print actions without writing"),
) -> None:
    _invoke(
        ctx,
        cmd_agent_onboard,
        username=username,
        password=password,
        user_pool_id=user_pool_id,
        credential_scope=credential_scope,
        profile_type=profile_type,
        agent_id=agent_id,
        groups=groups,
        client_id=client_id,
        create_inbox=create_inbox,
        inbox_queue_name=inbox_queue_name,
        dry_run=dry_run,
    )


@agent_admin_app.command("decommission", help="Fully decommission an agent (Cognito user + profile + group rows + inbox queue).")
def agent_decommission(
    ctx: typer.Context,
    username: str = typer.Argument(...),
    user_pool_id: str | None = typer.Option(None, "--user-pool-id", help="Override user pool id (otherwise stack output UserPoolId)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print actions without writing"),
) -> None:
    _invoke(
        ctx,
        cmd_agent_decommission,
        username=username,
        user_pool_id=user_pool_id,
        dry_run=dry_run,
    )


@handoff_admin_app.command("create", help="Create a bootstrap handoff JSON document for an agent.")
def agent_handoff_create(
    ctx: typer.Context,
    username: str = typer.Option(..., "--username", help="Bootstrap username"),
    password: str = typer.Option(..., "--password", help="Bootstrap password"),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="Override API key value (otherwise fetched from SSM)",
    ),
    api_key_ssm_name: str | None = typer.Option(
        None,
        "--api-key-ssm-name",
        help="Override SSM parameter name for API key lookup",
    ),
    out: str | None = typer.Option(
        None,
        "--out",
        help="Optional output file path (written with 0600 permissions)",
    ),
) -> None:
    _invoke(
        ctx,
        cmd_agent_handoff_create,
        username=username,
        password=password,
        api_key=api_key,
        api_key_ssm_name=api_key_ssm_name,
        out=out,
    )


@handoff_admin_app.command("print-env", help="Render ENABLER_COGNITO_* + ENABLER_* export lines from handoff JSON.")
def agent_handoff_print_env(
    ctx: typer.Context,
    file: str | None = typer.Option(
        None,
        "--file",
        help="Path to handoff JSON (otherwise read from stdin)",
    ),
) -> None:
    _invoke_from_locals(ctx, cmd_agent_handoff_print_env, locals())


@app.command("credentials", help="Request runtime credentials and print artifact locations (default).")
def agent_credentials(
    ctx: typer.Context,
    username: str | None = typer.Option(None, "--username", help=f"Cognito username (or env {ENABLER_COGNITO_USERNAME})"),
    password: str | None = typer.Option(None, "--password", help=f"Cognito password (or env {ENABLER_COGNITO_PASSWORD})"),
    endpoint: str | None = typer.Option(None, "--endpoint", help=f"Override credentials endpoint (or env {ENABLER_CREDENTIALS_ENDPOINT})"),
    api_key: str | None = typer.Option(None, "--api-key", help=f"Override API key value (or env {ENABLER_API_KEY})"),
    out: str | None = typer.Option(None, "--out", help="Write credentials response JSON to this path"),
    summary: bool = typer.Option(False, "--summary", help="Deprecated alias for default location output"),
    json_output: bool = typer.Option(False, "--json", help="Print full credentials response JSON"),
    include_headers: bool = typer.Option(False, "--include-headers", help="Include status and headers in JSON output"),
) -> None:
    _invoke(
        ctx,
        cmd_agent_credentials,
        username=username,
        password=password,
        endpoint=endpoint,
        api_key=api_key,
        out=out,
        summary=summary,
        json_output=json_output,
        include_headers=include_headers,
    )


@app.command("credential-process", help="Print AWS credential_process JSON for a specific credential set.")
def agent_credential_process(
    ctx: typer.Context,
    set_name: str = typer.Option(..., "--set", help="Credential set key (for example: agentEnablement)"),
    username: str | None = typer.Option(None, "--username", help=f"Cognito username (or env {ENABLER_COGNITO_USERNAME})"),
    password: str | None = typer.Option(None, "--password", help=f"Cognito password (or env {ENABLER_COGNITO_PASSWORD})"),
    endpoint: str | None = typer.Option(None, "--endpoint", help=f"Override credentials endpoint (or env {ENABLER_CREDENTIALS_ENDPOINT})"),
    api_key: str | None = typer.Option(None, "--api-key", help=f"Override API key value (or env {ENABLER_API_KEY})"),
) -> None:
    _invoke(
        ctx,
        cmd_agent_credential_process,
        set_name=set_name,
        username=username,
        password=password,
        endpoint=endpoint,
        api_key=api_key,
    )


@files_app.command(
    "share",
    help="Upload a file and return the external HTTPS URL (use --json for S3 metadata).",
)
def files_share(
    ctx: typer.Context,
    file_path: str = typer.Argument(..., help="Local file path to upload"),
    name: str | None = typer.Option(None, "--name", help="Optional object filename override"),
    json_output: bool = typer.Option(False, "--json", help="Print JSON details instead of plain text output"),
) -> None:
    _invoke_from_locals(ctx, cmd_files_share, locals())


@messages_app.command("send", help="Send a direct message event via EventBridge.")
def messages_send(
    ctx: typer.Context,
    to: str = typer.Option(..., "--to", help="Target recipient Cognito username"),
    text: str | None = typer.Option(None, "--text", help='Plain text message body (wrapped as {"text": ...})'),
    message_json: str | None = typer.Option(None, "--message-json", help="Raw JSON object for detail.message"),
    kind: str | None = typer.Option(None, "--kind", help="Optional message kind override"),
    meta_json: str | None = typer.Option(None, "--meta-json", help="Raw JSON object for detail.meta"),
    event_bus_arn: str | None = typer.Option(None, "--event-bus-arn", help="Override event bus ARN"),
) -> None:
    _invoke(
        ctx,
        cmd_messages_send,
        to=to,
        text=text,
        message_json=message_json,
        kind=kind,
        meta_json=meta_json,
        event_bus_arn=event_bus_arn,
    )


@messages_app.command("recv", help="Receive direct message events from the inbox SQS queue (loops batches until empty for this run).")
def messages_recv(
    ctx: typer.Context,
    queue_url: str | None = typer.Option(None, "--queue-url", help="Override inbox queue URL"),
    max_number: str = typer.Option("1", "--max-number", help="Max messages (1-10, default: 1)"),
    wait_seconds: str = typer.Option("10", "--wait-seconds", help="Long-poll wait seconds (0-20, default: 10)"),
    visibility_timeout: str | None = typer.Option(None, "--visibility-timeout", help="Visibility timeout override (seconds)"),
    ack_all: bool = typer.Option(
        False,
        "--ack-all",
        help="Drain queue for this run by receiving and deleting messages until empty (bounded by an internal batch limit)",
    ),
) -> None:
    _invoke(
        ctx,
        cmd_messages_recv,
        queue_url=queue_url,
        max_number=max_number,
        wait_seconds=wait_seconds,
        visibility_timeout=visibility_timeout,
        ack_all=ack_all,
    )


@messages_app.command("ack", help="Acknowledge/delete a previously received inbox message.")
def messages_ack(
    ctx: typer.Context,
    ack_token: str | None = typer.Option(None, "--ack-token", help="Ack token emitted by 'messages recv'"),
    receipt_handle: str | None = typer.Option(None, "--receipt-handle", help="Raw SQS receipt handle"),
    queue_url: str | None = typer.Option(None, "--queue-url", help="Override inbox queue URL when using --receipt-handle"),
) -> None:
    _invoke(
        ctx,
        cmd_messages_ack,
        ack_token=ack_token,
        receipt_handle=receipt_handle,
        queue_url=queue_url,
    )


@shortlinks_app.command("create", help="Create a short link code for a target URL.")
def shortlinks_create(
    ctx: typer.Context,
    target_url: str = typer.Argument(..., help="HTTPS URL to shorten"),
    alias: str | None = typer.Option(
        None,
        "--alias",
        help="Optional custom short code (exactly 22 Bitcoin Base58 chars)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Print JSON details instead of plain text output"),
) -> None:
    _invoke_from_locals(ctx, cmd_shortlinks_create, locals())


@shortlinks_app.command("resolve-url", help="Render the full shortlink resolve URL for a code.")
def shortlinks_resolve_url(
    ctx: typer.Context,
    code: str = typer.Argument(..., help="Short code"),
) -> None:
    _invoke_from_locals(ctx, cmd_shortlinks_resolve_url, locals())


@taskboard_app.command("create", help="Create a new taskboard. Use 'taskboard --json' for raw API response.")
def taskboard_create(
    ctx: typer.Context,
    name: str | None = typer.Option(None, "--name", help="Optional board name"),
) -> None:
    _invoke_taskboard(ctx, cmd_taskboard_create, name=name)


@taskboard_app.command("add", help="Add one or more tasks to a board. Use 'taskboard --json' for raw API response.")
def taskboard_add(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    lines: list[str] | None = typer.Argument(None, help="Task lines (or use --file / stdin)"),
    file: str | None = typer.Option(None, "--file", help="Read task lines from a UTF-8 file"),
) -> None:
    _invoke_taskboard(
        ctx,
        cmd_taskboard_add,
        board_id=board_id,
        lines=lines or [],
        file=file,
    )


@taskboard_app.command("list", help="List tasks on a board. Use 'taskboard --json' for raw API response.")
def taskboard_list(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    search: str | None = typer.Argument(None, help="Optional query (task ID first, then summary)"),
    query: str | None = typer.Option(None, "--query", help="Query text (task ID first, then summary)"),
    status: str | None = typer.Option(None, "--status", help="pending|claimed|done|failed"),
    limit: str | None = typer.Option(None, "--limit", help="Page size (default 25, max 100)"),
    next_token: str | None = typer.Option(None, "--next-token", help="Pagination token from prior response"),
) -> None:
    _invoke_taskboard(
        ctx,
        cmd_taskboard_list,
        board_id=board_id,
        search=search,
        query=query,
        status=status,
        limit=limit,
        next_token=next_token,
    )


def _taskboard_mutate(
    ctx: typer.Context,
    func: Any,
    board_id: str,
    target: str | None,
    task_id: str | None,
    query: str | None,
) -> None:
    _invoke_taskboard(
        ctx,
        func,
        board_id=board_id,
        target=target,
        task_id=task_id,
        query=query,
    )


@taskboard_app.command("claim", help="Claim a task by ID or query. Use 'taskboard --json' for raw API response.")
def taskboard_claim(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    target: str | None = typer.Argument(None, help="Task query string (task ID first, then summary) if --task-id is not provided"),
    task_id: str | None = typer.Option(None, "--task-id", help="Exact task ID"),
    query: str | None = typer.Option(None, "--query", help="Query text (task ID first, then summary)"),
) -> None:
    _taskboard_mutate(ctx, cmd_taskboard_claim, board_id, target, task_id, query)


@taskboard_app.command("unclaim", help="Release a previously claimed task. Use 'taskboard --json' for raw API response.")
def taskboard_unclaim(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    target: str | None = typer.Argument(None, help="Task query string (task ID first, then summary) if --task-id is not provided"),
    task_id: str | None = typer.Option(None, "--task-id", help="Exact task ID"),
    query: str | None = typer.Option(None, "--query", help="Query text (task ID first, then summary)"),
) -> None:
    _taskboard_mutate(ctx, cmd_taskboard_unclaim, board_id, target, task_id, query)


@taskboard_app.command("done", help="Mark a task as done. Use 'taskboard --json' for raw API response.")
def taskboard_done(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    target: str | None = typer.Argument(None, help="Task query string (task ID first, then summary) if --task-id is not provided"),
    task_id: str | None = typer.Option(None, "--task-id", help="Exact task ID"),
    query: str | None = typer.Option(None, "--query", help="Query text (task ID first, then summary)"),
) -> None:
    _taskboard_mutate(ctx, cmd_taskboard_done, board_id, target, task_id, query)


@taskboard_app.command("fail", help="Mark a task as failed. Use 'taskboard --json' for raw API response.")
def taskboard_fail(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    target: str | None = typer.Argument(None, help="Task query string (task ID first, then summary) if --task-id is not provided"),
    task_id: str | None = typer.Option(None, "--task-id", help="Exact task ID"),
    query: str | None = typer.Option(None, "--query", help="Query text (task ID first, then summary)"),
) -> None:
    _taskboard_mutate(ctx, cmd_taskboard_fail, board_id, target, task_id, query)


@taskboard_app.command("status", help="Show board status counters. Use 'taskboard --json' for raw API response.")
def taskboard_status(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
) -> None:
    _invoke_taskboard(
        ctx,
        cmd_taskboard_status,
        board_id=board_id,
    )


@taskboard_app.command("audit", help="List taskboard audit events as detailed JSON.")
def taskboard_audit(
    ctx: typer.Context,
    board_id: str = typer.Argument(..., help="Board ID (full or unique partial)"),
    task_id: str | None = typer.Option(None, "--task-id", help="Filter audit events by task ID"),
    limit: str | None = typer.Option(None, "--limit", help="Page size (default 25, max 100)"),
    next_token: str | None = typer.Option(None, "--next-token", help="Pagination token from prior response"),
) -> None:
    _invoke_taskboard(
        ctx,
        cmd_taskboard_audit,
        board_id=board_id,
        task_id=task_id,
        limit=limit,
        next_token=next_token,
    )


@taskboard_app.command("my-activity", help="Show activity for the calling principal. Use 'taskboard --json' for raw API response.")
def taskboard_my_activity(
    ctx: typer.Context,
    board_id: str | None = typer.Argument(None, help="Optional board ID filter (full or unique partial)"),
    limit: str | None = typer.Option(None, "--limit", help="Page size (default 25, max 100)"),
    next_token: str | None = typer.Option(None, "--next-token", help="Pagination token from prior response"),
) -> None:
    _invoke_taskboard(
        ctx,
        cmd_taskboard_my_activity,
        board_id=board_id,
        limit=limit,
        next_token=next_token,
    )


def _run_cli(*, root_app: typer.Typer, prog_name: str, role: str, argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        _bootstrap_env()
    except UsageError as e:
        _render_usage_error_with_help(
            message=str(e),
            fallback_help=_root_help_text(root_app=root_app, prog_name=prog_name),
        )
        return 2

    os.environ["ENABLER_CLI_ROLE"] = role
    try:
        result = root_app(args=argv, prog_name=prog_name, standalone_mode=False)
        if result is None:
            return 0
        return int(result)
    except typer.Exit as e:
        return int(e.exit_code)
    except click.ClickException as e:
        if isinstance(e, click.UsageError):
            _render_usage_error_with_help(message=e.format_message(), ctx=getattr(e, "ctx", None))
            return int(e.exit_code)
        _rich_error(e.format_message())
        return int(e.exit_code)
    except (UsageError, SharedUsageError) as e:
        _render_usage_error_with_help(
            message=str(e),
            fallback_help=_root_help_text(root_app=root_app, prog_name=prog_name),
        )
        return 2
    except (OpError, SharedOpError) as e:
        _rich_error(str(e))
        return 1


def main_agent(argv: list[str] | None = None) -> int:
    return _run_cli(root_app=app, prog_name="enabler", role="agent", argv=argv)


def main_admin(argv: list[str] | None = None) -> int:
    return _run_cli(root_app=admin_app, prog_name="enabler-admin", role="admin", argv=argv)


def main(argv: list[str] | None = None) -> int:
    return main_agent(argv)
