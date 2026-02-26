from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import click
import typer

from . import __version__
from .runtime_core import (
    OpError,
    UsageError,
    _bootstrap_env,
    _apply_global_env,
    _artifact_root,
    _credential_process_doc_to_output,
    _credential_set_doc,
    _credentials_cache_file,
    _credentials_expires_at,
    _credentials_freshness,
    _credentials_location_manifest,
    _fetch_credentials_doc_text_for_cache,
    _load_json_object,
    _namespace,
    _print_credentials_location_manifest_human,
    _print_json,
    _resolve_runtime_credentials_doc,
    _write_credentials_cache_from_text,
    _write_cognito_env_file_from_doc,
    _write_sts_env_files_from_doc,
    _rich_error,
)
from .cli_shared import (
    ENABLER_API_KEY,
    ENABLER_AGENT_ID,
    ENABLER_NO_AUTO_REFRESH_CREDS,
    GlobalOpts,
)
from .apps.agent_admin_cli import _http_post_json


app = typer.Typer(
    name="enabler-creds",
    help="Credential lifecycle and credential_process outputs.",
    no_args_is_help=True,
    add_completion=False,
)


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"enabler-creds {__version__}")
        raise typer.Exit(code=0)


def _ctx_global(ctx: typer.Context) -> GlobalOpts:
    if isinstance(ctx.obj, dict) and isinstance(ctx.obj.get("g"), GlobalOpts):
        return ctx.obj["g"]
    ns = _namespace(
        profile=None,
        region=None,
        stack=None,
        creds_cache=None,
        auto_refresh_creds=not _truthy(os.environ.get(ENABLER_NO_AUTO_REFRESH_CREDS)),
        plain_json=False,
        quiet=False,
    )
    return _apply_global_env(ns)


@app.callback()
def app_callback(
    ctx: typer.Context,
    agent_id: str | None = typer.Option(
        None,
        "--agent-id",
        help=f"Managed identity key (env override: {ENABLER_AGENT_ID})",
    ),
    no_auto_refresh_creds: bool = typer.Option(
        False,
        "--no-auto-refresh-creds",
        help="Disable automatic refresh when cache is missing/expired",
    ),
    plain_json: bool = typer.Option(False, "--plain-json", help="Emit compact JSON output"),
    quiet: bool = typer.Option(False, "--quiet", help="Reduce stderr logging"),
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
) -> None:
    del version
    os.environ["ENABLER_CLI_ROLE"] = "agent"
    ns = _namespace(
        profile=None,
        region=None,
        stack=None,
        agent_id=agent_id,
        auto_refresh_creds=not (
            no_auto_refresh_creds or _truthy(os.environ.get(ENABLER_NO_AUTO_REFRESH_CREDS))
        ),
        plain_json=plain_json,
        quiet=quiet,
    )
    g = _apply_global_env(ns)
    if not g.agent_id:
        raise UsageError(f"missing agent id (pass --agent-id or set {ENABLER_AGENT_ID})")
    ctx.obj = {"g": g}


def _ensure_doc(g: GlobalOpts) -> dict[str, object]:
    return _resolve_runtime_credentials_doc(argparse.Namespace(), g)


def _runtime_credentials_endpoint(doc: dict[str, object]) -> str:
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


def _id_token_from_doc(doc: dict[str, object]) -> str:
    tokens = doc.get("cognitoTokens")
    if isinstance(tokens, dict):
        tok = str(tokens.get("idToken") or "").strip()
        if tok:
            return tok
    sets = doc.get("credentialSets")
    if isinstance(sets, dict):
        for val in sets.values():
            if not isinstance(val, dict):
                continue
            st = val.get("cognitoTokens")
            if not isinstance(st, dict):
                continue
            tok = str(st.get("idToken") or "").strip()
            if tok:
                return tok
    return ""


def _derive_endpoint(credentials_endpoint: str, *, suffix: str) -> str:
    raw = str(credentials_endpoint or "").strip()
    if not raw:
        raise UsageError("missing credentials endpoint in cached auth metadata")
    parsed = urlparse(raw)
    path = str(parsed.path or "").rstrip("/")
    if not path.endswith("/v1/credentials"):
        raise UsageError(
            "cannot derive endpoint from credentials endpoint "
            f"{raw!r} (expected path ending with /v1/credentials)"
        )
    target_path = path[: -len("/v1/credentials")] + suffix
    return urlunparse(parsed._replace(path=target_path))


def _json_obj_or_error(*, raw: bytes, label: str) -> dict[str, object]:
    text = raw.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception as e:
        raise OpError(f"invalid JSON from {label}: {e}; body={text}") from e
    if not isinstance(parsed, dict):
        raise OpError(f"invalid JSON from {label}: expected object")
    return parsed


def _post_json_checked(*, url: str, headers: dict[str, str], body_obj: dict[str, object] | None = None, label: str) -> dict[str, object]:
    body = b""
    if isinstance(body_obj, dict):
        body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    status, _hdrs, raw = _http_post_json(url=url, headers=headers, body=body)
    if status < 200 or status >= 300:
        text = raw.decode("utf-8", errors="replace")
        raise OpError(f"{label} failed: status={status} body={text}")
    return _json_obj_or_error(raw=raw, label=label)


def _write_exchange_artifacts(*, g: GlobalOpts, response_obj: dict[str, object]) -> dict[str, object]:
    raw_text = json.dumps(response_obj, separators=(",", ":"), sort_keys=True)
    path = _write_credentials_cache_from_text(g=g, raw_text=raw_text)
    sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=response_obj)
    cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=response_obj))
    manifest = _credentials_location_manifest(
        g=g,
        doc=response_obj,
        sts_env_paths=sts_env_paths,
        cognito_env_path=cognito_env_path,
    )
    return {
        "cachePath": str(path),
        "manifest": manifest,
    }


@app.command("summary", help="Print credentials artifact locations and freshness summary.")
def summary(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
    g = _ctx_global(ctx)
    doc = _ensure_doc(g)
    sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=doc)
    cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=doc))
    manifest = _credentials_location_manifest(
        g=g,
        doc=doc,
        sts_env_paths=sts_env_paths,
        cognito_env_path=cognito_env_path,
    )
    if json_output:
        _print_json(manifest, pretty=g.pretty)
        return
    _print_credentials_location_manifest_human(manifest)


@app.command("status", help="Print cache freshness status.")
def status(ctx: typer.Context) -> None:
    g = _ctx_global(ctx)
    doc = _ensure_doc(g)
    expires_at = _credentials_expires_at(doc)
    freshness, seconds_to_expiry = _credentials_freshness(expires_at)
    sets = doc.get("credentialSets") if isinstance(doc.get("credentialSets"), dict) else {}
    payload = {
        "kind": "enabler.creds.status.v1",
        "expiresAt": expires_at,
        "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
        "credentialSets": sorted(list(sets.keys())),
        "cachePath": str(_credentials_cache_file(g)),
    }
    _print_json(payload, pretty=g.pretty)


@app.command("paths", help="Print deterministic artifact paths.")
def paths(ctx: typer.Context) -> None:
    g = _ctx_global(ctx)
    root = _artifact_root(g)
    payload = {
        "kind": "enabler.creds.paths.v1",
        "agentId": g.agent_id,
        "root": str(root),
        "credentialsJson": str(_credentials_cache_file(g)),
        "stsDefaultEnv": str((root / "sts.env").resolve()),
        "cognitoEnv": str((root / "cognito.env").resolve()),
    }
    _print_json(payload, pretty=g.pretty)


@app.command("refresh", help="Force-refresh credentials cache and rewrite artifacts.")
def refresh(ctx: typer.Context) -> None:
    g = _ctx_global(ctx)
    current_doc: dict[str, object] | None = None
    cache_path = _credentials_cache_file(g)
    if cache_path.exists():
        current_doc = _load_json_object(
            raw=cache_path.read_text(encoding="utf-8"),
            label=f"cached credentials JSON at {cache_path}",
        )

    raw_text, doc = _fetch_credentials_doc_text_for_cache(g, current_doc=current_doc)
    path = _write_credentials_cache_from_text(g=g, raw_text=raw_text)
    sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=doc)
    cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=doc))
    manifest = _credentials_location_manifest(
        g=g,
        doc=doc,
        sts_env_paths=sts_env_paths,
        cognito_env_path=cognito_env_path,
    )
    payload = {
        "kind": "enabler.creds.refresh.v1",
        "cachePath": str(path),
        "manifest": manifest,
    }
    _print_json(payload, pretty=g.pretty)


@app.command("credential-process", help="Print AWS credential_process JSON for a specific credential set.")
def credential_process(
    ctx: typer.Context,
    set_name: str = typer.Option(..., "--set", help="Credential set key"),
) -> None:
    g = _ctx_global(ctx)
    doc = _ensure_doc(g)
    selected_doc = _credential_set_doc(root_doc=doc, set_name=set_name)
    out = _credential_process_doc_to_output(selected_doc)
    sys.stdout.write(json.dumps(out, separators=(",", ":"), sort_keys=True) + "\n")


delegation_app = typer.Typer(
    help="Delegation request/approve/redeem helpers.",
    no_args_is_help=True,
)
app.add_typer(delegation_app, name="delegation")

session_app = typer.Typer(
    help="Managed agent-id session helpers.",
    no_args_is_help=True,
)
app.add_typer(session_app, name="session")


@delegation_app.command("request", help="Create a short-code delegation request.")
def delegation_request(
    ctx: typer.Context,
    scopes: str = typer.Option("taskboard,messages", "--scopes", help="Comma-separated scopes"),
    ttl_seconds: int = typer.Option(600, "--ttl-seconds", help="Delegation request TTL in seconds"),
    purpose: str = typer.Option("", "--purpose", help="Purpose text for audit metadata"),
) -> None:
    g = _ctx_global(ctx)
    doc = _ensure_doc(g)
    api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
    if not api_key:
        raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
    credentials_endpoint = _runtime_credentials_endpoint(doc)
    request_endpoint = _derive_endpoint(credentials_endpoint, suffix="/v1/delegation/requests")
    requested_scopes = [p.strip() for p in scopes.split(",") if p.strip()]
    payload = {"scopes": requested_scopes, "ttlSeconds": int(ttl_seconds), "purpose": str(purpose or "")}
    out = _post_json_checked(
        url=request_endpoint,
        headers={
            "x-api-key": api_key,
            "content-type": "application/json",
        },
        body_obj=payload,
        label="delegation request",
    )
    _print_json({"kind": "enabler.creds.delegation.request.v1", "request": out}, pretty=g.pretty)


@delegation_app.command("approve", help="Approve a pending delegation request as a named profile.")
def delegation_approve(
    ctx: typer.Context,
    request_code: str = typer.Option(..., "--request-code", help="Delegation request code"),
) -> None:
    g = _ctx_global(ctx)
    doc = _ensure_doc(g)
    id_token = _id_token_from_doc(doc)
    if not id_token:
        raise UsageError("cached credentials missing cognitoTokens.idToken")
    credentials_endpoint = _runtime_credentials_endpoint(doc)
    approval_endpoint = _derive_endpoint(credentials_endpoint, suffix="/v1/delegation/approvals")
    out = _post_json_checked(
        url=approval_endpoint,
        headers={
            "authorization": f"Bearer {id_token}",
            "content-type": "application/json",
        },
        body_obj={"requestCode": request_code},
        label="delegation approval request",
    )
    _print_json({"kind": "enabler.creds.delegation.approve.v1", "approval": out}, pretty=g.pretty)


@delegation_app.command("status", help="Read status for a delegation request code.")
def delegation_status(
    ctx: typer.Context,
    request_code: str = typer.Option(..., "--request-code", help="Delegation request code"),
) -> None:
    g = _ctx_global(ctx)
    api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
    if not api_key:
        raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
    doc = _ensure_doc(g)
    credentials_endpoint = _runtime_credentials_endpoint(doc)
    status_endpoint = _derive_endpoint(credentials_endpoint, suffix="/v1/delegation/status")
    out = _post_json_checked(
        url=status_endpoint,
        headers={
            "x-api-key": api_key,
            "content-type": "application/json",
        },
        body_obj={"requestCode": request_code},
        label="delegation status request",
    )
    _print_json({"kind": "enabler.creds.delegation.status.v1", "status": out}, pretty=g.pretty)


@delegation_app.command("redeem", help="Redeem an approved delegation request and write cache artifacts.")
def delegation_redeem(
    ctx: typer.Context,
    request_code: str = typer.Option(..., "--request-code", help="Delegation request code"),
) -> None:
    g = _ctx_global(ctx)
    api_key = str(os.environ.get(ENABLER_API_KEY) or "").strip()
    if not api_key:
        raise UsageError(f"missing {ENABLER_API_KEY} (set env var)")
    doc = _ensure_doc(g)
    credentials_endpoint = _runtime_credentials_endpoint(doc)
    redeem_endpoint = _derive_endpoint(credentials_endpoint, suffix="/v1/delegation/redeem")
    redeem_resp = _post_json_checked(
        url=redeem_endpoint,
        headers={
            "x-api-key": api_key,
            "content-type": "application/json",
        },
        body_obj={"requestCode": request_code},
        label="delegation redeem request",
    )
    artifacts = _write_exchange_artifacts(g=g, response_obj=redeem_resp)
    payload = {
        "kind": "enabler.creds.delegation.redeem.v1",
        "principal": redeem_resp.get("principal"),
        "credentialSets": sorted(
            list((redeem_resp.get("credentialSets") or {}).keys())
        )
        if isinstance(redeem_resp.get("credentialSets"), dict)
        else [],
        **artifacts,
    }
    _print_json(payload, pretty=g.pretty)


@session_app.command("status", help="Print session status for an agent id.")
def session_status(
    ctx: typer.Context,
    agent_id: str = typer.Option(..., "--agent-id", help="Agent identity key"),
) -> None:
    base = _ctx_global(ctx)
    g = GlobalOpts(
        stack=base.stack,
        pretty=base.pretty,
        quiet=base.quiet,
        auto_refresh_creds=base.auto_refresh_creds,
        agent_id=agent_id,
    )
    doc = _ensure_doc(g)
    expires_at = _credentials_expires_at(doc)
    freshness, seconds_to_expiry = _credentials_freshness(expires_at)
    payload = {
        "kind": "enabler.session.status.v1",
        "agentId": agent_id,
        "cachePath": str(_credentials_cache_file(g)),
        "freshness": {"status": freshness, "secondsToExpiry": seconds_to_expiry},
        "expiresAt": expires_at,
    }
    _print_json(payload, pretty=g.pretty)


@session_app.command("list", help="List locally managed sessions.")
def session_list(ctx: typer.Context) -> None:
    g = _ctx_global(ctx)
    root = _artifact_root(g)
    sessions_root = root.parent
    sessions: list[dict[str, object]] = []
    if sessions_root.exists():
        for session_dir in sorted([p for p in sessions_root.iterdir() if p.is_dir()]):
            session_file = session_dir / "session.json"
            if not session_file.exists():
                continue
            sessions.append(
                {
                    "agentId": session_dir.name,
                    "sessionPath": str(session_file.resolve()),
                    "exists": True,
                }
            )
    _print_json({"kind": "enabler.session.list.v1", "sessions": sessions}, pretty=g.pretty)


@session_app.command("revoke", help="Remove local session artifacts for an agent id.")
def session_revoke(
    ctx: typer.Context,
    agent_id: str = typer.Option(..., "--agent-id", help="Agent identity key"),
) -> None:
    base = _ctx_global(ctx)
    g = GlobalOpts(
        stack=base.stack,
        pretty=base.pretty,
        quiet=base.quiet,
        auto_refresh_creds=False,
        agent_id=agent_id,
    )
    path = _credentials_cache_file(g)
    removed = False
    if path.exists():
        path.unlink()
        removed = True
    root = _artifact_root(g)
    for child in root.glob("*.env"):
        child.unlink(missing_ok=True)
    _print_json(
        {
            "kind": "enabler.session.revoke.v1",
            "agentId": agent_id,
            "sessionPath": str(path),
            "removed": removed,
        },
        pretty=g.pretty,
    )


@session_app.command("bootstrap-named", help="Fetch named credentials into the target session.")
def session_bootstrap_named(
    ctx: typer.Context,
    agent_id: str = typer.Option(..., "--agent-id", help="Target agent identity key"),
) -> None:
    base = _ctx_global(ctx)
    g = GlobalOpts(
        stack=base.stack,
        pretty=base.pretty,
        quiet=base.quiet,
        auto_refresh_creds=True,
        agent_id=agent_id,
    )
    raw_text, doc = _fetch_credentials_doc_text_for_cache(g, current_doc=None)
    path = _write_credentials_cache_from_text(g=g, raw_text=raw_text)
    sts_env_paths = _write_sts_env_files_from_doc(g=g, root_doc=doc)
    cognito_env_path = str(_write_cognito_env_file_from_doc(g=g, root_doc=doc))
    manifest = _credentials_location_manifest(
        g=g,
        doc=doc,
        sts_env_paths=sts_env_paths,
        cognito_env_path=cognito_env_path,
    )
    _print_json(
        {
            "kind": "enabler.session.bootstrap-named.v1",
            "agentId": agent_id,
            "cachePath": str(path),
            "manifest": manifest,
        },
        pretty=g.pretty,
    )

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        _bootstrap_env()
        result = app(args=argv, prog_name="enabler-creds", standalone_mode=False)
        if result is None:
            return 0
        return int(result)
    except typer.Exit as e:
        return int(e.exit_code)
    except click.ClickException as e:
        _rich_error(e.format_message())
        return int(e.exit_code)
    except UsageError as e:
        _rich_error(str(e))
        return 2
    except OpError as e:
        _rich_error(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
