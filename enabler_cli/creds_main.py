from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

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
from .cli_shared import ENABLER_CREDS_CACHE, ENABLER_NO_AUTO_REFRESH_CREDS, GlobalOpts


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
    creds_cache: str | None = typer.Option(
        None,
        "--creds-cache",
        help=f"Path to cached credentials JSON (default: .enabler/credentials.json; env override: {ENABLER_CREDS_CACHE})",
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
        creds_cache=creds_cache,
        auto_refresh_creds=not (
            no_auto_refresh_creds or _truthy(os.environ.get(ENABLER_NO_AUTO_REFRESH_CREDS))
        ),
        plain_json=plain_json,
        quiet=quiet,
    )
    g = _apply_global_env(ns)
    ctx.obj = {"g": g}


def _ensure_doc(g: GlobalOpts) -> dict[str, object]:
    return _resolve_runtime_credentials_doc(argparse.Namespace(), g)


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
