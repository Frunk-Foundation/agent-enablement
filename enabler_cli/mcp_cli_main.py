from __future__ import annotations

import json
import sys
from typing import Any

import click
import typer

from . import __version__
from .mcp_server import EnablerMcp
from .runtime_core import OpError, UsageError, _bootstrap_env, _rich_error

app = typer.Typer(
    name="enabler-mcp-cli",
    help="Thin local wrapper around enabler-mcp tools.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"enabler-mcp-cli {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def app_callback(
    ctx: typer.Context,
    agent_id: str = typer.Option("", "--agent-id", help="Optional bound agent id"),
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
) -> None:
    del version
    ctx.obj = {"agent_id": str(agent_id or "").strip()}


def _server(ctx: typer.Context) -> EnablerMcp:
    obj = ctx.obj if isinstance(ctx.obj, dict) else {}
    return EnablerMcp(agent_id=str(obj.get("agent_id") or "").strip())


def _jsonrpc_call(*, method: str, params: dict[str, Any] | None = None, req_id: int = 1) -> dict[str, Any]:
    req: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
    }
    if isinstance(params, dict):
        req["params"] = params
    return req


def _extract_content_text(resp: dict[str, Any]) -> str:
    result = resp.get("result")
    if not isinstance(result, dict):
        return ""
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return ""
    first = content[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("text") or "")


def _send(server: EnablerMcp, req: dict[str, Any]) -> dict[str, Any]:
    resp = server.handle_request(req)
    if resp is None:
        return {"jsonrpc": "2.0", "result": None}
    if not isinstance(resp, dict):
        raise OpError("invalid response from MCP server")
    if isinstance(resp.get("error"), dict):
        err = resp["error"]
        msg = str(err.get("message") or "MCP error")
        data = err.get("data")
        if isinstance(data, dict) and str(data.get("message") or "").strip():
            msg = str(data.get("message"))
        raise OpError(msg)
    return resp


def _print_json(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


@app.command("list", help="List available MCP tools.")
def list_tools(ctx: typer.Context) -> None:
    server = _server(ctx)
    resp = _send(server, _jsonrpc_call(method="tools/list"))
    tools = []
    result = resp.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        tools = result.get("tools") or []
    _print_json(
        {
            "kind": "enabler.mcp-cli.tools.v1",
            "tools": tools,
        }
    )


@app.command("inspect", help="Inspect top-level help or help for one tool/action.")
def inspect(
    ctx: typer.Context,
    tool: str = typer.Argument("", help="Optional tool name"),
    action: str = typer.Option("", "--action", help="Optional action name"),
) -> None:
    server = _server(ctx)
    args: dict[str, Any] = {}
    if tool:
        args["tool"] = tool
    if action:
        args["action"] = action
    req = _jsonrpc_call(
        method="tools/call",
        params={
            "name": "help",
            "arguments": args,
        },
    )
    resp = _send(server, req)
    text = _extract_content_text(resp)
    if text:
        try:
            _print_json(json.loads(text))
            return
        except Exception:
            pass
    _print_json(resp)


@app.command("call", help="Call one MCP tool with optional action/args.")
def call(
    ctx: typer.Context,
    tool: str = typer.Argument(..., help="Tool name"),
    action: str = typer.Option("", "--action", help="Optional tool action"),
    args_json: str = typer.Option("{}", "--args-json", help="JSON object for tool args"),
    async_mode: bool = typer.Option(False, "--async", help="Set arguments.async=true"),
) -> None:
    server = _server(ctx)
    try:
        parsed_args = json.loads(args_json)
    except Exception as e:
        raise UsageError(f"invalid --args-json: {e}") from e
    if not isinstance(parsed_args, dict):
        raise UsageError("--args-json must decode to an object")

    arguments: dict[str, Any] = dict(parsed_args)
    if action:
        arguments["action"] = action
    if async_mode:
        arguments["async"] = True

    req = _jsonrpc_call(
        method="tools/call",
        params={
            "name": tool,
            "arguments": arguments,
        },
    )
    resp = _send(server, req)
    text = _extract_content_text(resp)
    if text:
        try:
            _print_json(json.loads(text))
            return
        except Exception:
            _print_json({"kind": "enabler.mcp-cli.call.v1", "text": text})
            return
    _print_json(resp)


@app.command("result", help="Fetch async operation result (ops.result).")
def result(
    ctx: typer.Context,
    operation_id: str = typer.Argument(..., help="Operation id from async call"),
) -> None:
    server = _server(ctx)
    req = _jsonrpc_call(
        method="tools/call",
        params={
            "name": "ops.result",
            "arguments": {"operationId": operation_id},
        },
    )
    resp = _send(server, req)
    text = _extract_content_text(resp)
    if text:
        try:
            _print_json(json.loads(text))
            return
        except Exception:
            _print_json({"kind": "enabler.mcp-cli.result.v1", "text": text})
            return
    _print_json(resp)


@app.command("raw", help="Send raw JSON-RPC request to local EnablerMcp handler.")
def raw(
    ctx: typer.Context,
    request_json: str = typer.Option("", "--request-json", help="JSON-RPC request object"),
    request_file: str = typer.Option("", "--request-file", help="Path to JSON-RPC request file"),
) -> None:
    if bool(request_json.strip()) == bool(request_file.strip()):
        raise UsageError("provide exactly one of --request-json or --request-file")
    raw_text = request_json
    if request_file:
        try:
            with open(request_file, "r", encoding="utf-8") as f:
                raw_text = f.read()
        except Exception as e:
            raise UsageError(f"failed to read --request-file: {e}") from e
    try:
        req = json.loads(raw_text)
    except Exception as e:
        raise UsageError(f"invalid JSON request: {e}") from e
    if not isinstance(req, dict):
        raise UsageError("raw request must be a JSON object")

    server = _server(ctx)
    resp = _send(server, req)
    _print_json(resp)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        _bootstrap_env()
        result = app(args=argv, prog_name="enabler-mcp-cli", standalone_mode=False)
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
    raise SystemExit(main(sys.argv[1:]))
