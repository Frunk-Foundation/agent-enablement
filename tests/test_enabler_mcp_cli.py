from __future__ import annotations

import json

from typer.testing import CliRunner

import enabler_cli.mcp_cli_main as mcp_cli


runner = CliRunner()


class _FakeMcp:
    created_agent_ids: list[str] = []
    requests: list[dict[str, object]] = []

    def __init__(self, agent_id: str = "") -> None:
        self.agent_id = agent_id
        _FakeMcp.created_agent_ids.append(agent_id)

    def handle_request(self, req: dict[str, object]) -> dict[str, object]:
        _FakeMcp.requests.append(req)
        method = str(req.get("method") or "")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"tools": [{"name": "help"}]}}
        if method == "tools/call":
            params = req.get("params") or {}
            if isinstance(params, dict):
                name = str(params.get("name") or "")
                if name == "taskboard.exec":
                    return {
                        "jsonrpc": "2.0",
                        "id": req.get("id"),
                        "result": {"content": [{"type": "text", "text": '{"kind":"ok","op":"taskboard.exec"}'}]},
                    }
                if name == "help":
                    return {
                        "jsonrpc": "2.0",
                        "id": req.get("id"),
                        "result": {"content": [{"type": "text", "text": '{"kind":"help"}'}]},
                    }
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}


def _reset_fake() -> None:
    _FakeMcp.created_agent_ids.clear()
    _FakeMcp.requests.clear()


def test_list_routes_to_tools_list(monkeypatch) -> None:
    _reset_fake()
    monkeypatch.setattr(mcp_cli, "EnablerMcp", _FakeMcp)
    result = runner.invoke(mcp_cli.app, ["--agent-id", "jay", "list"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.mcp-cli.tools.v1"
    assert parsed["tools"] == [{"name": "help"}]
    assert _FakeMcp.created_agent_ids == ["jay"]
    assert _FakeMcp.requests[-1]["method"] == "tools/list"


def test_call_maps_action_async_and_args_json(monkeypatch) -> None:
    _reset_fake()
    monkeypatch.setattr(mcp_cli, "EnablerMcp", _FakeMcp)
    result = runner.invoke(
        mcp_cli.app,
        [
            "--agent-id",
            "jay",
            "call",
            "taskboard.exec",
            "--action",
            "create",
            "--args-json",
            '{"args":{"name":"board-a"}}',
            "--async",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "ok"
    assert parsed["op"] == "taskboard.exec"
    req = _FakeMcp.requests[-1]
    assert req["method"] == "tools/call"
    params = req["params"]
    assert isinstance(params, dict)
    assert params["name"] == "taskboard.exec"
    args = params["arguments"]
    assert isinstance(args, dict)
    assert args["action"] == "create"
    assert args["async"] is True
    assert args["args"] == {"name": "board-a"}


def test_inspect_uses_help_tool(monkeypatch) -> None:
    _reset_fake()
    monkeypatch.setattr(mcp_cli, "EnablerMcp", _FakeMcp)
    result = runner.invoke(mcp_cli.app, ["inspect", "messages.exec", "--action", "recv"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "help"
    req = _FakeMcp.requests[-1]
    params = req["params"]
    assert isinstance(params, dict)
    assert params["name"] == "help"
    assert params["arguments"] == {"tool": "messages.exec", "action": "recv"}


def test_raw_requires_exactly_one_request_source() -> None:
    result = runner.invoke(mcp_cli.app, ["raw"])
    assert result.exit_code == 1
    assert result.exception is not None
    assert "provide exactly one of --request-json or --request-file" in str(result.exception)
