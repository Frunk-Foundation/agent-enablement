from __future__ import annotations

import json
import os
import select
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from enabler_cli.mcp_server import EnablerMcp


def _seed_cache(path: Path) -> None:
    exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = {
        "expiresAt": exp,
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "ASIAEXAMPLE",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiration": exp,
                },
                "references": {"awsRegion": "us-east-2"},
                "cognitoTokens": {
                    "idToken": "a.b.c",
                    "accessToken": "d.e.f",
                    "refreshToken": "refresh",
                },
            }
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _session_cache(tmp_path: Path, monkeypatch, *, agent_id: str = "agent-a") -> Path:
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    cache = tmp_path / "sessions" / agent_id / "session.json"
    _seed_cache(cache)
    return cache


def test_tools_list_matches_consolidated_contract(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)

    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert isinstance(resp, dict)
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "credentials.status",
        "credentials.ensure",
        "context.set_agentid",
        "taskboard.exec",
        "messages.exec",
        "shortlinks.exec",
        "files.exec",
        "ops.result",
    }


def test_tools_call_credentials_status(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)

    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "credentials.status", "arguments": {}},
        }
    )

    assert isinstance(resp, dict)
    text = resp["result"]["content"][0]["text"]
    parsed = json.loads(text)
    assert parsed["kind"] == "enabler.creds.status.v1"


def test_taskboard_tool_requires_cognito_id_token(monkeypatch, tmp_path: Path) -> None:
    cache = tmp_path / "sessions" / "agent-a" / "session.json"
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = {
        "expiresAt": exp,
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "ASIAEXAMPLE",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiration": exp,
                },
                "references": {"awsRegion": "us-east-2"},
            }
        },
    }
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(payload), encoding="utf-8")
    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "taskboard.exec", "arguments": {"action": "create", "args": {"name": "x"}}},
        }
    )

    assert isinstance(resp, dict)
    assert resp["error"]["data"]["code"] == "MISSING_ID_TOKEN"
    assert resp["error"]["data"]["retryable"] is False


def test_sts_tools_require_agent_enablement_set(monkeypatch, tmp_path: Path) -> None:
    cache = tmp_path / "sessions" / "agent-a" / "session.json"
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = {
        "expiresAt": exp,
        "credentialSets": {
            "agentAWSWorkshopRuntime": {
                "credentials": {
                    "accessKeyId": "ASIAEXAMPLE",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiration": exp,
                },
                "references": {"awsRegion": "us-east-2"},
            }
        },
    }
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(payload), encoding="utf-8")
    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "messages.exec", "arguments": {"action": "recv", "args": {}}},
        }
    )

    assert isinstance(resp, dict)
    assert resp["error"]["data"]["code"] == "MISSING_CREDENTIAL_SET"
    assert resp["error"]["data"]["retryable"] is False


def test_auth_refresh_failure_maps_to_structured_error(monkeypatch) -> None:
    from enabler_cli.runtime_core import OpError

    monkeypatch.setattr(
        "enabler_cli.mcp_server._resolve_runtime_credentials_doc",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OpError("credential auto-refresh failed after 3 attempts: boom")
        ),
    )

    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "credentials.status", "arguments": {}},
        }
    )

    assert isinstance(resp, dict)
    assert resp["error"]["data"]["code"] == "AUTH_REFRESH_FAILED"
    assert resp["error"]["data"]["retryable"] is False


def test_async_operation_lifecycle(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)

    def _fake_recv(_args, _g):
        print(json.dumps({"kind": "enabler.messages.recv.v1", "messages": []}))
        return 0

    monkeypatch.setattr("enabler_cli.mcp_server.cmd_messages_recv", _fake_recv)

    mcp = EnablerMcp(agent_id="agent-a")
    submit = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "messages.exec", "arguments": {"action": "recv", "args": {}, "async": True}},
        }
    )

    assert isinstance(submit, dict)
    accepted = json.loads(submit["result"]["content"][0]["text"])
    assert accepted["kind"] == "enabler.mcp.operation.accepted.v1"
    op_id = accepted["operationId"]

    final_state = "queued"
    result = None
    for _ in range(30):
        poll = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "ops.result", "arguments": {"operationId": op_id}},
            }
        )
        assert isinstance(poll, dict)
        result = json.loads(poll["result"]["content"][0]["text"])
        final_state = result["state"]
        if final_state in {"succeeded", "failed"}:
            break
        time.sleep(0.01)

    assert final_state == "succeeded"
    assert isinstance(result, dict)
    assert result["operationId"] == op_id
    assert result["result"]["kind"] == "enabler.messages.recv.v1"


def test_stdio_newline_transport_initialize_and_tools_list() -> None:
    env = dict(os.environ)
    env["ENABLER_AGENT_ID"] = "agent-a"
    proc = subprocess.Popen(
        ["./enabler-mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        proc.stdin.flush()

        ready, _, _ = select.select([proc.stdout], [], [], 3.0)
        assert ready, "timeout waiting for initialize response"
        init_resp = json.loads(proc.stdout.readline())
        assert init_resp["id"] == 1
        assert init_resp["result"]["serverInfo"]["name"] == "enabler-mcp"

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
        proc.stdin.flush()

        ready, _, _ = select.select([proc.stdout], [], [], 3.0)
        assert ready, "timeout waiting for tools/list response"
        list_resp = json.loads(proc.stdout.readline())
        names = {t["name"] for t in list_resp["result"]["tools"]}
        assert "credentials.status" in names
        assert "taskboard.exec" in names
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_stdio_initialize_from_non_repo_cwd_via_absolute_launcher() -> None:
    repo_root = str(Path(__file__).resolve().parents[1])
    launcher = str((Path(repo_root) / "enabler-mcp").resolve())
    env = dict(os.environ)
    env["ENABLER_AGENT_ID"] = "agent-a"
    proc = subprocess.Popen(
        [launcher],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd="/Users/jay",
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        proc.stdin.flush()

        ready, _, _ = select.select([proc.stdout], [], [], 3.0)
        assert ready, "timeout waiting for initialize response from non-repo cwd"
        init_resp = json.loads(proc.stdout.readline())
        assert init_resp["id"] == 1
        assert init_resp["result"]["serverInfo"]["name"] == "enabler-mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_stdio_startup_without_agent_id_exits_with_helpful_error() -> None:
    proc = subprocess.Popen(
        ["./enabler-mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
        env={k: v for k, v in os.environ.items() if k != "ENABLER_AGENT_ID"},
    )
    _out, err = proc.communicate(timeout=3)
    assert proc.returncode == 1
    assert "missing agent id" in (err or "").lower()


def test_context_set_agentid_switches_default_context(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch, agent_id="agent-a")
    _session_cache(tmp_path, monkeypatch, agent_id="agent-b")
    mcp = EnablerMcp(agent_id="agent-a")

    switch = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "context.set_agentid",
                "arguments": {"agentId": "agent-b"},
            },
        }
    )
    assert isinstance(switch, dict)
    payload = json.loads(switch["result"]["content"][0]["text"])
    assert payload["agentId"] == "agent-b"
    assert payload["previousAgentId"] == "agent-a"

    status = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "credentials.status", "arguments": {}},
        }
    )
    assert isinstance(status, dict)
    status_payload = json.loads(status["result"]["content"][0]["text"])
    assert status_payload["agentId"] == "agent-b"
    assert status_payload["defaultAgentId"] == "agent-b"


def test_context_set_agentid_rejects_missing_session(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch, agent_id="agent-a")
    mcp = EnablerMcp(agent_id="agent-a")
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "context.set_agentid",
                "arguments": {"agentId": "missing-agent"},
            },
        }
    )
    assert isinstance(resp, dict)
    assert resp["error"]["data"]["code"] in {"CREDENTIALS_UNAVAILABLE", "MISSING_FALLBACK_AUTH_INPUTS"}


def test_async_operations_pin_agentid_at_enqueue(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch, agent_id="agent-a")
    _session_cache(tmp_path, monkeypatch, agent_id="agent-b")
    mcp = EnablerMcp(agent_id="agent-a")

    def _fake_recv(_args, g):
        print(json.dumps({"kind": "enabler.messages.recv.v1", "agentIdSeen": g.agent_id, "messages": []}))
        return 0

    monkeypatch.setattr("enabler_cli.mcp_server.cmd_messages_recv", _fake_recv)
    submit = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "messages.exec", "arguments": {"action": "recv", "args": {}, "async": True}},
        }
    )
    assert isinstance(submit, dict)
    op_id = json.loads(submit["result"]["content"][0]["text"])["operationId"]

    switch = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "context.set_agentid", "arguments": {"agentId": "agent-b"}},
        }
    )
    assert isinstance(switch, dict)

    result_payload = None
    for _ in range(30):
        poll = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {"name": "ops.result", "arguments": {"operationId": op_id}},
            }
        )
        assert isinstance(poll, dict)
        if "result" not in poll:
            continue
        result_payload = json.loads(poll["result"]["content"][0]["text"])
        if result_payload["state"] in {"succeeded", "failed"}:
            break
        time.sleep(0.01)
    assert isinstance(result_payload, dict)
    assert result_payload["state"] == "succeeded"
    assert result_payload["agentId"] == "agent-a"
    assert result_payload["result"]["agentIdSeen"] == "agent-a"
