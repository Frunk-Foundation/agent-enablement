import argparse
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from enabler_cli.apps.agent_admin_cli import (
    GlobalOpts,
    UsageError,
    _taskboard_id_token_from_cache,
    _taskboard_target,
    app,
    cmd_taskboard_add,
    cmd_taskboard_audit,
    cmd_taskboard_claim,
    cmd_taskboard_create,
    cmd_taskboard_list,
    cmd_taskboard_my_activity,
    cmd_taskboard_status,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _g() -> GlobalOpts:
    return GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path="/tmp/enabler-test-credentials.json",
        auto_refresh_creds=True,
    )


def _auth_args(*, json_output: bool = False) -> dict:
    return {"json_output": json_output}


def test_taskboard_target_prefers_task_id():
    assert _taskboard_target("task-123", "q-value", "fallback") == {"taskId": "task-123"}
    assert _taskboard_target(None, "q-value", None) == {"q": "q-value"}
    assert _taskboard_target(None, None, "fallback") == {"q": "fallback"}


def test_cmd_taskboard_create_posts_board(monkeypatch, capsys):
    captured: dict = {}

    def fake_request(**kwargs):
        captured.update(kwargs)
        return {"boardId": "board-1", "name": "alpha"}

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))

    args = argparse.Namespace(
        name="alpha",
        **_auth_args(),
    )
    assert cmd_taskboard_create(args, _g()) == 0

    out = capsys.readouterr().out
    assert 'created board board-1 name="alpha"' in out
    assert captured["method"] == "POST"
    assert captured["path"] == "/boards"
    assert captured["body_obj"]["name"] == "alpha"


def test_cmd_taskboard_create_json_output(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {"boardId": "board-1", "name": "alpha"}

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))

    args = argparse.Namespace(
        name="alpha",
        **_auth_args(json_output=True),
    )
    assert cmd_taskboard_create(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["boardId"] == "board-1"


def test_cmd_taskboard_add_reads_file_and_posts_lines(monkeypatch, tmp_path, capsys):
    captured: dict = {}

    def fake_request(**kwargs):
        captured.update(kwargs)
        return {"boardId": "board-1", "added": 2}

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))

    src = Path(tmp_path) / "tasks.txt"
    src.write_text("first\n\n second \n", encoding="utf-8")

    args = argparse.Namespace(
        board_id="board-1",
        file=str(src),
        lines=[],
        **_auth_args(),
    )
    assert cmd_taskboard_add(args, _g()) == 0

    out = capsys.readouterr().out
    assert "added 2 task(s) to board board-1" in out
    assert captured["path"] == "/boards/board-1/tasks"
    assert captured["body_obj"]["lines"] == ["first", "second"]


def test_cmd_taskboard_list_passes_query_and_pagination(monkeypatch, capsys):
    captured: dict = {}

    def fake_request(**kwargs):
        captured.update(kwargs)
        return {"items": [], "nextToken": ""}

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))

    args = argparse.Namespace(
        board_id="board-1",
        search="menu",
        query=None,
        status="pending",
        limit="10",
        next_token="tok-1",
        **_auth_args(),
    )
    assert cmd_taskboard_list(args, _g()) == 0
    out = capsys.readouterr().out
    assert "No tasks." in out
    assert "items: 0" in out

    assert captured["method"] == "GET"
    assert captured["path"] == "/boards/board-1/tasks"
    assert captured["query"]["q"] == "menu"
    assert captured["query"]["status"] == "pending"
    assert captured["query"]["limit"] == "10"
    assert captured["query"]["nextToken"] == "tok-1"


def test_cmd_taskboard_list_prints_next_token_hint(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {
            "items": [
                {
                    "taskId": "task-1",
                    "status": "pending",
                    "line": "first task",
                    "updatedAt": "2026-02-18T00:00:00Z",
                    "addedByUsername": "agent-test",
                }
            ],
            "nextToken": "abc123",
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_local_short_timestamp", lambda _value: "2026-02-18 09:10:11")
    args = argparse.Namespace(
        board_id="board-1",
        search=None,
        query=None,
        status=None,
        limit=None,
        next_token=None,
        **_auth_args(),
    )
    assert cmd_taskboard_list(args, _g()) == 0
    out = capsys.readouterr().out
    assert "- task-1 [pending] owner=agent-test updated=2026-02-18 09:10:11 summary=first task" in out
    assert "next-token: abc123" in out
    assert "enabler taskboard list board-1 --next-token 'abc123'" in out


def test_cmd_taskboard_list_does_not_truncate_fields(monkeypatch, capsys):
    long_task_id = "task-1234567890abcdefghijklmnopqrstuvwxyz"
    long_owner = "very-long-owner-name-without-truncation"
    long_line = "this is a very long task summary that should remain fully visible in the output list"
    long_updated = "2026-02-18T00:00:00.123456Z"

    def fake_request(**_kwargs):
        return {
            "items": [
                {
                    "taskId": long_task_id,
                    "status": "pending",
                    "line": long_line,
                    "updatedAt": long_updated,
                    "addedByUsername": long_owner,
                }
            ],
            "nextToken": "",
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_local_short_timestamp", lambda _value: "2026-02-18 09:10:11")
    args = argparse.Namespace(
        board_id="board-1",
        search=None,
        query=None,
        status=None,
        limit=None,
        next_token=None,
        **_auth_args(),
    )
    assert cmd_taskboard_list(args, _g()) == 0
    out = capsys.readouterr().out
    assert long_task_id in out
    assert long_owner in out
    assert long_line in out
    assert "updated=2026-02-18 09:10:11" in out


def test_cmd_taskboard_list_json_output(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {"items": [{"taskId": "task-1"}], "nextToken": ""}

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    args = argparse.Namespace(
        board_id="board-1",
        search=None,
        query=None,
        status=None,
        limit=None,
        next_token=None,
        **_auth_args(json_output=True),
    )
    assert cmd_taskboard_list(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["items"][0]["taskId"] == "task-1"


def test_cmd_taskboard_audit_always_outputs_detailed_json(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {
            "items": [
                {
                    "timestamp": "2026-02-18T05:39:59.523735+00:00",
                    "action": "claim",
                    "taskId": "task-1",
                    "actorUsername": "agent-test",
                    "line": "first task",
                }
            ],
            "nextToken": "tok-2",
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    args = argparse.Namespace(
        board_id="board-1",
        task_id="task-1",
        limit="10",
        next_token="tok-1",
        **_auth_args(),
    )
    assert cmd_taskboard_audit(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["items"][0]["timestamp"] == "2026-02-18T05:39:59.523735+00:00"
    assert out["items"][0]["action"] == "claim"
    assert out["nextToken"] == "tok-2"


def test_cmd_taskboard_my_activity_keeps_table_with_local_short_timestamp(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {
            "items": [
                {
                    "timestamp": "2026-02-18T05:39:59.523735+00:00",
                    "action": "claim",
                    "boardId": "board-1",
                    "taskId": "task-1",
                    "line": "first task",
                }
            ],
            "nextToken": "tok-2",
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_local_short_timestamp", lambda _value: "2026-02-18 09:10:11")
    args = argparse.Namespace(
        board_id=None,
        limit="10",
        next_token=None,
        **_auth_args(),
    )
    assert cmd_taskboard_my_activity(args, _g()) == 0
    out = capsys.readouterr().out
    assert "timestamp" in out
    assert "action" in out
    assert "2026-02-18 09:10:11" in out
    assert "board-1" in out
    assert "task-1" in out
    assert "first task" in out
    assert "items: 1" in out
    assert "next-token: tok-2" in out


def test_cmd_taskboard_claim_prints_summary(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {
            "task": {
                "boardId": "board-1",
                "taskId": "task-7",
                "status": "claimed",
            }
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    args = argparse.Namespace(
        board_id="board-1",
        target=None,
        task_id="task-7",
        query=None,
        **_auth_args(),
    )
    assert cmd_taskboard_claim(args, _g()) == 0
    out = capsys.readouterr().out
    assert "claimed task task-7 on board board-1 status=claimed" in out


def test_cmd_taskboard_status_prints_compact_counts(monkeypatch, capsys):
    def fake_request(**_kwargs):
        return {
            "boardId": "board-1",
            "name": "Main",
            "total": 4,
            "pending": 1,
            "claimed": 1,
            "done": 1,
            "failed": 1,
        }

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_request", fake_request)
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._taskboard_auth_for_args", lambda _args, _g: ("https://example.invalid/v1/taskboard", "a.b.c"))
    args = argparse.Namespace(
        board_id="board-1",
        **_auth_args(),
    )
    assert cmd_taskboard_status(args, _g()) == 0
    out = capsys.readouterr().out
    assert "board: board-1" in out
    assert 'name: "Main"' in out
    assert "status" in out
    assert "pending" in out
    assert "total: 4" in out


def test_cmd_taskboard_create_fails_fast_when_taskboard_output_missing(monkeypatch):
    args = argparse.Namespace(
        name="alpha",
        **_auth_args(),
    )
    g = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path="/tmp/enabler-test-no-taskboard-creds.json",
        auto_refresh_creds=False,
    )
    with pytest.raises(UsageError, match="missing credentials cache"):
        cmd_taskboard_create(args, g)


def test_typer_includes_taskboard_group_help():
    runner = CliRunner()
    result = runner.invoke(app, ["taskboard", "--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "Taskboard helpers" in output
    assert "--json" in output
    assert "create" in output


def test_taskboard_list_help_mentions_partial_board_id():
    runner = CliRunner()
    result = runner.invoke(app, ["taskboard", "list", "--help"])
    assert result.exit_code == 0
    assert "Board ID (full or unique partial)" in result.output


def test_taskboard_audit_help_mentions_detailed_json():
    runner = CliRunner()
    result = runner.invoke(app, ["taskboard", "audit", "--help"])
    assert result.exit_code == 0
    assert "detailed JSON" in result.output


def test_taskboard_group_json_flag_reaches_command(monkeypatch):
    captured: dict = {}

    def fake_cmd(args, _g):
        captured["json_output"] = getattr(args, "json_output", None)
        return 0

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli.cmd_taskboard_create", fake_cmd)
    runner = CliRunner()
    result = runner.invoke(app, ["taskboard", "--json", "create"])
    assert result.exit_code == 0
    assert captured["json_output"] is True


def test_taskboard_id_token_from_cache_uses_root_token_with_credential_sets(tmp_path):
    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "cognitoTokens": {"idToken": "a.b.c"},
                "credentialSets": {
                    "agentEnablement": {
                        "credentials": {
                            "accessKeyId": "AKIA_TEST",
                            "secretAccessKey": "secret",
                            "sessionToken": "token",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    g = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path=str(cache_path),
        auto_refresh_creds=True,
    )
    assert _taskboard_id_token_from_cache(g) == "a.b.c"
