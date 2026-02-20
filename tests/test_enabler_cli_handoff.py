import argparse
import io
import json
from pathlib import Path

import pytest

from enabler_cli.cli import (
    GlobalOpts,
    UsageError,
    cmd_agent_handoff_create,
    cmd_agent_handoff_print_env,
)


def _g() -> GlobalOpts:
    return GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path="/tmp/enabler-test-credentials.json",
        auto_refresh_creds=False,
    )


def test_cmd_agent_handoff_create_resolves_from_stack_and_ssm(monkeypatch, tmp_path, capsys):
    class _Ctx:
        session = object()

        def require_output(self, _key: str) -> str:
            return "https://example.invalid/v1/bundle"

        def resolve_api_key_param_name(self, _override: str | None) -> str:
            return "/param"

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr("enabler_cli.admin_commands._ssm_get_value", lambda _session, *, name: "api-key-value")

    out_file = tmp_path / "handoff.json"
    args = argparse.Namespace(
        username="agent-a",
        password="pw-1",
        bundle_endpoint=None,
        api_key=None,
        api_key_ssm_name=None,
        out=str(out_file),
    )

    assert cmd_agent_handoff_create(args, _g()) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["kind"] == "enabler.admin.handoff.v1"
    assert parsed["username"] == "agent-a"
    assert parsed["bundleEndpoint"] == "https://example.invalid/v1/bundle"
    assert parsed["apiKey"] == "api-key-value"

    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["password"] == "pw-1"
    assert (out_file.stat().st_mode & 0o777) == 0o600


def test_cmd_agent_handoff_create_prefers_explicit_overrides(monkeypatch, capsys):
    class _Ctx:
        session = object()

        def require_output(self, _key: str) -> str:
            raise AssertionError("unexpected stack lookup")

        def resolve_api_key_param_name(self, _override: str | None) -> str:
            raise AssertionError("unexpected ssm name lookup")

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr(
        "enabler_cli.admin_commands._ssm_get_value",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected ssm value lookup")),
    )

    args = argparse.Namespace(
        username="agent-b",
        password="pw-2",
        bundle_endpoint="https://override.invalid/v1/bundle",
        api_key="k-2",
        api_key_ssm_name=None,
        out=None,
    )
    assert cmd_agent_handoff_create(args, _g()) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["bundleEndpoint"] == "https://override.invalid/v1/bundle"
    assert parsed["apiKey"] == "k-2"


def test_cmd_agent_handoff_print_env_from_file(tmp_path, capsys):
    handoff_path = Path(tmp_path) / "handoff.json"
    handoff_path.write_text(
        json.dumps(
            {
                "kind": "enabler.admin.handoff.v1",
                "schemaVersion": "2026-02-17",
                "username": "u",
                "password": "p",
                "apiKey": "k",
                "bundleEndpoint": "https://example.invalid/v1/bundle",
            }
        ),
        encoding="utf-8",
    )

    args = argparse.Namespace(file=str(handoff_path))
    assert cmd_agent_handoff_print_env(args, _g()) == 0
    captured = capsys.readouterr()
    err = captured.err
    out = captured.out
    assert "warning: emitting plaintext secrets" in err
    assert "export ENABLER_COGNITO_USERNAME='u'" in out
    assert "export ENABLER_BUNDLE_ENDPOINT='https://example.invalid/v1/bundle'" in out


def test_cmd_agent_handoff_print_env_from_stdin(monkeypatch, capsys):
    class _FakeStdin(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(
        "sys.stdin",
        _FakeStdin(
            json.dumps(
                {
                    "kind": "enabler.admin.handoff.v1",
                    "schemaVersion": "2026-02-17",
                    "username": "u2",
                    "password": "p2",
                    "apiKey": "k2",
                    "bundleEndpoint": "https://example.invalid/v1/bundle",
                }
            )
        ),
    )
    args = argparse.Namespace(file=None)
    assert cmd_agent_handoff_print_env(args, _g()) == 0
    out = capsys.readouterr().out
    assert "export ENABLER_API_KEY='k2'" in out


def test_cmd_agent_handoff_print_env_rejects_invalid_schema(tmp_path):
    handoff_path = Path(tmp_path) / "handoff-invalid.json"
    handoff_path.write_text(
        json.dumps(
            {
                "kind": "enabler.admin.handoff.v1",
                "schemaVersion": "bad-version",
                "username": "u",
                "password": "p",
                "apiKey": "k",
                "bundleEndpoint": "https://example.invalid/v1/bundle",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(UsageError, match="invalid handoff schemaVersion"):
        cmd_agent_handoff_print_env(argparse.Namespace(file=str(handoff_path)), _g())
