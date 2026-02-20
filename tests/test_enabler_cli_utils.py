import argparse
import base64
import json
import re
from collections.abc import Iterable

import pytest
from typer.testing import CliRunner
import click

from enabler_cli.cli import (
    GlobalOpts,
    OpError,
    UsageError,
    _apply_global_env,
    _aws_profile_region_from_env,
    _inbox_queue_name,
    _resolve_aws_credential_source_local,
    _parse_groups_csv,
    _parse_stage_from_api_key_param_name,
    _ssm_key_name_agent,
    _ssm_key_name_shared,
    admin_app,
    app,
    cmd_ssm_api_key,
    cmd_pack_publish,
    cmd_stack_output,
    main_agent,
    main_admin,
    main,
)
from enabler_cli.cli_shared import _jwt_payload


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _walk_click_commands(root: click.Command) -> Iterable[tuple[str, click.Command]]:
    stack: list[tuple[str, click.Command]] = [("", root)]
    while stack:
        base, cmd = stack.pop()
        if isinstance(cmd, click.Group):
            for name, sub in cmd.commands.items():
                path = f"{base} {name}".strip()
                yield path, sub
                stack.append((path, sub))


def test_all_agent_and_admin_commands_have_help_text():
    for root in (app, admin_app):
        for path, cmd in _walk_click_commands(root):
            if isinstance(cmd, click.Group):
                continue
            help_text = str(cmd.help or "").strip()
            assert help_text, f"missing help text for command: {path}"


def test_parse_groups_csv_dedupes_and_trims():
    assert _parse_groups_csv(None) == []
    assert _parse_groups_csv("") == []
    assert _parse_groups_csv("a, b, a, , c") == ["a", "b", "c"]


def test_inbox_queue_name_sanitizes_and_truncates():
    assert _inbox_queue_name("alice") == "agent-inbox-alice"
    assert _inbox_queue_name("a b") == "agent-inbox-a-b"
    assert _inbox_queue_name("!@#$") == "agent-inbox-----"

    long_id = "a" * 200
    name = _inbox_queue_name(long_id)
    assert name.startswith("agent-inbox-")
    assert len(name) == len("agent-inbox-") + 60


def test_jwt_payload_parses_sub():
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'abc'})}."
    assert _jwt_payload(token)["sub"] == "abc"


def test_jwt_payload_rejects_invalid():
    with pytest.raises(OpError):
        _jwt_payload("nope")


def test_parse_stage_from_api_key_param_name():
    assert (
        _parse_stage_from_api_key_param_name("/agent-enablement/AgentEnablementStack/prod/shared-api-key")
        == "prod"
    )
    assert _parse_stage_from_api_key_param_name("/other/stack/prod/shared-api-key") is None


def test_ssm_key_name_helpers_build_paths():
    assert _ssm_key_name_shared(stage="prod", key="openai") == "/agent-enablement/prod/shared/openai"
    assert (
        _ssm_key_name_agent(stage="prod", sub="sub-123", key="openai")
        == "/agent-enablement/prod/agent/sub-123/openai"
    )
    with pytest.raises(UsageError):
        _ssm_key_name_agent(stage="prod", sub="", key="k")


def test_apply_global_env_stack_ignores_legacy_cdk_stack_name(monkeypatch):
    monkeypatch.delenv("STACK", raising=False)
    monkeypatch.setenv("CDK_STACK_NAME", "LegacyStack")
    g = _apply_global_env(
        argparse.Namespace(
            profile=None,
            region=None,
            stack=None,
            creds_cache=None,
            auto_refresh_creds=True,
            plain_json=False,
            quiet=False,
        )
    )
    assert g.stack == "AgentEnablementStack"


def test_apply_global_env_defaults_to_pretty_json(monkeypatch):
    monkeypatch.delenv("STACK", raising=False)
    g = _apply_global_env(
        argparse.Namespace(
            profile=None,
            region=None,
            stack=None,
            creds_cache=None,
            auto_refresh_creds=True,
            plain_json=False,
            quiet=False,
        )
    )
    assert g.pretty is True


def test_apply_global_env_plain_json_disables_pretty(monkeypatch):
    monkeypatch.delenv("STACK", raising=False)
    g = _apply_global_env(
        argparse.Namespace(
            profile=None,
            region=None,
            stack=None,
            creds_cache=None,
            auto_refresh_creds=True,
            plain_json=True,
            quiet=False,
        )
    )
    assert g.pretty is False


def test_aws_profile_region_does_not_backfill_from_aws_default_env(monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_PROFILE", "legacy-profile")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-2")
    with pytest.raises(UsageError, match="missing AWS_PROFILE"):
        _aws_profile_region_from_env()


def test_main_loads_dotenv_with_package_defaults(monkeypatch):
    calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr("enabler_cli.cli.load_dotenv", lambda *a, **k: calls.append((a, k)) or True)
    monkeypatch.setattr("enabler_cli.cli.app", lambda *a, **k: None)
    assert main([]) == 0
    assert calls == [((), {})]


def test_main_returns_app_exit_code(monkeypatch):
    monkeypatch.setattr("enabler_cli.cli.load_dotenv", lambda *a, **k: True)
    monkeypatch.setattr("enabler_cli.cli.app", lambda *a, **k: 2)
    assert main(["files", "share"]) == 2


def test_main_admin_usage_error_prints_command_help(capsys):
    code = main_admin(["cognito", "rotate-password"])
    captured = capsys.readouterr()
    combined = _plain(f"{captured.err}\n{captured.out}")
    assert code == 2
    assert "Missing argument 'USERNAME'" in combined
    assert "Usage: enabler-admin cognito rotate-password" in combined
    assert "--user-pool-id" in combined


def test_admin_cognito_help_lists_remove_user():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["cognito", "--help"])
    assert result.exit_code == 0
    assert "remove-user" in result.output


def test_admin_agent_help_lists_decommission():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "decommission" in result.output


def test_main_agent_runtime_usage_error_prints_command_help(capsys, monkeypatch):
    monkeypatch.setattr("enabler_cli.cli.load_dotenv", lambda *a, **k: True)
    monkeypatch.delenv("ENABLER_COGNITO_USERNAME", raising=False)
    monkeypatch.delenv("ENABLER_COGNITO_PASSWORD", raising=False)
    monkeypatch.delenv("ENABLER_CREDENTIALS_ENDPOINT", raising=False)
    monkeypatch.delenv("ENABLER_API_KEY", raising=False)
    code = main_agent(["agent", "credentials"])
    captured = capsys.readouterr()
    combined = f"{captured.err}\n{captured.out}"
    assert code == 2
    assert "No such command 'agent'" in combined


def test_agent_group_removed_from_agent_cli():
    runner = CliRunner()
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code != 0
    assert "No such command 'agent'" in result.output


def test_main_agent_runtime_usage_error_prints_command_help_top_level(capsys, monkeypatch):
    monkeypatch.setattr("enabler_cli.cli.load_dotenv", lambda *a, **k: True)
    monkeypatch.delenv("ENABLER_COGNITO_USERNAME", raising=False)
    monkeypatch.delenv("ENABLER_COGNITO_PASSWORD", raising=False)
    monkeypatch.delenv("ENABLER_CREDENTIALS_ENDPOINT", raising=False)
    monkeypatch.delenv("ENABLER_API_KEY", raising=False)
    code = main_agent(["credentials"])
    captured = capsys.readouterr()
    combined = _plain(f"{captured.err}\n{captured.out}")
    assert code == 2
    assert "missing username (--username or env ENABLER_COGNITO_USERNAME)" in combined
    assert "Usage: enabler credentials" in combined
    assert "--username" in combined
    assert "--password" in combined
    assert "--endpoint" in combined
    assert "--api-key" in combined


def test_typer_root_help_excludes_custom_dotenv_flags():
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--help"],
        env={"ENABLER_HELP_CREDENTIALS_BANNER": "1", "ENABLER_CLI_ROLE": "agent", "STACK": ""},
    )
    assert result.exit_code == 0
    assert "Credentials: cognito.username=" in result.output
    assert "env ENABLER_COGNITO_USERNAME" in result.output
    assert "Cache:" in result.output
    assert "--env-file" not in result.output
    assert "--no-dotenv" not in result.output
    assert "CDK_STACK_NAME" not in result.output


def test_shortlinks_create_help_mentions_json_output_flag():
    runner = CliRunner()
    result = runner.invoke(app, ["shortlinks", "create", "--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "--json" in output
    assert "Print JSON details instead of plain text output" in output


def test_stack_output_help_renders_admin_context():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["stack-output", "--help"], env={"STACK": ""})
    assert result.exit_code == 0
    assert "Credentials: aws=" in result.output
    assert "Stack: AgentEnablementStack" in result.output
    assert "(source=default)" in result.output
    assert "Print CloudFormation stack outputs or a single output value." in result.output


def test_ssm_help_lists_command_descriptions():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["ssm", "--help"], env={"STACK": ""})
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "Stack: AgentEnablementStack" in output
    assert "(source=default)" in output
    assert "api-key" in output
    assert "shared API key SSM parameter name" in output
    assert "decrypted value" in output
    assert "base-paths" in output
    assert "per-agent SSM keys" in output
    assert "put-agent" in output
    assert "/agent-enablement/<stage>/agent/<sub>/" in output


def test_help_banner_includes_env_aws_and_cached_cognito_identity(tmp_path):
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'sub123', 'email': 'u', 'exp': 4102444800})}."
    cache_path = tmp_path / "credentials.json"
    cache_path.write_text(json.dumps({"cognitoTokens": {"idToken": token}}), encoding="utf-8")
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "ENABLER_CREDS_CACHE": str(cache_path),
        "ENABLER_HELP_CREDENTIALS_BANNER": "1",
        "STACK": "",
    }

    runner = CliRunner()
    result = runner.invoke(admin_app, ["ssm", "api-key", "--help"], env=env)
    assert result.exit_code == 0
    assert "Credentials: aws=env(AWS_ACCESS_KEY_ID); cognito=n/a" in result.output
    assert "Stack:" in result.output
    assert "AgentEnablementStack" in result.output
    assert "(source=default)" in result.output


def test_admin_help_banner_uses_stack_env_and_flag_sources():
    runner = CliRunner()

    env_result = runner.invoke(admin_app, ["ssm", "--help"], env={"STACK": "StackFromEnv"})
    assert env_result.exit_code == 0
    assert "Stack: StackFromEnv (source=env(STACK))" in _plain(env_result.output)

    flag_result = runner.invoke(admin_app, ["--stack", "StackFromFlag", "ssm", "--help"])
    assert flag_result.exit_code == 0
    assert "Stack: StackFromFlag (source=--stack)" in _plain(flag_result.output)


def test_pack_build_help_banner_includes_bucket_line_after_stack():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["pack-build", "--help"])
    assert result.exit_code == 0
    assert "Credentials:" in result.output
    assert "Stack:" in result.output
    assert "Bucket:" in result.output
    assert "source=stack output CommsSharedBucketName" in result.output
    assert result.output.index("Credentials:") < result.output.index("Stack:")
    assert result.output.index("Stack:") < result.output.index("Bucket:")


def test_admin_help_lists_pack_commands_at_bottom():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    stack_line = "│ stack-output"
    agent_line = "│ agent"
    build_line = "│ pack-build"
    publish_line = "│ pack-publish"
    assert stack_line in output
    assert agent_line in output
    assert build_line in output
    assert publish_line in output
    assert output.index(stack_line) < output.index(agent_line)
    assert output.index(agent_line) < output.index(build_line)
    assert output.index(build_line) < output.index(publish_line)


def test_cognito_help_banner_includes_pool_id_line_after_stack():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["cognito", "--help"])
    assert result.exit_code == 0
    assert "Credentials:" in result.output
    assert "Stack:" in result.output
    assert "PoolId:" in result.output
    assert "source=stack output UserPoolId" in result.output
    assert result.output.index("Credentials:") < result.output.index("Stack:")
    assert result.output.index("Stack:") < result.output.index("PoolId:")


def test_agent_cli_hard_break_rejects_admin_commands():
    runner = CliRunner()
    result = runner.invoke(app, ["stack", "--help"])
    assert result.exit_code != 0
    assert "No such command 'stack'" in result.output


def test_admin_cli_hard_break_rejects_taskboard_commands():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["taskboard", "--help"])
    assert result.exit_code != 0
    assert "No such command 'taskboard'" in result.output


def test_admin_agent_handoff_help_lists_commands():
    runner = CliRunner()
    result = runner.invoke(admin_app, ["agent", "handoff", "--help"])
    assert result.exit_code == 0
    assert "create" in result.output
    assert "print-env" in result.output


def test_help_banner_can_be_disabled():
    runner = CliRunner()
    result = runner.invoke(app, ["--help"], env={"ENABLER_HELP_CREDENTIALS_BANNER": "0"})
    assert result.exit_code == 0
    assert "Credentials:" not in result.output


def test_resolve_aws_credential_source_local_reports_profile_and_session_cache(monkeypatch, tmp_path):
    cache_path = tmp_path / "credentials.json"
    cache_path.write_text(
        json.dumps(
            {
                "credentials": {
                    "accessKeyId": "AKIAEXAMPLE",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.setenv("AWS_PROFILE", "dev")
    monkeypatch.setenv("AWS_REGION", "us-east-2")
    g = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path=str(cache_path),
        auto_refresh_creds=True,
    )
    assert _resolve_aws_credential_source_local(g) == "profile(dev/us-east-2)+session-token-file"


def test_cmd_stack_output_without_key_prints_all_outputs(monkeypatch, capsys):
    class _Ctx:
        session = object()
        stack = "AgentEnablementStack"

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr(
        "enabler_cli.admin_commands._cf_outputs",
        lambda _session, *, stack: [{"OutputKey": "A", "OutputValue": "1"}],
    )
    monkeypatch.setattr(
        "enabler_cli.admin_commands._stack_output_value",
        lambda _session, *, stack, key: None,
    )

    args = argparse.Namespace(output_key=None)
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    assert cmd_stack_output(args, g) == 0
    out = json.loads(capsys.readouterr().out)
    assert out[0]["OutputKey"] == "A"


def test_cmd_ssm_api_key_prints_parameter_name_and_value_json(monkeypatch, capsys):
    class _Ctx:
        session = object()

        def resolve_api_key_param_name(self, _override: str | None) -> str:
            return "/agent-enablement/AgentEnablementStack/prod/shared-api-key"

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr("enabler_cli.admin_commands._ssm_get_value", lambda _session, *, name: "k-123")

    args = argparse.Namespace(name=None)
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    assert cmd_ssm_api_key(args, g) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["parameterName"] == "/agent-enablement/AgentEnablementStack/prod/shared-api-key"
    assert out["value"] == "k-123"


def test_cmd_stack_output_with_key_prints_value(monkeypatch, capsys):
    class _Ctx:
        session = object()
        stack = "AgentEnablementStack"

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr(
        "enabler_cli.admin_commands._stack_output_value",
        lambda _session, *, stack, key: "value-1" if key == "A" else None,
    )

    args = argparse.Namespace(output_key="A")
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    assert cmd_stack_output(args, g) == 0
    assert capsys.readouterr().out.strip() == "value-1"


def test_cmd_stack_output_with_missing_key_errors(monkeypatch):
    class _Ctx:
        session = object()
        stack = "AgentEnablementStack"

    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: _Ctx())
    monkeypatch.setattr(
        "enabler_cli.admin_commands._stack_output_value",
        lambda _session, *, stack, key: None,
    )

    args = argparse.Namespace(output_key="Missing")
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    with pytest.raises(OpError, match="output key not found: Missing"):
        cmd_stack_output(args, g)


def test_cmd_pack_publish_uses_explicit_bucket_without_stack_lookup(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("enabler_cli.cli._aws_profile_region_from_env", lambda: ("dev", "us-east-2"))
    monkeypatch.setattr(
        "enabler_cli.cli._account_session",
        lambda: (_ for _ in ()).throw(AssertionError("unexpected account session lookup")),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._require_stack_output",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected stack output lookup")),
    )

    called: dict[str, object] = {}

    def _fake_publish(*, bucket, version, dist_root, prefix, dry_run):
        called.update(
            {
                "bucket": bucket,
                "version": version,
                "dist_root": dist_root,
                "prefix": prefix,
                "dry_run": dry_run,
            }
        )
        return {"ok": True, "bucket": bucket}

    monkeypatch.setattr("enablement_pack.publish_pack.publish", _fake_publish)

    args = argparse.Namespace(
        bucket="explicit-bucket",
        version="v1",
        dist_root=str(tmp_path),
        prefix="agent-enablement",
        dry_run=False,
    )
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    assert cmd_pack_publish(args, g) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["bucket"] == "explicit-bucket"
    assert called["bucket"] == "explicit-bucket"


def test_cmd_pack_publish_falls_back_to_comms_bucket_stack_output(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("enabler_cli.cli._aws_profile_region_from_env", lambda: ("dev", "us-east-2"))
    monkeypatch.setattr("enabler_cli.cli._account_session", lambda: object())
    monkeypatch.setattr(
        "enabler_cli.cli._require_stack_output",
        lambda _session, *, stack, key: "stack-comms-bucket",
    )

    called: dict[str, object] = {}

    def _fake_publish(*, bucket, version, dist_root, prefix, dry_run):
        called["bucket"] = bucket
        return {"ok": True, "bucket": bucket}

    monkeypatch.setattr("enablement_pack.publish_pack.publish", _fake_publish)

    args = argparse.Namespace(
        bucket=None,
        version="v1",
        dist_root=str(tmp_path),
        prefix="agent-enablement",
        dry_run=True,
    )
    g = GlobalOpts(stack="AgentEnablementStack", pretty=False, quiet=False)
    assert cmd_pack_publish(args, g) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["bucket"] == "stack-comms-bucket"
    assert called["bucket"] == "stack-comms-bucket"
