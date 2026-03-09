from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from enabler_cli.apps.agent_admin_cli import admin_app


runner = CliRunner()


class _FakeAdminContext:
    def __init__(self) -> None:
        self.session = self

    def outputs(self) -> dict[str, str]:
        return {
            "CredentialsInvokeUrl": "https://api.example.com/prod/v1/credentials",
            "ApiKeyParameterName": "/agent-enablement/prod/shared/api-key",
        }

    def output(self, key: str) -> str | None:
        return self.outputs().get(key)

    def require_output(self, key: str) -> str:
        value = self.output(key)
        if value is None:
            raise AssertionError(f"missing output {key}")
        return value

    def resolve_api_key_param_name(self, override: str | None) -> str:
        return override or self.require_output("ApiKeyParameterName")

    def client(self, name: str):
        assert name == "ssm"
        return self

    def get_parameter(self, *, Name: str, WithDecryption: bool):
        assert Name == "/agent-enablement/prod/shared/api-key"
        assert WithDecryption is True
        return {"Parameter": {"Value": "api-key-from-ssm"}}


def _bundle_payload() -> dict[str, object]:
    exp = "2099-01-01T00:00:00+00:00"
    return {
        "kind": "agent-enablement.credentials.v2",
        "expiresAt": exp,
        "auth": {"credentialsEndpoint": "https://api.example.com/prod/v1/credentials"},
        "principal": {"sub": "sub-bootstrap-1", "username": "agent-bootstrap"},
        "session": {
            "sessionKey": "sub-bootstrap-1",
            "principalSub": "sub-bootstrap-1",
            "agentId": "agent-bootstrap",
            "authMode": "admin-bootstrap",
            "renewalMode": "refresh-token-only",
        },
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "ASIABOOTSTRAP",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                    "expiration": exp,
                },
                "references": {"awsRegion": "us-east-2"},
            }
        },
        "cognitoTokens": {
            "idToken": "a.b.c",
            "accessToken": "d.e.f",
            "refreshToken": "refresh",
        },
    }


def test_admin_bootstrap_issue_uses_stack_endpoint_and_ssm_api_key(monkeypatch) -> None:
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli.build_admin_context", lambda _g: _FakeAdminContext())

    called: dict[str, object] = {}

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del timeout_seconds
        called["url"] = url
        called["headers"] = headers
        called["body"] = body
        return (200, {}, json.dumps(_bundle_payload()).encode("utf-8"))

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._http_post_json", _fake_post_json)

    result = runner.invoke(
        admin_app,
        ["agent", "bootstrap", "issue", "--username", "agent-bootstrap", "--password", "pw-1"],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "agent-enablement.credentials.v2"
    assert parsed["session"]["principalSub"] == "sub-bootstrap-1"
    assert called["url"] == "https://api.example.com/prod/v1/credentials"
    headers = called["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "api-key-from-ssm"
    assert "authorization" in headers
    assert called["body"] == b""


def test_admin_bootstrap_place_writes_managed_artifacts(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli.build_admin_context", lambda _g: _FakeAdminContext())

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del url, headers, body, timeout_seconds
        return (200, {}, json.dumps(_bundle_payload()).encode("utf-8"))

    monkeypatch.setattr("enabler_cli.apps.agent_admin_cli._http_post_json", _fake_post_json)

    result = runner.invoke(
        admin_app,
        [
            "agent",
            "bootstrap",
            "place",
            "--username",
            "agent-bootstrap",
            "--password",
            "pw-1",
            "--session-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.admin.bootstrap.place.v1"
    assert parsed["cachePath"].endswith("/sessions/sub-bootstrap-1/session.json")
    assert Path(parsed["cachePath"]).exists()
    assert parsed["manifest"]["exists"]["cognitoEnv"] is True
