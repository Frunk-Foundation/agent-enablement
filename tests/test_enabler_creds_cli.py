from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typer.testing import CliRunner

from enabler_cli.creds_main import app


runner = CliRunner()


def _seed_cache(path: Path, *, agent_id: str = "agent-a", principal_sub: str = "sub-agent-a") -> None:
    exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = {
        "expiresAt": exp,
        "auth": {"credentialsEndpoint": "https://api.example.com/prod/v1/credentials"},
        "principal": {"sub": principal_sub, "username": agent_id},
        "session": {
            "sessionKey": principal_sub,
            "principalSub": principal_sub,
            "agentId": agent_id,
            "authMode": "basic",
            "renewalMode": "refresh-token-only",
        },
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
        "cognitoTokens": {
            "idToken": "a.b.c",
            "accessToken": "d.e.f",
            "refreshToken": "refresh",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _session_cache(
    tmp_path: Path,
    monkeypatch,
    *,
    agent_id: str = "agent-a",
    principal_sub: str | None = None,
) -> Path:
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    resolved_sub = principal_sub or f"sub-{agent_id}"
    cache = tmp_path / "sessions" / resolved_sub / "session.json"
    _seed_cache(cache, agent_id=agent_id, principal_sub=resolved_sub)
    return cache


def test_credential_process_reads_cached_set(tmp_path: Path, monkeypatch) -> None:
    _session_cache(tmp_path, monkeypatch)

    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "credential-process",
            "--set",
            "agentEnablement",
        ],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["Version"] == 1
    assert parsed["AccessKeyId"] == "ASIAEXAMPLE"


def test_status_reports_set_names(tmp_path: Path, monkeypatch) -> None:
    _session_cache(tmp_path, monkeypatch)

    result = runner.invoke(
        app,
        ["--agent-id", "agent-a", "--no-auto-refresh-creds", "status"],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "agentEnablement" in parsed["credentialSets"]


def test_delegation_request_calls_request_endpoint(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.setenv("ENABLER_API_KEY", "key-1")
    called: dict[str, object] = {}

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del timeout_seconds
        called["url"] = url
        called["headers"] = headers
        called["body"] = json.loads(body.decode("utf-8"))
        return (
            200,
            {},
                json.dumps(
                    {
                        "kind": "agent-enablement.delegation.request.v1",
                        "requestCode": "abc123",
                        "expiresAt": "2099-01-01T00:00:00Z",
                    }
                ).encode("utf-8"),
            )

    monkeypatch.setattr("enabler_cli.creds_main._http_post_json", _fake_post_json)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegation",
            "request",
            "--scopes",
            "taskboard,eventbus",
            "--ttl-seconds",
            "300",
            "--purpose",
            "smoke",
        ],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["request"]["requestCode"] == "abc123"
    assert called["url"] == "https://api.example.com/prod/v1/delegation/requests"
    headers = called["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "key-1"
    assert called["body"] == {"scopes": ["taskboard", "eventbus"], "ttlSeconds": 300, "purpose": "smoke"}


def test_delegation_redeem_writes_cache_and_reports_manifest(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.setenv("ENABLER_API_KEY", "key-1")

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del headers, timeout_seconds
        assert url == "https://api.example.com/prod/v1/delegation/redeem"
        assert json.loads(body.decode("utf-8")) == {"requestCode": "code-1"}
        exp = "2099-01-01T00:00:00+00:00"
        payload = {
            "kind": "agent-enablement.credentials.v2",
            "expiresAt": exp,
            "principal": {"sub": "sub-1", "username": "ephem-1"},
            "credentials": {
                "accessKeyId": "ASIA1",
                "secretAccessKey": "secret",
                "sessionToken": "token",
                "expiration": exp,
            },
            "credentialSets": {
                "agentEnablement": {
                    "credentials": {
                        "accessKeyId": "ASIA1",
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
        return (200, {}, json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr("enabler_cli.creds_main._http_post_json", _fake_post_json)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegation",
            "redeem",
            "--request-code",
            "code-1",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.creds.delegation.redeem.v1"
    assert parsed["credentialSets"] == ["agentEnablement"]
    assert Path(parsed["cachePath"]).exists()
    assert parsed["cachePath"].endswith("/sessions/sub-1/session.json")


def test_delegation_redeem_requires_api_key_env(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.delenv("ENABLER_API_KEY", raising=False)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegation",
            "redeem",
            "--request-code",
            "code-1",
        ],
    )
    assert result.exit_code == 1
    assert "missing ENABLER_API_KEY" in str(result.exception)


def test_delegation_approve_calls_approval_endpoint(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    called: dict[str, object] = {}

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del timeout_seconds
        called["url"] = url
        called["headers"] = headers
        called["body"] = json.loads(body.decode("utf-8"))
        return (200, {}, json.dumps({"kind": "agent-enablement.delegation.approval.v1", "status": "approved"}).encode("utf-8"))

    monkeypatch.setattr("enabler_cli.creds_main._http_post_json", _fake_post_json)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegation",
            "approve",
            "--request-code",
            "code-1",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.creds.delegation.approve.v1"
    assert called["url"] == "https://api.example.com/prod/v1/delegation/approvals"
    assert called["body"] == {"requestCode": "code-1"}


def test_delegation_request_rejects_non_credentials_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    monkeypatch.setenv("ENABLER_API_KEY", "key-1")
    cache = tmp_path / "sessions" / "sub-agent-a" / "session.json"
    _seed_cache(cache, agent_id="agent-a", principal_sub="sub-agent-a")
    payload = json.loads(cache.read_text(encoding="utf-8"))
    payload["auth"]["credentialsEndpoint"] = "https://api.example.com/prod/v1/taskboard"
    cache.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegation",
            "request",
        ],
    )
    assert result.exit_code == 1
    assert "expected path ending with /v1/credentials" in str(result.exception)


def test_requires_agent_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_AGENT_ID", raising=False)
    monkeypatch.delenv("ENABLER_COGNITO_USERNAME", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "missing agent id" in str(result.exception)


def test_uses_cognito_username_as_default_agent_id(tmp_path: Path, monkeypatch) -> None:
    _session_cache(tmp_path, monkeypatch, agent_id="leticiaoc")
    monkeypatch.delenv("ENABLER_AGENT_ID", raising=False)
    monkeypatch.setenv("ENABLER_COGNITO_USERNAME", "leticiaoc")

    result = runner.invoke(app, ["--no-auto-refresh-creds", "status"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["cachePath"].endswith("/sessions/sub-leticiaoc/session.json")


def test_session_list_and_revoke(tmp_path: Path, monkeypatch) -> None:
    cache = _session_cache(tmp_path, monkeypatch, agent_id="agent-list")
    result = runner.invoke(app, ["--agent-id", "agent-list", "session", "list"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert any(
        item["agentId"] == "agent-list" and item["principalSub"] == "sub-agent-list"
        for item in parsed["sessions"]
    )

    revoke = runner.invoke(app, ["--agent-id", "agent-list", "session", "revoke", "--agent-id", "agent-list"])
    assert revoke.exit_code == 0
    revoke_payload = json.loads(revoke.stdout)
    assert revoke_payload["removed"] is True
    assert revoke_payload["principalSub"] == "sub-agent-list"
    assert not Path(revoke_payload["sessionPath"]).exists()


def test_session_import_from_file_writes_managed_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_AGENT_ID", raising=False)
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    source = tmp_path / "bundle.json"
    exp = "2099-01-01T00:00:00+00:00"
    source.write_text(
        json.dumps(
            {
                "kind": "agent-enablement.credentials.v2",
                "expiresAt": exp,
                "auth": {"credentialsEndpoint": "https://api.example.com/prod/v1/credentials"},
                "principal": {"sub": "sub-import-1", "username": "agent-import"},
                "session": {
                    "sessionKey": "sub-import-1",
                    "principalSub": "sub-import-1",
                    "agentId": "agent-import",
                    "authMode": "admin-bootstrap",
                    "renewalMode": "refresh-token-only",
                },
                "credentialSets": {
                    "agentEnablement": {
                        "credentials": {
                            "accessKeyId": "ASIAIMPORT",
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
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["session", "import", "--file", str(source)])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.session.import.v1"
    assert parsed["cachePath"].endswith("/sessions/sub-import-1/session.json")
    assert Path(parsed["cachePath"]).exists()
    manifest = parsed["manifest"]
    assert manifest["exists"]["credentialsJson"] is True
    assert manifest["exists"]["cognitoEnv"] is True


def test_session_import_from_stdin_reads_bundle_without_agent_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_AGENT_ID", raising=False)
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    exp = "2099-01-01T00:00:00+00:00"
    payload = json.dumps(
        {
            "kind": "agent-enablement.credentials.v2",
            "expiresAt": exp,
            "auth": {"credentialsEndpoint": "https://api.example.com/prod/v1/credentials"},
            "principal": {"sub": "sub-import-stdin", "username": "agent-stdin"},
            "session": {
                "sessionKey": "sub-import-stdin",
                "principalSub": "sub-import-stdin",
                "agentId": "agent-stdin",
                "authMode": "admin-bootstrap",
                "renewalMode": "refresh-token-only",
            },
            "credentialSets": {
                "agentEnablement": {
                    "credentials": {
                        "accessKeyId": "ASIASTDIN",
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
    )

    result = runner.invoke(app, ["session", "import"], input=payload)

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["cachePath"].endswith("/sessions/sub-import-stdin/session.json")
