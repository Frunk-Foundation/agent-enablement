from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typer.testing import CliRunner

from enabler_cli.creds_main import app


runner = CliRunner()


def _seed_cache(path: Path) -> None:
    exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = {
        "expiresAt": exp,
        "auth": {"credentialsEndpoint": "https://api.example.com/prod/v1/credentials"},
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


def _session_cache(tmp_path: Path, monkeypatch, *, agent_id: str = "agent-a") -> Path:
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    cache = tmp_path / "sessions" / agent_id / "session.json"
    _seed_cache(cache)
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


def test_delegate_token_create_calls_delegate_endpoint(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
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
                    "kind": "agent-enablement.delegate-token.v1",
                    "delegateToken": "a.b.c",
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
            "delegate-token",
            "create",
            "--scopes",
            "taskboard,messages",
            "--ttl-seconds",
            "300",
            "--purpose",
            "smoke",
        ],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["delegateToken"] == "a.b.c"
    assert called["url"] == "https://api.example.com/prod/v1/delegate-token"
    assert called["body"] == {"scopes": ["taskboard", "messages"], "ttlSeconds": 300, "purpose": "smoke"}


def test_exchange_writes_cache_and_reports_manifest(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.setenv("ENABLER_API_KEY", "key-1")

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del headers, body, timeout_seconds
        assert url == "https://api.example.com/prod/v1/credentials/exchange"
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
            "exchange",
            "--delegate-token",
            "a.b.c",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.creds.exchange.v1"
    assert parsed["credentialSets"] == ["agentEnablement"]
    assert Path(parsed["cachePath"]).exists()


def test_exchange_requires_api_key_env(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.delenv("ENABLER_API_KEY", raising=False)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "exchange",
            "--delegate-token",
            "a.b.c",
        ],
    )
    assert result.exit_code == 1
    assert "missing ENABLER_API_KEY" in str(result.exception)


def test_bootstrap_ephemeral_chains_delegate_and_exchange(monkeypatch, tmp_path: Path) -> None:
    _session_cache(tmp_path, monkeypatch)
    monkeypatch.setenv("ENABLER_API_KEY", "key-1")
    calls: list[str] = []

    def _fake_post_json(*, url: str, headers: dict[str, str], body: bytes = b"", timeout_seconds: int = 30):
        del headers, timeout_seconds
        calls.append(url)
        if url.endswith("/v1/delegate-token"):
            return (
                200,
                {},
                json.dumps(
                    {
                        "kind": "agent-enablement.delegate-token.v1",
                        "delegateToken": "a.b.c",
                        "expiresAt": "2099-01-01T00:00:00Z",
                        "scopes": ["taskboard", "messages"],
                        "ephemeralUsername": "ephem-1",
                        "ephemeralAgentId": "ephem-a1",
                    }
                ).encode("utf-8"),
            )
        if url.endswith("/v1/credentials/exchange"):
            exp = "2099-01-01T00:00:00+00:00"
            return (
                200,
                {},
                json.dumps(
                    {
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
                ).encode("utf-8"),
            )
        raise AssertionError(url)

    monkeypatch.setattr("enabler_cli.creds_main._http_post_json", _fake_post_json)
    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "bootstrap-ephemeral",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["kind"] == "enabler.creds.bootstrap-ephemeral.v1"
    assert calls == [
        "https://api.example.com/prod/v1/delegate-token",
        "https://api.example.com/prod/v1/credentials/exchange",
    ]


def test_delegate_token_create_rejects_non_credentials_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_CREDS_CACHE", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    cache = tmp_path / "sessions" / "agent-a" / "session.json"
    _seed_cache(cache)
    payload = json.loads(cache.read_text(encoding="utf-8"))
    payload["auth"]["credentialsEndpoint"] = "https://api.example.com/prod/v1/bundle"
    cache.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--agent-id",
            "agent-a",
            "--no-auto-refresh-creds",
            "delegate-token",
            "create",
        ],
    )
    assert result.exit_code == 1
    assert "expected path ending with /v1/credentials" in str(result.exception)


def test_requires_agent_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ENABLER_AGENT_ID", raising=False)
    monkeypatch.setenv("ENABLER_SESSION_ROOT", str(tmp_path))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "missing agent id" in str(result.exception)


def test_session_list_and_revoke(tmp_path: Path, monkeypatch) -> None:
    cache = _session_cache(tmp_path, monkeypatch, agent_id="agent-list")
    result = runner.invoke(app, ["--agent-id", "agent-list", "session", "list"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert any(item["agentId"] == "agent-list" for item in parsed["sessions"])

    revoke = runner.invoke(app, ["--agent-id", "agent-list", "session", "revoke", "--agent-id", "agent-list"])
    assert revoke.exit_code == 0
    revoke_payload = json.loads(revoke.stdout)
    assert revoke_payload["removed"] is True
    assert not Path(revoke_payload["sessionPath"]).exists()
