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


def test_credential_process_reads_cached_set(tmp_path: Path) -> None:
    cache = tmp_path / "credentials.json"
    _seed_cache(cache)

    result = runner.invoke(
        app,
        [
            "--creds-cache",
            str(cache),
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


def test_status_reports_set_names(tmp_path: Path) -> None:
    cache = tmp_path / "credentials.json"
    _seed_cache(cache)

    result = runner.invoke(
        app,
        ["--creds-cache", str(cache), "--no-auto-refresh-creds", "status"],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "agentEnablement" in parsed["credentialSets"]
