import argparse
import base64
import json
from pathlib import Path

import pytest

from enabler_cli.cli import (
    GlobalOpts,
    UsageError,
    _resolve_runtime_credentials_doc,
    _taskboard_endpoint_for_args,
    cmd_agent_bundle,
    cmd_agent_credential_process,
    cmd_agent_credentials,
    cmd_files_share,
    cmd_messages_ack,
    cmd_messages_recv,
    cmd_messages_send,
    cmd_shortlinks_create,
    cmd_shortlinks_resolve_url,
)


def _g(*, cache_path: str = "/tmp/enabler-test-credentials.json", auto_refresh_creds: bool = True) -> GlobalOpts:
    return GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path=cache_path,
        auto_refresh_creds=auto_refresh_creds,
    )


def _base_creds_doc() -> dict:
    return {
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
        "references": {
            "awsRegion": "us-east-2",
            "messages": {
                "agentId": "agent-test",
                "eventBusArn": "arn:aws:events:us-east-2:111122223333:event-bus/agent-bus",
                "eventBusName": "agent-bus",
                "inboxQueueArn": "arn:aws:sqs:us-east-2:111122223333:agent-inbox-agent-test",
                "inboxQueueUrl": "https://sqs.us-east-2.amazonaws.com/111122223333/agent-inbox-agent-test",
            },
            "s3": {"bucket": "bucket", "allowedPrefix": "uploads/u-1/"},
        },
        "grants": [
            {
                "service": "events",
                "actions": ["events:PutEvents"],
                "resources": ["arn:aws:events:us-east-2:111122223333:event-bus/agent-bus"],
            },
            {
                "service": "sqs",
                "actions": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:ChangeMessageVisibility",
                    "sqs:GetQueueAttributes",
                ],
                "resources": ["arn:aws:sqs:us-east-2:111122223333:agent-inbox-agent-test"],
            },
        ],
    }


def _base_creds_doc_credential_sets_only() -> dict:
    return {
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "credentialSets": {
            "agentEnablement": {
                "awsRegion": "us-east-2",
                "credentials": {
                    "accessKeyId": "AKIA_TEST",
                    "secretAccessKey": "secret",
                    "sessionToken": "token",
                },
                "grants": [
                    {
                        "service": "events",
                        "actions": ["events:PutEvents"],
                        "resources": ["arn:aws:events:us-east-2:111122223333:event-bus/agent-bus"],
                    },
                    {
                        "service": "sqs",
                        "actions": [
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:ChangeMessageVisibility",
                            "sqs:GetQueueAttributes",
                        ],
                        "resources": ["arn:aws:sqs:us-east-2:111122223333:agent-inbox-agent-test"],
                    },
                ],
            }
        },
    }


def test_cmd_messages_send_builds_eventbridge_entry(monkeypatch, capsys):
    captured: dict = {}

    class FakeEvents:
        def put_events(self, Entries):
            captured["entries"] = Entries
            return {"FailedEntryCount": 0, "Entries": [{"EventId": "evt-1"}]}

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session_kwargs"] = kwargs

        def client(self, name):
            assert name == "events"
            return FakeEvents()

    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    args = argparse.Namespace(
        to="alice",
        text="hello",
        message_json=None,
        kind=None,
        meta_json=None,
        event_bus_arn=None,
        region=None,
    )

    assert cmd_messages_send(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert captured["entries"][0]["Source"] == "agents.messages.sub.sub-123"
    assert captured["entries"][0]["DetailType"] == "agent.message.v2"
    detail = json.loads(captured["entries"][0]["Detail"])
    assert detail["toUsername"] == "alice"
    assert detail["message"]["text"] == "hello"


def test_cmd_messages_send_defaults_to_agent_enablement_set_when_present(monkeypatch, capsys):
    captured: dict = {}

    class FakeEvents:
        def put_events(self, Entries):
            captured["entries"] = Entries
            return {"FailedEntryCount": 0, "Entries": [{"EventId": "evt-1"}]}

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session_kwargs"] = kwargs

        def client(self, name):
            assert name == "events"
            return FakeEvents()

    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc_credential_sets_only(),
    )

    args = argparse.Namespace(
        to="alice",
        text="hello",
        message_json=None,
        kind=None,
        meta_json=None,
        event_bus_arn=None,
        region=None,
    )

    assert cmd_messages_send(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert captured["session_kwargs"]["region_name"] == "us-east-2"
    assert captured["entries"][0]["Source"] == "agents.messages.sub.sub-123"
    assert captured["entries"][0]["EventBusName"] == "agent-bus"


def test_cmd_messages_recv_loops_batches_without_ack_and_includes_ack_tokens(monkeypatch, capsys):
    deleted: list[str] = []
    waits: list[int] = []
    queue: list[dict[str, str]] = [
        {
            "MessageId": "msg-1",
            "ReceiptHandle": "rh-1",
            "Body": json.dumps({"kind": "text.v1", "message": {"text": "hello-1"}}),
            "Attributes": {"ApproximateReceiveCount": "1"},
        },
        {
            "MessageId": "msg-2",
            "ReceiptHandle": "rh-2",
            "Body": json.dumps({"kind": "text.v1", "message": {"text": "hello-2"}}),
            "Attributes": {"ApproximateReceiveCount": "1"},
        },
    ]

    class FakeSQS:
        def receive_message(self, **kwargs):
            assert kwargs["MaxNumberOfMessages"] == 1
            waits.append(int(kwargs.get("WaitTimeSeconds", -1)))
            if not queue:
                return {}
            batch = queue[:1]
            del queue[:1]
            return {"Messages": batch}

        def delete_message(self, QueueUrl, ReceiptHandle):
            deleted.append(f"{QueueUrl}:{ReceiptHandle}")

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sqs"
            return FakeSQS()

    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    args = argparse.Namespace(
        queue_url=None,
        max_number="1",
        wait_seconds="1",
        visibility_timeout=None,
        ack_all=False,
        region=None,
    )

    assert cmd_messages_recv(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["received"] == 2
    assert out["ackAllRequested"] is False
    assert out["messages"][0]["message"]["text"] == "hello-1"
    assert out["messages"][1]["message"]["text"] == "hello-2"
    assert out["messages"][0]["_ack"]["token"]
    assert out["messages"][1]["_ack"]["token"]
    assert waits == [1, 0, 0]
    assert not deleted


def test_cmd_messages_recv_ack_all_drains_multiple_batches(monkeypatch, capsys):
    deleted: list[str] = []
    waits: list[int] = []
    queue: list[dict[str, str]] = [
        {
            "MessageId": "msg-1",
            "ReceiptHandle": "rh-1",
            "Body": json.dumps({"kind": "text.v1", "message": {"text": "one"}}),
        },
        {
            "MessageId": "msg-2",
            "ReceiptHandle": "rh-2",
            "Body": json.dumps({"kind": "text.v1", "message": {"text": "two"}}),
        },
    ]

    class FakeSQS:
        def receive_message(self, **kwargs):
            waits.append(int(kwargs.get("WaitTimeSeconds", -1)))
            max_n = int(kwargs.get("MaxNumberOfMessages", 1))
            if not queue:
                return {}
            batch = queue[:max_n]
            del queue[:max_n]
            return {"Messages": batch}

        def delete_message(self, QueueUrl, ReceiptHandle):
            deleted.append(f"{QueueUrl}:{ReceiptHandle}")

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sqs"
            return FakeSQS()

    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    args = argparse.Namespace(
        queue_url=None,
        max_number="1",
        wait_seconds="1",
        visibility_timeout=None,
        ack_all=True,
        region=None,
    )

    assert cmd_messages_recv(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["received"] == 2
    assert out["ackAllRequested"] is True
    assert out["messages"][0]["message"]["text"] == "one"
    assert out["messages"][1]["message"]["text"] == "two"
    assert out["messages"][0]["_ack"]["deleted"] is True
    assert out["messages"][1]["_ack"]["deleted"] is True
    assert out["drain"]["enabled"] is True
    assert out["drain"]["truncated"] is False
    assert out["drain"]["batches"] == 3
    assert waits == [1, 0, 0]
    assert len(deleted) == 2


def test_cmd_messages_recv_ack_all_marks_truncated_on_batch_limit(monkeypatch, capsys):
    deleted: list[str] = []

    class FakeSQS:
        _counter = 0

        def receive_message(self, **kwargs):
            del kwargs
            self.__class__._counter += 1
            n = self.__class__._counter
            return {
                "Messages": [
                    {
                        "MessageId": f"msg-{n}",
                        "ReceiptHandle": f"rh-{n}",
                        "Body": json.dumps({"kind": "text.v1", "message": {"text": f"m-{n}"}}),
                    }
                ]
            }

        def delete_message(self, QueueUrl, ReceiptHandle):
            deleted.append(f"{QueueUrl}:{ReceiptHandle}")

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sqs"
            return FakeSQS()

    monkeypatch.setattr("enabler_cli.cli._MESSAGES_RECV_ACK_ALL_MAX_BATCHES", 2)
    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    args = argparse.Namespace(
        queue_url=None,
        max_number="1",
        wait_seconds="1",
        visibility_timeout=None,
        ack_all=True,
        region=None,
    )

    assert cmd_messages_recv(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["received"] == 2
    assert out["ackAllRequested"] is True
    assert out["drain"]["enabled"] is True
    assert out["drain"]["truncated"] is True
    assert out["drain"]["batches"] == 2
    assert len(deleted) == 2


def test_cmd_messages_recv_without_ack_stops_at_batch_limit(monkeypatch, capsys):
    deleted: list[str] = []

    class FakeSQS:
        _counter = 0

        def receive_message(self, **kwargs):
            del kwargs
            self.__class__._counter += 1
            n = self.__class__._counter
            return {
                "Messages": [
                    {
                        "MessageId": f"msg-{n}",
                        "ReceiptHandle": f"rh-{n}",
                        "Body": json.dumps({"kind": "text.v1", "message": {"text": f"m-{n}"}}),
                    }
                ]
            }

        def delete_message(self, QueueUrl, ReceiptHandle):
            deleted.append(f"{QueueUrl}:{ReceiptHandle}")

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sqs"
            return FakeSQS()

    monkeypatch.setattr("enabler_cli.cli._MESSAGES_RECV_MAX_BATCHES", 2)
    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    args = argparse.Namespace(
        queue_url=None,
        max_number="1",
        wait_seconds="1",
        visibility_timeout=None,
        ack_all=False,
        region=None,
    )

    assert cmd_messages_recv(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["received"] == 2
    assert out["ackAllRequested"] is False
    assert "drain" not in out
    assert not deleted


def test_cmd_messages_ack_deletes_from_token(monkeypatch, capsys):
    called: dict[str, str] = {}

    class FakeSQS:
        def delete_message(self, QueueUrl, ReceiptHandle):
            called["queue_url"] = QueueUrl
            called["receipt_handle"] = ReceiptHandle

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "sqs"
            return FakeSQS()

    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": FakeSession})})(),
    )
    monkeypatch.setattr(
        "enabler_cli.cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_creds_doc(),
    )

    token_payload = json.dumps(
        {
            "queueUrl": "https://sqs.us-east-2.amazonaws.com/111122223333/agent-inbox-agent-test",
            "receiptHandle": "rh-1",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    token = base64.urlsafe_b64encode(token_payload).decode("ascii").rstrip("=")
    args = argparse.Namespace(
        ack_token=token,
        receipt_handle=None,
        queue_url=None,
        region=None,
    )
    assert cmd_messages_ack(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert called["receipt_handle"] == "rh-1"


def test_cmd_agent_credentials_writes_file_and_prints_location_output(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-1",
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "expiresAt": "2026-02-16T12:00:00Z",
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
        },
        "references": {
            "credentialScope": "runtime",
            "awsRegion": "us-east-2",
            "s3": {"allowedPrefix": "uploads/u-1/"},
        },
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    out_path = tmp_path / "credentials.json"
    cache_path = tmp_path / ".enabler" / "cache.json"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=str(out_path),
        summary=True,
        json_output=False,
    )

    assert cmd_agent_credentials(args, _g(cache_path=str(cache_path))) == 0
    out = capsys.readouterr().out
    assert "Credentials Artifacts" in out
    assert f"- credentials.json: {cache_path}" in out
    assert "- freshness:" in out
    assert out_path.exists()
    saved = json.loads(out_path.read_text(encoding="utf-8"))
    assert saved["requestId"] == "req-1"
    assert (out_path.stat().st_mode & 0o777) == 0o600
    assert (cache_path.stat().st_mode & 0o777) == 0o600


def test_cmd_agent_credentials_default_output_is_location_manifest(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-2",
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "expiresAt": "2026-02-16T12:00:00Z",
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
        },
        "references": {
            "credentialScope": "runtime",
            "awsRegion": "us-east-2",
            "s3": {"allowedPrefix": "uploads/u-1/"},
        },
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=None,
        summary=False,
        json_output=False,
    )

    g = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path=str(tmp_path / "cache-summary.json"),
        auto_refresh_creds=True,
    )
    assert cmd_agent_credentials(args, g) == 0
    out = capsys.readouterr().out
    assert "Credentials Artifacts" in out
    assert f"- credentials.json: {tmp_path / 'cache-summary.json'}" in out
    assert "- sts.env:" in out
    assert "- cognito.env:" in out


def test_cmd_agent_credentials_json_output_respects_pretty_toggle(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-2",
        "principal": {"sub": "sub-123"},
        "references": {"awsRegion": "us-east-2"},
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=None,
        summary=False,
        json_output=True,
    )

    g_pretty = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=True,
        quiet=False,
        creds_cache_path=str(tmp_path / "cache-pretty.json"),
        auto_refresh_creds=True,
    )
    assert cmd_agent_credentials(args, g_pretty) == 0
    pretty_out = capsys.readouterr().out
    assert "\n  \"requestId\": \"req-2\"" in pretty_out

    g_plain = GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path=str(tmp_path / "cache-plain.json"),
        auto_refresh_creds=True,
    )
    assert cmd_agent_credentials(args, g_plain) == 0
    plain_out = capsys.readouterr().out.strip()
    assert plain_out == json.dumps(payload, separators=(",", ":"), sort_keys=True)


def test_cmd_agent_credentials_writes_sts_env_file(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-3",
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
        },
        "references": {
            "credentialScope": "runtime",
            "awsRegion": "us-east-2",
            "s3": {"allowedPrefix": "uploads/u-1/"},
        },
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    cache_path = tmp_path / ".enabler" / "credentials.json"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=None,
        summary=False,
        json_output=False,
    )

    assert cmd_agent_credentials(args, _g(cache_path=str(cache_path))) == 0
    out = capsys.readouterr().out
    sts_env_path = tmp_path / ".enabler" / "sts.env"
    assert sts_env_path == tmp_path / ".enabler" / "sts.env"
    assert sts_env_path.exists()
    assert (
        sts_env_path.read_text(encoding="utf-8")
        == "AWS_ACCESS_KEY_ID=AKIA_TEST\n"
        "AWS_SECRET_ACCESS_KEY=secret\n"
        "AWS_SESSION_TOKEN=token\n"
        "AWS_REGION=us-east-2\n"
    )
    assert (sts_env_path.stat().st_mode & 0o777) == 0o600
    assert f"- sts.env: {sts_env_path}" in out


def test_cmd_agent_credentials_writes_credential_set_sts_env_files(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-3b",
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
        },
        "credentialSets": {
            "agentEnablement": {
                "awsRegion": "us-east-2",
                "credentials": {
                    "accessKeyId": "AKIA_ENABLE",
                    "secretAccessKey": "secret-enable",
                    "sessionToken": "token-enable",
                },
            },
            "agentAWSWorkshopProvisioning": {
                "awsRegion": "us-east-2",
                "credentials": {
                    "accessKeyId": "AKIA_WORKSHOP",
                    "secretAccessKey": "secret-workshop",
                    "sessionToken": "token-workshop",
                },
            },
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    cache_path = tmp_path / ".enabler" / "credentials.json"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=None,
        summary=False,
        json_output=False,
    )

    assert cmd_agent_credentials(args, _g(cache_path=str(cache_path))) == 0
    out = capsys.readouterr().out
    set_enablement = tmp_path / ".enabler" / "sts-agentenablement.env"
    set_workshop = tmp_path / ".enabler" / "sts-agentawsworkshopprovisioning.env"
    assert set_enablement.exists()
    assert set_workshop.exists()
    assert "AWS_ACCESS_KEY_ID=AKIA_ENABLE" in set_enablement.read_text(encoding="utf-8")
    assert "AWS_ACCESS_KEY_ID=AKIA_WORKSHOP" in set_workshop.read_text(encoding="utf-8")
    assert f"agentEnablement: {set_enablement}" in out
    assert f"agentAWSWorkshopProvisioning: {set_workshop}" in out


def test_cmd_agent_credentials_writes_cognito_env_file(monkeypatch, tmp_path, capsys):
    payload = {
        "requestId": "req-3c",
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "cognitoTokens": {
            "idToken": "id.token.value",
            "accessToken": "access.token.value",
            "refreshToken": "refresh-token-value",
            "tokenType": "Bearer",
            "expiresIn": 3600,
        },
        "references": {
            "credentialScope": "runtime",
            "awsRegion": "us-east-2",
            "s3": {"allowedPrefix": "uploads/u-1/"},
        },
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    cache_path = tmp_path / ".enabler" / "credentials.json"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
        api_key_ssm_name=None,
        include_headers=False,
        out=None,
        summary=False,
        json_output=False,
    )

    assert cmd_agent_credentials(args, _g(cache_path=str(cache_path))) == 0
    out = capsys.readouterr().out
    cognito_env_path = tmp_path / ".enabler" / "cognito.env"
    assert cognito_env_path == tmp_path / ".enabler" / "cognito.env"
    text = cognito_env_path.read_text(encoding="utf-8")
    assert "ID_TOKEN=id.token.value" in text
    assert "ACCESS_TOKEN=access.token.value" in text
    assert "REFRESH_TOKEN=refresh-token-value" in text
    assert "COGNITO_ID_TOKEN=id.token.value" in text
    assert (cognito_env_path.stat().st_mode & 0o777) == 0o600
    assert f"- cognito.env: {cognito_env_path}" in out


def test_cmd_agent_credential_process_outputs_enablement_set_json(monkeypatch, capsys):
    payload = {
        "requestId": "req-cp-1",
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "AKIA_ENABLE",
                    "secretAccessKey": "secret-enable",
                    "sessionToken": "token-enable",
                    "expiration": "2026-02-20T00:00:00Z",
                }
            },
            "agentAWSWorkshopProvisioning": {
                "credentials": {
                    "accessKeyId": "AKIA_WORKSHOP",
                    "secretAccessKey": "secret-workshop",
                    "sessionToken": "token-workshop",
                    "expiration": "2026-02-20T00:00:00Z",
                }
            },
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    args = argparse.Namespace(
        set="agentEnablement",
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
    )

    assert cmd_agent_credential_process(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {
        "Version": 1,
        "AccessKeyId": "AKIA_ENABLE",
        "SecretAccessKey": "secret-enable",
        "SessionToken": "token-enable",
        "Expiration": "2026-02-20T00:00:00Z",
    }


def test_cmd_agent_credential_process_missing_requested_set_errors(monkeypatch):
    payload = {
        "requestId": "req-cp-2",
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "AKIA_ENABLE",
                    "secretAccessKey": "secret-enable",
                    "sessionToken": "token-enable",
                }
            }
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    args = argparse.Namespace(
        set="agentAWSWorkshopProvisioning",
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
    )

    with pytest.raises(UsageError, match="missing credential set: agentAWSWorkshopProvisioning"):
        cmd_agent_credential_process(args, _g())


def test_cmd_agent_credential_process_missing_required_keys_errors(monkeypatch):
    payload = {
        "requestId": "req-cp-3",
        "credentialSets": {
            "agentEnablement": {
                "credentials": {
                    "accessKeyId": "AKIA_ENABLE",
                    "secretAccessKey": "",
                    "sessionToken": "token-enable",
                }
            }
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    args = argparse.Namespace(
        set="agentEnablement",
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/credentials",
        api_key="k",
    )

    with pytest.raises(UsageError, match="missing accessKeyId/secretAccessKey/sessionToken"):
        cmd_agent_credential_process(args, _g())


def test_cmd_messages_send_requires_credentials_when_cache_missing_and_refresh_disabled(tmp_path):
    args = argparse.Namespace(
        to="alice",
        text="hello",
        message_json=None,
        kind=None,
        meta_json=None,
        event_bus_arn=None,
        region=None,
    )
    with pytest.raises(UsageError, match="missing credentials"):
        cmd_messages_send(
            args,
            _g(
                cache_path=str(tmp_path / "missing-cache.json"),
                auto_refresh_creds=False,
            ),
        )


def test_resolve_runtime_credentials_doc_prefers_refresh_token_flow(monkeypatch, tmp_path):
    cache_path = tmp_path / "credentials.json"
    cache_path.write_text(
        json.dumps(
            {
                "expiresAt": "2000-01-01T00:00:00Z",
                "auth": {"credentialsEndpoint": "https://api.example.com/v1/credentials"},
                "cognitoTokens": {"refreshToken": "rt-old"},
                "credentials": {
                    "accessKeyId": "AKIA_OLD",
                    "secretAccessKey": "old-secret",
                    "sessionToken": "old-token",
                    "expiration": "2000-01-01T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    calls: list[dict[str, object]] = []

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        calls.append({"url": url, "headers": dict(headers)})
        payload = _base_creds_doc()
        payload["auth"] = {"credentialsEndpoint": "https://api.example.com/v1/credentials"}
        payload["expiresAt"] = "2099-01-01T00:00:00Z"
        payload["credentials"]["expiration"] = "2099-01-01T00:00:00Z"
        payload["cognitoTokens"] = {"idToken": "a.b.c", "refreshToken": "rt-new"}
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setenv("ENABLER_API_KEY", "api-key")
    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    doc = _resolve_runtime_credentials_doc(
        argparse.Namespace(),
        _g(cache_path=str(cache_path), auto_refresh_creds=True),
    )
    assert doc["cognitoTokens"]["refreshToken"] == "rt-new"
    assert calls[0]["url"] == "https://api.example.com/v1/credentials/refresh"
    headers = calls[0]["headers"]
    assert isinstance(headers, dict)
    assert headers["x-enabler-refresh-token"] == "rt-old"
    assert "authorization" not in headers


def test_resolve_runtime_credentials_doc_falls_back_to_basic_when_refresh_fails(monkeypatch, tmp_path):
    cache_path = tmp_path / "credentials.json"
    cache_path.write_text(
        json.dumps(
            {
                "expiresAt": "2000-01-01T00:00:00Z",
                "auth": {"credentialsEndpoint": "https://api.example.com/v1/credentials"},
                "cognitoTokens": {"refreshToken": "rt-old"},
                "credentials": {
                    "accessKeyId": "AKIA_OLD",
                    "secretAccessKey": "old-secret",
                    "sessionToken": "old-token",
                    "expiration": "2000-01-01T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    calls: list[dict[str, object]] = []

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        calls.append({"url": url, "headers": dict(headers)})
        if str(url).endswith("/v1/credentials/refresh"):
            return 401, {}, b'{"message":"expired refresh token"}'
        payload = _base_creds_doc()
        payload["auth"] = {"credentialsEndpoint": "https://api.example.com/v1/credentials"}
        payload["expiresAt"] = "2099-01-01T00:00:00Z"
        payload["credentials"]["expiration"] = "2099-01-01T00:00:00Z"
        payload["cognitoTokens"] = {"idToken": "a.b.c", "refreshToken": "rt-fresh"}
        return 200, {}, json.dumps(payload).encode("utf-8")

    monkeypatch.setenv("ENABLER_API_KEY", "api-key")
    monkeypatch.setenv("ENABLER_COGNITO_USERNAME", "agent-test")
    monkeypatch.setenv("ENABLER_COGNITO_PASSWORD", "pw")
    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)

    doc = _resolve_runtime_credentials_doc(
        argparse.Namespace(),
        _g(cache_path=str(cache_path), auto_refresh_creds=True),
    )
    assert doc["cognitoTokens"]["refreshToken"] == "rt-fresh"
    assert len(calls) == 2
    assert calls[0]["url"] == "https://api.example.com/v1/credentials/refresh"
    assert calls[1]["url"] == "https://api.example.com/v1/credentials"
    headers = calls[1]["headers"]
    assert isinstance(headers, dict)
    assert str(headers.get("authorization", "")).startswith("Basic ")


def test_cmd_agent_bundle_downloads_without_cache_update(monkeypatch, tmp_path, capsys):
    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps({"bundleUrl": "https://download.invalid/bundle.zip"}).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"zip-bytes")
        return out_path.stat().st_size

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    cache_path = tmp_path / "bundle-cache.json"
    out_zip = tmp_path / "bundle.zip"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=str(out_zip),
        no_download=False,
        print_response=False,
    )

    assert cmd_agent_bundle(args, _g(cache_path=str(cache_path), auto_refresh_creds=True)) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == str(out_zip)
    assert captured.err == ""
    assert out_zip.exists()


def test_cmd_agent_bundle_defaults_output_under_creds_cache_dir(monkeypatch, tmp_path, capsys):
    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps({"bundleUrl": "https://download.invalid/bundle.zip"}).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"zip-bytes")
        return out_path.stat().st_size

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    cache_path = tmp_path / ".enabler" / "credentials.json"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=None,
        no_download=False,
        print_response=False,
    )

    assert cmd_agent_bundle(args, _g(cache_path=str(cache_path), auto_refresh_creds=True)) == 0
    captured = capsys.readouterr()
    bundle_out_path = Path(captured.out.strip())
    assert bundle_out_path.exists()
    assert bundle_out_path.parent == cache_path.parent / "bundles"
    assert bundle_out_path.name.startswith("agent-enablement-bundle-")
    assert captured.err == ""


def test_cmd_agent_bundle_print_response_and_downloads(monkeypatch, tmp_path, capsys):
    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(
            {"bundleUrl": "https://download.invalid/bundle.zip", "requestId": "req-1"}
        ).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"zip-bytes")
        return out_path.stat().st_size

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    out_zip = tmp_path / "bundle.zip"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=str(out_zip),
        no_download=False,
        print_response=True,
    )

    assert cmd_agent_bundle(args, _g()) == 0
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 2
    payload = json.loads(lines[0])
    assert payload["requestId"] == "req-1"
    assert lines[1] == str(out_zip)
    assert captured.err == ""


def test_cmd_agent_bundle_persists_connection_json(monkeypatch, tmp_path, capsys):
    payload = {
        "bundleUrl": "https://download.invalid/bundle.zip",
        "requestId": "req-1",
        "connection": {
            "schemaVersion": "2026-02-17",
            "taskboard": {"invokeUrl": "https://api.example.com/prod/v1/taskboard"},
            "shortlinks": {
                "createUrl": "https://api.example.com/prod/v1/links",
                "redirectBaseUrl": "https://d111111abcdef8.cloudfront.net/l/",
            },
        },
    }

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(payload).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"zip-bytes")
        return out_path.stat().st_size

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    cache_path = tmp_path / ".enabler" / "credentials.json"
    out_zip = tmp_path / "bundle.zip"
    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=str(out_zip),
        no_download=False,
        print_response=False,
    )

    assert cmd_agent_bundle(args, _g(cache_path=str(cache_path), auto_refresh_creds=True)) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == str(out_zip)
    connection_path = cache_path.parent / "connection.json"
    saved = json.loads(connection_path.read_text(encoding="utf-8"))
    assert saved["taskboard"]["invokeUrl"] == "https://api.example.com/prod/v1/taskboard"
    assert (connection_path.stat().st_mode & 0o777) == 0o600


def test_cmd_agent_bundle_no_download_prints_nothing_by_default(monkeypatch, tmp_path, capsys):
    called = {"get": 0}

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps({"bundleUrl": "https://download.invalid/bundle.zip"}).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        called["get"] += 1
        return 0

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=None,
        no_download=True,
        print_response=False,
    )

    assert cmd_agent_bundle(args, _g()) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert called["get"] == 0


def test_cmd_agent_bundle_no_download_with_print_response(monkeypatch, capsys):
    called = {"get": 0}

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps(
            {"bundleUrl": "https://download.invalid/bundle.zip", "requestId": "req-1"}
        ).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        called["get"] += 1
        return 0

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=None,
        no_download=True,
        print_response=True,
    )

    assert cmd_agent_bundle(args, _g()) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["requestId"] == "req-1"
    assert called["get"] == 0
    assert captured.err == ""


def test_cmd_agent_bundle_no_download_warns_when_out_set(monkeypatch, tmp_path, capsys):
    called = {"get": 0}
    out_zip = tmp_path / "bundle.zip"

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        return 200, {}, json.dumps({"bundleUrl": "https://download.invalid/bundle.zip"}).encode("utf-8")

    def fake_http_get_to_file(*, url, out_path, timeout_seconds=120):
        called["get"] += 1
        return 0

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setattr("enabler_cli.cli._http_get_to_file", fake_http_get_to_file)

    args = argparse.Namespace(
        username="agent-test",
        password="pw",
        endpoint="https://example.invalid/v1/bundle",
        api_key="api-key",
        api_key_ssm_name=None,
        ttl_seconds=None,
        out=str(out_zip),
        no_download=True,
        print_response=False,
    )

    assert cmd_agent_bundle(args, _g()) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "warning: --out ignored when --no-download is set" in captured.err
    assert called["get"] == 0
    assert not out_zip.exists()


def test_taskboard_endpoint_uses_connection_cache(monkeypatch, tmp_path):
    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps(
            {
                "taskboard": {
                    "invokeUrl": "https://bundle.example.com/prod/v1/taskboard",
                }
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace()
    endpoint = _taskboard_endpoint_for_args(args, _g(cache_path=str(cache_path)))
    assert endpoint == "https://bundle.example.com/prod/v1/taskboard"


def test_cmd_shortlinks_create_uses_connection_and_bearer(monkeypatch, tmp_path, capsys):
    captured = {}

    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = json.loads(body.decode("utf-8"))
        return 201, {}, json.dumps(
            {
                "code": "abc123",
                "shortPath": "/l/abc123",
                "createdBy": {"sub": "sub-1", "username": "agent-test"},
            }
        ).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setenv("ENABLER_COGNITO_USERNAME", "agent-test")
    monkeypatch.setenv("ENABLER_COGNITO_PASSWORD", "pw")
    monkeypatch.setenv("ENABLER_API_KEY", "k")

    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps(
            {
                "awsRegion": "us-east-2",
                "shortlinks": {
                    "createUrl": "https://bundle.example.com/prod/v1/links",
                    "redirectBaseUrl": "https://bundle.example.com/prod/l/",
                }
            }
        ),
        encoding="utf-8",
    )

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

    args = argparse.Namespace(
        target_url="https://s3.us-east-2.amazonaws.com/bucket/key",
        alias="Alias1",
        json_output=False,
    )
    assert cmd_shortlinks_create(args, _g(cache_path=str(cache_path))) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines == [
        "code: abc123",
        "shortURL: https://bundle.example.com/prod/l/abc123",
    ]
    assert captured["url"] == "https://bundle.example.com/prod/v1/links"
    assert captured["body"]["alias"] == "Alias1"
    assert captured["headers"]["authorization"] == "Bearer a.b.c"


def test_cmd_shortlinks_create_json_output_uses_current_payload_shape(monkeypatch, tmp_path, capsys):
    def fake_http_post_json(*, url, headers, body, timeout_seconds=30):
        del url, headers, body, timeout_seconds
        return 201, {}, json.dumps(
            {
                "code": "abc123",
                "shortPath": "/l/abc123",
                "createdBy": {"sub": "sub-1", "username": "agent-test"},
            }
        ).encode("utf-8")

    monkeypatch.setattr("enabler_cli.cli._http_post_json", fake_http_post_json)
    monkeypatch.setenv("ENABLER_COGNITO_USERNAME", "agent-test")
    monkeypatch.setenv("ENABLER_COGNITO_PASSWORD", "pw")
    monkeypatch.setenv("ENABLER_API_KEY", "k")

    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps(
            {
                "awsRegion": "us-east-2",
                "shortlinks": {
                    "createUrl": "https://bundle.example.com/prod/v1/links",
                    "redirectBaseUrl": "https://bundle.example.com/prod/l/",
                },
            }
        ),
        encoding="utf-8",
    )
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

    args = argparse.Namespace(
        target_url="https://s3.us-east-2.amazonaws.com/bucket/key",
        alias=None,
        json_output=True,
    )
    assert cmd_shortlinks_create(args, _g(cache_path=str(cache_path))) == 0
    out = json.loads(capsys.readouterr().out)
    assert list(out.keys())[0] == "shortUrl"
    assert out["shortUrl"] == "https://bundle.example.com/prod/l/abc123"
    assert out["redirectBaseUrl"] == "https://bundle.example.com/prod/l/"
    assert out["code"] == "abc123"
    assert "createdBy" not in out


def test_cmd_shortlinks_resolve_url_uses_connection_cache(monkeypatch, tmp_path, capsys):
    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps({"shortlinks": {"redirectBaseUrl": "https://bundle.example.com/prod/l/"}}),
        encoding="utf-8",
    )
    args = argparse.Namespace(code="code123")
    assert cmd_shortlinks_resolve_url(args, _g(cache_path=str(cache_path))) == 0
    assert capsys.readouterr().out.strip() == "https://bundle.example.com/prod/l/code123"


def test_cmd_shortlinks_create_requires_redirect_base_url(monkeypatch, tmp_path):
    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps({"shortlinks": {"createUrl": "https://bundle.example.com/prod/v1/links"}}),
        encoding="utf-8",
    )
    cache_path.write_text(
        json.dumps({"cognitoTokens": {"idToken": "a.b.c"}}),
        encoding="utf-8",
    )

    args = argparse.Namespace(
        target_url="https://example.com",
        alias=None,
    )
    with pytest.raises(UsageError, match="missing shortlinks redirect base url"):
        cmd_shortlinks_create(args, _g(cache_path=str(cache_path)))


def test_cmd_files_share_uploads_and_returns_public_url(monkeypatch, tmp_path, capsys):
    source_file = tmp_path / "payload.txt"
    source_file.write_text("hello", encoding="utf-8")
    cache_path = tmp_path / ".enabler" / "credentials.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    (cache_path.parent / "connection.json").write_text(
        json.dumps(
            {
                "awsRegion": "us-east-2",
                "files": {"publicBaseUrl": "https://files.example.net/"},
            }
        ),
        encoding="utf-8",
    )
    creds_doc = {
        "awsRegion": "us-east-2",
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2099-01-01T00:00:00Z",
        },
        "grants": [
            {
                "service": "s3",
                "resources": ["arn:aws:s3:::upload-bucket/uploads/u-1/*"],
            }
        ],
    }

    uploaded: dict[str, str] = {}

    class _FakeS3:
        def upload_file(self, local_path, bucket, key):
            uploaded["local_path"] = str(local_path)
            uploaded["bucket"] = bucket
            uploaded["key"] = key

    class _FakeSession:
        def __init__(self, **kwargs):
            uploaded["region"] = str(kwargs.get("region_name") or "")

        def client(self, name):
            assert name == "s3"
            return _FakeS3()

    monkeypatch.setattr("enabler_cli.cli._resolve_runtime_credentials_doc", lambda _args, _g: creds_doc)
    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": _FakeSession})})(),
    )
    monkeypatch.setattr("enabler_cli.cli.uuid4_base58_22", lambda: "1111111111111111111111")

    args = argparse.Namespace(
        file_path=str(source_file),
        name=None,
        json_output=False,
    )

    assert cmd_files_share(args, _g(cache_path=str(cache_path))) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        "https://files.example.net/uploads/u-1/1111111111111111111111/payload.txt",
    ]
    assert uploaded["bucket"] == "upload-bucket"
    assert uploaded["key"] == "uploads/u-1/1111111111111111111111/payload.txt"
    assert uploaded["region"] == "us-east-2"


def test_cmd_files_share_json_output(monkeypatch, tmp_path, capsys):
    source_file = tmp_path / "payload.txt"
    source_file.write_text("hello", encoding="utf-8")
    creds_doc = {
        "awsRegion": "us-east-2",
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2099-01-01T00:00:00Z",
        },
        "grants": [
            {
                "service": "s3",
                "resources": ["arn:aws:s3:::upload-bucket/uploads/u-1/*"],
            }
        ],
    }

    class _FakeS3:
        def __init__(self):
            self.uploaded_key = ""

        def upload_file(self, local_path, bucket, key):
            self.uploaded_key = key
            return None

    class _FakeSession:
        def __init__(self, **kwargs):
            pass

        def client(self, name):
            assert name == "s3"
            return _FakeS3()

    monkeypatch.setattr("enabler_cli.cli._resolve_runtime_credentials_doc", lambda _args, _g: creds_doc)
    monkeypatch.setattr(
        "enabler_cli.cli.boto3",
        type("B3", (), {"session": type("S", (), {"Session": _FakeSession})})(),
    )
    monkeypatch.setattr("enabler_cli.cli._connection_region_from_cache", lambda g: "us-east-2")
    monkeypatch.setattr("enabler_cli.cli._files_public_base_url_from_connection_cache", lambda g: "https://files.example.net/")
    monkeypatch.setattr("enabler_cli.cli.uuid4_base58_22", lambda: "1111111111111111111111")

    args = argparse.Namespace(
        file_path=str(source_file),
        name="renamed.txt",
        json_output=True,
    )

    assert cmd_files_share(args, _g(cache_path=str(tmp_path / ".enabler" / "credentials.json"))) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "enabler.files.upload.v1"
    assert payload["s3Uri"] == "s3://upload-bucket/uploads/u-1/1111111111111111111111/renamed.txt"
    assert payload["publicUrl"] == "https://files.example.net/uploads/u-1/1111111111111111111111/renamed.txt"
    assert payload["publicBaseUrl"] == "https://files.example.net/"
    assert payload["bucket"] == "upload-bucket"
    assert payload["key"] == "uploads/u-1/1111111111111111111111/renamed.txt"


def test_cmd_files_share_requires_connection_region(monkeypatch, tmp_path):
    source_file = tmp_path / "payload.txt"
    source_file.write_text("hello", encoding="utf-8")
    creds_doc = {
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2099-01-01T00:00:00Z",
        },
        "grants": [
            {
                "service": "s3",
                "resources": ["arn:aws:s3:::upload-bucket/uploads/u-1/*"],
            }
        ],
    }
    monkeypatch.setattr("enabler_cli.cli._resolve_runtime_credentials_doc", lambda _args, _g: creds_doc)
    monkeypatch.setattr("enabler_cli.cli._connection_region_from_cache", lambda g: "")

    args = argparse.Namespace(
        file_path=str(source_file),
        name=None,
        json_output=False,
    )
    with pytest.raises(UsageError, match="missing awsRegion in bundle connection.json"):
        cmd_files_share(args, _g(cache_path=str(tmp_path / ".enabler" / "credentials.json")))


def test_cmd_files_share_requires_files_public_base_url(monkeypatch, tmp_path):
    source_file = tmp_path / "payload.txt"
    source_file.write_text("hello", encoding="utf-8")
    creds_doc = {
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": "2099-01-01T00:00:00Z",
        },
        "grants": [
            {
                "service": "s3",
                "resources": ["arn:aws:s3:::upload-bucket/uploads/u-1/*"],
            }
        ],
    }
    monkeypatch.setattr("enabler_cli.cli._resolve_runtime_credentials_doc", lambda _args, _g: creds_doc)
    monkeypatch.setattr("enabler_cli.cli._connection_region_from_cache", lambda g: "us-east-2")
    monkeypatch.setattr("enabler_cli.cli._files_public_base_url_from_connection_cache", lambda g: "")

    args = argparse.Namespace(
        file_path=str(source_file),
        name=None,
        json_output=False,
    )
    with pytest.raises(UsageError, match="missing files public base url in bundle connection.json"):
        cmd_files_share(args, _g(cache_path=str(tmp_path / ".enabler" / "credentials.json")))
