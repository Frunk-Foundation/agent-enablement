import json
import re
import urllib.request
import base64
import time

import boto3
import pytest

from enabler_cli.id58 import uuid_text_to_base58_22


def test_credentials_contract(deploy_stack, subject_sub, credentials_json):
    assert credentials_json["kind"] == "agent-enablement.credentials.v2"
    assert credentials_json["schemaVersion"]
    assert credentials_json["principal"]["sub"] == subject_sub
    ct = credentials_json.get("cognitoTokens")
    assert isinstance(ct, dict)
    assert ct.get("idToken")
    assert ct.get("accessToken")
    assert ct.get("refreshToken")
    assert "RefreshToken" not in ct
    assert credentials_json["references"]["cognito"]["issuer"] == credentials_json["principal"]["issuer"]

    upload_id = credentials_json["constraints"]["uploadPrefixBase58"]
    assert re.match(r"^[1-9A-HJ-NP-Za-km-z]{22}$", upload_id)
    assert credentials_json["references"]["s3"]["allowedPrefix"] == f"f/{upload_id}/"
    assert upload_id == uuid_text_to_base58_22(subject_sub)
    assert "uploadPrefixUuid" not in credentials_json["constraints"]

    services = {g["service"] for g in credentials_json["grants"]}
    assert "s3" in services
    assert "sqs" in services
    assert "events" in services

    assert credentials_json["humanUploadGuidance"]["mode"] == "agent-presigns"
    assert isinstance(credentials_json.get("agentGuides", {}).get("s3"), str)
    assert credentials_json["references"]["messages"]["sharedFiles"]["bucket"]
    assert credentials_json["references"]["apiAccess"]["apiKeySsmParameterName"]
    assert "x-api-key" in credentials_json["references"]["apiAccess"]["requiredHeaders"]


def test_s3_put_object_allowed(deploy_stack, credentials_json, issued_session):
    prefix = credentials_json["references"]["s3"]["allowedPrefix"]
    key = f"{prefix}it-direct.txt"

    s3 = issued_session.client("s3")
    s3.put_object(Bucket=deploy_stack.upload_bucket, Key=key, Body=b"hello")


def test_s3_presign_put_allows_human_upload(deploy_stack, credentials_json, issued_session):
    prefix = credentials_json["references"]["s3"]["allowedPrefix"]
    key = f"{prefix}it-presign.txt"

    s3 = issued_session.client("s3")
    url = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": deploy_stack.upload_bucket, "Key": key},
        ExpiresIn=60,
    )

    req = urllib.request.Request(url, data=b"hello", method="PUT")
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status in (200, 204)


def test_s3_presign_get_allows_human_download(deploy_stack, credentials_json, issued_session):
    prefix = credentials_json["references"]["s3"]["allowedPrefix"]
    key = f"{prefix}it-download.txt"

    s3 = issued_session.client("s3")
    s3.put_object(Bucket=deploy_stack.upload_bucket, Key=key, Body=b"hello-download")

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": deploy_stack.upload_bucket, "Key": key},
        ExpiresIn=60,
    )

    with urllib.request.urlopen(url, timeout=30) as resp:
        assert resp.status == 200
        assert resp.read() == b"hello-download"


def test_sqs_send_message_allowed(deploy_stack, issued_session):
    sqs = issued_session.client("sqs")
    queue_name = deploy_stack.queue_arn.split(":")[-1]
    url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    out = sqs.send_message(QueueUrl=url, MessageBody="it")
    assert out.get("MessageId")


def test_eventbridge_put_events_allowed(deploy_stack, credentials_json, issued_session):
    ev = issued_session.client("events")
    sender_sub = credentials_json["principal"]["sub"]
    out = ev.put_events(
        Entries=[
            {
                "EventBusName": deploy_stack.event_bus_arn,
                "Source": f"agents.messages.sub.{sender_sub}",
                "DetailType": "agent.message.v2",
                "Detail": json.dumps(
                    {
                        "toUsername": "nobody",
                        "kind": "text.v1",
                        "message": {"ok": True},
                    }
                ),
            }
        ]
    )
    assert out.get("FailedEntryCount") == 0


def test_eventbridge_direct_message_routes_to_inbox(credentials_json, issued_session):
    ev = issued_session.client("events")
    sqs = issued_session.client("sqs")
    inbox_url = credentials_json["references"]["messages"]["inboxQueueUrl"]
    agent_id = credentials_json["references"]["messages"]["agentId"]
    sender_sub = credentials_json["principal"]["sub"]

    out = ev.put_events(
        Entries=[
            {
                "EventBusName": credentials_json["references"]["messages"]["eventBusArn"],
                "Source": f"agents.messages.sub.{sender_sub}",
                "DetailType": "agent.message.v2",
                "Detail": json.dumps(
                    {
                        "toUsername": agent_id,
                        "kind": "json.v1",
                        "message": {"kind": "integration", "ok": True},
                    }
                ),
            }
        ]
    )
    assert out.get("FailedEntryCount") == 0

    deadline = time.time() + 30
    while time.time() < deadline:
        resp = sqs.receive_message(
            QueueUrl=inbox_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            VisibilityTimeout=5,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        payload = json.loads(msgs[0]["Body"])
        assert payload["toUsername"] == agent_id
        assert payload["senderUsername"] == agent_id
        assert payload["message"]["kind"] == "integration"
        sqs.delete_message(QueueUrl=inbox_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
        return

    raise AssertionError("timed out waiting for routed message")


def test_eventbridge_put_events_rejects_invalid_source(deploy_stack, issued_session):
    ev = issued_session.client("events")
    with pytest.raises(Exception):
        ev.put_events(
            Entries=[
                {
                    "EventBusName": deploy_stack.event_bus_arn,
                    "Source": "agents.messages",
                    "DetailType": "agent.message.v2",
                    "Detail": json.dumps(
                        {
                            "toUsername": "nobody",
                            "kind": "text.v1",
                            "message": {"ok": False},
                        }
                    ),
                }
            ]
        )


def test_denied_operations(issued_session):
    # These should be denied by boundary/session policy.
    with pytest.raises(Exception):
        issued_session.client("s3").list_buckets()
    with pytest.raises(Exception):
        issued_session.client("sqs").list_queues()


def test_post_basic_auth_returns_sts_creds_with_cognito_tokens_without_refresh(
    deploy_stack, cognito_user, credentials_json, shared_api_key
):
    # Call POST /v1/credentials using HTTP Basic Auth (username/password).
    userpass = f"{cognito_user['username']}:{cognito_user['password']}".encode("utf-8")
    b64 = base64.b64encode(userpass).decode("ascii")

    url = deploy_stack.credentials_url  # same path; method differs
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {b64}", "x-api-key": shared_api_key},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    b = json.loads(raw)

    ct = b.get("cognitoTokens")
    assert isinstance(ct, dict)
    assert ct.get("idToken")
    assert ct.get("accessToken")
    assert ct.get("refreshToken")
    assert "RefreshToken" not in ct
    assert b["credentials"]["accessKeyId"]
