import argparse
import json
from pathlib import Path

from enabler_cli.apps.agent_admin_cli import (
    GlobalOpts,
    cmd_jmap_contacts_query,
    cmd_jmap_contacts_set,
    cmd_jmap_mail_query,
    cmd_jmap_mail_submission_set,
)


def _g() -> GlobalOpts:
    return GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path="/tmp/enabler-test-credentials.json",
        auto_refresh_creds=True,
    )


def _base_jmap_doc() -> dict:
    return {
        "principal": {"sub": "sub-123", "username": "agent-test"},
        "credentials": {
            "accessKeyId": "AKIA_TEST",
            "secretAccessKey": "secret",
            "sessionToken": "token",
        },
        "references": {
            "awsRegion": "us-east-2",
            "files": {"publicBaseUrl": "https://files.example.com"},
            "directory": {
                "profileTableName": "AgentProfiles",
                "profileAgentIdIndex": "agentId-index",
            },
            "jmapContacts": {
                "tableName": "AgentContacts",
            },
            "jmapMail": {
                "tableName": "AgentMail",
                "defaultMailboxId": "inbox",
            },
        },
        "grants": [
            {
                "service": "s3",
                "actions": ["s3:PutObject"],
                "resources": ["arn:aws:s3:::files-bucket/public/sub-123/*"],
            }
        ],
    }


class _FakeDdb:
    def __init__(self):
        self.contacts: dict[tuple[str, str], dict] = {}
        self.mail: dict[tuple[str, str], dict] = {}

    def query(self, **kwargs):
        table = kwargs["TableName"]
        if table == "AgentProfiles":
            agent_id = kwargs["ExpressionAttributeValues"][":agentId"]["S"]
            if agent_id == "alice":
                return {
                    "Items": [
                        {
                            "sub": {"S": "sub-alice"},
                            "agentId": {"S": "alice"},
                            "enabled": {"BOOL": True},
                        }
                    ]
                }
            return {"Items": []}
        owner_sub = kwargs["ExpressionAttributeValues"][":ownerSub"]["S"]
        if table == "AgentContacts":
            items = [item for (sub, _), item in self.contacts.items() if sub == owner_sub]
            return {"Items": items}
        if table == "AgentMail":
            items = [item for (sub, _), item in self.mail.items() if sub == owner_sub]
            return {"Items": items}
        raise AssertionError(f"unexpected query table: {table}")

    def put_item(self, **kwargs):
        table = kwargs["TableName"]
        item = kwargs["Item"]
        if table == "AgentContacts":
            self.contacts[(item["ownerSub"]["S"], item["contactId"]["S"])] = item
            return {}
        if table == "AgentMail":
            self.mail[(item["ownerSub"]["S"], item["emailId"]["S"])] = item
            return {}
        raise AssertionError(f"unexpected put table: {table}")

    def get_item(self, **kwargs):
        table = kwargs["TableName"]
        key = kwargs["Key"]
        if table == "AgentContacts":
            return {
                "Item": self.contacts.get((key["ownerSub"]["S"], key["contactId"]["S"]))
            }
        if table == "AgentMail":
            return {
                "Item": self.mail.get((key["ownerSub"]["S"], key["emailId"]["S"]))
            }
        raise AssertionError(f"unexpected get table: {table}")


class _FakeS3:
    def __init__(self):
        self.uploads: list[dict[str, str]] = []

    def upload_file(self, local_path, bucket, key, ExtraArgs=None):
        self.uploads.append(
            {
                "local_path": str(local_path),
                "bucket": bucket,
                "key": key,
                "content_type": str((ExtraArgs or {}).get("ContentType") or ""),
            }
        )


class _FakeSession:
    def __init__(self, ddb, *, s3=None):
        self._ddb = ddb
        self._s3 = s3

    def client(self, name):
        if name == "dynamodb":
            return self._ddb
        if name == "s3":
            assert self._s3 is not None
            return self._s3
        raise AssertionError(f"unexpected client: {name}")


def test_jmap_contacts_set_and_query(monkeypatch, capsys):
    ddb = _FakeDdb()
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_jmap_doc(),
    )
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._issued_session_from_doc",
        lambda doc: (_FakeSession(ddb), doc["references"], "us-east-2"),
    )

    create_args = argparse.Namespace(
        name="Alice",
        target_agent_id="alice",
        contact_id=None,
        description="review partner",
    )
    assert cmd_jmap_contacts_set(create_args, _g()) == 0
    created = json.loads(capsys.readouterr().out)
    contact_id = next(iter(created["created"].keys()))

    query_args = argparse.Namespace(text="alice")
    assert cmd_jmap_contacts_query(query_args, _g()) == 0
    queried = json.loads(capsys.readouterr().out)
    assert queried["list"][0]["contactId"] == contact_id
    assert queried["list"][0]["targetAgentId"] == "alice"


def test_jmap_mail_submission_creates_inbox_mail(monkeypatch, capsys):
    ddb = _FakeDdb()
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_jmap_doc(),
    )
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._issued_session_from_doc",
        lambda doc: (_FakeSession(ddb), doc["references"], "us-east-2"),
    )

    args = argparse.Namespace(
        subject="Review",
        body="doorstop review uploaded",
        to_agent_ids=["alice"],
        to_contact_ids=[],
        meta_json=None,
        attachments=None,
        attachment_file_paths=[],
    )
    assert cmd_jmap_mail_submission_set(args, _g()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["submissionId"]
    created = next(iter(payload["created"].values()))
    assert created["to"]["agentId"] == "alice"
    assert created["mailboxIds"] == ["inbox"]
    assert created["isUnread"] is True
    assert created["attachments"] == []


def test_jmap_mail_submission_persists_preuploaded_attachments(monkeypatch, capsys):
    ddb = _FakeDdb()
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_jmap_doc(),
    )
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._issued_session_from_doc",
        lambda doc: (_FakeSession(ddb), doc["references"], "us-east-2"),
    )

    args = argparse.Namespace(
        subject="Review",
        body="See attachment",
        to_agent_ids=["alice"],
        to_contact_ids=[],
        meta_json=None,
        attachments=json.dumps(
            [
                {
                    "name": "report.txt",
                    "url": "https://files.example.com/public/sub-123/file-1/report.txt",
                    "contentType": "text/plain",
                    "sizeBytes": 42,
                    "storageKey": "public/sub-123/file-1/report.txt",
                }
            ]
        ),
        attachment_file_paths=[],
    )
    assert cmd_jmap_mail_submission_set(args, _g()) == 0
    payload = json.loads(capsys.readouterr().out)
    created = next(iter(payload["created"].values()))
    assert created["attachments"][0]["name"] == "report.txt"
    assert created["attachments"][0]["storageKey"] == "public/sub-123/file-1/report.txt"
    assert created["attachments"][0]["url"].startswith("https://files.example.com/")


def test_jmap_mail_submission_uploads_local_attachment_paths(monkeypatch, tmp_path: Path, capsys):
    ddb = _FakeDdb()
    s3 = _FakeS3()
    local_file = tmp_path / "report.txt"
    local_file.write_text("hello attachment", encoding="utf-8")
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_jmap_doc(),
    )
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._issued_session_from_doc",
        lambda doc: (_FakeSession(ddb, s3=s3), doc["references"], "us-east-2"),
    )

    args = argparse.Namespace(
        subject="Review",
        body="See local attachment",
        to_agent_ids=["alice"],
        to_contact_ids=[],
        meta_json=None,
        attachments=None,
        attachment_file_paths=[str(local_file)],
    )
    assert cmd_jmap_mail_submission_set(args, _g()) == 0
    payload = json.loads(capsys.readouterr().out)
    created = next(iter(payload["created"].values()))
    assert created["attachments"][0]["name"] == "report.txt"
    assert created["attachments"][0]["url"].startswith("https://files.example.com/")
    assert s3.uploads[0]["bucket"] == "files-bucket"
    assert s3.uploads[0]["key"].startswith("public/sub-123/")


def test_jmap_mail_query_returns_received_mail(monkeypatch, capsys):
    ddb = _FakeDdb()
    ddb.mail[("sub-123", "mail-1")] = {
        "ownerSub": {"S": "sub-123"},
        "emailId": {"S": "mail-1"},
        "threadId": {"S": "thread-1"},
        "mailboxIds": {"SS": ["inbox"]},
        "fromAgentId": {"S": "alice"},
        "fromSub": {"S": "sub-alice"},
        "toAgentId": {"S": "agent-test"},
        "toSub": {"S": "sub-123"},
        "subject": {"S": "Review"},
        "body": {"S": "doorstop review uploaded"},
        "preview": {"S": "doorstop review uploaded"},
        "keywords": {"SS": ["$unread"]},
        "isUnread": {"BOOL": True},
        "receivedAt": {"S": "2026-03-09T00:00:00+00:00"},
        "createdAt": {"S": "2026-03-09T00:00:00+00:00"},
        "submissionId": {"S": "subm-1"},
        "attachmentsJson": {
            "S": json.dumps(
                [
                    {
                        "attachmentId": "att-1",
                        "name": "report.txt",
                        "url": "https://files.example.com/public/sub-123/report.txt",
                    }
                ]
            )
        },
        "metaJson": {"S": "{}"},
    }
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._resolve_runtime_credentials_doc",
        lambda _args, _g: _base_jmap_doc(),
    )
    monkeypatch.setattr(
        "enabler_cli.apps.agent_admin_cli._issued_session_from_doc",
        lambda doc: (_FakeSession(ddb), doc["references"], "us-east-2"),
    )

    args = argparse.Namespace(mailbox_id="inbox", text="review", unread_only=True)
    assert cmd_jmap_mail_query(args, _g()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ids"] == ["mail-1"]
    assert payload["list"][0]["from"]["agentId"] == "alice"
    assert payload["list"][0]["attachments"][0]["attachmentId"] == "att-1"
