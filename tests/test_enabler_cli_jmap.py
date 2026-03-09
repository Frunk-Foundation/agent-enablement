import argparse
import json

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


class _FakeSession:
    def __init__(self, ddb):
        self._ddb = ddb

    def client(self, name):
        assert name == "dynamodb"
        return self._ddb


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
    )
    assert cmd_jmap_mail_submission_set(args, _g()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["submissionId"]
    created = next(iter(payload["created"].values()))
    assert created["to"]["agentId"] == "alice"
    assert created["mailboxIds"] == ["inbox"]
    assert created["isUnread"] is True


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
