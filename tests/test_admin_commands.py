import argparse
import json
from datetime import datetime, timezone

from enabler_cli.admin_commands import cmd_agent_decommission
from enabler_cli.admin_commands import cmd_cognito_list_users
from enabler_cli.admin_commands import cmd_cognito_remove_user
from enabler_cli.admin_commands import cmd_agent_seed_profile
from enabler_cli.cli_shared import GlobalOpts
from enabler_cli.cli_shared import UsageError


def _g() -> GlobalOpts:
    return GlobalOpts(
        stack="AgentEnablementStack",
        pretty=False,
        quiet=False,
        creds_cache_path="/tmp/enabler-admin-test-credentials.json",
        auto_refresh_creds=False,
    )


class _FakeAdminContext:
    def __init__(self, session, outputs, user_pool_id="pool-1"):
        self.session = session
        self._outputs = outputs
        self._user_pool_id = user_pool_id

    def outputs(self):
        return self._outputs

    def resolve_user_pool_id(self, override):
        return override or self._user_pool_id


def test_cmd_cognito_remove_user_calls_admin_delete_user(monkeypatch, capsys):
    calls: dict[str, str] = {}

    class FakeCognito:
        def admin_delete_user(self, **kwargs):
            calls["user_pool_id"] = kwargs["UserPoolId"]
            calls["username"] = kwargs["Username"]

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(username="alice", user_pool_id=None)
    assert cmd_cognito_remove_user(args, _g()) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["removed"] is True
    assert calls == {"user_pool_id": "pool-1", "username": "alice"}


def test_cmd_cognito_list_users_filters_ephemeral_by_default(monkeypatch, capsys):
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["UserPoolId"] == "pool-1"
            return [
                {
                    "Users": [
                        {
                            "Username": "ephem-abc",
                            "UserStatus": "CONFIRMED",
                            "Enabled": True,
                            "UserCreateDate": datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc),
                            "UserLastModifiedDate": datetime(2026, 2, 27, 12, 1, 0, tzinfo=timezone.utc),
                            "Attributes": [{"Name": "email", "Value": "ephem@example.com"}],
                        },
                        {
                            "Username": "alice",
                            "UserStatus": "CONFIRMED",
                            "Enabled": True,
                            "UserCreateDate": datetime(2026, 2, 27, 12, 2, 0, tzinfo=timezone.utc),
                            "UserLastModifiedDate": datetime(2026, 2, 27, 12, 3, 0, tzinfo=timezone.utc),
                            "Attributes": [{"Name": "email", "Value": "alice@example.com"}],
                        },
                    ]
                }
            ]

    class FakeCognito:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(user_pool_id=None, include_ephemeral=False, json=False)
    assert cmd_cognito_list_users(args, _g()) == 0
    out = capsys.readouterr().out
    assert "alice" in out
    assert "ephem-abc" not in out


def test_cmd_cognito_list_users_json_includes_ephemeral_when_requested(monkeypatch, capsys):
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["UserPoolId"] == "pool-x"
            return [
                {
                    "Users": [
                        {
                            "Username": "ephem-abc",
                            "UserStatus": "CONFIRMED",
                            "Enabled": True,
                            "UserCreateDate": datetime(2026, 2, 27, 12, 0, 0, tzinfo=timezone.utc),
                            "UserLastModifiedDate": datetime(2026, 2, 27, 12, 1, 0, tzinfo=timezone.utc),
                            "Attributes": [{"Name": "custom:type", "Value": "ephemeral"}],
                        }
                    ]
                }
            ]

    class FakeCognito:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(user_pool_id="pool-x", include_ephemeral=True, json=True)
    assert cmd_cognito_list_users(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["userPoolId"] == "pool-x"
    assert out["includeEphemeral"] is True
    assert out["count"] == 1
    assert out["users"][0]["username"] == "ephem-abc"
    assert out["users"][0]["attributes"] == [{"name": "custom:type", "value": "ephemeral"}]


def test_cmd_cognito_list_users_merges_pagination(monkeypatch, capsys):
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["UserPoolId"] == "pool-1"
            return [
                {
                    "Users": [
                        {
                            "Username": "alice",
                            "UserStatus": "CONFIRMED",
                            "Enabled": True,
                        }
                    ]
                },
                {
                    "Users": [
                        {
                            "Username": "bob",
                            "UserStatus": "CONFIRMED",
                            "Enabled": True,
                        }
                    ]
                },
            ]

    class FakeCognito:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(user_pool_id=None, include_ephemeral=False, json=True)
    assert cmd_cognito_list_users(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["count"] == 2
    assert [u["username"] for u in out["users"]] == ["alice", "bob"]


def test_cmd_cognito_list_users_empty_result(monkeypatch, capsys):
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["UserPoolId"] == "pool-1"
            return [{"Users": []}]

    class FakeCognito:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(user_pool_id=None, include_ephemeral=False, json=True)
    assert cmd_cognito_list_users(args, _g()) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["count"] == 0
    assert out["users"] == []


def test_cmd_cognito_list_users_empty_result_plain_text(monkeypatch, capsys):
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["UserPoolId"] == "pool-1"
            return [{"Users": []}]

    class FakeCognito:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

    class FakeSession:
        def client(self, name):
            assert name == "cognito-idp"
            return FakeCognito()

    fake_ctx = _FakeAdminContext(session=FakeSession(), outputs={})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(user_pool_id=None, include_ephemeral=False, json=False)
    assert cmd_cognito_list_users(args, _g()) == 0
    out = capsys.readouterr().out
    assert "No users found." in out


def test_cmd_agent_decommission_dry_run_outputs_actions(monkeypatch, capsys):
    calls = {"deleted_user": 0, "deleted_profile": 0, "deleted_queue": 0}

    class FakeCognito:
        def admin_get_user(self, **kwargs):
            assert kwargs["Username"] == "alice"
            return {
                "UserAttributes": [
                    {"Name": "sub", "Value": "sub-1"},
                ]
            }

        def admin_delete_user(self, **kwargs):
            calls["deleted_user"] += 1

    class FakeDDB:
        def get_item(self, **kwargs):
            return {
                "Item": {
                    "agentId": {"S": "alice"},
                    "groups": {"SS": ["ops", "oncall"]},
                    "inboxQueueUrl": {"S": "https://sqs.us-east-2.amazonaws.com/111122223333/agent-inbox-alice"},
                }
            }

        def delete_item(self, **kwargs):
            calls["deleted_profile"] += 1

    class FakeSQS:
        def delete_queue(self, **kwargs):
            calls["deleted_queue"] += 1

    class FakeSession:
        def client(self, name):
            if name == "cognito-idp":
                return FakeCognito()
            if name == "dynamodb":
                return FakeDDB()
            if name == "sqs":
                return FakeSQS()
            raise AssertionError(name)

    fake_ctx = _FakeAdminContext(
        session=FakeSession(),
        outputs={
            "AgentProfilesTableName": "profiles-table",
            "AgentGroupMembersTableName": "group-members-table",
        },
    )
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(username="alice", user_pool_id=None, dry_run=True)
    assert cmd_agent_decommission(args, _g()) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["dryRun"] is True
    assert out["sub"] == "sub-1"
    assert len(out["actions"]) >= 5
    assert calls == {"deleted_user": 0, "deleted_profile": 0, "deleted_queue": 0}


def test_cmd_agent_decommission_executes_full_teardown(monkeypatch, capsys):
    calls = {"deleted_user": 0, "ddb_deletes": [], "deleted_queue": 0}

    class FakeCognito:
        def admin_get_user(self, **kwargs):
            return {
                "UserAttributes": [
                    {"Name": "sub", "Value": "sub-1"},
                ]
            }

        def admin_delete_user(self, **kwargs):
            calls["deleted_user"] += 1

    class FakeDDB:
        def get_item(self, **kwargs):
            return {
                "Item": {
                    "agentId": {"S": "alice"},
                    "groups": {"SS": ["ops", "oncall"]},
                    "inboxQueueUrl": {"S": "https://sqs.us-east-2.amazonaws.com/111122223333/agent-inbox-alice"},
                }
            }

        def delete_item(self, **kwargs):
            calls["ddb_deletes"].append(kwargs)

    class FakeSQS:
        def delete_queue(self, **kwargs):
            calls["deleted_queue"] += 1

    class FakeSession:
        def client(self, name):
            if name == "cognito-idp":
                return FakeCognito()
            if name == "dynamodb":
                return FakeDDB()
            if name == "sqs":
                return FakeSQS()
            raise AssertionError(name)

    fake_ctx = _FakeAdminContext(
        session=FakeSession(),
        outputs={
            "AgentProfilesTableName": "profiles-table",
            "AgentGroupMembersTableName": "group-members-table",
        },
    )
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(username="alice", user_pool_id=None, dry_run=False)
    assert cmd_agent_decommission(args, _g()) == 0

    out = json.loads(capsys.readouterr().out)
    assert out["results"]["cognitoDeleted"] is True
    assert out["results"]["profileDeleted"] is True
    assert out["results"]["groupRowsDeleted"] == 2
    assert out["results"]["inboxDeleted"] is True
    assert calls["deleted_user"] == 1
    assert calls["deleted_queue"] == 1
    # One profile delete + two group membership deletes.
    assert len(calls["ddb_deletes"]) == 3


def test_cmd_agent_seed_profile_defaults_profile_type_named(monkeypatch, capsys):
    put_calls: list[dict] = []

    class FakeCreds:
        username = "alice"
        password = "secret"

    class FakeSQS:
        def create_queue(self, **kwargs):
            return {"QueueUrl": "https://sqs.us-east-2.amazonaws.com/111122223333/agent-inbox-alice"}

        def get_queue_attributes(self, **kwargs):
            return {"Attributes": {"QueueArn": "arn:aws:sqs:us-east-2:111122223333:agent-inbox-alice"}}

        def tag_queue(self, **kwargs):
            return None

    class FakeDDB:
        def put_item(self, **kwargs):
            put_calls.append(kwargs)

    class FakeSession:
        def client(self, name):
            if name == "sqs":
                return FakeSQS()
            if name == "dynamodb":
                return FakeDDB()
            raise AssertionError(name)

    fake_ctx = _FakeAdminContext(
        session=FakeSession(),
        outputs={
            "AgentProfilesTableName": "profiles-table",
            "AgentGroupMembersTableName": "group-members-table",
            "BrokerRuntimeRoleArn": "arn:aws:iam::123456789012:role/BrokerRuntime",
            "BrokerProvisioningRoleArn": "arn:aws:iam::123456789012:role/BrokerProvisioning",
            "UploadBucketName": "upload-bucket",
            "CommsSharedBucketName": "comms-bucket",
            "QueueArn": "arn:aws:sqs:us-east-2:123456789012:q",
            "EventBusArn": "arn:aws:events:us-east-2:123456789012:event-bus/b",
        },
    )
    monkeypatch.setattr("enabler_cli.admin_commands._resolve_cognito_basic_credentials", lambda **_kwargs: FakeCreds())
    monkeypatch.setattr("enabler_cli.admin_commands._cognito_auth_result", lambda **_kwargs: {"IdToken": "a.b.c"})
    monkeypatch.setattr("enabler_cli.admin_commands._jwt_payload", lambda _tok: {"sub": "sub-1"})
    monkeypatch.setattr("enabler_cli.admin_commands.build_admin_context", lambda _g: fake_ctx)

    args = argparse.Namespace(
        username="alice",
        password="secret",
        credential_scope=None,
        profile_type=None,
        agent_id=None,
        groups=None,
        create_inbox=True,
        inbox_queue_name=None,
        dry_run=False,
        client_id=None,
    )
    assert cmd_agent_seed_profile(args, _g()) == 0
    _ = capsys.readouterr()
    profile_put = next(c for c in put_calls if c["TableName"] == "profiles-table")
    assert profile_put["Item"]["profileType"]["S"] == "named"


def test_cmd_agent_seed_profile_rejects_invalid_profile_type(monkeypatch):
    class FakeCreds:
        username = "alice"
        password = "secret"

    monkeypatch.setattr("enabler_cli.admin_commands._resolve_cognito_basic_credentials", lambda **_kwargs: FakeCreds())
    args = argparse.Namespace(
        username="alice",
        password="secret",
        credential_scope=None,
        profile_type="bad-value",
        agent_id=None,
        groups=None,
        create_inbox=True,
        inbox_queue_name=None,
        dry_run=True,
        client_id=None,
    )
    try:
        cmd_agent_seed_profile(args, _g())
    except UsageError as e:
        assert "profile type must be named or ephemeral" in str(e)
        return
    raise AssertionError("expected UsageError")
