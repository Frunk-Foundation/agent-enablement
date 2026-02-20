import argparse
import json

from enabler_cli.admin_commands import cmd_agent_decommission
from enabler_cli.admin_commands import cmd_cognito_remove_user
from enabler_cli.cli_shared import GlobalOpts


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
