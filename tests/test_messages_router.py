import importlib
import json
import sys


def _load_router(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("PROFILE_AGENT_ID_INDEX", "agentId-index")
    monkeypatch.setenv("SCHEMA_VERSION", "2026-02-18")
    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import messages_router as module

    return importlib.reload(module)


def _profile(sub: str, agent_id: str, *, enabled: bool = True):
    return {
        "sub": {"S": sub},
        "agentId": {"S": agent_id},
        "enabled": {"BOOL": enabled},
        "inboxQueueUrl": {"S": f"https://sqs.us-east-1.amazonaws.com/123/agent-inbox-{agent_id}"},
    }


class FakeDdb:
    def __init__(self, profiles: list[dict]):
        self._profiles = profiles

    def get_item(self, **kwargs):
        assert kwargs["TableName"] == "AgentProfiles"
        sub = kwargs["Key"]["sub"]["S"]
        for item in self._profiles:
            if item["sub"]["S"] == sub:
                return {"Item": item}
        return {}

    def query(self, **kwargs):
        table = kwargs["TableName"]
        assert table == "AgentProfiles"
        agent_id = kwargs["ExpressionAttributeValues"][":agentId"]["S"]
        return {"Items": [p for p in self._profiles if p["agentId"]["S"] == agent_id]}


class FakeSqs:
    def __init__(self):
        self.sent = []

    def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return {"MessageId": "m1"}


def test_direct_routing_derives_sender_from_source(monkeypatch):
    module = _load_router(monkeypatch)
    ddb = FakeDdb(
        profiles=[
            _profile("sub-alice", "alice"),
            _profile("sub-bob", "bob"),
        ],
    )
    sqs = FakeSqs()
    module._ddb_client = ddb
    module._sqs_client = sqs

    event = {
        "id": "evt-1",
        "source": "agents.messages.sub.sub-bob",
        "detail-type": "agent.message.v2",
        "time": "2026-02-18T00:00:00Z",
        "detail": {
            "kind": "text.v1",
            "toUsername": "alice",
            "message": {"text": "hi"},
            "senderUsername": "forged",
        },
    }
    out = module.handler(event, None)

    assert out["ok"] is True
    assert out["sent"] == 1
    assert sqs.sent[0]["QueueUrl"].endswith("/agent-inbox-alice")
    body = json.loads(sqs.sent[0]["MessageBody"])
    assert body["toUsername"] == "alice"
    assert body["senderUsername"] == "bob"
    assert body["senderSub"] == "sub-bob"
    assert body["message"]["text"] == "hi"


def test_recipient_not_found(monkeypatch):
    module = _load_router(monkeypatch)
    ddb = FakeDdb(
        profiles=[_profile("sub-bob", "bob")],
    )
    module._ddb_client = ddb
    module._sqs_client = FakeSqs()

    event = {
        "id": "evt-2",
        "source": "agents.messages.sub.sub-bob",
        "detail-type": "agent.message.v2",
        "time": "2026-02-18T00:00:00Z",
        "detail": {
            "kind": "text.v1",
            "toUsername": "alice",
            "message": {"text": "hi"},
        },
    }
    out = module.handler(event, None)

    assert out["ok"] is False
    assert out["error"] == "recipient_not_found"


def test_invalid_source_is_rejected(monkeypatch):
    module = _load_router(monkeypatch)
    module._ddb_client = FakeDdb(profiles=[])
    module._sqs_client = FakeSqs()

    event = {
        "id": "evt-3",
        "source": "agents.messages",
        "detail-type": "agent.message.v2",
        "time": "2026-02-18T00:00:00Z",
        "detail": {
            "kind": "text.v1",
            "toUsername": "alice",
            "message": {"text": "nope"},
        },
    }
    out = module.handler(event, None)

    assert out["ok"] is False
    assert out["error"] == "invalid_source"


def test_invalid_to_is_rejected(monkeypatch):
    module = _load_router(monkeypatch)
    module._ddb_client = FakeDdb(profiles=[_profile("sub-bob", "bob")])
    module._sqs_client = FakeSqs()

    event = {
        "id": "evt-4",
        "source": "agents.messages.sub.sub-bob",
        "detail-type": "agent.message.v2",
        "time": "2026-02-18T00:00:00Z",
        "detail": {
            "kind": "text.v1",
            "toUsername": "agent:alice",
            "message": {"text": "nope"},
        },
    }
    out = module.handler(event, None)

    assert out["ok"] is False
    assert out["error"] == "invalid_to"
