import importlib
import json
import re
import sys


def _load_handler(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("LINKS_TABLE_NAME", "ShortLinks")
    monkeypatch.setenv("SCHEMA_VERSION", "2026-02-10")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import shortlink_create as module

    return importlib.reload(module)


def test_create_shortlink_success_and_persists_creator(monkeypatch):
    module = _load_handler(monkeypatch)

    writes = []

    class FakeDdb:
        def get_item(self, **kwargs):
            assert kwargs["TableName"] == "AgentProfiles"
            return {"Item": {"enabled": {"BOOL": True}}}

        def put_item(self, **kwargs):
            writes.append(kwargs)
            return {}

    module._ddb_client = FakeDdb()

    event = {
        "requestContext": {
            "requestId": "r1",
            "authorizer": {"claims": {"sub": "sub-1", "cognito:username": "agent-a"}},
        },
        "body": json.dumps(
            {
                "targetUrl": "https://bucket.s3.us-east-1.amazonaws.com/path/file.txt?X-Amz-Signature=abc",
                "alias": "1111111111111111111111",
            }
        ),
    }

    out = module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 201
    assert body["code"] == "1111111111111111111111"
    assert body["createdBy"]["sub"] == "sub-1"
    assert body["createdBy"]["username"] == "agent-a"
    assert body["shortPath"] == "/l/1111111111111111111111"
    assert "shortUrl" not in body

    assert len(writes) == 1
    item = writes[0]["Item"]
    assert item["createdBySub"]["S"] == "sub-1"
    assert item["createdByUsername"]["S"] == "agent-a"


def test_create_shortlink_short_path_ignores_forwarded_host_headers(monkeypatch):
    module = _load_handler(monkeypatch)

    class FakeDdb:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

        def put_item(self, **kwargs):
            return {}

    module._ddb_client = FakeDdb()

    event = {
        "requestContext": {
            "requestId": "r1",
            "authorizer": {"jwt": {"claims": {"sub": "sub-1", "cognito:username": "agent-a"}}},
        },
        "body": json.dumps(
            {
                "targetUrl": "https://bucket.s3.us-east-1.amazonaws.com/path/file.txt?X-Amz-Signature=abc",
                "alias": "2222222222222222222222",
            }
        ),
    }

    out = module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 201
    assert body["shortPath"] == "/l/2222222222222222222222"
    assert "shortUrl" not in body


def test_create_shortlink_rejects_non_https(monkeypatch):
    module = _load_handler(monkeypatch)

    class FakeDdb:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

        def put_item(self, **kwargs):
            raise AssertionError("put_item should not be called")

    module._ddb_client = FakeDdb()

    event = {
        "requestContext": {
            "requestId": "r1",
            "authorizer": {"claims": {"sub": "sub-1", "cognito:username": "agent-a"}},
        },
        "body": json.dumps({"targetUrl": "http://bucket.s3.us-east-1.amazonaws.com/path/file.txt"}),
    }

    out = module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 400
    assert body["errorCode"] == "INVALID_TARGET_URL"
    assert "https" in body["message"]


def test_create_shortlink_allows_general_https_host(monkeypatch):
    module = _load_handler(monkeypatch)

    class FakeDdb:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

        def put_item(self, **kwargs):
            return {}

    module._ddb_client = FakeDdb()

    event = {
        "requestContext": {
            "requestId": "r1",
            "authorizer": {"claims": {"sub": "sub-1", "cognito:username": "agent-a"}},
        },
        "body": json.dumps({"targetUrl": "https://example.org/path"}),
    }

    out = module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 201
    assert body["target"]["host"] == "example.org"
    assert re.match(r"^[1-9A-HJ-NP-Za-km-z]{22}$", str(body["code"]))
    assert body["shortPath"] == f"/l/{body['code']}"


def test_create_shortlink_requires_authorizer_claims(monkeypatch):
    module = _load_handler(monkeypatch)
    module._ddb_client = object()
    out = module.handler({"requestContext": {"requestId": "r1"}, "body": "{}"}, None)
    body = json.loads(out["body"])
    assert out["statusCode"] == 401
    assert body["errorCode"] == "UNAUTHORIZED"
