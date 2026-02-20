import base64
import importlib
import json
import sys


def _load_bundle_handler(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("USER_POOL_CLIENT_ID", "client-1")
    monkeypatch.setenv(
        "ENABLEMENT_BUNDLE_URL",
        "https://comms-bucket.s3.us-east-1.amazonaws.com/agent-enablement/latest/agent-enablement-bundle.zip",
    )
    monkeypatch.setenv("CREDENTIALS_INVOKE_URL", "https://api.example.com/prod/v1/credentials")
    monkeypatch.setenv("BUNDLE_INVOKE_URL", "https://api.example.com/prod/v1/bundle")
    monkeypatch.setenv("TASKBOARD_INVOKE_URL", "https://api.example.com/prod/v1/taskboard")
    monkeypatch.setenv("SHORTLINK_CREATE_URL", "https://api.example.com/prod/v1/links")
    monkeypatch.setenv("SHORTLINK_REDIRECT_BASE_URL", "https://d111111abcdef8.cloudfront.net/l/")
    monkeypatch.setenv("FILES_PUBLIC_BASE_URL", "https://d222222abcdef8.cloudfront.net/")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")

    import bundle_handler as mod

    return importlib.reload(mod)


def test_bundle_handler_returns_presigned_static_bundle_url(monkeypatch):
    mod = _load_bundle_handler(monkeypatch)

    class FakeS3:
        def __init__(self):
            self.heads = []

        def head_object(self, *, Bucket, Key):
            self.heads.append((Bucket, Key))
            return {}

        def generate_presigned_url(self, op, *, Params, ExpiresIn):
            assert op == "get_object"
            assert Params["Bucket"] == "comms-bucket"
            assert Params["Key"] == "agent-enablement/latest/agent-enablement-bundle.zip"
            return f"https://example.invalid/presigned/{Params['Key']}?exp={ExpiresIn}"

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = json.dumps(
                {"sub": "sub-1", "iss": "https://issuer.invalid/pool", "cognito:username": "agent-user"}
            ).encode("utf-8")
            jwt_payload = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
            id_token = f"aaa.{jwt_payload}.bbb"
            return {"AuthenticationResult": {"IdToken": id_token}}

    class FakeDDB:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

    mod._s3_client = FakeS3()
    mod._cognito_client = FakeCognito()
    mod._ddb_client = FakeDDB()

    basic = base64.b64encode(b"agent-user:pass").decode("ascii")
    event = {
        "requestContext": {"requestId": "req-1"},
        "queryStringParameters": {"ttlSeconds": "600"},
        "headers": {"authorization": f"Basic {basic}"},
    }
    resp = mod.handler(event, None)

    assert int(resp["statusCode"]) == 200
    parsed = json.loads(resp["body"])
    assert parsed["requestId"] == "req-1"
    assert "bundleUrl" in parsed
    assert set(parsed.keys()) == {"bundleUrl", "connection", "requestId"}
    assert parsed["connection"]["schemaVersion"] == "2026-02-17"
    assert parsed["connection"]["awsRegion"] == "us-east-1"
    assert parsed["connection"]["auth"]["credentialsEndpoint"] == "https://api.example.com/prod/v1/credentials"
    assert parsed["connection"]["taskboard"]["invokeUrl"] == "https://api.example.com/prod/v1/taskboard"
    assert parsed["connection"]["shortlinks"]["createUrl"] == "https://api.example.com/prod/v1/links"
    assert parsed["connection"]["shortlinks"]["redirectBaseUrl"] == "https://d111111abcdef8.cloudfront.net/l/"
    assert parsed["connection"]["files"]["publicBaseUrl"] == "https://d222222abcdef8.cloudfront.net/"
    assert parsed["connection"]["cognito"]["issuer"] == "https://issuer.invalid/pool"
    assert parsed["connection"]["cognito"]["userPoolClientId"] == "client-1"
    assert parsed["connection"]["ssmKeys"]["stage"] == "prod"
    assert parsed["connection"]["ssmKeys"]["sharedBasePath"] == "/agent-enablement/prod/shared/"
    assert mod._s3_client.heads == [
        ("comms-bucket", "agent-enablement/latest/agent-enablement-bundle.zip")
    ]


def test_bundle_handler_returns_unavailable_when_static_bundle_missing(monkeypatch):
    mod = _load_bundle_handler(monkeypatch)

    class FakeS3:
        def head_object(self, *, Bucket, Key):
            raise RuntimeError("missing")

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = json.dumps({"sub": "sub-1", "cognito:username": "agent-user"}).encode("utf-8")
            jwt_payload = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
            return {"AuthenticationResult": {"IdToken": f"aaa.{jwt_payload}.bbb"}}

    class FakeDDB:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

    mod._s3_client = FakeS3()
    mod._cognito_client = FakeCognito()
    mod._ddb_client = FakeDDB()

    basic = base64.b64encode(b"agent-user:pass").decode("ascii")
    resp = mod.handler(
        {
            "requestContext": {"requestId": "req-2"},
            "headers": {"authorization": f"Basic {basic}"},
        },
        None,
    )

    assert int(resp["statusCode"]) == 503
    parsed = json.loads(resp["body"])
    assert parsed["errorCode"] == "BUNDLE_UNAVAILABLE"
    assert parsed["requestId"] == "req-2"


def test_bundle_handler_connection_derives_execute_api_stage_urls(monkeypatch):
    mod = _load_bundle_handler(monkeypatch)
    monkeypatch.setenv("CREDENTIALS_INVOKE_URL", "")
    monkeypatch.setenv("BUNDLE_INVOKE_URL", "")
    monkeypatch.setenv("TASKBOARD_INVOKE_URL", "")
    monkeypatch.setenv("SHORTLINK_CREATE_URL", "")
    monkeypatch.setenv("SHORTLINK_REDIRECT_BASE_URL", "")
    monkeypatch.setenv("CREDENTIALS_PATH", "/v1/credentials")
    monkeypatch.setenv("BUNDLE_PATH", "/v1/bundle")
    monkeypatch.setenv("TASKBOARD_PATH", "/v1/taskboard")
    monkeypatch.setenv("SHORTLINK_CREATE_PATH", "/v1/links")
    monkeypatch.setenv("SHORTLINK_REDIRECT_PREFIX", "/l/")
    mod = importlib.reload(mod)

    class FakeS3:
        def head_object(self, *, Bucket, Key):
            return {}

        def generate_presigned_url(self, op, *, Params, ExpiresIn):
            return f"https://example.invalid/presigned/{Params['Key']}?exp={ExpiresIn}"

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = json.dumps({"sub": "sub-1", "cognito:username": "agent-user"}).encode("utf-8")
            jwt_payload = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
            return {"AuthenticationResult": {"IdToken": f"aaa.{jwt_payload}.bbb"}}

    class FakeDDB:
        def get_item(self, **kwargs):
            return {"Item": {"enabled": {"BOOL": True}}}

    mod._s3_client = FakeS3()
    mod._cognito_client = FakeCognito()
    mod._ddb_client = FakeDDB()

    basic = base64.b64encode(b"agent-user:pass").decode("ascii")
    event = {
        "requestContext": {"requestId": "req-3", "stage": "prod"},
        "headers": {
            "authorization": f"Basic {basic}",
            "host": "555428dtw9.execute-api.us-east-2.amazonaws.com",
            "x-forwarded-proto": "https",
        },
    }
    resp = mod.handler(event, None)
    parsed = json.loads(resp["body"])
    conn = parsed["connection"]
    assert conn["auth"]["bundleEndpoint"] == "https://555428dtw9.execute-api.us-east-2.amazonaws.com/prod/v1/bundle"
    assert conn["auth"]["credentialsEndpoint"] == "https://555428dtw9.execute-api.us-east-2.amazonaws.com/prod/v1/credentials"
    assert conn["awsRegion"] == "us-east-1"
    assert conn["taskboard"]["invokeUrl"] == "https://555428dtw9.execute-api.us-east-2.amazonaws.com/prod/v1/taskboard"
    assert conn["shortlinks"]["createUrl"] == "https://555428dtw9.execute-api.us-east-2.amazonaws.com/prod/v1/links"
    assert conn["shortlinks"]["redirectBaseUrl"] == "https://555428dtw9.execute-api.us-east-2.amazonaws.com/prod/l/"
    assert conn["files"]["publicBaseUrl"] == "https://d222222abcdef8.cloudfront.net/"
    assert conn["cognito"]["userPoolClientId"] == "client-1"
    assert conn["ssmKeys"]["stage"] == "prod"
