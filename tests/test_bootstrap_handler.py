import importlib
import json
import sys
from datetime import datetime, timezone


def _load_handler(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("ASSUME_ROLE_ARN", "arn:aws:iam::123456789012:role/BrokerTarget")
    monkeypatch.setenv("DEFAULT_TTL_SECONDS", "900")
    monkeypatch.setenv("MAX_TTL_SECONDS", "900")
    monkeypatch.setenv("SCHEMA_VERSION", "2026-02-10")
    monkeypatch.setenv("UPLOAD_BUCKET", "test-bucket")
    monkeypatch.setenv("UPLOAD_BASE_PREFIX", "uploads/")
    monkeypatch.setenv("SQS_QUEUE_ARN", "arn:aws:sqs:us-east-1:123456789012:q")
    monkeypatch.setenv("EVENT_BUS_ARN", "arn:aws:events:us-east-1:123456789012:event-bus/b")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import bootstrap_handler as handler_module
    return importlib.reload(handler_module)


def test_success_response_contains_credentials_and_catalog(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    def fake_get_item(**kwargs):
        assert kwargs["TableName"] == "AgentProfiles"
        return {
            "Item": {
                "sub": {"S": "sub-1"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerTarget"},
                "s3Bucket": {"S": "test-bucket"},
                "s3BasePrefix": {"S": "uploads/"},
                "sqsQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:q"},
                "eventBusArn": {"S": "arn:aws:events:us-east-1:123456789012:event-bus/b"},
                "instructionText": {"S": "do the thing"},
                }
            }

    class FakeSts:
        def assume_role(self, **kwargs):
            assert kwargs["DurationSeconds"] == 900
            assert "Policy" in kwargs
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA123",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                    "Expiration": datetime(2026, 2, 10, tzinfo=timezone.utc),
                }
            }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._sts_client = FakeSts()

    event = {"requestContext": {"requestId": "r1", "authorizer": {"claims": {"sub": "sub-1", "iss": "iss"}}}}
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    assert body["principal"]["sub"] == "sub-1"
    assert body["credentials"]["accessKeyId"] == "ASIA123"
    assert body["schemaVersion"] == "2026-02-10"
    assert body["constraints"]["ttlSeconds"] == 900
    assert len(body["grants"]) >= 1


def test_unmapped_api_key_returns_403(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    def fake_get_item(**kwargs):
        return {}

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    event = {"requestContext": {"requestId": "r1", "authorizer": {"claims": {"sub": "sub-x"}}}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 404


def test_sts_failure_returns_500(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "sub-1"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerTarget"},
                "s3Bucket": {"S": "test-bucket"},
            }
        }

    class FakeSts:
        def assume_role(self, **kwargs):
            raise RuntimeError("boom")

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._sts_client = FakeSts()

    event = {"requestContext": {"requestId": "r1", "authorizer": {"claims": {"sub": "sub-1"}}}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 500
    assert "STS_ISSUE_FAILED" in out["body"]


def test_duration_is_bounded(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DEFAULT_TTL_SECONDS", "99999")
    monkeypatch.setenv("MAX_TTL_SECONDS", "900")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("ASSUME_ROLE_ARN", "arn:aws:iam::123456789012:role/BrokerTarget")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import bootstrap_handler as handler_module
    handler_module = importlib.reload(handler_module)
    assert handler_module._duration_seconds() == 900
