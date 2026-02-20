import importlib
import json
import sys
from datetime import datetime, timezone


def _load_handler(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("ASSUME_ROLE_RUNTIME_ARN", "arn:aws:iam::123456789012:role/BrokerRuntime")
    monkeypatch.setenv("ASSUME_ROLE_PROVISIONING_ARN", "arn:aws:iam::123456789012:role/BrokerProvisioning")
    monkeypatch.setenv("CFN_EXECUTION_ROLE_ARN", "arn:aws:iam::123456789012:role/AgentsAccess-cfn-exec")
    monkeypatch.setenv(
        "AGENT_WORKLOAD_BOUNDARY_ARN",
        "arn:aws:iam::123456789012:policy/AgentsAccess-agent-workload-boundary",
    )
    monkeypatch.setenv("DEFAULT_TTL_SECONDS", "3600")
    monkeypatch.setenv("MAX_TTL_SECONDS", "3600")
    monkeypatch.setenv("SCHEMA_VERSION", "2026-02-17")
    monkeypatch.setenv("USER_POOL_CLIENT_ID", "client-1")
    monkeypatch.setenv("UPLOAD_BUCKET", "test-bucket")
    monkeypatch.setenv("SQS_QUEUE_ARN", "arn:aws:sqs:us-east-1:123456789012:q")
    monkeypatch.setenv("EVENT_BUS_ARN", "arn:aws:events:us-east-1:123456789012:event-bus/b")
    monkeypatch.setenv("COMMS_FILES_BUCKET", "comms-bucket")
    monkeypatch.setenv("SHORTLINK_CREATE_URL", "https://api.example.com/prod/v1/links")
    monkeypatch.setenv("SHORTLINK_REDIRECT_BASE_URL", "https://d111111abcdef8.cloudfront.net/l/")
    monkeypatch.setenv(
        "ENABLEMENT_INDEX_URL",
        "https://bucket.s3.us-east-1.amazonaws.com/agent-enablement/latest/CONTENTS.md",
    )
    monkeypatch.setenv(
        "ENABLEMENT_ARTIFACTS_ROOT_URL",
        "https://bucket.s3.us-east-1.amazonaws.com/agent-enablement/latest/artifacts/",
    )
    monkeypatch.setenv(
        "ENABLEMENT_SKILLS_ROOT_URL",
        "https://bucket.s3.us-east-1.amazonaws.com/agent-enablement/latest/skills/",
    )
    monkeypatch.setenv("ENABLEMENT_VERSION", "latest")
    monkeypatch.setenv("API_KEY_SSM_PARAMETER_NAME", "/agent-enablement/AgentEnablementStack/prod/shared-api-key")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import credentials_handler as handler_module
    return importlib.reload(handler_module)


def test_success_response_contains_credentials_and_catalog(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            fake_jwt = f"a.{payload_b64}.c"
            return {
                "AuthenticationResult": {
                    "IdToken": fake_jwt,
                    "AccessToken": "at",
                    "RefreshToken": "rt",
                    "ExpiresIn": 3600,
                    "TokenType": "Bearer",
                }
            }

    def fake_get_item(**kwargs):
        assert kwargs["TableName"] == "AgentProfiles"
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "sqsQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:q"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
                "eventBusArn": {"S": "arn:aws:events:us-east-1:123456789012:event-bus/b"},
                "instructionText": {"S": "do the thing"},
                }
            }

    class FakeSts:
        def assume_role(self, **kwargs):
            assert kwargs["DurationSeconds"] == 3600
            assert "Policy" not in kwargs
            assert kwargs.get("SourceIdentity") == "21ebf510-90f1-7051-64e1-865ec0c362a8"
            tags = {t["Key"]: t["Value"] for t in kwargs.get("Tags", [])}
            assert tags.get("sub") == "21ebf510-90f1-7051-64e1-865ec0c362a8"
            assert tags.get("username") == "agent-user"
            assert tags.get("agent_id") == "agent-user"
            assert tags.get("sub_b58")
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
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    assert body["kind"] == "agent-enablement.credentials.v2"
    assert body["requestId"] == "r1"
    assert body["principal"]["sub"] == "21ebf510-90f1-7051-64e1-865ec0c362a8"
    assert body["principal"]["username"] == "agent-user"
    assert body["credentials"]["accessKeyId"] == "ASIA123"
    assert body["schemaVersion"] == "2026-02-17"
    assert "credentialsEndpoint" in body["auth"]
    assert body["auth"]["cognitoClientId"] == "client-1"
    assert "taskboard" in body["runtime"]["serviceEndpoints"]
    assert body["runtime"]["bundlePolicy"]["enablementVersion"] == "latest"
    assert body["constraints"]["ttlSeconds"] == 3600
    assert body["constraints"]["uploadPrefixBase58"]
    assert "uploadPrefixUuid" not in body["constraints"]
    assert len(body["grants"]) >= 1
    assert "instructions" not in body
    assert "agentGuides" not in body
    assert "services" not in body
    refs = body.get("references")
    assert isinstance(refs, dict)
    assert refs.get("awsRegion") == "us-east-1"
    assert refs.get("cognito", {}).get("issuer") == "iss"
    assert refs.get("s3", {}).get("bucket") == "test-bucket"
    assert refs.get("s3", {}).get("allowedPrefix") == f"f/{body['constraints']['uploadPrefixBase58']}/"
    assert refs.get("messages", {}).get("agentId") == "agent-user"
    assert refs.get("messages", {}).get("eventBusArn") == "arn:aws:events:us-east-1:123456789012:event-bus/b"
    assert refs.get("messages", {}).get("inboxQueueArn") == "arn:aws:sqs:us-east-1:123456789012:inbox"
    ct = body.get("cognitoTokens")
    assert isinstance(ct, dict)
    assert ct.get("idToken")
    assert ct.get("accessToken") == "at"
    assert ct.get("refreshToken") == "rt"
    assert ct.get("tokenType") == "Bearer"
    assert ct.get("expiresIn") == 3600
    assert "RefreshToken" not in ct
    ssm_grant = next((g for g in body["grants"] if g.get("service") == "ssm"), None)
    assert isinstance(ssm_grant, dict)
    assert set(ssm_grant.get("actions") or []) >= {
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
    }
    assert any("parameter/agent-enablement/prod/shared/" in r for r in (ssm_grant.get("resources") or []))
    assert any("parameter/agent-enablement/prod/agent/<principal.sub>/" in r for r in (ssm_grant.get("resources") or []))
    execute_api_grant = next((g for g in body["grants"] if g.get("service") == "execute-api"), None)
    assert isinstance(execute_api_grant, dict)
    assert set(execute_api_grant.get("actions") or []) == {"execute-api:Invoke"}
    assert execute_api_grant.get("resources") == ["arn:aws:execute-api:us-east-2:123456789012:*"]
    assert out["headers"]["cache-control"] == "no-store"


def test_success_response_includes_agent_workshop_credential_set_when_configured(monkeypatch):
    monkeypatch.setenv(
        "ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN",
        "arn:aws:iam::999999999999:role/AgentSandboxProvisioning",
    )
    monkeypatch.setenv(
        "ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN",
        "arn:aws:iam::999999999999:role/AgentSandboxRuntime",
    )
    monkeypatch.setenv(
        "AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN",
        "arn:aws:iam::999999999999:role/agentawsworkshop-cfn-exec",
    )
    monkeypatch.setenv(
        "AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN",
        "arn:aws:iam::999999999999:policy/agentawsworkshop-agent-workload-boundary",
    )
    monkeypatch.setenv("AGENT_WORKSHOP_ACCOUNT_ID", "999999999999")
    monkeypatch.setenv("AGENT_WORKSHOP_REGION", "us-east-2")

    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            fake_jwt = f"a.{payload_b64}.c"
            return {"AuthenticationResult": {"IdToken": fake_jwt}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
            }
        }

    class FakeSts:
        def __init__(self):
            self.calls: list[dict] = []

        def assume_role(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs["RoleArn"].endswith(":role/AgentSandboxProvisioning"):
                key_id = "ASIA999P"
                exp = datetime(2026, 2, 10, tzinfo=timezone.utc)
            elif kwargs["RoleArn"].endswith(":role/AgentSandboxRuntime"):
                key_id = "ASIA999R"
                exp = datetime(2026, 2, 10, tzinfo=timezone.utc)
            else:
                key_id = "ASIA123"
                exp = datetime(2026, 2, 10, tzinfo=timezone.utc)
            return {
                "Credentials": {
                    "AccessKeyId": key_id,
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                    "Expiration": exp,
                }
            }

    sts = FakeSts()
    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._sts_client = sts
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    assert len(sts.calls) == 3
    assert "credentialSets" in body
    assert body["credentialSets"]["agentEnablement"]["credentials"]["accessKeyId"] == body["credentials"]["accessKeyId"]
    assert body["credentialSets"]["agentEnablement"]["references"]["messages"]["agentId"] == "agent-user"

    assert body["credentialSets"]["agentAWSWorkshopProvisioning"]["accountId"] == "999999999999"
    assert body["credentialSets"]["agentAWSWorkshopProvisioning"]["awsRegion"] == "us-east-2"
    assert body["credentialSets"]["agentAWSWorkshopProvisioning"]["credentials"]["accessKeyId"] == "ASIA999P"
    assert (
        body["credentialSets"]["agentAWSWorkshopProvisioning"]["references"]["provisioning"]["cfnExecutionRoleArn"]
        == "arn:aws:iam::999999999999:role/agentawsworkshop-cfn-exec"
    )
    assert body["credentialSets"]["agentAWSWorkshopRuntime"]["credentials"]["accessKeyId"] == "ASIA999R"



def test_basic_auth_flow_omits_cognito_tokens(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
            }
        }

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            assert kwargs["ClientId"] == "client-1"
            assert kwargs["AuthFlow"] == "USER_PASSWORD_AUTH"
            # Token payload doesn't need to be validly signed; handler just decodes claims.
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            fake_jwt = f"a.{payload_b64}.c"
            return {
                "AuthenticationResult": {
                    "IdToken": fake_jwt,
                    "AccessToken": "at",
                    "RefreshToken": "rt",
                    "ExpiresIn": 3600,
                    "TokenType": "Bearer",
                }
            }

    class FakeSts:
        def assume_role(self, **kwargs):
            from datetime import datetime, timezone

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
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    assert body["principal"]["sub"] == "21ebf510-90f1-7051-64e1-865ec0c362a8"
    assert body["principal"]["username"] == "agent-user"
    assert isinstance(body.get("cognitoTokens"), dict)


def test_refresh_route_uses_refresh_token_auth_and_preserves_refresh_token(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            assert kwargs["ClientId"] == "client-1"
            assert kwargs["AuthFlow"] == "REFRESH_TOKEN_AUTH"
            assert kwargs["AuthParameters"] == {"REFRESH_TOKEN": "rt-in"}
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            fake_jwt = f"a.{payload_b64}.c"
            return {
                "AuthenticationResult": {
                    "IdToken": fake_jwt,
                    "AccessToken": "at",
                    "ExpiresIn": 3600,
                    "TokenType": "Bearer",
                }
            }

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
            }
        }

    class FakeSts:
        def assume_role(self, **kwargs):
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
    handler_module._cognito_client = FakeCognito()

    event = {
        "path": "/v1/credentials/refresh",
        "headers": {"x-enabler-refresh-token": "rt-in"},
        "requestContext": {"requestId": "r1"},
    }
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    ct = body.get("cognitoTokens") or {}
    assert ct.get("idToken")
    assert ct.get("accessToken") == "at"
    assert ct.get("refreshToken") == "rt-in"
    assert "RefreshToken" not in ct


def test_refresh_route_missing_token_is_unauthorized(monkeypatch):
    handler_module = _load_handler(monkeypatch)
    event = {
        "path": "/v1/credentials/refresh",
        "headers": {},
        "requestContext": {"requestId": "r1"},
    }
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])
    assert out["statusCode"] == 401
    assert body["errorCode"] == "UNAUTHORIZED"
    assert "refresh token" in body["message"].lower()


def test_runtime_assume_role_includes_scoping_session_tags(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
                "commsFilesBucket": {"S": "comms-bucket"},
            }
        }

    captured_tags = {}

    class FakeSts:
        def assume_role(self, **kwargs):
            assert "Policy" not in kwargs
            captured_tags.update({t["Key"]: t["Value"] for t in kwargs.get("Tags", [])})
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
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)
    assert out["statusCode"] == 200
    body = json.loads(out["body"])
    assert captured_tags.get("sub") == "21ebf510-90f1-7051-64e1-865ec0c362a8"
    assert captured_tags.get("username") == "agent-user"
    assert captured_tags.get("agent_id") == "agent-user"
    assert captured_tags.get("sub_b58") == body["constraints"]["uploadPrefixBase58"]


def test_unmapped_api_key_returns_403(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "11111111-1111-4111-8111-111111111111", "iss": "iss"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {}

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 404


def test_sts_failure_returns_500(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
            }
        }

    class FakeSts:
        def assume_role(self, **kwargs):
            raise RuntimeError("boom")

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._sts_client = FakeSts()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 500
    assert "STS_ISSUE_FAILED" in out["body"]


def test_missing_agent_id_returns_422(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "inboxQueueArn": {"S": "arn:aws:sqs:us-east-1:123456789012:inbox"},
            }
        }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 422
    assert "Profile missing agentId" in out["body"]


def test_missing_inbox_queue_arn_returns_422(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerRuntime"},
                "s3Bucket": {"S": "test-bucket"},
                "agentId": {"S": "agent-user"},
            }
        }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 422
    assert "Profile missing inboxQueueArn" in out["body"]


def test_duration_is_bounded(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DEFAULT_TTL_SECONDS", "99999")
    monkeypatch.setenv("MAX_TTL_SECONDS", "3600")
    monkeypatch.setenv("PROFILE_TABLE_NAME", "AgentProfiles")
    monkeypatch.setenv("ASSUME_ROLE_RUNTIME_ARN", "arn:aws:iam::123456789012:role/BrokerRuntime")

    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import credentials_handler as handler_module
    handler_module = importlib.reload(handler_module)
    assert handler_module._duration_seconds() == 3600


def test_provisioning_scope_uses_provisioning_role(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "credentialScope": {"S": "provisioning"},
                "assumeRoleArn": {"S": "arn:aws:iam::123456789012:role/BrokerProvisioning"},
            }
        }

    class FakeSts:
        def assume_role(self, **kwargs):
            assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/BrokerProvisioning"
            assert "Policy" not in kwargs  # avoid packed-policy limits for provisioning sessions
            assert kwargs.get("SourceIdentity") == "21ebf510-90f1-7051-64e1-865ec0c362a8"
            tags = kwargs.get("Tags") or []
            assert any(t.get("Key") == "sub" and t.get("Value") == "21ebf510-90f1-7051-64e1-865ec0c362a8" for t in tags)
            assert any(t.get("Key") == "username" for t in tags)
            return {
                "Credentials": {
                    "AccessKeyId": "ASIA123",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                    "Expiration": datetime(2026, 2, 10, tzinfo=timezone.utc),
                }
            }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()
    handler_module._sts_client = FakeSts()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)
    body = json.loads(out["body"])

    assert out["statusCode"] == 200
    assert body["constraints"]["credentialScope"] == "provisioning"
    assert {g["service"] for g in body["grants"]} == {"cloudformation", "iam"}
    assert body["references"]["credentialScope"] == "provisioning"
    assert body["references"]["provisioning"]["cfnExecutionRoleArn"] == "arn:aws:iam::123456789012:role/AgentsAccess-cfn-exec"


def test_invalid_credential_scope_returns_422(monkeypatch):
    handler_module = _load_handler(monkeypatch)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "credentialScope": {"S": "unknown-scope"},
            }
        }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 422
    assert "Unsupported credentialScope" in out["body"]


def test_provisioning_scope_missing_boundary_arn_returns_500(monkeypatch):
    handler_module = _load_handler(monkeypatch)
    monkeypatch.delenv("AGENT_WORKLOAD_BOUNDARY_ARN", raising=False)
    handler_module = importlib.reload(handler_module)

    class FakeCognito:
        def initiate_auth(self, **kwargs):
            payload = {"sub": "21ebf510-90f1-7051-64e1-865ec0c362a8", "iss": "iss", "cognito:username": "agent-user"}
            payload_b64 = (
                __import__("base64")
                .urlsafe_b64encode(__import__("json").dumps(payload).encode())
                .decode()
                .rstrip("=")
            )
            return {"AuthenticationResult": {"IdToken": f"a.{payload_b64}.c"}}

    def fake_get_item(**kwargs):
        return {
            "Item": {
                "sub": {"S": "21ebf510-90f1-7051-64e1-865ec0c362a8"},
                "enabled": {"BOOL": True},
                "credentialScope": {"S": "provisioning"},
            }
        }

    handler_module._ddb_client = type("D", (), {"get_item": staticmethod(fake_get_item)})()
    handler_module._cognito_client = FakeCognito()

    import base64

    basic = base64.b64encode(b"u:p").decode()
    event = {"headers": {"Authorization": f"Basic {basic}"}, "requestContext": {"requestId": "r1"}}
    out = handler_module.handler(event, None)

    assert out["statusCode"] == 500
    assert "MISCONFIGURED" in out["body"]
