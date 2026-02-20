import base64
import json
import os
import time
import urllib.error
import urllib.request

import boto3
import pytest
from botocore.exceptions import ClientError


def _rand_suffix(n: int = 8) -> str:
    import secrets
    import string

    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _basic_auth_header(username: str, password: str) -> str:
    userpass = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(userpass).decode('ascii')}"


def _http_post(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int = 30,
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return int(resp.status), dict(resp.headers.items()), raw
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            pass
        return int(e.code), dict(e.headers.items()) if e.headers else {}, raw


def _maybe_json(raw: str) -> dict | None:
    s = (raw or "").strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _session_from_creds(creds: dict, *, region: str) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
        region_name=region,
    )


def _queue_url_from_arn(queue_arn: str) -> str:
    parts = (queue_arn or "").split(":")
    if len(parts) < 6:
        raise ValueError(f"unexpected SQS queue ARN: {queue_arn}")
    region = parts[3]
    account_id = parts[4]
    queue_name = parts[5]
    return f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"


def _assert_access_denied(exc: Exception) -> None:
    if isinstance(exc, ClientError):
        code = (exc.response.get("Error") or {}).get("Code") or ""
        if "AccessDenied" in code:
            return
        msg = (exc.response.get("Error") or {}).get("Message") or ""
        if "not authorized" in msg.lower() or "access denied" in msg.lower():
            return
    raise AssertionError(f"expected AccessDenied, got: {exc!r}")


def _expected_agent_workshop_account() -> str:
    return (os.environ.get("SYSTEM_EXPECT_AGENT_WORKSHOP_ACCOUNT_ID") or "").strip()


def _require_agent_workshop_provisioning_set(payload: dict, *, expected_account_id: str) -> dict:
    agent_set = (payload.get("credentialSets") or {}).get("agentAWSWorkshopProvisioning")
    if not isinstance(agent_set, dict):
        if expected_account_id:
            raise AssertionError(
                "expected credentialSets.agentAWSWorkshopProvisioning to be present, but it was missing"
            )
        pytest.skip(
            "stack is not configured for AgentAWSWorkshop credential sets "
            "(set SYSTEM_EXPECT_AGENT_WORKSHOP_ACCOUNT_ID to require these assertions)"
        )

    if expected_account_id:
        assert agent_set.get("accountId") == expected_account_id
    else:
        assert agent_set.get("accountId")
    return agent_set


def test_credentials_contract_includes_agent_workshop_credential_set(
    system_env,
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    expected_agent_workshop_account = _expected_agent_workshop_account()

    user = system_user_factory()
    seeded = system_seed_profile_factory(user, groups=["system-it"], credential_scope="runtime")

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 200, raw

    payload = json.loads(raw)

    assert payload.get("kind") == "agent-enablement.credentials.v2"
    assert payload.get("schemaVersion")
    assert payload.get("principal", {}).get("sub") == user.sub
    ct = payload.get("cognitoTokens")
    assert isinstance(ct, dict)
    assert ct.get("idToken")
    assert ct.get("accessToken")
    assert ct.get("refreshToken")
    assert "RefreshToken" not in ct
    assert payload.get("references", {}).get("cognito", {}).get("issuer") == payload.get(
        "principal", {}
    ).get("issuer")

    assert payload.get("credentials", {}).get("accessKeyId")
    assert payload.get("references", {}).get("s3", {}).get("bucket") == system_stack_outputs.upload_bucket

    cred_sets = payload.get("credentialSets")
    assert isinstance(cred_sets, dict)
    enablement_set = cred_sets.get("agentEnablement")
    assert isinstance(enablement_set, dict)
    assert enablement_set["credentials"]["accessKeyId"] == payload["credentials"]["accessKeyId"]

    agent_set = _require_agent_workshop_provisioning_set(
        payload, expected_account_id=expected_agent_workshop_account
    )
    assert agent_set.get("credentialScope") == "provisioning"

    prov_refs = (agent_set.get("references") or {}).get("provisioning") or {}
    assert prov_refs.get("cfnExecutionRoleArn")
    assert prov_refs.get("requiredRoleBoundaryArn")

    # Basic messages references should point at the seeded inbox.
    assert payload.get("references", {}).get("messages", {}).get("inboxQueueUrl") == seeded.inbox_queue_url


def test_credentials_missing_api_key_is_forbidden(system_stack_outputs, system_user_factory):
    headers = {
        # API Gateway rejects the request before invoking Lambda when the API key is missing,
        # so these credentials do not need to exist.
        "authorization": _basic_auth_header("user", "pass"),
        # Intentionally omit x-api-key
    }
    status, _resp_headers, _raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 403


def test_credentials_missing_basic_auth_is_unauthorized(system_stack_outputs, system_shared_api_key):
    headers = {
        "x-api-key": system_shared_api_key,
        # Intentionally omit Basic auth
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 401

    payload = _maybe_json(raw)
    assert isinstance(payload, dict)
    assert payload.get("errorCode") == "UNAUTHORIZED"


def test_credentials_wrong_password_is_unauthorized(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
):
    user = system_user_factory()

    headers = {
        "authorization": _basic_auth_header(user.username, "wrong-password"),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 401

    payload = _maybe_json(raw)
    assert isinstance(payload, dict)
    assert payload.get("errorCode") == "UNAUTHORIZED"


def test_credentials_profile_not_found(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
):
    user = system_user_factory()

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 404

    payload = _maybe_json(raw)
    assert isinstance(payload, dict)
    assert payload.get("errorCode") == "PROFILE_NOT_FOUND"


def test_credentials_profile_disabled(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    user = system_user_factory()
    system_seed_profile_factory(user, enabled=False)

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 403

    payload = _maybe_json(raw)
    assert isinstance(payload, dict)
    assert payload.get("errorCode") == "UNAUTHORIZED"


def test_sandbox_runtime_permissions_allow_and_deny(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    user = system_user_factory()
    system_seed_profile_factory(user, groups=["system-it"])

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 200, raw
    payload = json.loads(raw)

    runtime_region = (
        payload.get("references", {}).get("awsRegion")
        or os.environ.get("AWS_REGION")
        or os.environ.get("SYSTEM_AWS_REGION")
        or ""
    ).strip()
    assert runtime_region
    runtime_sess = _session_from_creds(payload["credentials"], region=runtime_region)

    # Allowed: S3 PutObject within the issued ID prefix.
    prefix = payload["references"]["s3"]["allowedPrefix"]
    key = f"{prefix}system-test.txt"
    runtime_sess.client("s3").put_object(
        Bucket=system_stack_outputs.upload_bucket,
        Key=key,
        Body=b"hello-system",
    )

    # Allowed: SQS SendMessage to the shared queue.
    queue_url = _queue_url_from_arn(payload["references"]["sqs"]["queueArn"])
    out = runtime_sess.client("sqs").send_message(QueueUrl=queue_url, MessageBody="system")
    assert out.get("MessageId")

    # Allowed: EventBridge PutEvents with restricted Source/DetailType.
    sub = payload["principal"]["sub"]
    bus_arn = payload["references"]["eventbridge"]["eventBusArn"]
    out = runtime_sess.client("events").put_events(
        Entries=[
            {
                "EventBusName": bus_arn,
                "Source": f"agents.messages.sub.{sub}",
                "DetailType": "agent.message.v2",
                "Detail": json.dumps({"toUsername": "nobody", "kind": "text.v1", "message": {"ok": True}}),
            }
        ]
    )
    assert out.get("FailedEntryCount") == 0

    # Denied: broad account enumeration.
    with pytest.raises(Exception):
        runtime_sess.client("s3").list_buckets()
    with pytest.raises(Exception):
        runtime_sess.client("sqs").list_queues()

    # Denied: invalid EventBridge source.
    with pytest.raises(Exception) as excinfo:
        runtime_sess.client("events").put_events(
            Entries=[
                {
                    "EventBusName": bus_arn,
                    "Source": "agents.messages",
                    "DetailType": "agent.message.v2",
                    "Detail": json.dumps({"toUsername": "nobody", "kind": "text.v1", "message": {"ok": False}}),
                }
            ]
        )
    _assert_access_denied(excinfo.value)


def test_eventbridge_direct_message_routes_to_inbox(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    user = system_user_factory()
    seeded = system_seed_profile_factory(user)

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 200, raw
    payload = json.loads(raw)

    runtime_region = (
        payload.get("references", {}).get("awsRegion")
        or os.environ.get("AWS_REGION")
        or os.environ.get("SYSTEM_AWS_REGION")
        or ""
    ).strip()
    assert runtime_region
    runtime_sess = _session_from_creds(payload["credentials"], region=runtime_region)

    ev = runtime_sess.client("events")
    sqs = runtime_sess.client("sqs")

    agent_id = seeded.agent_id
    sender_sub = payload["principal"]["sub"]
    bus_arn = payload["references"]["messages"]["eventBusArn"]
    inbox_url = payload["references"]["messages"]["inboxQueueUrl"]

    out = ev.put_events(
        Entries=[
            {
                "EventBusName": bus_arn,
                "Source": f"agents.messages.sub.{sender_sub}",
                "DetailType": "agent.message.v2",
                "Detail": json.dumps(
                    {
                        "toUsername": agent_id,
                        "kind": "json.v1",
                        "message": {"kind": "system", "ok": True},
                    }
                ),
            }
        ]
    )
    assert out.get("FailedEntryCount") == 0

    deadline = time.time() + 45
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

        payload2 = json.loads(msgs[0]["Body"])
        assert payload2["toUsername"] == agent_id
        assert payload2["senderUsername"] == agent_id
        assert payload2["message"]["kind"] == "system"

        sqs.delete_message(QueueUrl=inbox_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
        return

    raise AssertionError("timed out waiting for routed message")


def test_agent_workshop_provisioning_creds_can_create_and_delete_stack(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    expected_agent_workshop_account = _expected_agent_workshop_account()

    user = system_user_factory()
    system_seed_profile_factory(user)

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 200, raw
    payload = json.loads(raw)

    agent_set = _require_agent_workshop_provisioning_set(
        payload, expected_account_id=expected_agent_workshop_account
    )
    agent_region = agent_set.get("awsRegion") or agent_set.get("references", {}).get("awsRegion")
    assert agent_region

    agent_sess = _session_from_creds(agent_set["credentials"], region=agent_region)

    # Basic sanity check that the creds really land in the expected account.
    ident = agent_sess.client("sts").get_caller_identity()
    if expected_agent_workshop_account:
        assert ident.get("Account") == expected_agent_workshop_account
    else:
        assert ident.get("Account") == agent_set.get("accountId")

    cfn_role_arn = agent_set["references"]["provisioning"]["cfnExecutionRoleArn"]
    sub = payload["principal"]["sub"]
    username = payload["principal"]["username"]

    stack_name = f"agent-{sub}-systemtest-{_rand_suffix(6)}"
    template_body = """AWSTemplateFormatVersion: '2010-09-09'
Description: agent-workshop system test
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
"""

    cfn = agent_sess.client("cloudformation")

    keep_stacks = (os.environ.get("SYSTEM_KEEP_AGENT_WORKSHOP_STACKS") or "").strip() == "1"

    created = False
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            RoleARN=cfn_role_arn,
            Tags=[
                {"Key": "agent_sub", "Value": sub},
                {"Key": "agent_username", "Value": username},
            ],
        )
        created = True

        waiter = cfn.get_waiter("stack_create_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 30})

        # Ensure the stack is real.
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert desc["StackStatus"] == "CREATE_COMPLETE"
    finally:
        if created and not keep_stacks:
            try:
                cfn.delete_stack(StackName=stack_name, RoleARN=cfn_role_arn)
                dw = cfn.get_waiter("stack_delete_complete")
                dw.wait(StackName=stack_name, WaiterConfig={"Delay": 10, "MaxAttempts": 30})
            except Exception:
                pass


def test_agent_workshop_provisioning_guardrails_reject_invalid_requests(
    system_stack_outputs,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    expected_agent_workshop_account = _expected_agent_workshop_account()

    user = system_user_factory()
    system_seed_profile_factory(user)

    headers = {
        "authorization": _basic_auth_header(user.username, user.password),
        "x-api-key": system_shared_api_key,
    }
    status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
    assert status == 200, raw
    payload = json.loads(raw)

    agent_set = _require_agent_workshop_provisioning_set(
        payload, expected_account_id=expected_agent_workshop_account
    )
    agent_region = agent_set.get("awsRegion") or agent_set.get("references", {}).get("awsRegion")
    assert agent_region

    agent_sess = _session_from_creds(agent_set["credentials"], region=agent_region)
    cfn = agent_sess.client("cloudformation")

    cfn_role_arn = agent_set["references"]["provisioning"]["cfnExecutionRoleArn"]
    sub = payload["principal"]["sub"]
    username = payload["principal"]["username"]

    template_body = """AWSTemplateFormatVersion: '2010-09-09'
Description: agent-workshop negative system test
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
"""

    # 1) Stack name must match agent-<sub>-*
    bad_name = f"agent-NOT{sub}-bad-{_rand_suffix(6)}"
    with pytest.raises(Exception) as excinfo:
        cfn.create_stack(
            StackName=bad_name,
            TemplateBody=template_body,
            RoleARN=cfn_role_arn,
            Tags=[
                {"Key": "agent_sub", "Value": sub},
                {"Key": "agent_username", "Value": username},
            ],
        )
    _assert_access_denied(excinfo.value)

    # 2) Request tags are required.
    good_name = f"agent-{sub}-missing-tags-{_rand_suffix(6)}"
    with pytest.raises(Exception) as excinfo:
        cfn.create_stack(
            StackName=good_name,
            TemplateBody=template_body,
            RoleARN=cfn_role_arn,
            Tags=[],
        )
    _assert_access_denied(excinfo.value)

    # 3) RoleArn must be the referenced execution role.
    good_name2 = f"agent-{sub}-missing-role-{_rand_suffix(6)}"
    wrong_role_arn = f"arn:aws:iam::{cfn_role_arn.split(':')[4]}:role/OrganizationAccountAccessRole"
    with pytest.raises(Exception) as excinfo:
        cfn.create_stack(
            StackName=good_name2,
            TemplateBody=template_body,
            # Intentionally pass the wrong role; the provisioning creds should not be able to PassRole it.
            RoleARN=wrong_role_arn,
            Tags=[
                {"Key": "agent_sub", "Value": sub},
                {"Key": "agent_username", "Value": username},
            ],
        )
    _assert_access_denied(excinfo.value)

    # 4) Non-CFN calls should be denied.
    with pytest.raises(Exception) as excinfo:
        agent_sess.client("s3").list_buckets()
    _assert_access_denied(excinfo.value)
