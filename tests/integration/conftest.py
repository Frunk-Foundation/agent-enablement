import base64
import json
import os
import secrets
import string
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator

import boto3
import pytest


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"missing required env var: {name}")
    return val


def _run(cmd: str, *, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(["bash", "-lc", cmd], env=env, text=True).strip()


def _rand_suffix(n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _password() -> str:
    # Cognito default policy in stack requires: upper, lower, digit, symbol, min length 12.
    return f"It{_rand_suffix(10)}!9aA"  # length >= 14, includes !, digit, upper/lower


def _jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())


@dataclass
class StackOutputs:
    stack_name: str
    credentials_url: str
    links_create_url: str
    user_pool_id: str
    user_pool_client_id: str
    profiles_table: str
    group_members_table: str
    broker_role_arn: str
    upload_bucket: str
    comms_bucket: str
    queue_arn: str
    event_bus_arn: str
    api_key_parameter_name: str


def pytest_collection_modifyitems(config, items):
    if os.environ.get("RUN_INTEGRATION") == "1":
        return
    skip = pytest.mark.skip(reason="integration tests require RUN_INTEGRATION=1")
    for item in items:
        if item.nodeid.startswith("tests/integration/"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def it_env() -> dict[str, str]:
    # Require explicit opt-in.
    if os.environ.get("RUN_INTEGRATION") != "1":
        pytest.skip("set RUN_INTEGRATION=1 to run integration tests")

    # We intentionally rely on the caller to provide AWS_PROFILE/AWS_REGION.
    _require_env("AWS_PROFILE")
    _require_env("AWS_REGION")

    env = os.environ.copy()
    env.setdefault("JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION", "1")
    return env


@pytest.fixture(scope="session")
def stack_name(it_env: dict[str, str]) -> str:
    prefix = it_env.get("IT_STACK_PREFIX", "AgentsAccessIT")
    ts = time.strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{ts}-{_rand_suffix()}"


@pytest.fixture(scope="session")
def deploy_stack(it_env: dict[str, str], stack_name: str) -> StackOutputs:
    # Deploy ephemeral stack.
    env = dict(it_env)
    env["CDK_STACK_NAME"] = stack_name

    _run(f"npx --yes aws-cdk deploy {stack_name} --require-approval never", env=env)

    cfn = boto3.session.Session(profile_name=env["AWS_PROFILE"], region_name=env["AWS_REGION"]).client(
        "cloudformation"
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}

    return StackOutputs(
        stack_name=stack_name,
        credentials_url=outputs["CredentialsInvokeUrl"],
        links_create_url=outputs["LinksCreateInvokeUrl"],
        user_pool_id=outputs["UserPoolId"],
        user_pool_client_id=outputs["UserPoolClientId"],
        profiles_table=outputs["AgentProfilesTableName"],
        group_members_table=outputs["AgentGroupMembersTableName"],
        broker_role_arn=outputs["BrokerTargetRoleArn"],
        upload_bucket=outputs["UploadBucketName"],
        comms_bucket=outputs["CommsSharedBucketName"],
        queue_arn=outputs["QueueArn"],
        event_bus_arn=outputs["EventBusArn"],
        api_key_parameter_name=outputs["ApiKeyParameterName"],
    )


@pytest.fixture(scope="session")
def shared_api_key(it_env: dict[str, str], deploy_stack: StackOutputs) -> str:
    sess = boto3.session.Session(profile_name=it_env["AWS_PROFILE"], region_name=it_env["AWS_REGION"])
    ssm = sess.client("ssm")
    out = ssm.get_parameter(Name=deploy_stack.api_key_parameter_name, WithDecryption=True)
    return out["Parameter"]["Value"]


@pytest.fixture(scope="session")
def cognito_user(it_env: dict[str, str], deploy_stack: StackOutputs) -> dict[str, str]:
    sess = boto3.session.Session(profile_name=it_env["AWS_PROFILE"], region_name=it_env["AWS_REGION"]) 
    cognito = sess.client("cognito-idp")

    username_prefix = it_env.get("IT_USERNAME_PREFIX", "agent-it")
    username = f"{username_prefix}-{_rand_suffix(10)}"
    password = it_env.get("IT_PASSWORD", _password())

    cognito.admin_create_user(
        UserPoolId=deploy_stack.user_pool_id,
        Username=username,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=deploy_stack.user_pool_id,
        Username=username,
        Password=password,
        Permanent=True,
    )

    return {"username": username, "password": password}


@pytest.fixture(scope="session")
def id_token(it_env: dict[str, str], deploy_stack: StackOutputs, cognito_user: dict[str, str]) -> str:
    sess = boto3.session.Session(profile_name=it_env["AWS_PROFILE"], region_name=it_env["AWS_REGION"]) 
    cognito = sess.client("cognito-idp")

    resp = cognito.initiate_auth(
        ClientId=deploy_stack.user_pool_client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": cognito_user["username"],
            "PASSWORD": cognito_user["password"],
        },
    )
    return resp["AuthenticationResult"]["IdToken"]


@pytest.fixture(scope="session")
def subject_sub(id_token: str) -> str:
    claims = _jwt_claims(id_token)
    return claims["sub"]


@pytest.fixture(scope="session")
def seed_profile(it_env: dict[str, str], deploy_stack: StackOutputs, subject_sub: str) -> dict[str, str]:
    sess = boto3.session.Session(profile_name=it_env["AWS_PROFILE"], region_name=it_env["AWS_REGION"]) 
    ddb = sess.client("dynamodb")
    sqs = sess.client("sqs")

    inbox_name = f"agent-inbox-it-{_rand_suffix(8)}"
    inbox_url = sqs.create_queue(QueueName=inbox_name)["QueueUrl"]
    # Required by runtime guardrails: inbox access is authorized by queue tags.
    sqs.tag_queue(QueueUrl=inbox_url, Tags={"agent_sub": subject_sub})
    inbox_arn = sqs.get_queue_attributes(
        QueueUrl=inbox_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    ddb.put_item(
        TableName=deploy_stack.profiles_table,
        Item={
            "sub": {"S": subject_sub},
            "enabled": {"BOOL": True},
            "assumeRoleArn": {"S": deploy_stack.broker_role_arn},
            "agentId": {"S": "agent-it"},
            "groups": {"SS": ["it-group"]},
            "s3Bucket": {"S": deploy_stack.upload_bucket},
            "commsFilesBucket": {"S": deploy_stack.comms_bucket},
            "sqsQueueArn": {"S": deploy_stack.queue_arn},
            "inboxQueueArn": {"S": inbox_arn},
            "inboxQueueUrl": {"S": inbox_url},
            "eventBusArn": {"S": deploy_stack.event_bus_arn},
            "instructionText": {"S": "integration test profile"},
        },
    )
    ddb.put_item(
        TableName=deploy_stack.group_members_table,
        Item={
            "groupId": {"S": "it-group"},
            "agentId": {"S": "agent-it"},
            "sub": {"S": subject_sub},
            "enabled": {"BOOL": True},
            "inboxQueueUrl": {"S": inbox_url},
        },
    )
    return {"inboxQueueUrl": inbox_url}


@pytest.fixture(scope="session")
def credentials_json(
    seed_profile: dict[str, str],
    deploy_stack: StackOutputs,
    cognito_user: dict[str, str],
    shared_api_key: str,
) -> dict[str, Any]:
    import urllib.request

    userpass = f"{cognito_user['username']}:{cognito_user['password']}".encode("utf-8")
    b64 = base64.b64encode(userpass).decode("ascii")

    req = urllib.request.Request(
        deploy_stack.credentials_url,
        headers={"Authorization": f"Basic {b64}", "x-api-key": shared_api_key},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


@pytest.fixture(scope="session")
def issued_session(it_env: dict[str, str], credentials_json: dict[str, Any]) -> boto3.session.Session:
    creds = credentials_json["credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
        region_name=it_env["AWS_REGION"],
    )


@pytest.fixture(scope="session", autouse=True)
def teardown(
    it_env: dict[str, str],
    deploy_stack: StackOutputs,
    cognito_user: dict[str, str],
    seed_profile: dict[str, str],
    request,
) -> Iterator[None]:
    yield

    # Best-effort cleanup.
    sess = boto3.session.Session(profile_name=it_env["AWS_PROFILE"], region_name=it_env["AWS_REGION"]) 

    try:
        sess.client("cognito-idp").admin_delete_user(
            UserPoolId=deploy_stack.user_pool_id,
            Username=cognito_user["username"],
        )
    except Exception:
        pass
    try:
        sess.client("sqs").delete_queue(QueueUrl=seed_profile["inboxQueueUrl"])
    except Exception:
        pass

    destroy_on_success = it_env.get("IT_DESTROY_ON_SUCCESS", "1") == "1"
    destroy_on_failure = it_env.get("IT_DESTROY_ON_FAILURE", "1") == "1"

    failed = request.session.testsfailed > 0
    if (failed and not destroy_on_failure) or ((not failed) and not destroy_on_success):
        return

    env = dict(it_env)
    env["CDK_STACK_NAME"] = deploy_stack.stack_name
    try:
        _run(f"npx --yes aws-cdk destroy {deploy_stack.stack_name} --force", env=env)
    except Exception:
        pass
