import base64
import json
import os
import re
import secrets
import string
from dataclasses import dataclass
from typing import Any, Callable, Iterator

import boto3
import pytest


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"missing required env var: {name}")
    return val


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


def pytest_collection_modifyitems(config, items):
    if os.environ.get("RUN_SYSTEM") == "1":
        return
    skip = pytest.mark.skip(reason="system tests require RUN_SYSTEM=1")
    for item in items:
        if item.nodeid.startswith("tests/system/"):
            item.add_marker(skip)


@dataclass(frozen=True)
class SystemEnv:
    aws_profile: str
    aws_region: str
    stack_name: str


@dataclass(frozen=True)
class SystemStackOutputs:
    stack_name: str
    credentials_url: str
    user_pool_id: str
    user_pool_client_id: str
    profiles_table: str
    group_members_table: str
    upload_bucket: str
    comms_bucket: str
    queue_arn: str
    event_bus_arn: str
    api_key_parameter_name: str


@dataclass(frozen=True)
class SystemUser:
    username: str
    password: str
    sub: str


@dataclass(frozen=True)
class SeededProfile:
    user: SystemUser
    agent_id: str
    inbox_queue_url: str
    inbox_queue_arn: str


@pytest.fixture(scope="session")
def system_env() -> SystemEnv:
    # Require explicit opt-in.
    if os.environ.get("RUN_SYSTEM") != "1":
        pytest.skip("set RUN_SYSTEM=1 to run system tests")

    # We intentionally rely on the caller to provide AWS_PROFILE/AWS_REGION.
    aws_profile = (os.environ.get("SYSTEM_AWS_PROFILE") or os.environ.get("AWS_PROFILE") or "").strip()
    aws_region = (os.environ.get("SYSTEM_AWS_REGION") or os.environ.get("AWS_REGION") or "").strip()
    stack_name = (os.environ.get("SYSTEM_STACK_NAME") or os.environ.get("STACK") or "").strip()

    if not aws_profile:
        raise RuntimeError("missing required env var: AWS_PROFILE (or SYSTEM_AWS_PROFILE)")
    if not aws_region:
        raise RuntimeError("missing required env var: AWS_REGION (or SYSTEM_AWS_REGION)")
    if not stack_name:
        raise RuntimeError("missing required env var: SYSTEM_STACK_NAME (or STACK)")

    return SystemEnv(aws_profile=aws_profile, aws_region=aws_region, stack_name=stack_name)


@pytest.fixture(scope="session")
def system_admin_session(system_env: SystemEnv) -> boto3.session.Session:
    return boto3.session.Session(profile_name=system_env.aws_profile, region_name=system_env.aws_region)


@pytest.fixture(scope="session")
def system_stack_outputs(system_admin_session: boto3.session.Session, system_env: SystemEnv) -> SystemStackOutputs:
    cfn = system_admin_session.client("cloudformation")
    desc = cfn.describe_stacks(StackName=system_env.stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}

    def require_output(key: str) -> str:
        val = (outputs.get(key) or "").strip()
        if not val:
            raise RuntimeError(f"missing required CloudFormation output {key} on stack {system_env.stack_name}")
        return val

    return SystemStackOutputs(
        stack_name=system_env.stack_name,
        credentials_url=require_output("CredentialsInvokeUrl"),
        user_pool_id=require_output("UserPoolId"),
        user_pool_client_id=require_output("UserPoolClientId"),
        profiles_table=require_output("AgentProfilesTableName"),
        group_members_table=require_output("AgentGroupMembersTableName"),
        upload_bucket=require_output("UploadBucketName"),
        comms_bucket=require_output("CommsSharedBucketName"),
        queue_arn=require_output("QueueArn"),
        event_bus_arn=require_output("EventBusArn"),
        api_key_parameter_name=require_output("ApiKeyParameterName"),
    )


@pytest.fixture(scope="session")
def system_shared_api_key(system_admin_session: boto3.session.Session, system_stack_outputs: SystemStackOutputs) -> str:
    ssm = system_admin_session.client("ssm")
    out = ssm.get_parameter(Name=system_stack_outputs.api_key_parameter_name, WithDecryption=True)
    return out["Parameter"]["Value"]


@pytest.fixture(scope="session")
def system_user_factory(
    system_admin_session: boto3.session.Session,
    system_stack_outputs: SystemStackOutputs,
) -> Iterator[Callable[..., SystemUser]]:
    cognito = system_admin_session.client("cognito-idp")

    created_usernames: list[str] = []

    def create_user(*, username_prefix: str = "agent-system", password: str | None = None) -> SystemUser:
        username = f"{username_prefix}-{_rand_suffix(10)}"
        pwd = password or _password()

        cognito.admin_create_user(
            UserPoolId=system_stack_outputs.user_pool_id,
            Username=username,
            MessageAction="SUPPRESS",
        )
        cognito.admin_set_user_password(
            UserPoolId=system_stack_outputs.user_pool_id,
            Username=username,
            Password=pwd,
            Permanent=True,
        )
        created_usernames.append(username)

        resp = cognito.initiate_auth(
            ClientId=system_stack_outputs.user_pool_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": pwd},
        )
        id_token = (resp.get("AuthenticationResult") or {}).get("IdToken") or ""
        sub = str(_jwt_claims(id_token).get("sub") or "").strip()
        if not sub:
            raise RuntimeError("failed to extract sub from Cognito IdToken")

        return SystemUser(username=username, password=pwd, sub=sub)

    yield create_user

    # Best-effort cleanup.
    for username in created_usernames:
        try:
            cognito.admin_delete_user(UserPoolId=system_stack_outputs.user_pool_id, Username=username)
        except Exception:
            pass


@pytest.fixture(scope="session")
def system_inbox_factory(system_admin_session: boto3.session.Session) -> Iterator[Callable[[str], dict[str, str]]]:
    sqs = system_admin_session.client("sqs")
    created_queue_urls: list[str] = []

    def create_inbox(agent_id: str) -> dict[str, str]:
        # Match the MessagesRouter lambda policy which only allows sending to agent-inbox-*.
        safe = re.sub(r"[^A-Za-z0-9_-]", "-", (agent_id or "")).strip("-")
        safe = (safe[:40] or _rand_suffix(8))
        queue_name = f"agent-inbox-{safe}-{_rand_suffix(6)}"

        url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

        created_queue_urls.append(url)
        return {"queueName": queue_name, "queueUrl": url, "queueArn": arn}

    yield create_inbox

    for url in created_queue_urls:
        try:
            sqs.delete_queue(QueueUrl=url)
        except Exception:
            pass


@pytest.fixture(scope="session")
def system_seed_profile_factory(
    system_admin_session: boto3.session.Session,
    system_stack_outputs: SystemStackOutputs,
    system_inbox_factory: Callable[[str], dict[str, str]],
) -> Iterator[Callable[..., SeededProfile]]:
    ddb = system_admin_session.client("dynamodb")
    sqs = system_admin_session.client("sqs")

    seeded_subs: set[str] = set()
    seeded_group_members: set[tuple[str, str]] = set()  # (groupId, agentId)

    def seed_profile(
        user: SystemUser,
        *,
        enabled: bool = True,
        credential_scope: str = "runtime",
        agent_id: str | None = None,
        groups: list[str] | None = None,
    ) -> SeededProfile:
        if credential_scope not in {"runtime", "provisioning"}:
            raise ValueError("credential_scope must be runtime or provisioning")

        aid = (agent_id or user.username).strip()
        if not aid:
            raise ValueError("agent_id must be non-empty")

        groups = groups or []

        inbox = system_inbox_factory(aid)
        # Required by runtime guardrails: inbox access is authorized by queue tags.
        sqs.tag_queue(QueueUrl=inbox["queueUrl"], Tags={"agent_sub": user.sub})

        item: dict[str, Any] = {
            "sub": {"S": user.sub},
            "enabled": {"BOOL": bool(enabled)},
            "credentialScope": {"S": credential_scope},
            "agentId": {"S": aid},
            "s3Bucket": {"S": system_stack_outputs.upload_bucket},
            "commsFilesBucket": {"S": system_stack_outputs.comms_bucket},
            "sqsQueueArn": {"S": system_stack_outputs.queue_arn},
            "inboxQueueArn": {"S": inbox["queueArn"]},
            "inboxQueueUrl": {"S": inbox["queueUrl"]},
            "eventBusArn": {"S": system_stack_outputs.event_bus_arn},
            "instructionText": {"S": "system test profile"},
        }
        if groups:
            item["groups"] = {"SS": [g for g in groups if g.strip()]}

        ddb.put_item(TableName=system_stack_outputs.profiles_table, Item=item)
        seeded_subs.add(user.sub)

        for group in [g.strip() for g in groups if g.strip()]:
            ddb.put_item(
                TableName=system_stack_outputs.group_members_table,
                Item={
                    "groupId": {"S": group},
                    "agentId": {"S": aid},
                    "sub": {"S": user.sub},
                    "enabled": {"BOOL": True},
                    "inboxQueueUrl": {"S": inbox["queueUrl"]},
                },
            )
            seeded_group_members.add((group, aid))

        return SeededProfile(
            user=user,
            agent_id=aid,
            inbox_queue_url=inbox["queueUrl"],
            inbox_queue_arn=inbox["queueArn"],
        )

    yield seed_profile

    # Best-effort cleanup.
    for group_id, agent_id in seeded_group_members:
        try:
            ddb.delete_item(
                TableName=system_stack_outputs.group_members_table,
                Key={"groupId": {"S": group_id}, "agentId": {"S": agent_id}},
            )
        except Exception:
            pass

    for sub in seeded_subs:
        try:
            ddb.delete_item(TableName=system_stack_outputs.profiles_table, Key={"sub": {"S": sub}})
        except Exception:
            pass
