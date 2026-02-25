from __future__ import annotations

import argparse
import contextlib
import json
import sys
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

from . import auth_inputs
from .cli_shared import (
    ENABLER_ADMIN_HANDOFF_KIND,
    ENABLER_ADMIN_HANDOFF_SCHEMA_VERSION,
    ENABLER_API_KEY,
    ENABLER_ADMIN_COGNITO_PASSWORD,
    ENABLER_ADMIN_COGNITO_USERNAME,
    ENABLER_COGNITO_PASSWORD,
    ENABLER_COGNITO_USERNAME,
    GlobalOpts,
    OpError,
    UsageError,
    _account_session,
    _cf_outputs,
    _env_or_none,
    _eprint,
    _inbox_queue_name,
    _jwt_payload,
    _load_json_object,
    _parse_groups_csv,
    _print_json,
    _require_str,
    _stack_output_value,
    _write_secure_json,
)


@dataclass
class AdminContext:
    session: Any
    stack: str
    _outputs: dict[str, str] = field(default_factory=dict)

    def outputs(self) -> dict[str, str]:
        if self._outputs:
            return self._outputs
        self._outputs = {
            str(o.get("OutputKey", "")).strip(): str(o.get("OutputValue", "")).strip()
            for o in _cf_outputs(self.session, stack=self.stack)
        }
        return self._outputs

    def output(self, key: str) -> str | None:
        val = self.outputs().get(key)
        if val is not None:
            return val
        return _stack_output_value(self.session, stack=self.stack, key=key)

    def require_output(self, key: str) -> str:
        v = self.output(key)
        if v is None:
            raise OpError(f"missing CloudFormation output {key!r} on stack {self.stack!r}")
        return v

    def resolve_api_key_param_name(self, override: str | None) -> str:
        if override:
            return override.strip()
        return self.require_output("ApiKeyParameterName")

    def resolve_user_pool_id(self, override: str | None) -> str:
        if override:
            return override.strip()
        return self.require_output("UserPoolId")

    def resolve_user_pool_client_id(self, override: str | None) -> str:
        if override:
            return override.strip()
        return self.require_output("UserPoolClientId")


def build_admin_context(g: GlobalOpts) -> AdminContext:
    return AdminContext(session=_account_session(), stack=g.stack)


def _ssm_get_value(session: Any, *, name: str) -> str:
    ssm = session.client("ssm")
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=True)
    except Exception as e:
        raise OpError(f"ssm get-parameter failed for {name!r}: {e}") from e
    return str(resp.get("Parameter", {}).get("Value", "")).strip()


def _ssm_put_value(
    session: Any,
    *,
    name: str,
    value: str,
    type_name: str,
    description: str,
    overwrite: bool,
) -> None:
    ssm = session.client("ssm")
    try:
        ssm.put_parameter(
            Name=name,
            Value=value,
            Type=type_name,
            Description=description,
            Overwrite=overwrite,
        )
    except Exception as e:
        raise OpError(f"ssm put-parameter failed for {name!r}: {e}") from e


def _parse_stage_from_api_key_param_name(name: str) -> str | None:
    parts = [p for p in (name or "").split("/") if p]
    if len(parts) >= 4 and parts[0] == "agent-enablement":
        stage = str(parts[2] or "").strip()
        return stage or None
    return None


def _resolve_ssm_keys_stage(ctx: AdminContext, *, override: str | None) -> str:
    if override:
        return override.strip()
    api_key_param_name = ctx.resolve_api_key_param_name(None)
    parsed = _parse_stage_from_api_key_param_name(api_key_param_name)
    return parsed or "prod"


def _require_value(*, value: str | None, value_file: str | None) -> str:
    if value and value_file:
        raise UsageError("provide only one of --value or --value-file")
    if value_file:
        return Path(value_file).read_text(encoding="utf-8")
    return _require_str(value, "value", hint="--value or --value-file")


def _ssm_key_name_shared(*, stage: str, key: str) -> str:
    k = (key or "").strip().lstrip("/")
    if not k:
        raise UsageError("key name cannot be empty")
    return f"/agent-enablement/{stage}/shared/{k}"


def _ssm_key_name_agent(*, stage: str, sub: str, key: str) -> str:
    s = (sub or "").strip()
    if not s:
        raise UsageError("sub cannot be empty")
    k = (key or "").strip().lstrip("/")
    if not k:
        raise UsageError("key name cannot be empty")
    return f"/agent-enablement/{stage}/agent/{s}/{k}"


def cmd_stack_output(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    key = str(getattr(args, "output_key", "") or "").strip()
    if not key:
        outputs = _cf_outputs(ctx.session, stack=g.stack)
        _print_json(outputs, pretty=g.pretty)
        return 0
    v = _stack_output_value(ctx.session, stack=g.stack, key=key)
    if v is None:
        raise OpError(f"output key not found: {key}")
    sys.stdout.write(v + "\n")
    return 0


def cmd_ssm_api_key(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    name = ctx.resolve_api_key_param_name(args.name)
    val = _ssm_get_value(ctx.session, name=name)
    _print_json({"parameterName": name, "value": val}, pretty=g.pretty)
    return 0


def cmd_ssm_key_base_paths(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    stage = _resolve_ssm_keys_stage(ctx, override=args.stage)
    out = {
        "stage": stage,
        "sharedBasePath": f"/agent-enablement/{stage}/shared/",
        "agentBasePathTemplate": "/agent-enablement/{stage}/agent/<principal.sub>/".format(stage=stage),
    }
    _print_json(out, pretty=g.pretty)
    return 0


def cmd_ssm_key_put_shared(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    stage = _resolve_ssm_keys_stage(ctx, override=args.stage)
    name = _ssm_key_name_shared(stage=stage, key=args.key)
    value = _require_value(value=args.value, value_file=args.value_file)
    _ssm_put_value(
        ctx.session,
        name=name,
        value=value,
        type_name=args.type,
        description=(args.description or "").strip(),
        overwrite=bool(args.overwrite),
    )
    _print_json({"name": name, "stage": stage, "type": args.type, "overwrote": bool(args.overwrite)}, pretty=g.pretty)
    return 0


def cmd_ssm_key_put_agent(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    stage = _resolve_ssm_keys_stage(ctx, override=args.stage)
    name = _ssm_key_name_agent(stage=stage, sub=args.sub, key=args.key)
    value = _require_value(value=args.value, value_file=args.value_file)
    _ssm_put_value(
        ctx.session,
        name=name,
        value=value,
        type_name=args.type,
        description=(args.description or "").strip(),
        overwrite=bool(args.overwrite),
    )
    _print_json({"name": name, "stage": stage, "type": args.type, "overwrote": bool(args.overwrite)}, pretty=g.pretty)
    return 0


def cmd_ssm_key_get_shared(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    stage = _resolve_ssm_keys_stage(ctx, override=args.stage)
    name = _ssm_key_name_shared(stage=stage, key=args.key)
    sys.stdout.write(_ssm_get_value(ctx.session, name=name) + "\n")
    return 0


def cmd_ssm_key_get_agent(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    stage = _resolve_ssm_keys_stage(ctx, override=args.stage)
    name = _ssm_key_name_agent(stage=stage, sub=args.sub, key=args.key)
    sys.stdout.write(_ssm_get_value(ctx.session, name=name) + "\n")
    return 0


def _resolve_cognito_basic_credentials(*, username: str | None, password: str | None) -> auth_inputs.BasicCredentials:
    try:
        return auth_inputs.resolve_basic_credentials(
            username=username,
            password=password,
            env_or_none=_env_or_none,
            username_env_names=(ENABLER_ADMIN_COGNITO_USERNAME,),
            password_env_names=(ENABLER_ADMIN_COGNITO_PASSWORD,),
        )
    except auth_inputs.AuthInputError as e:
        raise UsageError(str(e)) from e


def _cognito_auth_result(
    *,
    ctx: AdminContext,
    client_id_override: str | None,
    username: str,
    password: str,
) -> dict[str, Any]:
    client_id = ctx.resolve_user_pool_client_id(client_id_override)
    c = ctx.session.client("cognito-idp")
    try:
        resp = c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    except Exception as e:
        raise OpError(f"cognito initiate-auth failed: {e}") from e
    auth = resp.get("AuthenticationResult")
    return auth if isinstance(auth, dict) else {}


def cmd_cognito_create_user(args: argparse.Namespace, g: GlobalOpts) -> int:
    creds = _resolve_cognito_basic_credentials(username=args.username, password=args.password)
    ctx = build_admin_context(g)
    user_pool_id = ctx.resolve_user_pool_id(args.user_pool_id)
    c = ctx.session.client("cognito-idp")

    created = True
    try:
        c.admin_create_user(UserPoolId=user_pool_id, Username=creds.username, MessageAction="SUPPRESS")
    except Exception as e:
        if type(e).__name__ != "UsernameExistsException":
            raise OpError(f"cognito admin-create-user failed: {e}") from e
        created = False

    try:
        c.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=creds.username,
            Password=creds.password,
            Permanent=True,
        )
    except Exception as e:
        raise OpError(f"cognito admin-set-user-password failed: {e}") from e

    _print_json({"username": creds.username, "userPoolId": user_pool_id, "created": created}, pretty=g.pretty)
    return 0


def cmd_cognito_rotate_password(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    user_pool_id = ctx.resolve_user_pool_id(args.user_pool_id)
    c = ctx.session.client("cognito-idp")
    try:
        c.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=args.username,
            Password=args.new_password,
            Permanent=True,
        )
    except Exception as e:
        raise OpError(f"cognito admin-set-user-password failed: {e}") from e
    _print_json({"username": args.username, "userPoolId": user_pool_id, "rotated": True}, pretty=g.pretty)
    return 0


def cmd_cognito_remove_user(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    user_pool_id = ctx.resolve_user_pool_id(args.user_pool_id)
    username = str(args.username or "").strip()
    if not username:
        raise UsageError("username cannot be empty")
    c = ctx.session.client("cognito-idp")
    try:
        c.admin_delete_user(UserPoolId=user_pool_id, Username=username)
    except Exception as e:
        raise OpError(f"cognito admin-delete-user failed: {e}") from e
    _print_json({"username": username, "userPoolId": user_pool_id, "removed": True}, pretty=g.pretty)
    return 0


def cmd_cognito_id_token(args: argparse.Namespace, g: GlobalOpts) -> int:
    creds = _resolve_cognito_basic_credentials(username=args.username, password=args.password)
    ctx = build_admin_context(g)
    resp = {
        "AuthenticationResult": _cognito_auth_result(
            ctx=ctx,
            client_id_override=args.client_id,
            username=creds.username,
            password=creds.password,
        )
    }

    if args.raw:
        _print_json(resp, pretty=g.pretty)
        return 0

    auth = resp.get("AuthenticationResult") or {}
    if args.json:
        out = {
            "idToken": auth.get("IdToken"),
            "accessToken": auth.get("AccessToken"),
            "refreshToken": auth.get("RefreshToken"),
            "expiresIn": auth.get("ExpiresIn"),
            "tokenType": auth.get("TokenType"),
        }
        _print_json(out, pretty=g.pretty)
        return 0

    tok = str(auth.get("IdToken") or "").strip()
    if not tok:
        raise OpError("missing IdToken in Cognito response")
    sys.stdout.write(tok + "\n")
    return 0


def cmd_agent_decommission(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    username = str(args.username or "").strip()
    if not username:
        raise UsageError("username cannot be empty")
    dry_run = bool(args.dry_run)
    user_pool_id = ctx.resolve_user_pool_id(args.user_pool_id)

    c = ctx.session.client("cognito-idp")
    ddb = ctx.session.client("dynamodb")
    sqs = ctx.session.client("sqs")

    try:
        user = c.admin_get_user(UserPoolId=user_pool_id, Username=username)
    except Exception as e:
        raise OpError(f"cognito admin-get-user failed: {e}") from e

    sub = ""
    for attr in (user.get("UserAttributes") or []):
        if not isinstance(attr, dict):
            continue
        if str(attr.get("Name") or "").strip() == "sub":
            sub = str(attr.get("Value") or "").strip()
            break
    if not sub:
        raise OpError("unable to resolve Cognito sub for user")

    outputs = ctx.outputs()
    profiles_table = str(outputs.get("AgentProfilesTableName") or "").strip()
    if not profiles_table:
        raise OpError("missing stack output AgentProfilesTableName")
    group_table = str(outputs.get("AgentGroupMembersTableName") or "").strip()

    profile: dict[str, Any] | None = None
    try:
        profile = ddb.get_item(
            TableName=profiles_table,
            Key={"sub": {"S": sub}},
            ConsistentRead=True,
        ).get("Item")
    except Exception as e:
        raise OpError(f"dynamodb get-item failed for profiles table {profiles_table!r}: {e}") from e

    agent_id = ""
    inbox_queue_url = ""
    groups: list[str] = []
    if isinstance(profile, dict):
        agent_id = str((profile.get("agentId") or {}).get("S") or "").strip()
        inbox_queue_url = str((profile.get("inboxQueueUrl") or {}).get("S") or "").strip()
        raw_groups = (profile.get("groups") or {}).get("SS") or []
        if isinstance(raw_groups, list):
            groups = [str(v).strip() for v in raw_groups if str(v).strip()]

    actions: list[dict[str, Any]] = [
        {"action": "cognito:admin_get_user", "username": username, "userPoolId": user_pool_id},
        {"action": "cognito:admin_delete_user", "username": username, "userPoolId": user_pool_id},
        {"action": "dynamodb:get_item", "table": profiles_table, "key": {"sub": sub}},
        {"action": "dynamodb:delete_item", "table": profiles_table, "key": {"sub": sub}},
    ]
    if group_table and groups and agent_id:
        for grp in groups:
            actions.append(
                {
                    "action": "dynamodb:delete_item",
                    "table": group_table,
                    "key": {"groupId": grp, "agentId": agent_id},
                }
            )
    if inbox_queue_url:
        actions.append({"action": "sqs:delete_queue", "queueUrl": inbox_queue_url})

    result: dict[str, Any] = {
        "username": username,
        "sub": sub,
        "dryRun": dry_run,
        "actions": actions,
        "results": {
            "cognitoDeleted": False,
            "profileDeleted": False,
            "groupRowsDeleted": 0,
            "inboxDeleted": False,
        },
    }

    if dry_run:
        _print_json(result, pretty=g.pretty)
        return 0

    try:
        c.admin_delete_user(UserPoolId=user_pool_id, Username=username)
        result["results"]["cognitoDeleted"] = True
    except Exception as e:
        raise OpError(f"cognito admin-delete-user failed: {e}") from e

    try:
        ddb.delete_item(TableName=profiles_table, Key={"sub": {"S": sub}})
        result["results"]["profileDeleted"] = bool(profile)
    except Exception as e:
        raise OpError(f"dynamodb delete-item failed for profiles table {profiles_table!r}: {e}") from e

    if group_table and groups and agent_id:
        deleted = 0
        for grp in groups:
            try:
                ddb.delete_item(
                    TableName=group_table,
                    Key={"groupId": {"S": grp}, "agentId": {"S": agent_id}},
                )
                deleted += 1
            except Exception as e:
                raise OpError(
                    f"dynamodb delete-item failed for group table {group_table!r} group {grp!r}: {e}"
                ) from e
        result["results"]["groupRowsDeleted"] = deleted

    if inbox_queue_url:
        try:
            sqs.delete_queue(QueueUrl=inbox_queue_url)
            result["results"]["inboxDeleted"] = True
        except Exception as e:
            raise OpError(f"sqs delete-queue failed for {inbox_queue_url!r}: {e}") from e

    _print_json(result, pretty=g.pretty)
    return 0


def _capture_json(run: Any) -> str:
    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        run()
    return buf.getvalue().strip()


def cmd_agent_seed_profile(args: argparse.Namespace, g: GlobalOpts) -> int:
    creds = _resolve_cognito_basic_credentials(username=args.username, password=args.password)
    username = creds.username
    password = creds.password
    scope = (args.credential_scope or _env_or_none("CREDENTIAL_SCOPE") or "runtime").strip().lower()
    if scope in ("", "runtime"):
        scope = "runtime"
    elif scope in ("provisioning", "cfn", "cloudformation"):
        scope = "provisioning"
    else:
        raise UsageError("credential scope must be runtime or provisioning")

    agent_id = (args.agent_id or username).strip()
    if not agent_id:
        raise UsageError("agent id cannot be empty")
    profile_type = str(getattr(args, "profile_type", "") or "named").strip().lower()
    if profile_type not in {"named", "ephemeral"}:
        raise UsageError("profile type must be named or ephemeral")

    groups = _parse_groups_csv(args.groups or _env_or_none("AGENT_GROUPS"))
    dry_run = bool(args.dry_run)
    create_inbox = bool(args.create_inbox)
    inbox_queue_name = (args.inbox_queue_name or _inbox_queue_name(agent_id)).strip()

    ctx = build_admin_context(g)
    auth = _cognito_auth_result(
        ctx=ctx,
        client_id_override=args.client_id,
        username=username,
        password=password,
    )
    id_token = str(auth.get("IdToken") or "").strip()
    if not id_token:
        raise OpError("missing IdToken in Cognito response")
    sub = str(_jwt_payload(id_token).get("sub", "")).strip()
    if not sub:
        raise OpError("missing sub claim in ID token payload")

    outputs = ctx.outputs()
    profiles_table = str(outputs.get("AgentProfilesTableName") or "").strip()
    if not profiles_table:
        raise OpError("missing stack output AgentProfilesTableName")
    group_table = str(outputs.get("AgentGroupMembersTableName") or "").strip()

    runtime_role_arn = str(outputs.get("BrokerRuntimeRoleArn") or "").strip()
    provisioning_role_arn = str(outputs.get("BrokerProvisioningRoleArn") or "").strip()
    if not runtime_role_arn or not provisioning_role_arn:
        raise OpError("missing stack outputs BrokerRuntimeRoleArn/BrokerProvisioningRoleArn")
    assume_role_arn = provisioning_role_arn if scope == "provisioning" else runtime_role_arn

    upload_bucket = str(outputs.get("UploadBucketName") or "").strip()
    comms_bucket = str(outputs.get("CommsSharedBucketName") or "").strip()
    queue_arn = str(outputs.get("QueueArn") or "").strip()
    bus_arn = str(outputs.get("EventBusArn") or "").strip()
    if not upload_bucket or not comms_bucket or not queue_arn or not bus_arn:
        raise OpError("missing one or more stack outputs: UploadBucketName, CommsSharedBucketName, QueueArn, EventBusArn")

    sqs = ctx.session.client("sqs")
    ddb = ctx.session.client("dynamodb")
    inbox_queue_url = ""
    inbox_queue_arn = ""
    actions: list[dict[str, Any]] = []

    if create_inbox:
        actions.append({"action": "sqs:create_queue", "queueName": inbox_queue_name})
    else:
        actions.append({"action": "sqs:get_queue_url", "queueName": inbox_queue_name})
    actions.append({"action": "sqs:get_queue_attributes", "queueName": inbox_queue_name, "attributeNames": ["QueueArn"]})
    actions.append({"action": "sqs:tag_queue", "queueName": inbox_queue_name, "tags": {"agent_sub": sub}})
    actions.append({"action": "dynamodb:put_item", "table": profiles_table, "key": {"sub": sub}})
    if group_table and groups:
        for grp in groups:
            actions.append({"action": "dynamodb:put_item", "table": group_table, "key": {"groupId": grp, "agentId": agent_id}})

    if not dry_run:
        try:
            if create_inbox:
                inbox_queue_url = ctx.session.client("sqs").create_queue(QueueName=inbox_queue_name).get("QueueUrl", "")
            else:
                inbox_queue_url = ctx.session.client("sqs").get_queue_url(QueueName=inbox_queue_name).get("QueueUrl", "")
        except Exception as e:
            raise OpError(f"sqs queue resolution failed for {inbox_queue_name!r}: {e}") from e

        if not inbox_queue_url:
            raise OpError("failed to resolve inbox queue url")

        try:
            inbox_queue_arn = (
                sqs.get_queue_attributes(QueueUrl=inbox_queue_url, AttributeNames=["QueueArn"])
                .get("Attributes", {})
                .get("QueueArn", "")
            )
        except Exception as e:
            raise OpError(f"sqs get-queue-attributes failed: {e}") from e

        if not inbox_queue_arn:
            raise OpError("failed to resolve inbox queue arn")

        try:
            sqs.tag_queue(QueueUrl=inbox_queue_url, Tags={"agent_sub": sub})
        except Exception as e:
            raise OpError(f"sqs tag-queue failed: {e}") from e

        item: dict[str, Any] = {
            "sub": {"S": sub},
            "enabled": {"BOOL": True},
            "profileType": {"S": profile_type},
            "credentialScope": {"S": scope},
            "assumeRoleArn": {"S": assume_role_arn},
            "agentId": {"S": agent_id},
            "s3Bucket": {"S": upload_bucket},
            "commsFilesBucket": {"S": comms_bucket},
            "sqsQueueArn": {"S": queue_arn},
            "inboxQueueArn": {"S": inbox_queue_arn},
            "inboxQueueUrl": {"S": inbox_queue_url},
            "eventBusArn": {"S": bus_arn},
            "instructionText": {
                "S": "Use EventBridge for direct/broadcast messaging and shared S3 prefixes for file exchange."
            },
        }
        if groups:
            item["groups"] = {"SS": groups}

        try:
            ddb.put_item(TableName=profiles_table, Item=item)
        except Exception as e:
            raise OpError(f"dynamodb put-item failed for profiles table {profiles_table!r}: {e}") from e

        if group_table and groups:
            for grp in groups:
                gitem = {
                    "groupId": {"S": grp},
                    "agentId": {"S": agent_id},
                    "sub": {"S": sub},
                    "enabled": {"BOOL": True},
                    "inboxQueueUrl": {"S": inbox_queue_url},
                }
                try:
                    ddb.put_item(TableName=group_table, Item=gitem)
                except Exception as e:
                    raise OpError(
                        f"dynamodb put-item failed for group table {group_table!r} group {grp!r}: {e}"
                    ) from e

    out = {
        "sub": sub,
        "username": username,
        "agentId": agent_id,
        "credentialScope": scope,
        "profileType": profile_type,
        "groups": groups,
        "inbox": {"queueName": inbox_queue_name, "queueUrl": inbox_queue_url, "queueArn": inbox_queue_arn},
        "tables": {"agentProfiles": profiles_table, "agentGroupMembers": group_table},
        "references": {
            "assumeRoleArn": assume_role_arn,
            "runtimeRoleArn": runtime_role_arn,
            "provisioningRoleArn": provisioning_role_arn,
            "uploadBucket": upload_bucket,
            "commsFilesBucket": comms_bucket,
            "queueArn": queue_arn,
            "eventBusArn": bus_arn,
        },
        "dryRun": dry_run,
        "actions": actions,
    }
    _print_json(out, pretty=g.pretty)
    return 0


def cmd_agent_onboard(args: argparse.Namespace, g: GlobalOpts) -> int:
    username = args.username.strip()
    password = args.password

    create_args = argparse.Namespace(username=username, password=password, user_pool_id=args.user_pool_id)
    seed_args = argparse.Namespace(
        username=username,
        password=password,
        credential_scope=args.credential_scope,
        profile_type=getattr(args, "profile_type", None),
        agent_id=args.agent_id,
        groups=args.groups,
        create_inbox=args.create_inbox,
        inbox_queue_name=args.inbox_queue_name,
        dry_run=args.dry_run,
        client_id=args.client_id,
    )

    result: dict[str, Any] = {"username": username, "dryRun": bool(args.dry_run)}
    if bool(args.dry_run):
        result["createUser"] = {"skipped": True}
        result["seedProfile"] = json.loads(_capture_json(lambda: cmd_agent_seed_profile(seed_args, g)))
        _print_json(result, pretty=g.pretty)
        return 0

    _ = _capture_json(lambda: cmd_cognito_create_user(create_args, g))
    seed_json = _capture_json(lambda: cmd_agent_seed_profile(seed_args, g))
    result["createUser"] = {"ok": True}
    result["seedProfile"] = json.loads(seed_json)
    _print_json(result, pretty=g.pretty)
    return 0


def _handoff_doc(*, username: str, password: str, api_key: str) -> dict[str, Any]:
    return {
        "kind": ENABLER_ADMIN_HANDOFF_KIND,
        "schemaVersion": ENABLER_ADMIN_HANDOFF_SCHEMA_VERSION,
        "username": username,
        "password": password,
        "apiKey": api_key,
    }


def _validate_handoff_doc(doc: dict[str, Any]) -> dict[str, str]:
    kind = str(doc.get("kind") or "").strip()
    if kind != ENABLER_ADMIN_HANDOFF_KIND:
        raise UsageError(f"invalid handoff kind: expected {ENABLER_ADMIN_HANDOFF_KIND!r}, got {kind!r}")
    schema = str(doc.get("schemaVersion") or "").strip()
    if schema != ENABLER_ADMIN_HANDOFF_SCHEMA_VERSION:
        raise UsageError(
            f"invalid handoff schemaVersion: expected {ENABLER_ADMIN_HANDOFF_SCHEMA_VERSION!r}, got {schema!r}"
        )
    required = {
        "username": str(doc.get("username") or "").strip(),
        "password": str(doc.get("password") or "").strip(),
        "apiKey": str(doc.get("apiKey") or "").strip(),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise UsageError(f"handoff JSON missing required fields: {', '.join(missing)}")
    return required


def _shell_quote(val: str) -> str:
    return "'" + str(val).replace("'", "'\"'\"'") + "'"


def _render_handoff_exports(validated: dict[str, str]) -> str:
    mapping = {
        ENABLER_COGNITO_USERNAME: validated["username"],
        ENABLER_COGNITO_PASSWORD: validated["password"],
        ENABLER_API_KEY: validated["apiKey"],
    }
    lines = [f"export {name}={_shell_quote(value)}" for name, value in mapping.items()]
    return "\n".join(lines) + "\n"


def _read_handoff_doc(*, handoff_file: str | None) -> dict[str, Any]:
    if handoff_file:
        raw = Path(handoff_file).read_text(encoding="utf-8")
        return _load_json_object(raw=raw, label=f"handoff JSON at {handoff_file}")
    if sys.stdin.isatty():
        raise UsageError("provide --file or pipe handoff JSON on stdin")
    raw = sys.stdin.read()
    return _load_json_object(raw=raw, label="handoff JSON from stdin")


def cmd_agent_handoff_create(args: argparse.Namespace, g: GlobalOpts) -> int:
    ctx = build_admin_context(g)
    username = _require_str(args.username, "username", hint="--username")
    password = _require_str(args.password, "password", hint="--password")
    api_key = str(args.api_key or "").strip()
    if not api_key:
        param_name = ctx.resolve_api_key_param_name(args.api_key_ssm_name)
        api_key = _ssm_get_value(ctx.session, name=param_name)
    if not api_key:
        raise OpError("failed to resolve API key")

    doc = _handoff_doc(username=username, password=password, api_key=api_key)
    _ = _validate_handoff_doc(doc)
    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        _write_secure_json(path=out_path, obj=doc)
    _print_json(doc, pretty=g.pretty)
    return 0


def cmd_agent_handoff_print_env(args: argparse.Namespace, g: GlobalOpts) -> int:
    del g
    doc = _read_handoff_doc(handoff_file=args.file)
    validated = _validate_handoff_doc(doc)
    _eprint("warning: emitting plaintext secrets to stdout; treat this output as sensitive")
    sys.stdout.write(_render_handoff_exports(validated))
    return 0
