import json
import os
import re
import time
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import boto3
from id58 import uuid_text_to_base58_22
from profile_codec import ddb_str_list as profile_ddb_str_list

_sts_client = None
_ddb_client = None
_cognito_client = None

PROFILE_TABLE_NAME = os.environ.get("PROFILE_TABLE_NAME", "")
DELEGATION_REQUESTS_TABLE_NAME = os.environ.get("DELEGATION_REQUESTS_TABLE_NAME", "")
ASSUME_ROLE_RUNTIME_ARN = os.environ.get("ASSUME_ROLE_RUNTIME_ARN", "")
ASSUME_ROLE_PROVISIONING_ARN = os.environ.get("ASSUME_ROLE_PROVISIONING_ARN", "")
ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN = os.environ.get(
    "ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN", ""
)
ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN = os.environ.get(
    "ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN", ""
)
CFN_EXECUTION_ROLE_ARN = os.environ.get("CFN_EXECUTION_ROLE_ARN", "")
AGENT_WORKLOAD_BOUNDARY_ARN = os.environ.get("AGENT_WORKLOAD_BOUNDARY_ARN", "")
AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN = os.environ.get(
    "AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN", ""
)
AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN = os.environ.get(
    "AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN", ""
)
AGENT_WORKSHOP_ACCOUNT_ID = os.environ.get("AGENT_WORKSHOP_ACCOUNT_ID", "")
AGENT_WORKSHOP_REGION = os.environ.get("AGENT_WORKSHOP_REGION", "")
DEFAULT_TTL_SECONDS = int(os.environ.get("DEFAULT_TTL_SECONDS", "3600"))
MAX_TTL_SECONDS = int(os.environ.get("MAX_TTL_SECONDS", "3600"))
SCHEMA_VERSION = os.environ.get("SCHEMA_VERSION", "2026-02-17")
USER_POOL_CLIENT_ID = os.environ.get("USER_POOL_CLIENT_ID", "")

UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET", "")
SQS_QUEUE_ARN = os.environ.get("SQS_QUEUE_ARN", "")
EVENT_BUS_ARN = os.environ.get("EVENT_BUS_ARN", "")
COMMS_FILES_BUCKET = os.environ.get("COMMS_FILES_BUCKET", "")
SHORTLINK_CREATE_URL = os.environ.get("SHORTLINK_CREATE_URL", "")
SHORTLINK_REDIRECT_BASE_URL = os.environ.get("SHORTLINK_REDIRECT_BASE_URL", "")
CREDENTIALS_PATH = os.environ.get("CREDENTIALS_PATH", "/v1/credentials")
CREDENTIALS_REFRESH_PATH = os.environ.get(
    "CREDENTIALS_REFRESH_PATH", "/v1/credentials/refresh"
)
DELEGATION_REQUEST_PATH = os.environ.get("DELEGATION_REQUEST_PATH", "/v1/delegation/requests")
DELEGATION_APPROVAL_PATH = os.environ.get("DELEGATION_APPROVAL_PATH", "/v1/delegation/approvals")
DELEGATION_REDEEM_PATH = os.environ.get("DELEGATION_REDEEM_PATH", "/v1/delegation/redeem")
DELEGATION_STATUS_PATH = os.environ.get("DELEGATION_STATUS_PATH", "/v1/delegation/status")
DELEGATION_DEFAULT_TTL_SECONDS = int(os.environ.get("DELEGATION_DEFAULT_TTL_SECONDS", "600"))
DELEGATION_MAX_TTL_SECONDS = int(os.environ.get("DELEGATION_MAX_TTL_SECONDS", "600"))
USER_POOL_ID = os.environ.get("USER_POOL_ID", "")
SHORTLINK_CREATE_PATH = os.environ.get("SHORTLINK_CREATE_PATH", "/v1/links")
SHORTLINK_REDIRECT_PREFIX = os.environ.get("SHORTLINK_REDIRECT_PREFIX", "/l/")
ENABLEMENT_INDEX_URL = os.environ.get("ENABLEMENT_INDEX_URL", "")
ENABLEMENT_ARTIFACTS_ROOT_URL = os.environ.get("ENABLEMENT_ARTIFACTS_ROOT_URL", "")
ENABLEMENT_SKILLS_ROOT_URL = os.environ.get("ENABLEMENT_SKILLS_ROOT_URL", "")
ENABLEMENT_VERSION = os.environ.get("ENABLEMENT_VERSION", "latest")
API_KEY_SSM_PARAMETER_NAME = os.environ.get("API_KEY_SSM_PARAMETER_NAME", "")
SSM_KEYS_STAGE = os.environ.get("SSM_KEYS_STAGE", "")
API_REQUIRED_HEADERS = os.environ.get("API_REQUIRED_HEADERS", "x-api-key,authorization")
STACK_NAME_PATTERN_TEMPLATE = "agent-${aws:PrincipalTag/sub}-*"
_DELEGATION_ALLOWED_SCOPES = {"taskboard", "messages", "files", "shortlinks"}


def _arn_account_id(arn: str) -> str:
    # arn:partition:service:region:account-id:resource
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def _parse_stage_from_api_key_param_name(name: str) -> str:
    """
    The shared API key parameter convention is:

      /agent-enablement/<stackName>/<stage>/shared-api-key

    This is a fallback only; prefer env var SSM_KEYS_STAGE.
    """

    parts = [p for p in (name or "").split("/") if p]
    if len(parts) >= 4 and parts[0] == "agent-enablement":
        return str(parts[2] or "").strip()
    return ""


def _ssm_keys_stage() -> str:
    stage = (SSM_KEYS_STAGE or "").strip()
    if stage:
        return stage
    stage = _parse_stage_from_api_key_param_name(API_KEY_SSM_PARAMETER_NAME)
    if stage:
        return stage
    return "prod"


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(body),
    }


def _session_name(agent_id: str) -> str:
    # STS RoleSessionName constraints are relatively strict (<= 64 chars, limited charset).
    sanitized = re.sub(r"[^a-zA-Z0-9+=,.@_-]", "", f"agent-{agent_id}")
    return (sanitized[:64] or "agent-session")


def _duration_seconds() -> int:
    return min(max(DEFAULT_TTL_SECONDS, 60), min(MAX_TTL_SECONDS, 3600))


def _get_header(event: dict[str, Any], name: str) -> str:
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    # API Gateway can canonicalize headers; treat them case-insensitively.
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == name.lower():
            return str(v) if v is not None else ""
    return ""


def _get_request_id(event: dict[str, Any]) -> str:
    return (
        event.get("requestContext", {}).get("requestId")
        or event.get("requestContext", {}).get("requestId")
        or ""
    )


def _request_path_values(event: dict[str, Any]) -> list[str]:
    out: list[str] = []
    rc = event.get("requestContext") or {}
    candidates = [
        event.get("rawPath"),
        event.get("path"),
        event.get("resource"),
        rc.get("path") if isinstance(rc, dict) else None,
        rc.get("resourcePath") if isinstance(rc, dict) else None,
    ]
    for raw in candidates:
        val = str(raw or "").strip()
        if val:
            out.append(val)
    return out


def _request_matches_path(event: dict[str, Any], expected_path: str) -> bool:
    expected = str(expected_path or "").strip().rstrip("/")
    if not expected:
        return False
    for raw in _request_path_values(event):
        candidate = raw.rstrip("/")
        if candidate == expected or candidate.endswith(expected):
            return True
    return False


def _parse_refresh_token(event: dict[str, Any]) -> str:
    return _get_header(event, "x-enabler-refresh-token").strip()


def _ddb_get_profile(sub: str) -> dict[str, Any] | None:
    out = _ddb().get_item(
        TableName=PROFILE_TABLE_NAME,
        Key={"sub": {"S": sub}},
        ConsistentRead=True,
    )
    return out.get("Item")


def _ddb_bool(item: dict[str, Any], key: str, default: bool = False) -> bool:
    val = item.get(key)
    if not val or "BOOL" not in val:
        return default
    return bool(val["BOOL"])


def _ddb_str(item: dict[str, Any], key: str, default: str = "") -> str:
    val = item.get(key)
    if not val or "S" not in val:
        return default
    return str(val["S"])


def _normalize_optional_arn(val: str) -> str:
    # AWS CLI --output text sometimes yields 'None' when a query doesn't match.
    if not val:
        return ""
    v = val.strip()
    if v.lower() in ("none", "null"):
        return ""
    return v


def _comms_prefixes(agent_id: str, groups: list[str]) -> tuple[list[str], list[str]]:
    if not agent_id:
        return [], []
    write_prefixes = [
        f"direct/{agent_id}/",
        f"broadcast/{agent_id}/",
    ]
    read_prefixes = [
        f"direct/*/{agent_id}/",
        "broadcast/",
    ]
    return write_prefixes, read_prefixes


def _credential_scope(item: dict[str, Any]) -> str:
    raw = _ddb_str(item, "credentialScope", default="runtime").strip().lower()
    if raw in ("", "runtime"):
        return "runtime"
    if raw in ("provisioning", "cfn", "cloudformation"):
        return "provisioning"
    return "invalid"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _aws_region() -> str | None:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")


def _sts():
    global _sts_client
    if _sts_client is None:
        _sts_client = boto3.client("sts", region_name=_aws_region())
    return _sts_client


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb", region_name=_aws_region())
    return _ddb_client


def _cognito():
    global _cognito_client
    if _cognito_client is None:
        _cognito_client = boto3.client("cognito-idp", region_name=_aws_region())
    return _cognito_client


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _parse_json_body(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("body")
    if raw is None:
        return {}
    text = str(raw)
    if not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _delegation_scopes(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("scopes")
    scopes: list[str] = []
    if isinstance(raw, list):
        for val in raw:
            scope = str(val or "").strip().lower()
            if scope in _DELEGATION_ALLOWED_SCOPES and scope not in scopes:
                scopes.append(scope)
    if not scopes:
        scopes = ["taskboard", "messages"]
    return scopes


def _delegation_ttl_seconds(payload: dict[str, Any]) -> int:
    try:
        ttl = int(payload.get("ttlSeconds"))
    except Exception:
        ttl = DELEGATION_DEFAULT_TTL_SECONDS
    max_ttl = max(60, min(DELEGATION_MAX_TTL_SECONDS, _duration_seconds()))
    return max(60, min(ttl, max_ttl))


def _new_b58_id() -> str:
    return uuid_text_to_base58_22(str(uuid.uuid4()))


def _delegation_now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _delegation_table() -> str:
    return str(DELEGATION_REQUESTS_TABLE_NAME or "").strip()


def _delegation_get(request_code: str) -> dict[str, Any] | None:
    out = _ddb().get_item(
        TableName=_delegation_table(),
        Key={"requestCode": {"S": request_code}},
        ConsistentRead=True,
    )
    return out.get("Item")


def _delegation_status(item: dict[str, Any]) -> str:
    return _ddb_str(item, "status", default="").strip().lower()


def _delegation_expired(item: dict[str, Any]) -> bool:
    try:
        exp_epoch = int((item.get("expiresAtEpoch") or {}).get("N") or "0")
    except Exception:
        exp_epoch = 0
    return exp_epoch <= _delegation_now_epoch()


def _delegation_item_to_payload(item: dict[str, Any], *, request_id: str) -> dict[str, Any]:
    scopes = sorted(list(profile_ddb_str_list(item.get("scopes"))))
    return {
        "kind": "agent-enablement.delegation.status.v1",
        "requestId": request_id,
        "requestCode": _ddb_str(item, "requestCode"),
        "delegationRequestId": _ddb_str(item, "requestId"),
        "status": _ddb_str(item, "status"),
        "scopes": scopes,
        "purpose": _ddb_str(item, "purpose"),
        "requestedAt": _ddb_str(item, "requestedAt"),
        "approvedAt": _ddb_str(item, "approvedAt"),
        "approvedBySub": _ddb_str(item, "approvedBySub"),
        "approvedByUsername": _ddb_str(item, "approvedByUsername"),
        "redeemedAt": _ddb_str(item, "redeemedAt"),
        "expiresAt": _ddb_str(item, "expiresAt"),
        "ephemeralAgentId": _ddb_str(item, "ephemeralAgentId"),
        "ephemeralUsername": _ddb_str(item, "ephemeralUsername"),
    }


def _profile_type(item: dict[str, Any]) -> str:
    raw = _ddb_str(item, "profileType", default="named").strip().lower()
    if raw in ("", "named"):
        return "named"
    if raw == "ephemeral":
        return "ephemeral"
    return "invalid"


def _authorizer_claim(event: dict[str, Any], key: str) -> str:
    rc = event.get("requestContext") or {}
    if not isinstance(rc, dict):
        return ""
    auth = rc.get("authorizer") or {}
    if not isinstance(auth, dict):
        return ""
    claims = auth.get("claims") or {}
    if not isinstance(claims, dict):
        return ""
    return str(claims.get(key) or "").strip()


def _parse_basic_auth(event: dict[str, Any]) -> tuple[str, str] | None:
    auth = _get_header(event, "authorization")
    if not auth:
        return None
    if not auth.lower().startswith("basic "):
        return None
    b64 = auth.split(" ", 1)[1].strip()
    if not b64:
        return None
    try:
        decoded = base64.b64decode(b64.encode("utf-8")).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    if not username or not password:
        return None
    return username, password


def _parse_queue_name_from_arn(queue_arn: str) -> str:
    # arn:aws:sqs:region:account:queueName
    return queue_arn.split(":")[-1] if queue_arn else ""


def _queue_url_from_arn(queue_arn: str) -> str:
    # arn:aws:sqs:region:account:queueName
    parts = (queue_arn or "").split(":")
    if len(parts) < 6:
        return ""
    region = parts[3]
    account_id = parts[4]
    queue_name = parts[5]
    if not region or not account_id or not queue_name:
        return ""
    return f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"


def _parse_event_bus_name_from_arn(bus_arn: str) -> str:
    # arn:aws:events:region:account:event-bus/busName
    if not bus_arn:
        return ""
    return bus_arn.split("/", 1)[-1]


def _parse_user_pool_id_from_issuer(issuer: str) -> str:
    # Cognito issuer commonly looks like:
    #   https://cognito-idp.<region>.amazonaws.com/<userPoolId>
    if not issuer:
        return ""
    try:
        path = str(urlparse(issuer).path or "")
        parts = [p for p in path.split("/") if p]
        return parts[-1] if parts else ""
    except Exception:
        return issuer.rstrip("/").split("/")[-1]


def _join_url(base: str, path: str) -> str:
    if not base:
        return ""
    if not path:
        return base
    return base.rstrip("/") + "/" + path.lstrip("/")


def _url_path(url: str) -> str:
    """
    Best-effort URL -> path extraction.

    Example:
      https://bucket.s3.us-east-2.amazonaws.com/agent-enablement/latest/CONTENTS.md
      -> agent-enablement/latest/CONTENTS.md
    """

    if not url:
        return ""
    try:
        return str(urlparse(url).path or "").lstrip("/")
    except Exception:
        return ""


def _enablement_key(index_url: str, rel: str) -> str:
    """
    Derive a stable S3 key under the enablement pack from the enablement contents URL.

    We intentionally publish stable copies under agent-enablement/latest/... so
    consumers can reference durable keys.
    """

    path = _url_path(index_url)
    if not path:
        return ""
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return ""
    base = "/".join(parts[:-1])  # drop CONTENTS.md
    return f"{base.rstrip('/')}/{rel.lstrip('/')}"


def _normalize_enablement_contents_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if raw.endswith("/contents.md"):
        return raw[: -len("/contents.md")] + "/CONTENTS.md"
    return raw


def _best_effort_base_url(event: dict[str, Any]) -> str:
    """
    Avoid CloudFormation-time URL wiring (which can create circular dependencies).

    Best-effort behavior:
    - For execute-api domains, include the stage in the base URL.
    - For non-execute-api domains (custom domain), omit stage.
    """

    rc = event.get("requestContext") or {}
    if not isinstance(rc, dict):
        return ""
    domain = str(rc.get("domainName") or "").strip()
    stage = str(rc.get("stage") or "").strip()
    if not domain:
        return ""
    if "execute-api" in domain and stage:
        return f"https://{domain}/{stage}"
    return f"https://{domain}"


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    start = time.time()
    request_id = _get_request_id(event)

    wide_event: dict[str, Any] = {
        "event": "agents_accessaws_issue_credentials",
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "ts": _now_iso(),
    }

    status_code = 500
    body: dict[str, Any] = {}

    try:
        if not PROFILE_TABLE_NAME:
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": "Server misconfigured",
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        if not USER_POOL_CLIENT_ID:
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": "Server misconfigured",
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        if not ASSUME_ROLE_RUNTIME_ARN:
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": "Server misconfigured",
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        agent_workshop_enabled = bool(
            (ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN or "").strip()
        )
        if agent_workshop_enabled and not (
            (ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN or "").strip()
            and (AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN or "").strip()
            and (AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN or "").strip()
        ):
            status_code = 500
            body = {
                "errorCode": "MISCONFIGURED",
                "message": (
                    "Agent-workshop credentials enabled but missing required env vars "
                    "(ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN, AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN, "
                    "AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN)."
                ),
                "requestId": request_id,
            }
            wide_event["outcome"] = "error"
            return _response(status_code, body)

        if _request_matches_path(event, DELEGATION_REQUEST_PATH):
            if not _delegation_table():
                return _response(
                    500,
                    {
                        "errorCode": "MISCONFIGURED",
                        "message": "Server misconfigured",
                        "requestId": request_id,
                    },
                )
            payload = _parse_json_body(event)
            scopes = _delegation_scopes(payload)
            ttl_seconds = _delegation_ttl_seconds(payload)
            purpose = str(payload.get("purpose") or "").strip()[:256]
            now = datetime.now(timezone.utc)
            exp = now + timedelta(seconds=ttl_seconds)
            request_code = _new_b58_id()
            delegation_request_id = _new_b58_id()
            ephemeral_session_id = _new_b58_id()
            ephemeral_agent_id = f"ephem-{ephemeral_session_id}"
            ephemeral_username = ephemeral_agent_id
            source_ip = (
                str((event.get("requestContext") or {}).get("identity", {}).get("sourceIp") or "").strip()
            )
            ip_hash = hashlib.sha256(source_ip.encode("utf-8")).hexdigest() if source_ip else ""
            _ddb().put_item(
                TableName=_delegation_table(),
                Item={
                    "requestCode": {"S": request_code},
                    "requestId": {"S": delegation_request_id},
                    "status": {"S": "pending"},
                    "requestedAt": {"S": _iso(now)},
                    "expiresAt": {"S": _iso(exp)},
                    "expiresAtEpoch": {"N": str(int(exp.timestamp()))},
                    "scopes": {"SS": scopes},
                    "purpose": {"S": purpose},
                    "ephemeralAgentId": {"S": ephemeral_agent_id},
                    "ephemeralUsername": {"S": ephemeral_username},
                    "requestedByIpHash": {"S": ip_hash},
                },
            )
            return _response(
                200,
                {
                    "kind": "agent-enablement.delegation.request.v1",
                    "requestId": request_id,
                    "delegationRequestId": delegation_request_id,
                    "requestCode": request_code,
                    "status": "pending",
                    "scopes": scopes,
                    "purpose": purpose,
                    "ttlSeconds": ttl_seconds,
                    "expiresAt": _iso(exp),
                    "ephemeralAgentId": ephemeral_agent_id,
                    "ephemeralUsername": ephemeral_username,
                },
            )

        if _request_matches_path(event, DELEGATION_APPROVAL_PATH):
            if not _delegation_table():
                return _response(
                    500,
                    {
                        "errorCode": "MISCONFIGURED",
                        "message": "Server misconfigured",
                        "requestId": request_id,
                    },
                )
            caller_sub = _authorizer_claim(event, "sub")
            caller_username = _authorizer_claim(event, "cognito:username")
            if not caller_sub:
                return _response(
                    401,
                    {
                        "errorCode": "UNAUTHORIZED",
                        "message": "Missing or invalid caller identity",
                        "requestId": request_id,
                    },
                )
            caller_profile = _ddb_get_profile(caller_sub)
            if not caller_profile:
                return _response(
                    404,
                    {
                        "errorCode": "PROFILE_NOT_FOUND",
                        "message": "No profile for subject",
                        "requestId": request_id,
                    },
                )
            if not _ddb_bool(caller_profile, "enabled", default=False):
                return _response(
                    403,
                    {
                        "errorCode": "UNAUTHORIZED",
                        "message": "Profile disabled",
                        "requestId": request_id,
                    },
                )
            caller_profile_type = _profile_type(caller_profile)
            if caller_profile_type != "named":
                return _response(
                    403,
                    {
                        "errorCode": "UNAUTHORIZED",
                        "message": "Only named agent profiles may approve delegation requests",
                        "requestId": request_id,
                    },
                )
            payload = _parse_json_body(event)
            request_code = str(payload.get("requestCode") or "").strip()
            if not request_code:
                return _response(
                    400,
                    {
                        "errorCode": "INVALID_REQUEST",
                        "message": "Missing requestCode",
                        "requestId": request_id,
                    },
                )
            existing = _delegation_get(request_code)
            if not existing:
                return _response(
                    404,
                    {
                        "errorCode": "NOT_FOUND",
                        "message": "Delegation request not found",
                        "requestId": request_id,
                    },
                )
            if _delegation_expired(existing):
                return _response(
                    410,
                    {
                        "errorCode": "EXPIRED",
                        "message": "Delegation request expired",
                        "requestId": request_id,
                    },
                )
            try:
                out = _ddb().update_item(
                    TableName=_delegation_table(),
                    Key={"requestCode": {"S": request_code}},
                    ConditionExpression="#st = :pending AND expiresAtEpoch > :now_epoch",
                    UpdateExpression="SET #st = :approved, approvedAt = :approved_at, approvedBySub = :approved_by_sub, approvedByUsername = :approved_by_username",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":pending": {"S": "pending"},
                        ":approved": {"S": "approved"},
                        ":approved_at": {"S": _now_iso()},
                        ":approved_by_sub": {"S": caller_sub},
                        ":approved_by_username": {"S": caller_username},
                        ":now_epoch": {"N": str(_delegation_now_epoch())},
                    },
                    ReturnValues="ALL_NEW",
                )
            except Exception as e:
                if type(e).__name__ == "ConditionalCheckFailedException":
                    return _response(
                        409,
                        {
                            "errorCode": "INVALID_STATE",
                            "message": "Delegation request is not pending or is expired",
                            "requestId": request_id,
                        },
                    )
                raise
            attrs = out.get("Attributes") or {}
            payload_out = _delegation_item_to_payload(attrs, request_id=request_id)
            payload_out["kind"] = "agent-enablement.delegation.approval.v1"
            return _response(200, payload_out)

        if _request_matches_path(event, DELEGATION_STATUS_PATH):
            if not _delegation_table():
                return _response(
                    500,
                    {
                        "errorCode": "MISCONFIGURED",
                        "message": "Server misconfigured",
                        "requestId": request_id,
                    },
                )
            payload = _parse_json_body(event)
            request_code = str(payload.get("requestCode") or "").strip()
            if not request_code:
                return _response(
                    400,
                    {
                        "errorCode": "INVALID_REQUEST",
                        "message": "Missing requestCode",
                        "requestId": request_id,
                    },
                )
            existing = _delegation_get(request_code)
            if not existing:
                return _response(
                    404,
                    {
                        "errorCode": "NOT_FOUND",
                        "message": "Delegation request not found",
                        "requestId": request_id,
                    },
                )
            return _response(200, _delegation_item_to_payload(existing, request_id=request_id))

        auth_result: dict[str, Any] = {}
        claims: dict[str, Any] = {}
        input_username = ""
        auth_mode = "basic"
        if _request_matches_path(event, DELEGATION_REDEEM_PATH):
            if not _delegation_table():
                status_code = 500
                body = {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)
            if not USER_POOL_ID:
                status_code = 500
                body = {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)
            payload = _parse_json_body(event)
            request_code = str(payload.get("requestCode") or "").strip()
            if not request_code:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Missing requestCode",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)
            try:
                out = _ddb().update_item(
                    TableName=_delegation_table(),
                    Key={"requestCode": {"S": request_code}},
                    ConditionExpression="#st = :approved AND expiresAtEpoch > :now_epoch",
                    UpdateExpression="SET #st = :redeemed, redeemedAt = :redeemed_at",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":approved": {"S": "approved"},
                        ":redeemed": {"S": "redeemed"},
                        ":redeemed_at": {"S": _now_iso()},
                        ":now_epoch": {"N": str(_delegation_now_epoch())},
                    },
                    ReturnValues="ALL_NEW",
                )
            except Exception as e:
                if type(e).__name__ == "ConditionalCheckFailedException":
                    status_code = 401
                    body = {
                        "errorCode": "UNAUTHORIZED",
                        "message": "Delegation request is not redeemable",
                        "requestId": request_id,
                    }
                    wide_event["outcome"] = "unauthorized"
                    return _response(status_code, body)
                raise
            claims = out.get("Attributes") or {}
            ephemeral_username = _ddb_str(claims, "ephemeralUsername", default="").strip()
            ephemeral_agent_id = _ddb_str(claims, "ephemeralAgentId", default="").strip()
            if not ephemeral_username or not ephemeral_agent_id:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Invalid delegation request",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)
            generated_password = (
                f"{secrets.token_urlsafe(12)}A1!"
            )[:32]
            try:
                _cognito().admin_create_user(
                    UserPoolId=USER_POOL_ID,
                    Username=ephemeral_username,
                    MessageAction="SUPPRESS",
                )
            except Exception as e:
                if type(e).__name__ == "UsernameExistsException":
                    status_code = 401
                    body = {
                        "errorCode": "UNAUTHORIZED",
                        "message": "Delegation request already used",
                        "requestId": request_id,
                    }
                    wide_event["outcome"] = "unauthorized"
                    return _response(status_code, body)
                raise
            _cognito().admin_set_user_password(
                UserPoolId=USER_POOL_ID,
                Username=ephemeral_username,
                Password=generated_password,
                Permanent=True,
            )
            resp = _cognito().initiate_auth(
                ClientId=USER_POOL_CLIENT_ID,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": ephemeral_username, "PASSWORD": generated_password},
            )
            auth_mode = "delegation-redeem"
            auth_result = resp.get("AuthenticationResult") or {}
            input_username = ephemeral_username
        elif _request_matches_path(event, CREDENTIALS_REFRESH_PATH):
            auth_mode = "refresh-token"
            refresh_token = _parse_refresh_token(event)
            if not refresh_token:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Missing or invalid refresh token",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)
            try:
                resp = _cognito().initiate_auth(
                    ClientId=USER_POOL_CLIENT_ID,
                    AuthFlow="REFRESH_TOKEN_AUTH",
                    AuthParameters={"REFRESH_TOKEN": refresh_token},
                )
            except Exception:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Invalid refresh token",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)
            auth_result = resp.get("AuthenticationResult") or {}
            if not auth_result.get("RefreshToken"):
                # Cognito refresh auth usually omits RefreshToken. Preserve the inbound token.
                auth_result["RefreshToken"] = refresh_token
        else:
            basic = _parse_basic_auth(event)
            if not basic:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Missing or invalid Basic authorization",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)

            username, password = basic
            input_username = username
            try:
                resp = _cognito().initiate_auth(
                    ClientId=USER_POOL_CLIENT_ID,
                    AuthFlow="USER_PASSWORD_AUTH",
                    AuthParameters={"USERNAME": username, "PASSWORD": password},
                )
            except Exception:
                status_code = 401
                body = {
                    "errorCode": "UNAUTHORIZED",
                    "message": "Incorrect username or password",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "unauthorized"
                return _response(status_code, body)
            auth_result = resp.get("AuthenticationResult") or {}

        id_token = auth_result.get("IdToken") or ""
        access_token = auth_result.get("AccessToken") or ""
        refresh_token = auth_result.get("RefreshToken") or ""
        token_type = auth_result.get("TokenType") or ""
        expires_in = auth_result.get("ExpiresIn") or 0
        try:
            expires_in = int(expires_in)
        except Exception:
            expires_in = 0

        jwt_claims = _decode_jwt_claims(id_token)
        sub = jwt_claims.get("sub")
        iss = jwt_claims.get("iss")
        cognito_username = jwt_claims.get("cognito:username") or input_username
        if not cognito_username:
            cognito_username = "unknown"

        wide_event["principal"] = {
            "sub": sub,
            "issuer": iss,
            "username": cognito_username,
            "auth_mode": auth_mode,
        }

        if not sub:
            status_code = 401
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Missing subject claim",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)
        try:
            sub_b58 = uuid_text_to_base58_22(sub)
        except Exception:
            status_code = 401
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Invalid subject claim",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)

        if auth_mode == "delegation-redeem":
            try:
                _ddb().put_item(
                    TableName=PROFILE_TABLE_NAME,
                    Item={
                        "sub": {"S": sub},
                        "enabled": {"BOOL": True},
                        "profileType": {"S": "ephemeral"},
                        "credentialScope": {"S": "runtime"},
                        "assumeRoleArn": {"S": ASSUME_ROLE_RUNTIME_ARN},
                        "agentId": {"S": _ddb_str(claims, "ephemeralAgentId", default="ephemeral")},
                        "s3Bucket": {"S": UPLOAD_BUCKET},
                        "commsFilesBucket": {"S": COMMS_FILES_BUCKET},
                        "sqsQueueArn": {"S": SQS_QUEUE_ARN},
                        "inboxQueueArn": {"S": SQS_QUEUE_ARN},
                        "inboxQueueUrl": {"S": _queue_url_from_arn(SQS_QUEUE_ARN)},
                        "eventBusArn": {"S": EVENT_BUS_ARN},
                        "instructionText": {"S": "Ephemeral delegated profile"},
                    },
                )
            except Exception as e:
                status_code = 500
                body = {
                    "errorCode": "PROFILE_UPSERT_FAILED",
                    "message": f"Failed to upsert ephemeral profile: {e}",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)

        profile_item = _ddb_get_profile(sub)
        if not profile_item:
            status_code = 404
            body = {
                "errorCode": "PROFILE_NOT_FOUND",
                "message": "No profile for subject",
                "requestId": request_id,
            }
            wide_event["outcome"] = "not_found"
            return _response(status_code, body)

        enabled = _ddb_bool(profile_item, "enabled", default=False)
        if not enabled:
            status_code = 403
            body = {
                "errorCode": "UNAUTHORIZED",
                "message": "Profile disabled",
                "requestId": request_id,
            }
            wide_event["outcome"] = "unauthorized"
            return _response(status_code, body)

        scope = _credential_scope(profile_item)
        if scope == "invalid":
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Unsupported credentialScope",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)
        profile_type = _profile_type(profile_item)
        if profile_type == "invalid":
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Unsupported profileType",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)

        if scope == "provisioning":
            assume_role_arn = ASSUME_ROLE_PROVISIONING_ARN
            if not assume_role_arn:
                status_code = 500
                body = {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)
            if not CFN_EXECUTION_ROLE_ARN:
                status_code = 500
                body = {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)
            if not AGENT_WORKLOAD_BOUNDARY_ARN:
                status_code = 500
                body = {
                    "errorCode": "MISCONFIGURED",
                    "message": "Server misconfigured",
                    "requestId": request_id,
                }
                wide_event["outcome"] = "error"
                return _response(status_code, body)
        else:
            assume_role_arn = ASSUME_ROLE_RUNTIME_ARN

        profile_assume_role_arn = _ddb_str(profile_item, "assumeRoleArn", default="")
        # Safety: only allow profile role override if it matches the role for this credential scope.
        if profile_assume_role_arn and profile_assume_role_arn != assume_role_arn:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "assumeRoleArn not permitted",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)
        s3_bucket = _ddb_str(profile_item, "s3Bucket", default=UPLOAD_BUCKET)
        sqs_arn = _normalize_optional_arn(_ddb_str(profile_item, "sqsQueueArn", default=SQS_QUEUE_ARN))
        inbox_queue_arn = _normalize_optional_arn(_ddb_str(profile_item, "inboxQueueArn", default=""))
        inbox_queue_url = _ddb_str(profile_item, "inboxQueueUrl", default="")
        if not inbox_queue_url:
            inbox_queue_url = _queue_url_from_arn(inbox_queue_arn)
        bus_arn = _normalize_optional_arn(_ddb_str(profile_item, "eventBusArn", default=EVENT_BUS_ARN))
        agent_id = _ddb_str(profile_item, "agentId", default="")
        groups = profile_ddb_str_list(profile_item, "groups")
        comms_bucket = _ddb_str(profile_item, "commsFilesBucket", default=COMMS_FILES_BUCKET)
        if not assume_role_arn:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile missing assumeRoleArn",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)
        if scope == "runtime" and not agent_id:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile missing agentId",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)
        if scope == "runtime" and not inbox_queue_arn:
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile missing inboxQueueArn",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)

        issued_prefix = f"f/{sub_b58}/"

        # Avoid issuing empty profiles: if the runtime profile doesn't grant anything, reject.
        if scope == "runtime" and not any([s3_bucket, sqs_arn, inbox_queue_arn, bus_arn, comms_bucket]):
            status_code = 422
            body = {
                "errorCode": "INVALID_PROFILE",
                "message": "Profile grants no permissions",
                "requestId": request_id,
            }
            wide_event["outcome"] = "invalid_profile"
            return _response(status_code, body)

        wide_event["grants"] = {
            "s3_bucket": s3_bucket,
            "s3_prefix": issued_prefix,
            "sqs_queue_arn": sqs_arn,
            "inbox_queue_arn": inbox_queue_arn,
            "event_bus_arn": bus_arn,
            "comms_bucket": comms_bucket,
            "agent_id": agent_id,
            "credential_scope": scope,
            "cfn_execution_role_arn": CFN_EXECUTION_ROLE_ARN,
            "agent_workload_boundary_arn": AGENT_WORKLOAD_BOUNDARY_ARN,
            "assume_role_arn": assume_role_arn,
            "sub_b58": sub_b58,
            "profile_type": profile_type,
        }

        tags = [
            {"Key": "sub", "Value": sub},
            {"Key": "username", "Value": cognito_username[:256]},
            {"Key": "request_id", "Value": request_id[:256] if request_id else ""},
        ]
        if scope == "runtime":
            # Used by the runtime role policy to scope S3/SQS access.
            tags.append({"Key": "sub_b58", "Value": sub_b58})
            tags.append({"Key": "agent_id", "Value": agent_id[:256]})

        assume_kwargs = {
            "RoleArn": assume_role_arn,
            "RoleSessionName": _session_name(f"{cognito_username}-{sub[:8]}"),
            "DurationSeconds": _duration_seconds(),
            "SourceIdentity": sub,
            "Tags": tags,
        }

        assumed_sandbox = _sts().assume_role(**assume_kwargs)

        creds = assumed_sandbox.get("Credentials", {})
        expiration = creds.get("Expiration")
        if hasattr(expiration, "isoformat"):
            expiration_iso = expiration.isoformat()
        else:
            expiration_iso = str(expiration)

        agent_workshop_provisioning_creds: dict[str, Any] = {}
        agent_workshop_provisioning_expiration_iso = ""
        agent_workshop_runtime_creds: dict[str, Any] = {}
        agent_workshop_runtime_expiration_iso = ""
        workshop_sets_issued = False
        if agent_workshop_enabled and profile_type == "named":
            agent_workshop_assume_common_kwargs = {
                "RoleSessionName": _session_name(f"{cognito_username}-{sub[:8]}"),
                "DurationSeconds": _duration_seconds(),
                "SourceIdentity": sub,
                "Tags": [
                    {"Key": "sub", "Value": sub},
                    {"Key": "username", "Value": cognito_username[:256]},
                    {"Key": "request_id", "Value": request_id[:256] if request_id else ""},
                ],
            }

            agent_workshop_provisioning_assumed = _sts().assume_role(
                RoleArn=ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN,
                **agent_workshop_assume_common_kwargs,
            )
            agent_workshop_provisioning_creds = agent_workshop_provisioning_assumed.get(
                "Credentials", {}
            )
            agent_workshop_provisioning_exp = agent_workshop_provisioning_creds.get(
                "Expiration"
            )
            if hasattr(agent_workshop_provisioning_exp, "isoformat"):
                agent_workshop_provisioning_expiration_iso = (
                    agent_workshop_provisioning_exp.isoformat()
                )
            else:
                agent_workshop_provisioning_expiration_iso = str(
                    agent_workshop_provisioning_exp
                )

            agent_workshop_runtime_assumed = _sts().assume_role(
                RoleArn=ASSUME_ROLE_AGENT_WORKSHOP_RUNTIME_ARN,
                **agent_workshop_assume_common_kwargs,
            )
            agent_workshop_runtime_creds = agent_workshop_runtime_assumed.get(
                "Credentials", {}
            )
            agent_workshop_runtime_exp = agent_workshop_runtime_creds.get("Expiration")
            if hasattr(agent_workshop_runtime_exp, "isoformat"):
                agent_workshop_runtime_expiration_iso = (
                    agent_workshop_runtime_exp.isoformat()
                )
            else:
                agent_workshop_runtime_expiration_iso = str(agent_workshop_runtime_exp)

        issued_at = _now_iso()
        ssm_stage = _ssm_keys_stage()
        ssm_shared_base_path = f"/agent-enablement/{ssm_stage}/shared/"
        ssm_agent_base_path_template = f"/agent-enablement/{ssm_stage}/agent/<principal.sub>/"
        ssm_grant_resources: list[str] = []
        enablement_account_id = _arn_account_id(assume_role_arn)
        enablement_region = (_aws_region() or "").strip()
        if enablement_region and enablement_account_id:
            ssm_grant_resources = [
                f"arn:aws:ssm:{enablement_region}:{enablement_account_id}:parameter/agent-enablement/{ssm_stage}/shared/*",
                f"arn:aws:ssm:{enablement_region}:{enablement_account_id}:parameter/agent-enablement/{ssm_stage}/agent/<principal.sub>/*",
            ]
        else:
            # Best-effort: still return the paths for humans/agents to use.
            ssm_grant_resources = ["*"]
        execute_api_grant_resources: list[str] = []
        if enablement_account_id:
            execute_api_grant_resources = [
                f"arn:aws:execute-api:us-east-2:{enablement_account_id}:*"
            ]
        else:
            execute_api_grant_resources = ["*"]

        grants: list[dict[str, Any]] = []
        comms_write_prefixes, comms_read_prefixes = _comms_prefixes(agent_id, groups)
        if scope == "provisioning":
            grants.append(
                {
                    "service": "cloudformation",
                    "actions": [
                        "cloudformation:CreateStack",
                        "cloudformation:UpdateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:CreateChangeSet",
                        "cloudformation:ExecuteChangeSet",
                        "cloudformation:DeleteChangeSet",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:DescribeStackResources",
                        "cloudformation:DescribeChangeSet",
                        "cloudformation:GetTemplate",
                        "cloudformation:GetTemplateSummary",
                        "cloudformation:ListStackResources",
                        "cloudformation:ListStacks",
                        "cloudformation:ValidateTemplate",
                    ],
                    "resources": ["*"],
                    "instructions": (
                        "Use CloudFormation with stack names matching "
                        "'agent-<principal.sub>-*', set RoleArn to references.provisioning.cfnExecutionRoleArn, "
                        "set IAM role PermissionsBoundary to references.provisioning.requiredRoleBoundaryArn, "
                        "and include agent_sub/agent_username tags."
                    ),
                }
            )
            grants.append(
                {
                    "service": "iam",
                    "actions": ["iam:PassRole"],
                    "resources": [CFN_EXECUTION_ROLE_ARN],
                    "instructions": "Pass role only to cloudformation.amazonaws.com.",
                }
            )
        else:
            if s3_bucket:
                grants.append(
                    {
                        "service": "s3",
                        "actions": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:AbortMultipartUpload",
                            "s3:CreateMultipartUpload",
                            "s3:UploadPart",
                            "s3:CompleteMultipartUpload",
                            "s3:ListMultipartUploadParts",
                            "s3:ListBucketMultipartUploads",
                            "s3:ListBucket",
                        ],
                        "resources": [f"arn:aws:s3:::{s3_bucket}/{issued_prefix}*"],
                        "instructions": "Upload only to the assigned prefix.",
                    }
                )
            if comms_bucket and (comms_write_prefixes or comms_read_prefixes):
                grants.append(
                    {
                        "service": "s3",
                        "actions": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:AbortMultipartUpload",
                            "s3:CreateMultipartUpload",
                            "s3:UploadPart",
                            "s3:CompleteMultipartUpload",
                            "s3:ListMultipartUploadParts",
                            "s3:ListBucket",
                        ],
                        "resources": [f"arn:aws:s3:::{comms_bucket}/*"],
                        "instructions": "Use the shared-files prefixes in references.messages.sharedFiles.",
                    }
                )
            if sqs_arn:
                grants.append(
                    {
                        "service": "sqs",
                        "actions": ["sqs:SendMessage"],
                        "resources": [sqs_arn],
                    }
                )
            if inbox_queue_arn:
                grants.append(
                    {
                        "service": "sqs",
                        "actions": [
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:ChangeMessageVisibility",
                            "sqs:GetQueueAttributes",
                        ],
                        "resources": [inbox_queue_arn],
                    }
                )
            if bus_arn:
                grants.append(
                    {
                        "service": "events",
                        "actions": ["events:PutEvents"],
                        "resources": [bus_arn],
                    }
                )
            grants.append(
                {
                    "service": "execute-api",
                    "actions": ["execute-api:Invoke"],
                    "resources": execute_api_grant_resources,
                    "instructions": "Invoke API Gateway APIs in the sandbox account within us-east-2.",
                }
            )
            grants.append(
                {
                    "service": "ssm",
                    "actions": [
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                    ],
                    "resources": ssm_grant_resources,
                    "instructions": (
                        "Read SecureString parameters under references.ssmKeys.sharedBasePath "
                        "and your own per-agent path (references.ssmKeys.agentBasePathTemplate)."
                    ),
                }
            )

        base_url = _best_effort_base_url(event)
        credentials_invoke_url = _join_url(base_url, CREDENTIALS_PATH)
        taskboard_invoke_url = _join_url(base_url, "/v1/taskboard")
        shortlink_create_url = (SHORTLINK_CREATE_URL or "").strip() or _join_url(
            base_url, SHORTLINK_CREATE_PATH
        )
        shortlink_redirect_base_url = (
            (SHORTLINK_REDIRECT_BASE_URL or "").strip()
            or _join_url(base_url, SHORTLINK_REDIRECT_PREFIX)
        )

        enablement_contents_url = _normalize_enablement_contents_url(ENABLEMENT_INDEX_URL)
        readme_key = _enablement_key(enablement_contents_url, "artifacts/README.md")
        readme_url = _join_url(ENABLEMENT_ARTIFACTS_ROOT_URL, "README.md")
        readme_s3_uri = (
            f"s3://{comms_bucket}/{readme_key}" if comms_bucket and readme_key else ""
        )
        docs = {
            "readmeUrl": readme_url,
            "readmeS3Uri": readme_s3_uri,
            "readmeKey": readme_key,
        }

        enablement_refs: dict[str, Any] = {
            "version": ENABLEMENT_VERSION,
            "indexUrl": enablement_contents_url,
            "artifactsRootUrl": ENABLEMENT_ARTIFACTS_ROOT_URL,
            "skillsRootUrl": ENABLEMENT_SKILLS_ROOT_URL,
            "docs": docs,
        }

        cognito_tokens: dict[str, Any] = {}
        if id_token:
            cognito_tokens["idToken"] = id_token
        if access_token:
            cognito_tokens["accessToken"] = access_token
        if refresh_token:
            cognito_tokens["refreshToken"] = refresh_token
        if token_type:
            cognito_tokens["tokenType"] = token_type
        if expires_in:
            cognito_tokens["expiresIn"] = expires_in

        issuer = (iss or "").strip()
        cognito_refs = {
            "issuer": issuer,
            "userPoolId": _parse_user_pool_id_from_issuer(issuer),
            "userPoolClientId": USER_POOL_CLIENT_ID,
            "openidConfigurationUrl": _join_url(issuer, ".well-known/openid-configuration")
            if issuer
            else "",
            "jwksUrl": _join_url(issuer, ".well-known/jwks.json") if issuer else "",
            "reauth": {"mode": "refresh-token-first-fallback-basic"},
        }
        references = {
            "awsRegion": (_aws_region() or ""),
            "credentialScope": scope,
            "docs": docs,
            "enablement": enablement_refs,
            "apiAccess": {
                "apiKeySsmParameterName": API_KEY_SSM_PARAMETER_NAME,
                "requiredHeaders": [
                    h.strip().lower()
                    for h in API_REQUIRED_HEADERS.split(",")
                    if h.strip()
                ],
            },
            "ssmKeys": {
                "stage": ssm_stage,
                "sharedBasePath": ssm_shared_base_path,
                "agentBasePathTemplate": ssm_agent_base_path_template,
                "docs": docs,
            },
            "cognito": cognito_refs,
            "provisioning": {
                "cfnExecutionRoleArn": CFN_EXECUTION_ROLE_ARN,
                "requiredRoleBoundaryArn": AGENT_WORKLOAD_BOUNDARY_ARN,
                "stackNamePattern": STACK_NAME_PATTERN_TEMPLATE,
                "requiredTags": ["agent_sub", "agent_username"],
                "docs": docs,
            },
            "shortlinks": {
                "createUrl": shortlink_create_url,
                "redirectBaseUrl": shortlink_redirect_base_url,
                "createPath": SHORTLINK_CREATE_PATH,
                "redirectPrefix": SHORTLINK_REDIRECT_PREFIX,
                "docs": docs,
            },
            "taskboard": {
                "invokeUrl": taskboard_invoke_url,
                "docs": docs,
            },
            "s3": {
                "bucket": s3_bucket,
                "allowedPrefix": issued_prefix,
                "docs": docs,
            },
            "sqs": {
                "queueArn": sqs_arn,
                "queueName": _parse_queue_name_from_arn(sqs_arn),
            },
            "eventbridge": {
                "eventBusArn": bus_arn,
                "eventBusName": _parse_event_bus_name_from_arn(bus_arn),
            },
            "messages": {
                "agentId": agent_id,
                "groups": groups,
                "eventBusArn": bus_arn,
                "eventBusName": _parse_event_bus_name_from_arn(bus_arn),
                "inboxQueueArn": inbox_queue_arn,
                "inboxQueueName": _parse_queue_name_from_arn(inbox_queue_arn),
                "inboxQueueUrl": inbox_queue_url,
                "sharedFiles": {
                    "bucket": comms_bucket,
                    "allowedWritePrefixes": comms_write_prefixes,
                    "allowedReadPrefixes": comms_read_prefixes,
                },
                "routing": {
                    "sourceFormat": "agents.messages.sub.<principal.sub>",
                    "detailType": "agent.message.v2",
                    "toUsernameField": "toUsername",
                },
                "docs": docs,
            },
        }

        status_code = 200
        next_bundle_after = _iso(datetime.now(timezone.utc) + timedelta(hours=24))
        body = {
            "kind": "agent-enablement.credentials.v2",
            "schemaVersion": SCHEMA_VERSION,
            "requestId": request_id,
            "principal": {"sub": sub, "issuer": iss, "username": cognito_username},
            "issuedAt": issued_at,
            "expiresAt": expiration_iso,
            "auth": {
                "credentialsEndpoint": credentials_invoke_url,
                "cognitoClientId": USER_POOL_CLIENT_ID,
                "renewalPolicy": {
                    "refreshBeforeSeconds": 60,
                    "maxRenewAttempts": 3,
                    "backoffSeconds": [1, 2, 4],
                },
            },
            "runtime": {
                "serviceEndpoints": {
                    "taskboard": taskboard_invoke_url,
                },
                "bundlePolicy": {
                    "enablementVersion": ENABLEMENT_VERSION,
                    "nextBundleAfter": next_bundle_after,
                    "forceRebundleOnVersionMismatch": True,
                },
            },
            "cognitoTokens": cognito_tokens,
            "credentials": {
                "accessKeyId": creds.get("AccessKeyId"),
                "secretAccessKey": creds.get("SecretAccessKey"),
                "sessionToken": creds.get("SessionToken"),
                "expiration": expiration_iso,
            },
            "grants": grants,
            "constraints": {
                "ttlSeconds": _duration_seconds(),
                "uploadPrefixBase58": sub_b58,
                "credentialScope": scope,
            },
            "references": references,
            "humanUploadGuidance": {
                "mode": "agent-presigns",
                "recommendedExpiresInSeconds": 900,
                "notes": [
                    "Generate presigned PUT URLs for keys under your principal-scoped prefix.",
                    "Presigned URLs are bearer secrets. Treat them like credentials.",
                    "For large files, use multipart upload and presign each part.",
                ],
            },
        }
        enablement_set = {
            "accountId": _arn_account_id(assume_role_arn),
            "awsRegion": _aws_region(),
            "credentialScope": scope,
            "issuedAt": issued_at,
            "expiresAt": expiration_iso,
            "credentials": body["credentials"],
            "references": body["references"],
            "grants": body["grants"],
            "constraints": body["constraints"],
        }
        body["credentialSets"] = {
            "agentEnablement": enablement_set,
        }

        if agent_workshop_enabled and profile_type == "named":
            agent_workshop_region = (AGENT_WORKSHOP_REGION or "").strip() or _aws_region()
            agent_workshop_account_id = (AGENT_WORKSHOP_ACCOUNT_ID or "").strip() or _arn_account_id(
                ASSUME_ROLE_AGENT_WORKSHOP_PROVISIONING_ARN
            )
            agent_workshop_provisioning_grants = [
                {
                    "service": "cloudformation",
                    "actions": [
                        "cloudformation:CreateStack",
                        "cloudformation:UpdateStack",
                        "cloudformation:DeleteStack",
                        "cloudformation:CreateChangeSet",
                        "cloudformation:ExecuteChangeSet",
                        "cloudformation:DeleteChangeSet",
                        "cloudformation:DescribeStacks",
                        "cloudformation:DescribeStackEvents",
                        "cloudformation:DescribeStackResources",
                        "cloudformation:DescribeChangeSet",
                        "cloudformation:GetTemplate",
                        "cloudformation:GetTemplateSummary",
                        "cloudformation:ListStackResources",
                        "cloudformation:ListStacks",
                        "cloudformation:ValidateTemplate",
                    ],
                    "resources": ["*"],
                    "instructions": (
                        "Use CloudFormation with stack names matching "
                        "'agent-<principal.sub>-*', set RoleArn to references.provisioning.cfnExecutionRoleArn, "
                        "set IAM role PermissionsBoundary to references.provisioning.requiredRoleBoundaryArn, "
                        "and include agent_sub/agent_username tags."
                    ),
                },
                {
                    "service": "iam",
                    "actions": ["iam:PassRole"],
                    "resources": [AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN],
                    "instructions": "Pass role only to cloudformation.amazonaws.com.",
                },
                {
                    "service": "sts",
                    "actions": ["sts:GetCallerIdentity"],
                    "resources": ["*"],
                },
            ]

            agent_workshop_runtime_grants = [
                {
                    "service": "read-only",
                    "actions": ["ReadOnlyAccess (AWS managed policy)"],
                    "resources": ["*"],
                    "instructions": (
                        "Broad read-only access across AWS services for troubleshooting. IAM/Organizations/"
                        "Account/Billing/Support are explicitly blocked by the runtime permissions boundary."
                    ),
                },
                {
                    "service": "sns",
                    "actions": ["sns:Publish"],
                    "resources": [
                        f"arn:aws:sns:{agent_workshop_region}:{agent_workshop_account_id}:*",
                    ],
                    "instructions": (
                        "Publish only within your agent namespace. Topics must be tagged with "
                        "agent_sub/agent_username matching your principal tags. Naming topics "
                        "'agent-<principal.sub>-*' is recommended for discoverability."
                    ),
                },
                {
                    "service": "sqs",
                    "actions": [
                        "sqs:SendMessage",
                        "sqs:SendMessageBatch",
                        "sqs:DeleteMessage",
                        "sqs:DeleteMessageBatch",
                        "sqs:ChangeMessageVisibility",
                    ],
                    "resources": [
                        f"arn:aws:sqs:{agent_workshop_region}:{agent_workshop_account_id}:*",
                    ],
                    "instructions": (
                        "Send/delete/change-visibility is allowed only on queues tagged with "
                        "agent_sub/agent_username matching your principal tags."
                    ),
                },
                {
                    "service": "s3",
                    "actions": ["s3:PutObject", "s3:DeleteObject"],
                    "resources": [
                        "arn:aws:s3:::agent-<principal.sub>-*/*",
                    ],
                    "instructions": (
                        "S3 object writes/deletes are allowed only in buckets named with your full principal sub. "
                        "If you want direct S3 write access in this account, set an explicit BucketName like "
                        "'agent-<principal.sub>-data-<accountId>' in your template."
                    ),
                },
                {
                    "service": "cloudfront",
                    "actions": ["cloudfront:CreateInvalidation"],
                    "resources": [
                        f"arn:aws:cloudfront::{agent_workshop_account_id}:distribution/*",
                    ],
                    "instructions": (
                        "Invalidations are allowed only for distributions tagged with "
                        "agent_sub/agent_username matching your principal tags."
                    ),
                },
                {
                    "service": "dynamodb",
                    "actions": [
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:TransactWriteItems",
                    ],
                    "resources": [
                        f"arn:aws:dynamodb:{agent_workshop_region}:{agent_workshop_account_id}:table/*",
                        f"arn:aws:dynamodb:{agent_workshop_region}:{agent_workshop_account_id}:table/*/index/*",
                    ],
                    "instructions": (
                        "Writes are allowed only for tables tagged with agent_sub/agent_username "
                        "matching your principal tags."
                    ),
                },
                {
                    "service": "events",
                    "actions": ["events:PutEvents"],
                    "resources": [
                        f"arn:aws:events:{agent_workshop_region}:{agent_workshop_account_id}:event-bus/*",
                    ],
                    "instructions": (
                        "PutEvents is allowed only for event buses tagged with agent_sub/agent_username "
                        "matching your principal tags."
                    ),
                },
                {
                    "service": "states",
                    "actions": ["states:StartExecution", "states:StopExecution"],
                    "resources": [
                        f"arn:aws:states:{agent_workshop_region}:{agent_workshop_account_id}:stateMachine:*",
                        f"arn:aws:states:{agent_workshop_region}:{agent_workshop_account_id}:execution:*:*",
                    ],
                    "instructions": (
                        "StartExecution is allowed only for state machines tagged with agent_sub/agent_username "
                        "matching your principal tags."
                    ),
                },
                {
                    "service": "bedrock",
                    "actions": [
                        "bedrock:Converse",
                        "bedrock:ConverseStream",
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream",
                    ],
                    "resources": ["*"],
                    "instructions": (
                        "Bedrock runtime consumption is allowed in select regions only (currently us-east-1, us-west-2). "
                        "You may need to run Bedrock calls with AWS_REGION set to one of those regions."
                    ),
                },
                {
                    "service": "secretsmanager",
                    "actions": ["secretsmanager:GetSecretValue"],
                    "resources": [f"arn:aws:secretsmanager:{agent_workshop_region}:{agent_workshop_account_id}:secret:*"],
                    "instructions": (
                        "Secret reads are allowed only for secrets tagged with agent_sub/agent_username "
                        "matching your principal tags."
                    ),
                },
                {
                    "service": "kms",
                    "actions": ["kms:Decrypt"],
                    "resources": [f"arn:aws:kms:{agent_workshop_region}:{agent_workshop_account_id}:key/*"],
                    "instructions": (
                        "Decrypt is allowed only for KMS keys tagged with agent_sub/agent_username "
                        "matching your principal tags (typically used with tagged secrets)."
                    ),
                },
            ]

            agent_workshop_provisioning_set = {
                "accountId": agent_workshop_account_id,
                "awsRegion": agent_workshop_region,
                "credentialScope": "provisioning",
                "issuedAt": issued_at,
                "expiresAt": agent_workshop_provisioning_expiration_iso,
                "credentials": {
                    "accessKeyId": agent_workshop_provisioning_creds.get("AccessKeyId"),
                    "secretAccessKey": agent_workshop_provisioning_creds.get("SecretAccessKey"),
                    "sessionToken": agent_workshop_provisioning_creds.get("SessionToken"),
                    "expiration": agent_workshop_provisioning_expiration_iso,
                },
                "grants": agent_workshop_provisioning_grants,
                "constraints": {
                    "ttlSeconds": _duration_seconds(),
                    "credentialScope": "provisioning",
                },
                "references": {
                    "awsRegion": agent_workshop_region,
                    "credentialScope": "provisioning",
                    "docs": docs,
                    "provisioning": {
                        "cfnExecutionRoleArn": AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN,
                        "requiredRoleBoundaryArn": AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN,
                        "stackNamePattern": STACK_NAME_PATTERN_TEMPLATE,
                        "requiredTags": ["agent_sub", "agent_username"],
                        "docs": docs,
                    },
                },
            }

            agent_workshop_runtime_set = {
                "accountId": agent_workshop_account_id,
                "awsRegion": agent_workshop_region,
                "credentialScope": "runtime",
                "issuedAt": issued_at,
                "expiresAt": agent_workshop_runtime_expiration_iso,
                "credentials": {
                    "accessKeyId": agent_workshop_runtime_creds.get("AccessKeyId"),
                    "secretAccessKey": agent_workshop_runtime_creds.get("SecretAccessKey"),
                    "sessionToken": agent_workshop_runtime_creds.get("SessionToken"),
                    "expiration": agent_workshop_runtime_expiration_iso,
                },
                "grants": agent_workshop_runtime_grants,
                "constraints": {
                    "ttlSeconds": _duration_seconds(),
                    "credentialScope": "runtime",
                },
                "references": {
                    "awsRegion": agent_workshop_region,
                    "credentialScope": "runtime",
                    "docs": docs,
                    "provisioning": {
                        "cfnExecutionRoleArn": AGENT_WORKSHOP_CFN_EXECUTION_ROLE_ARN,
                        "requiredRoleBoundaryArn": AGENT_WORKSHOP_WORKLOAD_BOUNDARY_ARN,
                        "stackNamePattern": STACK_NAME_PATTERN_TEMPLATE,
                        "requiredTags": ["agent_sub", "agent_username"],
                        "docs": docs,
                    },
                    "runtime": {
                        "requiredTags": ["agent_sub", "agent_username"],
                        "docs": docs,
                    },
                },
            }
            body["credentialSets"]["agentAWSWorkshopProvisioning"] = (
                agent_workshop_provisioning_set
            )
            body["credentialSets"]["agentAWSWorkshopRuntime"] = (
                agent_workshop_runtime_set
            )
            workshop_sets_issued = True

        wide_event["outcome"] = "success"
        wide_event["workshop_sets_issued"] = workshop_sets_issued
        wide_event["status_code"] = 200
        return _response(status_code, body)
    except Exception as exc:
        wide_event["outcome"] = "error"
        wide_event["status_code"] = status_code
        wide_event["error"] = {"type": type(exc).__name__, "message": str(exc)}
        status_code = 500
        body = {
            "errorCode": "STS_ISSUE_FAILED",
            "message": "Failed to issue scoped credentials",
            "requestId": request_id,
        }
        return _response(status_code, body)
    finally:
        wide_event["duration_ms"] = int((time.time() - start) * 1000)
        # Never log credential material.
        print(json.dumps(wide_event, separators=(",", ":"), sort_keys=True))
